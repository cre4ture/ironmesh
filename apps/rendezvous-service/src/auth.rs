use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::FromRequestParts;
use common::NodeId;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio_rustls::server::TlsStream;
use tower::Service;
use transport_sdk::peer::PeerIdentity;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone)]
pub struct AuthenticatedNode {
    pub node_id: NodeId,
}

#[derive(Debug, Clone, Default)]
pub struct MaybeAuthenticatedNode(pub Option<AuthenticatedNode>);

impl MaybeAuthenticatedNode {
    pub fn node_id(&self) -> Option<NodeId> {
        self.0.as_ref().map(|node| node.node_id)
    }
}

impl<S> FromRequestParts<S> for MaybeAuthenticatedNode
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        let authenticated = parts.extensions.get::<AuthenticatedNode>().cloned();
        std::future::ready(Ok(Self(authenticated)))
    }
}

pub fn peer_identity_key(identity: &PeerIdentity) -> String {
    match identity {
        PeerIdentity::Node(node_id) => format!("node:{node_id}"),
        PeerIdentity::Device(device_id) => format!("device:{device_id}"),
    }
}

pub fn require_authenticated_node(
    mtls_enabled: bool,
    authenticated_node: &MaybeAuthenticatedNode,
) -> Result<Option<NodeId>> {
    if !mtls_enabled {
        return Ok(None);
    }

    authenticated_node
        .node_id()
        .map(Some)
        .context("rendezvous mTLS requires an authenticated node certificate")
}

pub fn ensure_authenticated_peer_identity(
    mtls_enabled: bool,
    authenticated_node: &MaybeAuthenticatedNode,
    identity: &PeerIdentity,
    field_name: &str,
) -> Result<()> {
    let Some(authenticated_node_id) = require_authenticated_node(mtls_enabled, authenticated_node)?
    else {
        return Ok(());
    };

    match identity {
        PeerIdentity::Node(node_id) if *node_id == authenticated_node_id => Ok(()),
        PeerIdentity::Node(node_id) => bail!(
            "{field_name} node_id {node_id} does not match authenticated rendezvous client node_id {authenticated_node_id}"
        ),
        PeerIdentity::Device(device_id) => bail!(
            "{field_name} device identity {device_id} is not allowed on the mTLS-authenticated rendezvous control plane"
        ),
    }
}

#[derive(Clone)]
pub struct WithAuthenticatedNode<S> {
    inner: S,
    authenticated_node: AuthenticatedNode,
}

impl<S> WithAuthenticatedNode<S> {
    pub fn new(inner: S, authenticated_node: AuthenticatedNode) -> Self {
        Self {
            inner,
            authenticated_node,
        }
    }
}

impl<S, B> Service<axum::http::Request<B>> for WithAuthenticatedNode<S>
where
    S: Service<axum::http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.authenticated_node.clone());
        self.inner.call(req)
    }
}

#[derive(Clone)]
pub struct MtlsAuthenticatedNodeAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl MtlsAuthenticatedNodeAcceptor {
    pub fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            inner: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for MtlsAuthenticatedNodeAcceptor
where
    axum_server::tls_rustls::RustlsAcceptor: axum_server::accept::Accept<
            tokio::net::TcpStream,
            S,
            Stream = TlsStream<tokio::net::TcpStream>,
        >,
    <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
        tokio::net::TcpStream,
        S,
    >>::Service: Send + 'static,
    <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
        tokio::net::TcpStream,
        S,
    >>::Future: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<tokio::net::TcpStream>;
    type Service = WithAuthenticatedNode<
        <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
            tokio::net::TcpStream,
            S,
        >>::Service,
    >;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls_stream, service) = fut.await?;
            let authenticated_node = authenticated_node_from_tls_stream(&tls_stream)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err))?;
            Ok((
                tls_stream,
                WithAuthenticatedNode::new(service, authenticated_node),
            ))
        })
    }
}

pub fn authenticated_node_from_tls_stream<T>(
    tls_stream: &TlsStream<T>,
) -> Result<AuthenticatedNode> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn
        .peer_certificates()
        .context("missing peer certificate")?;

    let node_id = extract_node_id_from_peer_certs(certs)?;
    Ok(AuthenticatedNode { node_id })
}

pub fn build_mtls_rustls_config(
    client_ca_cert_path: &std::path::PathBuf,
    cert_path: &std::path::PathBuf,
    key_path: &std::path::PathBuf,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_reader = BufReader::new(
        File::open(client_ca_cert_path)
            .with_context(|| format!("failed reading {}", client_ca_cert_path.display()))?,
    );
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
        let cert = cert.context("failed parsing rendezvous client CA certificate")?;
        roots
            .add(cert)
            .context("failed adding rendezvous client CA certificate to trust store")?;
    }

    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("failed reading {}", cert_path.display()))?,
    );
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed parsing rendezvous TLS certificate chain")?;

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("failed reading {}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing rendezvous TLS private key")?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed creating rendezvous client certificate verifier")?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .context("failed creating rendezvous rustls server config")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

fn extract_node_id_from_peer_certs(certs: &[CertificateDer<'_>]) -> Result<NodeId> {
    let cert = certs
        .first()
        .context("missing end-entity peer certificate")?;

    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("failed parsing peer certificate")?;

    for extension in parsed.extensions() {
        let parsed_extension = extension.parsed_extension();
        if let ParsedExtension::SubjectAlternativeName(san) = parsed_extension {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name
                    && let Some(node_id) = parse_node_id_from_san_uri(uri)
                {
                    return Ok(node_id);
                }
            }
        }
    }

    bail!("missing urn:ironmesh:node:<uuid> SAN URI in peer certificate")
}

fn parse_node_id_from_san_uri(uri: &str) -> Option<NodeId> {
    let prefix = "urn:ironmesh:node:";
    uri.strip_prefix(prefix)
        .and_then(|rest| rest.trim().parse::<NodeId>().ok())
}
