use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::FromRequestParts;
use common::{DeviceId, NodeId};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio_rustls::server::TlsStream;
use tower::Service;
use transport_sdk::peer::PeerIdentity;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

use crate::config::{RendezvousMtlsConfig, RendezvousServerTlsIdentity};

#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub identity: PeerIdentity,
}

#[derive(Debug, Clone, Default)]
pub struct MaybeAuthenticatedPeer(pub Option<AuthenticatedPeer>);

impl MaybeAuthenticatedPeer {
    pub fn identity(&self) -> Option<&PeerIdentity> {
        self.0.as_ref().map(|peer| &peer.identity)
    }
}

impl<S> FromRequestParts<S> for MaybeAuthenticatedPeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        let authenticated = parts.extensions.get::<AuthenticatedPeer>().cloned();
        std::future::ready(Ok(Self(authenticated)))
    }
}

pub fn require_authenticated_node(
    mtls_enabled: bool,
    authenticated_peer: &MaybeAuthenticatedPeer,
) -> Result<Option<NodeId>> {
    if !mtls_enabled {
        return Ok(None);
    }

    match authenticated_peer.identity() {
        Some(PeerIdentity::Node(node_id)) => Ok(Some(*node_id)),
        Some(PeerIdentity::Device(device_id)) => bail!(
            "rendezvous mTLS requires an authenticated node certificate, got device:{device_id}"
        ),
        None => bail!("rendezvous mTLS requires an authenticated peer certificate"),
    }
}

pub fn ensure_authenticated_peer_identity(
    mtls_enabled: bool,
    authenticated_peer: &MaybeAuthenticatedPeer,
    identity: &PeerIdentity,
    field_name: &str,
) -> Result<()> {
    if !mtls_enabled {
        return Ok(());
    }
    let Some(authenticated_identity) = authenticated_peer.identity() else {
        bail!("rendezvous mTLS requires an authenticated peer certificate");
    };

    if authenticated_identity == identity {
        Ok(())
    } else {
        bail!(
            "{field_name} {identity} does not match authenticated rendezvous client {authenticated_identity}"
        )
    }
}

#[derive(Clone)]
pub struct WithAuthenticatedPeer<S> {
    inner: S,
    authenticated_peer: Option<AuthenticatedPeer>,
}

impl<S> WithAuthenticatedPeer<S> {
    pub fn new(inner: S, authenticated_peer: Option<AuthenticatedPeer>) -> Self {
        Self {
            inner,
            authenticated_peer,
        }
    }
}

impl<S, B> Service<axum::http::Request<B>> for WithAuthenticatedPeer<S>
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
        if let Some(authenticated_peer) = self.authenticated_peer.clone() {
            req.extensions_mut().insert(authenticated_peer);
        }
        self.inner.call(req)
    }
}

#[derive(Clone)]
pub struct MtlsAuthenticatedPeerAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl MtlsAuthenticatedPeerAcceptor {
    pub fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            inner: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for MtlsAuthenticatedPeerAcceptor
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
    type Service = WithAuthenticatedPeer<
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
            let authenticated_peer = authenticated_peer_from_tls_stream(&tls_stream)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err))?;
            Ok((
                tls_stream,
                WithAuthenticatedPeer::new(service, authenticated_peer),
            ))
        })
    }
}

pub fn authenticated_peer_from_tls_stream<T>(
    tls_stream: &TlsStream<T>,
) -> Result<Option<AuthenticatedPeer>> {
    let (_, conn) = tls_stream.get_ref();
    let Some(certs) = conn.peer_certificates() else {
        return Ok(None);
    };

    let identity = extract_peer_identity_from_peer_certs(certs)?;
    Ok(Some(AuthenticatedPeer { identity }))
}

pub fn build_mtls_rustls_config(
    mtls: &RendezvousMtlsConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_reader = BufReader::new(
        File::open(&mtls.client_ca_cert_path)
            .with_context(|| format!("failed reading {}", mtls.client_ca_cert_path.display()))?,
    );
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
        let cert = cert.context("failed parsing rendezvous client CA certificate")?;
        roots
            .add(cert)
            .context("failed adding rendezvous client CA certificate to trust store")?;
    }

    let (cert_chain, key) = match &mtls.server_identity {
        RendezvousServerTlsIdentity::Files {
            cert_path,
            key_path,
        } => {
            let mut cert_reader = BufReader::new(
                File::open(cert_path)
                    .with_context(|| format!("failed reading {}", cert_path.display()))?,
            );
            let cert_chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_reader_iter(&mut cert_reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("failed parsing rendezvous TLS certificate chain")?;

            let mut key_reader = BufReader::new(
                File::open(key_path)
                    .with_context(|| format!("failed reading {}", key_path.display()))?,
            );
            let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
                .context("failed parsing rendezvous TLS private key")?;
            (cert_chain, key)
        }
        RendezvousServerTlsIdentity::InlinePem { cert_pem, key_pem } => {
            let mut cert_reader = BufReader::new(cert_pem.as_bytes());
            let cert_chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_reader_iter(&mut cert_reader)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("failed parsing rendezvous TLS certificate chain")?;

            let mut key_reader = BufReader::new(key_pem.as_bytes());
            let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
                .context("failed parsing rendezvous TLS private key")?;
            (cert_chain, key)
        }
    };

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
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

fn extract_peer_identity_from_peer_certs(certs: &[CertificateDer<'_>]) -> Result<PeerIdentity> {
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
                    && let Some(identity) = parse_peer_identity_from_san_uri(uri)
                {
                    return Ok(identity);
                }
            }
        }
    }

    bail!("missing urn:ironmesh:(node|device):<uuid> SAN URI in peer certificate")
}

fn parse_peer_identity_from_san_uri(uri: &str) -> Option<PeerIdentity> {
    if let Some(rest) = uri.strip_prefix("urn:ironmesh:node:") {
        return rest.trim().parse::<NodeId>().ok().map(PeerIdentity::Node);
    }
    if let Some(rest) = uri.strip_prefix("urn:ironmesh:device:") {
        return rest
            .trim()
            .parse::<DeviceId>()
            .ok()
            .map(PeerIdentity::Device);
    }
    None
}
