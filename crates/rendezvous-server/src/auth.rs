use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::{FromRequestParts, connect_info::ConnectInfo};
use common::ClusterId;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio_rustls::server::TlsStream;
use tower::Service;
use transport_sdk::peer::PeerIdentity;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

use crate::{RendezvousClientCa, RendezvousMtlsConfig, RendezvousServerTlsIdentity};

#[derive(Debug, Clone)]
pub(crate) struct AuthenticatedPeer {
    pub(crate) identity: PeerIdentity,
    pub(crate) cluster_id: Option<ClusterId>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MaybeAuthenticatedPeer(pub(crate) Option<AuthenticatedPeer>);

impl MaybeAuthenticatedPeer {
    pub(crate) fn identity(&self) -> Option<&PeerIdentity> {
        self.0.as_ref().map(|peer| &peer.identity)
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MaybeObservedPeerAddr(pub(crate) Option<SocketAddr>);

impl MaybeObservedPeerAddr {
    pub(crate) fn socket_addr(&self) -> Option<SocketAddr> {
        self.0
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

impl<S> FromRequestParts<S> for MaybeObservedPeerAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        let observed = parts
            .extensions
            .get::<MaybeObservedPeerAddr>()
            .copied()
            .or_else(|| {
                parts
                    .extensions
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|connect_info| Self(Some(connect_info.0)))
            })
            .unwrap_or_default();
        std::future::ready(Ok(observed))
    }
}

pub(crate) fn require_any_authenticated_peer(
    mtls_enabled: bool,
    authenticated_peer: &MaybeAuthenticatedPeer,
) -> Result<()> {
    if !mtls_enabled {
        return Ok(());
    }

    if authenticated_peer.identity().is_some() {
        Ok(())
    } else {
        bail!("rendezvous mTLS requires an authenticated peer certificate")
    }
}

pub(crate) fn ensure_authenticated_peer_identity(
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

pub(crate) fn ensure_authenticated_peer_cluster(
    mtls_enabled: bool,
    authenticated_peer: &MaybeAuthenticatedPeer,
    cluster_id: ClusterId,
    field_name: &str,
) -> Result<()> {
    if !mtls_enabled {
        return Ok(());
    }

    let Some(authenticated_peer) = authenticated_peer.0.as_ref() else {
        bail!("rendezvous mTLS requires an authenticated peer certificate");
    };
    let Some(authenticated_cluster_id) = authenticated_peer.cluster_id else {
        bail!("authenticated rendezvous client certificate is missing a cluster URI SAN");
    };

    if authenticated_cluster_id == cluster_id {
        Ok(())
    } else {
        bail!(
            "{field_name} cluster_id {cluster_id} does not match authenticated rendezvous client cluster_id {authenticated_cluster_id}"
        )
    }
}

#[derive(Clone)]
pub(crate) struct WithAuthenticatedPeer<S> {
    inner: S,
    authenticated_peer: Option<AuthenticatedPeer>,
    observed_peer_addr: Option<SocketAddr>,
}

impl<S> WithAuthenticatedPeer<S> {
    pub(crate) fn new(
        inner: S,
        authenticated_peer: Option<AuthenticatedPeer>,
        observed_peer_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            inner,
            authenticated_peer,
            observed_peer_addr,
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
        if let Some(observed_peer_addr) = self.observed_peer_addr {
            req.extensions_mut()
                .insert(MaybeObservedPeerAddr(Some(observed_peer_addr)));
        }
        self.inner.call(req)
    }
}

#[derive(Clone)]
pub(crate) struct MtlsAuthenticatedPeerAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl MtlsAuthenticatedPeerAcceptor {
    pub(crate) fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
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
        let observed_peer_addr = stream.peer_addr().ok();
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls_stream, service) = fut.await?;
            let authenticated_peer = authenticated_peer_from_tls_stream(&tls_stream)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err))?;
            Ok((
                tls_stream,
                WithAuthenticatedPeer::new(service, authenticated_peer, observed_peer_addr),
            ))
        })
    }
}

fn authenticated_peer_from_tls_stream<T>(
    tls_stream: &TlsStream<T>,
) -> Result<Option<AuthenticatedPeer>> {
    let (_, conn) = tls_stream.get_ref();
    let Some(certs) = conn.peer_certificates() else {
        return Ok(None);
    };

    Ok(Some(extract_authenticated_peer_from_peer_certs(certs)?))
}

pub(crate) fn build_mtls_rustls_config(
    mtls: &RendezvousMtlsConfig,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    match &mtls.client_ca {
        RendezvousClientCa::File { cert_path } => {
            let mut ca_reader = BufReader::new(
                File::open(cert_path)
                    .with_context(|| format!("failed reading {}", cert_path.display()))?,
            );
            for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
                let cert = cert.context("failed parsing rendezvous client CA certificate")?;
                roots
                    .add(cert)
                    .context("failed adding rendezvous client CA certificate to trust store")?;
            }
        }
        RendezvousClientCa::InlinePem { cert_pem } => {
            let mut ca_reader = BufReader::new(cert_pem.as_bytes());
            for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
                let cert = cert.context("failed parsing rendezvous client CA certificate")?;
                roots
                    .add(cert)
                    .context("failed adding rendezvous client CA certificate to trust store")?;
            }
        }
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

fn extract_authenticated_peer_from_peer_certs(
    certs: &[CertificateDer<'_>],
) -> Result<AuthenticatedPeer> {
    let cert = certs
        .first()
        .context("missing end-entity peer certificate")?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("failed parsing peer certificate")?;
    let mut identity = None;
    let mut cluster_id = None;
    for extension in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if let Some(parsed_identity) = parse_peer_identity_from_san_uri(uri) {
                        if let Some(existing_identity) = identity.as_ref()
                            && existing_identity != &parsed_identity
                        {
                            bail!(
                                "peer certificate contains conflicting ironmesh identity URI SANs"
                            );
                        }
                        identity = Some(parsed_identity);
                    }
                    if let Some(parsed_cluster_id) = parse_cluster_id_from_san_uri(uri)? {
                        if let Some(existing_cluster_id) = cluster_id
                            && existing_cluster_id != parsed_cluster_id
                        {
                            bail!(
                                "peer certificate contains conflicting ironmesh cluster URI SANs"
                            );
                        }
                        cluster_id = Some(parsed_cluster_id);
                    }
                }
            }
        }
    }

    let identity = identity.context("peer certificate missing URI SAN for ironmesh identity")?;
    Ok(AuthenticatedPeer {
        identity,
        cluster_id,
    })
}

fn parse_peer_identity_from_san_uri(uri: &str) -> Option<PeerIdentity> {
    if let Some(rest) = uri.strip_prefix("urn:ironmesh:node:") {
        return rest.parse().ok().map(PeerIdentity::Node);
    }

    uri.strip_prefix("urn:ironmesh:device:")
        .and_then(|rest| rest.parse().ok())
        .map(PeerIdentity::Device)
}

fn parse_cluster_id_from_san_uri(uri: &str) -> Result<Option<ClusterId>> {
    let Some(value) = uri.strip_prefix("urn:ironmesh:cluster:") else {
        return Ok(None);
    };

    let cluster_id = value
        .parse::<ClusterId>()
        .context("invalid urn:ironmesh:cluster:<uuid> SAN URI in peer certificate")?;
    if cluster_id.is_nil() {
        bail!("peer certificate cluster SAN must not use the nil UUID");
    }
    Ok(Some(cluster_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::{ClusterId, DeviceId};

    fn authenticated_peer(cluster_id: Option<ClusterId>) -> MaybeAuthenticatedPeer {
        MaybeAuthenticatedPeer(Some(AuthenticatedPeer {
            identity: PeerIdentity::Device(DeviceId::now_v7()),
            cluster_id,
        }))
    }

    #[test]
    fn require_any_authenticated_peer_accepts_device_certificate() {
        let peer = authenticated_peer(Some(ClusterId::now_v7()));

        require_any_authenticated_peer(true, &peer)
            .expect("device certificates should satisfy read-only rendezvous auth");
    }

    #[test]
    fn require_any_authenticated_peer_rejects_missing_certificate_when_mtls_enabled() {
        let error = require_any_authenticated_peer(true, &MaybeAuthenticatedPeer::default())
            .expect_err("missing certificates should be rejected");

        assert!(error.to_string().contains("authenticated peer certificate"));
    }

    #[test]
    fn authenticated_cluster_san_authorizes_only_its_cluster() {
        let cluster_a = ClusterId::now_v7();
        let cluster_b = ClusterId::now_v7();
        let peer = authenticated_peer(Some(cluster_a));

        ensure_authenticated_peer_cluster(true, &peer, cluster_a, "presence registration")
            .expect("matching cluster SAN should authorize the request");
        let error =
            ensure_authenticated_peer_cluster(true, &peer, cluster_b, "presence registration")
                .expect_err("cluster A certificate must not authorize cluster B");

        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn authenticated_cluster_check_rejects_legacy_certificate_without_cluster_san() {
        let error = ensure_authenticated_peer_cluster(
            true,
            &authenticated_peer(None),
            ClusterId::now_v7(),
            "relay ticket",
        )
        .expect_err("cluster-bound requests require a cluster SAN");

        assert!(error.to_string().contains("missing a cluster URI SAN"));
    }

    #[test]
    fn cluster_san_parser_requires_a_non_nil_uuid() {
        let cluster_id = ClusterId::now_v7();
        assert_eq!(
            parse_cluster_id_from_san_uri(&format!("urn:ironmesh:cluster:{cluster_id}"))
                .expect("cluster SAN should parse"),
            Some(cluster_id)
        );
        assert!(parse_cluster_id_from_san_uri("urn:ironmesh:cluster:not-a-uuid").is_err());
        assert!(
            parse_cluster_id_from_san_uri(
                "urn:ironmesh:cluster:00000000-0000-0000-0000-000000000000"
            )
            .is_err()
        );
    }
}
