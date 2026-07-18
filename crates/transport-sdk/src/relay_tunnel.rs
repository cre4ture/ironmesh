use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsConnector;
use tokio_rustls::{TlsAcceptor, TlsConnector as InnerTlsConnector};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::mux::{MultiplexConfig, MultiplexMode, MultiplexedSession};
use crate::peer::PeerIdentity;
use crate::relay::{RelayTicket, RelayTunnelSessionKind};
use crate::relay_security::{
    RelayTunnelSourceSecurityConfig, RelayTunnelTargetSecurityConfig, build_source_tls_config,
    build_target_tls_config, relay_tls_server_name,
};
use crate::ws_stream::WebSocketByteStream;
use common::ClusterId;

const RELAY_TUNNEL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_TUNNEL_INNER_TLS_TIMEOUT: Duration = Duration::from_secs(10);

trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTunnelAcceptRequest {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
    #[serde(default)]
    pub wait_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTunnelSession {
    pub cluster_id: ClusterId,
    pub session_id: String,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayTunnelControlMessage {
    ConnectSource { ticket: RelayTicket },
    AcceptTarget { request: RelayTunnelAcceptRequest },
    Paired { session: RelayTunnelSession },
    CloseWrite,
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTunnelEvent {
    Data(Vec<u8>),
    CloseWrite,
    Closed,
}

pub struct RelayTunnelClient {
    session: RelayTunnelSession,
    websocket: WebSocketStream<Box<dyn AsyncIo>>,
}

impl RelayTunnelAcceptRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay tunnel accept request must include a non-nil cluster_id");
        }
        Ok(())
    }
}

impl RelayTunnelSession {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay tunnel session must include a non-nil cluster_id");
        }
        if self.session_id.trim().is_empty() {
            bail!("relay tunnel session must include a session_id");
        }
        Ok(())
    }
}

impl RelayTunnelClient {
    pub async fn connect_source(
        base_url: &str,
        server_ca_pem: Option<&str>,
        client_identity_pem: Option<&[u8]>,
        ticket: &RelayTicket,
    ) -> Result<Self> {
        ticket.validate()?;
        let control = RelayTunnelControlMessage::ConnectSource {
            ticket: ticket.clone(),
        };
        Self::connect(base_url, server_ca_pem, client_identity_pem, control).await
    }

    pub async fn accept_target(
        base_url: &str,
        server_ca_pem: Option<&str>,
        client_identity_pem: Option<&[u8]>,
        request: RelayTunnelAcceptRequest,
    ) -> Result<Self> {
        request.validate()?;
        let control = RelayTunnelControlMessage::AcceptTarget { request };
        Self::connect(base_url, server_ca_pem, client_identity_pem, control).await
    }

    pub fn session(&self) -> &RelayTunnelSession {
        &self.session
    }

    /// Converts a paired tunnel directly into Yamux without inner peer-to-peer encryption.
    ///
    /// This legacy compatibility method is not production-safe for relay traffic. Use
    /// [`Self::into_secure_multiplexed_source_session`] or
    /// [`Self::into_secure_multiplexed_target_session`] instead.
    pub fn into_multiplexed_session(
        self,
        mode: MultiplexMode,
        config: MultiplexConfig,
    ) -> Result<(RelayTunnelSession, MultiplexedSession)> {
        let RelayTunnelClient { session, websocket } = self;
        let transport = WebSocketByteStream::new(websocket);
        let multiplexed = MultiplexedSession::spawn(transport, mode, config)
            .context("failed creating multiplexed relay tunnel session")?;
        Ok((session, multiplexed))
    }

    /// Converts a paired relay source endpoint into a TLS 1.3-protected multiplexed session.
    ///
    /// This validates the paired cluster and target before the handshake, then requires the
    /// target certificate to chain to `cluster_ca_pem` and contain the expected node and cluster
    /// URI SANs. Unlike [`Self::into_multiplexed_session`], this is suitable for production use.
    pub async fn into_secure_multiplexed_source_session(
        self,
        security: RelayTunnelSourceSecurityConfig,
        config: MultiplexConfig,
    ) -> Result<(RelayTunnelSession, MultiplexedSession)> {
        security.validate()?;
        let RelayTunnelClient { session, websocket } = self;
        validate_source_security_context(&session, &security)?;

        let transport = WebSocketByteStream::new(websocket).compat();
        let tls_stream = timeout(
            RELAY_TUNNEL_INNER_TLS_TIMEOUT,
            InnerTlsConnector::from(std::sync::Arc::new(build_source_tls_config(&security)?))
                .connect(relay_tls_server_name()?, transport),
        )
        .await
        .context("inner relay TLS source handshake timed out")?
        .context("inner relay TLS source handshake failed")?;
        let multiplexed =
            MultiplexedSession::spawn(tls_stream.compat(), MultiplexMode::Client, config)
                .context("failed creating secure multiplexed relay source session")?;
        Ok((session, multiplexed))
    }

    /// Converts a paired relay target endpoint into a TLS 1.3-protected multiplexed session.
    ///
    /// The target requires a client certificate chaining to `cluster_ca_pem` whose URI SAN equals
    /// `expected_source`; it does not allow an unauthenticated plaintext fallback.
    pub async fn into_secure_multiplexed_target_session(
        self,
        security: RelayTunnelTargetSecurityConfig,
        config: MultiplexConfig,
    ) -> Result<(RelayTunnelSession, MultiplexedSession)> {
        security.validate()?;
        let RelayTunnelClient { session, websocket } = self;
        validate_target_security_context(&session, &security)?;

        let transport = WebSocketByteStream::new(websocket).compat();
        let tls_stream = timeout(
            RELAY_TUNNEL_INNER_TLS_TIMEOUT,
            TlsAcceptor::from(std::sync::Arc::new(build_target_tls_config(&security)?))
                .accept(transport),
        )
        .await
        .context("inner relay TLS target handshake timed out")?
        .context("inner relay TLS target handshake failed")?;
        let multiplexed =
            MultiplexedSession::spawn(tls_stream.compat(), MultiplexMode::Server, config)
                .context("failed creating secure multiplexed relay target session")?;
        Ok((session, multiplexed))
    }

    pub async fn send_data(&mut self, bytes: &[u8]) -> Result<()> {
        self.websocket
            .send(Message::Binary(bytes.to_vec()))
            .await
            .context("failed sending relay tunnel data frame")
    }

    pub async fn send_close_write(&mut self) -> Result<()> {
        self.send_control(&RelayTunnelControlMessage::CloseWrite)
            .await
    }

    pub async fn recv_event(&mut self) -> Result<RelayTunnelEvent> {
        loop {
            let next = match self.websocket.next().await {
                Some(next) => next,
                None => return Ok(RelayTunnelEvent::Closed),
            };
            let message = next.context("relay tunnel websocket read failed")?;
            match message {
                Message::Binary(bytes) => return Ok(RelayTunnelEvent::Data(bytes)),
                Message::Text(text) => {
                    match serde_json::from_str::<RelayTunnelControlMessage>(&text)
                        .context("failed parsing relay tunnel control message")?
                    {
                        RelayTunnelControlMessage::CloseWrite => {
                            return Ok(RelayTunnelEvent::CloseWrite);
                        }
                        RelayTunnelControlMessage::Error { message } => {
                            bail!("relay tunnel peer reported error: {message}");
                        }
                        RelayTunnelControlMessage::Paired { .. }
                        | RelayTunnelControlMessage::ConnectSource { .. }
                        | RelayTunnelControlMessage::AcceptTarget { .. } => {
                            bail!("unexpected relay tunnel control message after pairing");
                        }
                    }
                }
                Message::Close(_) => return Ok(RelayTunnelEvent::Closed),
                Message::Ping(payload) => {
                    self.websocket
                        .send(Message::Pong(payload))
                        .await
                        .context("failed sending relay tunnel pong")?;
                }
                Message::Pong(_) => {}
                Message::Frame(_) => {}
            }
        }
    }

    pub async fn close(mut self) -> Result<()> {
        self.websocket
            .close(None)
            .await
            .context("failed closing relay tunnel websocket")
    }

    async fn connect(
        base_url: &str,
        server_ca_pem: Option<&str>,
        client_identity_pem: Option<&[u8]>,
        control: RelayTunnelControlMessage,
    ) -> Result<Self> {
        let ws_url = relay_tunnel_ws_url(base_url)?;
        let stream = open_websocket_io(&ws_url, server_ca_pem, client_identity_pem).await?;
        let (mut websocket, _response) = timeout(
            RELAY_TUNNEL_CONNECT_TIMEOUT,
            client_async(ws_url.as_str(), stream),
        )
        .await
        .context("relay tunnel websocket handshake timed out")?
        .context("relay tunnel websocket handshake failed")?;
        send_control_message(&mut websocket, &control).await?;

        let session = loop {
            let next = websocket
                .next()
                .await
                .ok_or_else(|| anyhow!("relay tunnel websocket closed before pairing"))?;
            match next.context("failed reading relay tunnel pairing response")? {
                Message::Text(text) => {
                    match serde_json::from_str::<RelayTunnelControlMessage>(&text)
                        .context("failed parsing relay tunnel pairing response")?
                    {
                        RelayTunnelControlMessage::Paired { session } => {
                            session.validate()?;
                            break session;
                        }
                        RelayTunnelControlMessage::Error { message } => {
                            bail!("relay tunnel establishment failed: {message}");
                        }
                        other => bail!(
                            "unexpected relay tunnel pairing message: {}",
                            serde_json::to_string(&other)
                                .unwrap_or_else(|_| "<unserializable>".to_string())
                        ),
                    }
                }
                Message::Ping(payload) => {
                    websocket
                        .send(Message::Pong(payload))
                        .await
                        .context("failed sending relay tunnel pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    bail!("relay tunnel websocket closed before pairing");
                }
                Message::Binary(_) | Message::Frame(_) => {
                    bail!("relay tunnel websocket sent data before pairing");
                }
            }
        };

        Ok(Self { session, websocket })
    }

    async fn send_control(&mut self, control: &RelayTunnelControlMessage) -> Result<()> {
        send_control_message(&mut self.websocket, control).await
    }
}

fn validate_source_security_context(
    session: &RelayTunnelSession,
    security: &RelayTunnelSourceSecurityConfig,
) -> Result<()> {
    session.validate()?;
    if session.cluster_id != security.cluster_id {
        bail!(
            "paired relay session cluster_id {} does not match relay TLS source cluster_id {}",
            session.cluster_id,
            security.cluster_id
        );
    }
    let expected_target = PeerIdentity::Node(security.expected_target_node_id);
    if session.target != expected_target {
        bail!(
            "paired relay session target {} does not match relay TLS expected target {}",
            session.target,
            expected_target
        );
    }
    Ok(())
}

fn validate_target_security_context(
    session: &RelayTunnelSession,
    security: &RelayTunnelTargetSecurityConfig,
) -> Result<()> {
    session.validate()?;
    if session.source != security.expected_source {
        bail!(
            "paired relay session source {} does not match relay TLS expected source {}",
            session.source,
            security.expected_source
        );
    }
    Ok(())
}

pub fn relay_tunnel_ws_url(base_url: &str) -> Result<Url> {
    let mut url = Url::parse(base_url.trim())
        .with_context(|| format!("invalid rendezvous base URL {base_url}"))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        "ws" => "ws",
        "wss" => "wss",
        other => bail!("unsupported relay tunnel base URL scheme {other}"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow!("failed setting relay tunnel websocket URL scheme"))?;
    url = url
        .join("relay/tunnel/ws")
        .with_context(|| format!("failed building relay tunnel URL from {base_url}"))?;
    Ok(url)
}

async fn send_control_message(
    websocket: &mut WebSocketStream<Box<dyn AsyncIo>>,
    control: &RelayTunnelControlMessage,
) -> Result<()> {
    let payload = serde_json::to_string(control).context("failed encoding relay tunnel control")?;
    websocket
        .send(Message::Text(payload))
        .await
        .context("failed sending relay tunnel control")
}

async fn open_websocket_io(
    url: &Url,
    server_ca_pem: Option<&str>,
    client_identity_pem: Option<&[u8]>,
) -> Result<Box<dyn AsyncIo>> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("relay tunnel URL is missing a host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("relay tunnel URL is missing a port"))?;
    let tcp = timeout(
        RELAY_TUNNEL_CONNECT_TIMEOUT,
        TcpStream::connect((host, port)),
    )
    .await
    .with_context(|| format!("timed out connecting relay tunnel TCP stream to {host}:{port}"))?
    .with_context(|| format!("failed connecting relay tunnel TCP stream to {host}:{port}"))?;

    match url.scheme() {
        "ws" => Ok(Box::new(tcp)),
        "wss" => {
            let server_name = ServerName::try_from(host.to_string())
                .context("failed building relay tunnel TLS server name")?;
            let tls_stream = timeout(
                RELAY_TUNNEL_CONNECT_TIMEOUT,
                TlsConnector::from(std::sync::Arc::new(build_tls_client_config(
                    server_ca_pem,
                    client_identity_pem,
                )?))
                .connect(server_name, tcp),
            )
            .await
            .with_context(|| {
                format!("timed out establishing relay tunnel TLS stream to {host}:{port}")
            })?
            .with_context(|| {
                format!("failed establishing relay tunnel TLS stream to {host}:{port}")
            })?;
            Ok(Box::new(tls_stream))
        }
        other => bail!("unsupported relay tunnel scheme {other}"),
    }
}

fn build_tls_client_config(
    server_ca_pem: Option<&str>,
    client_identity_pem: Option<&[u8]>,
) -> Result<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    if let Some(server_ca_pem) = server_ca_pem {
        let mut reader = std::io::Cursor::new(server_ca_pem.as_bytes());
        for cert in CertificateDer::pem_reader_iter(&mut reader) {
            let cert = cert.context("failed parsing relay tunnel server CA certificate")?;
            roots
                .add(cert)
                .context("failed adding relay tunnel server CA certificate")?;
        }
    } else {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            roots
                .add(cert)
                .context("failed adding native relay tunnel root certificate")?;
        }
        if !native.errors.is_empty() && roots.is_empty() {
            bail!("failed loading native root certificates for relay tunnel TLS");
        }
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    match client_identity_pem {
        Some(identity_pem) => {
            let (cert_chain, key) = parse_client_identity_pem(identity_pem)?;
            builder
                .with_client_auth_cert(cert_chain, key)
                .context("failed building relay tunnel TLS client identity")
        }
        None => Ok(builder.with_no_client_auth()),
    }
}

fn parse_client_identity_pem(
    identity_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = std::io::Cursor::new(identity_pem);
    let cert_chain = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing relay tunnel client certificate chain")?;
    if cert_chain.is_empty() {
        bail!("relay tunnel client identity PEM is missing a certificate chain");
    }

    let mut key_reader = std::io::Cursor::new(identity_pem);
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing relay tunnel client private key")?;
    Ok((cert_chain, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_security::RelayTunnelTlsIdentity;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use futures_util::{SinkExt, StreamExt};
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;
    use tokio_tungstenite::tungstenite::protocol::Role;
    use uuid::Uuid;

    struct TestCa {
        pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    struct TestTunnel {
        source: RelayTunnelClient,
        target: RelayTunnelClient,
        binary_frames: Arc<Mutex<Vec<Vec<u8>>>>,
        relay_task: JoinHandle<()>,
    }

    fn issue_test_ca() -> TestCa {
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ironmesh-relay-security-test-ca");
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let certificate = params
            .self_signed(&key_pair)
            .expect("test CA certificate should issue");
        TestCa {
            pem: certificate.pem(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    fn issue_node_identity(ca: &TestCa, node_id: Uuid, cluster_id: Uuid) -> RelayTunnelTlsIdentity {
        let key_pair = KeyPair::generate().expect("node key should generate");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("ironmesh-node-{node_id}"));
        params.subject_alt_names = vec![
            SanType::URI(
                format!("urn:ironmesh:node:{node_id}")
                    .try_into()
                    .expect("node URI SAN should be valid"),
            ),
            SanType::URI(
                format!("urn:ironmesh:cluster:{cluster_id}")
                    .try_into()
                    .expect("cluster URI SAN should be valid"),
            ),
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key_pair, &ca.issuer)
            .expect("node certificate should issue");
        RelayTunnelTlsIdentity::new(certificate.pem(), key_pair.serialize_pem())
    }

    fn issue_device_identity(ca: &TestCa, device_id: Uuid) -> RelayTunnelTlsIdentity {
        let key_pair = KeyPair::generate().expect("device key should generate");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("ironmesh-device-{device_id}"));
        params.subject_alt_names = vec![SanType::URI(
            format!("urn:ironmesh:device:{device_id}")
                .try_into()
                .expect("device URI SAN should be valid"),
        )];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params
            .signed_by(&key_pair, &ca.issuer)
            .expect("device certificate should issue");
        RelayTunnelTlsIdentity::new(certificate.pem(), key_pair.serialize_pem())
    }

    fn relay_session(
        cluster_id: Uuid,
        source: PeerIdentity,
        target: PeerIdentity,
    ) -> RelayTunnelSession {
        RelayTunnelSession {
            cluster_id,
            session_id: format!("relay-security-test-{}", Uuid::now_v7()),
            source,
            target,
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
        }
    }

    async fn test_tunnel(session: RelayTunnelSession) -> TestTunnel {
        let (source_io, relay_source_io) = tokio::io::duplex(128 * 1024);
        let (relay_target_io, target_io) = tokio::io::duplex(128 * 1024);
        let source_websocket = WebSocketStream::from_raw_socket(
            Box::new(source_io) as Box<dyn AsyncIo>,
            Role::Client,
            None,
        )
        .await;
        let target_websocket = WebSocketStream::from_raw_socket(
            Box::new(target_io) as Box<dyn AsyncIo>,
            Role::Client,
            None,
        )
        .await;
        let relay_source_websocket = WebSocketStream::from_raw_socket(
            Box::new(relay_source_io) as Box<dyn AsyncIo>,
            Role::Server,
            None,
        )
        .await;
        let relay_target_websocket = WebSocketStream::from_raw_socket(
            Box::new(relay_target_io) as Box<dyn AsyncIo>,
            Role::Server,
            None,
        )
        .await;

        let binary_frames = Arc::new(Mutex::new(Vec::new()));
        let source_frames = Arc::clone(&binary_frames);
        let target_frames = Arc::clone(&binary_frames);
        let relay_task = tokio::spawn(async move {
            let (mut source_sink, mut source_stream) = relay_source_websocket.split();
            let (mut target_sink, mut target_stream) = relay_target_websocket.split();
            let source_to_target = async move {
                while let Some(Ok(message)) = source_stream.next().await {
                    if let Message::Binary(bytes) = &message {
                        source_frames
                            .lock()
                            .expect("frame recorder lock should succeed")
                            .push(bytes.to_vec());
                    }
                    if target_sink.send(message).await.is_err() {
                        return;
                    }
                }
                let _ = target_sink.close().await;
            };
            let target_to_source = async move {
                while let Some(Ok(message)) = target_stream.next().await {
                    if let Message::Binary(bytes) = &message {
                        target_frames
                            .lock()
                            .expect("frame recorder lock should succeed")
                            .push(bytes.to_vec());
                    }
                    if source_sink.send(message).await.is_err() {
                        return;
                    }
                }
                let _ = source_sink.close().await;
            };
            tokio::join!(source_to_target, target_to_source);
        });

        TestTunnel {
            source: RelayTunnelClient {
                session: session.clone(),
                websocket: source_websocket,
            },
            target: RelayTunnelClient {
                session,
                websocket: target_websocket,
            },
            binary_frames,
            relay_task,
        }
    }

    fn source_security(
        cluster_id: Uuid,
        target_node_id: Uuid,
        ca_pem: &str,
        identity: RelayTunnelTlsIdentity,
    ) -> RelayTunnelSourceSecurityConfig {
        RelayTunnelSourceSecurityConfig {
            cluster_id,
            expected_target_node_id: target_node_id,
            cluster_ca_pem: ca_pem.as_bytes().to_vec(),
            identity,
        }
    }

    fn target_security(
        expected_source: PeerIdentity,
        ca_pem: &str,
        identity: RelayTunnelTlsIdentity,
    ) -> RelayTunnelTargetSecurityConfig {
        RelayTunnelTargetSecurityConfig {
            expected_source,
            cluster_ca_pem: ca_pem.as_bytes().to_vec(),
            identity,
        }
    }

    async fn await_target_handshake(
        target_task: JoinHandle<Result<(RelayTunnelSession, MultiplexedSession)>>,
    ) -> Result<(RelayTunnelSession, MultiplexedSession)> {
        timeout(Duration::from_secs(2), target_task)
            .await
            .expect("target TLS handshake should resolve")
            .expect("target TLS task should not panic")
    }

    #[tokio::test]
    async fn secure_relay_tls_handshake_encrypts_multiplexed_payload() {
        let cluster_id = Uuid::now_v7();
        let source_device_id = Uuid::now_v7();
        let target_node_id = Uuid::now_v7();
        let ca = issue_test_ca();
        let source_identity = issue_device_identity(&ca, source_device_id);
        let target_identity = issue_node_identity(&ca, target_node_id, cluster_id);
        let tunnel = test_tunnel(relay_session(
            cluster_id,
            PeerIdentity::Device(source_device_id),
            PeerIdentity::Node(target_node_id),
        ))
        .await;

        let target_task = tokio::spawn(tunnel.target.into_secure_multiplexed_target_session(
            target_security(
                PeerIdentity::Device(source_device_id),
                &ca.pem,
                target_identity,
            ),
            MultiplexConfig::default(),
        ));
        let (_session, source_mux) = tunnel
            .source
            .into_secure_multiplexed_source_session(
                source_security(cluster_id, target_node_id, &ca.pem, source_identity),
                MultiplexConfig::default(),
            )
            .await
            .expect("source TLS handshake should succeed");
        let (_session, mut target_mux) = await_target_handshake(target_task)
            .await
            .expect("target TLS handshake should succeed");

        let secret = b"relay-mtls-payload-must-not-appear-in-websocket-frames";
        let mut outbound = source_mux
            .open_stream()
            .await
            .expect("source should open a multiplexed stream");
        outbound
            .write_all(secret)
            .await
            .expect("source should write payload");
        outbound.close().await.expect("source stream should close");

        let mut inbound = target_mux
            .accept_stream()
            .await
            .expect("target should accept the multiplexed stream")
            .expect("target stream should be present");
        let mut received = Vec::new();
        inbound
            .read_to_end(&mut received)
            .await
            .expect("target should read payload");
        assert_eq!(received, secret);

        {
            let frames = tunnel
                .binary_frames
                .lock()
                .expect("frame recorder lock should succeed");
            assert!(
                frames
                    .iter()
                    .all(|frame| !frame.windows(secret.len()).any(|window| window == secret)),
                "the plaintext payload must not occur in websocket binary frames"
            );
        }

        source_mux.close().await.expect("source mux should close");
        target_mux.close().await.expect("target mux should close");
        tunnel.relay_task.abort();
    }

    #[tokio::test]
    async fn secure_relay_tls_rejects_wrong_target_node_san() {
        let cluster_id = Uuid::now_v7();
        let source_device_id = Uuid::now_v7();
        let expected_target_node_id = Uuid::now_v7();
        let certificate_target_node_id = Uuid::now_v7();
        let ca = issue_test_ca();
        let tunnel = test_tunnel(relay_session(
            cluster_id,
            PeerIdentity::Device(source_device_id),
            PeerIdentity::Node(expected_target_node_id),
        ))
        .await;
        let target_task = tokio::spawn(tunnel.target.into_secure_multiplexed_target_session(
            target_security(
                PeerIdentity::Device(source_device_id),
                &ca.pem,
                issue_node_identity(&ca, certificate_target_node_id, cluster_id),
            ),
            MultiplexConfig::default(),
        ));

        let source_error = match tunnel
            .source
            .into_secure_multiplexed_source_session(
                source_security(
                    cluster_id,
                    expected_target_node_id,
                    &ca.pem,
                    issue_device_identity(&ca, source_device_id),
                ),
                MultiplexConfig::default(),
            )
            .await
        {
            Ok(_) => panic!("wrong target node SAN must fail the source handshake"),
            Err(error) => error,
        };
        assert!(
            source_error
                .to_string()
                .contains("inner relay TLS source handshake failed")
        );
        assert!(
            await_target_handshake(target_task).await.is_err(),
            "target must not establish a session when source rejects its identity"
        );
        tunnel.relay_task.abort();
    }

    #[tokio::test]
    async fn secure_relay_tls_rejects_wrong_target_cluster_san() {
        let cluster_id = Uuid::now_v7();
        let certificate_cluster_id = Uuid::now_v7();
        let source_device_id = Uuid::now_v7();
        let target_node_id = Uuid::now_v7();
        let ca = issue_test_ca();
        let tunnel = test_tunnel(relay_session(
            cluster_id,
            PeerIdentity::Device(source_device_id),
            PeerIdentity::Node(target_node_id),
        ))
        .await;
        let target_task = tokio::spawn(tunnel.target.into_secure_multiplexed_target_session(
            target_security(
                PeerIdentity::Device(source_device_id),
                &ca.pem,
                issue_node_identity(&ca, target_node_id, certificate_cluster_id),
            ),
            MultiplexConfig::default(),
        ));

        let source_error = match tunnel
            .source
            .into_secure_multiplexed_source_session(
                source_security(
                    cluster_id,
                    target_node_id,
                    &ca.pem,
                    issue_device_identity(&ca, source_device_id),
                ),
                MultiplexConfig::default(),
            )
            .await
        {
            Ok(_) => panic!("wrong cluster SAN must fail the source handshake"),
            Err(error) => error,
        };
        assert!(
            source_error
                .to_string()
                .contains("inner relay TLS source handshake failed")
        );
        assert!(
            await_target_handshake(target_task).await.is_err(),
            "target must not establish a session when source rejects its cluster"
        );
        tunnel.relay_task.abort();
    }

    #[tokio::test]
    async fn secure_relay_tls_rejects_source_outside_target_ca() {
        let cluster_id = Uuid::now_v7();
        let source_device_id = Uuid::now_v7();
        let target_node_id = Uuid::now_v7();
        let cluster_ca = issue_test_ca();
        let unrelated_ca = issue_test_ca();
        let tunnel = test_tunnel(relay_session(
            cluster_id,
            PeerIdentity::Device(source_device_id),
            PeerIdentity::Node(target_node_id),
        ))
        .await;
        let target_task = tokio::spawn(tunnel.target.into_secure_multiplexed_target_session(
            target_security(
                PeerIdentity::Device(source_device_id),
                &unrelated_ca.pem,
                issue_node_identity(&cluster_ca, target_node_id, cluster_id),
            ),
            MultiplexConfig::default(),
        ));

        let _ = tunnel
            .source
            .into_secure_multiplexed_source_session(
                source_security(
                    cluster_id,
                    target_node_id,
                    &cluster_ca.pem,
                    issue_device_identity(&cluster_ca, source_device_id),
                ),
                MultiplexConfig::default(),
            )
            .await;
        assert!(
            await_target_handshake(target_task).await.is_err(),
            "target must reject a source certificate outside its configured CA"
        );
        tunnel.relay_task.abort();
    }

    #[tokio::test]
    async fn secure_relay_tls_rejects_unexpected_source_peer_san() {
        let cluster_id = Uuid::now_v7();
        let certificate_device_id = Uuid::now_v7();
        let expected_source_device_id = Uuid::now_v7();
        let target_node_id = Uuid::now_v7();
        let ca = issue_test_ca();
        let tunnel = test_tunnel(relay_session(
            cluster_id,
            PeerIdentity::Device(expected_source_device_id),
            PeerIdentity::Node(target_node_id),
        ))
        .await;
        let target_task = tokio::spawn(tunnel.target.into_secure_multiplexed_target_session(
            target_security(
                PeerIdentity::Device(expected_source_device_id),
                &ca.pem,
                issue_node_identity(&ca, target_node_id, cluster_id),
            ),
            MultiplexConfig::default(),
        ));

        let _ = tunnel
            .source
            .into_secure_multiplexed_source_session(
                source_security(
                    cluster_id,
                    target_node_id,
                    &ca.pem,
                    issue_device_identity(&ca, certificate_device_id),
                ),
                MultiplexConfig::default(),
            )
            .await;
        assert!(
            await_target_handshake(target_task).await.is_err(),
            "target must reject a source certificate with the wrong peer SAN"
        );
        tunnel.relay_task.abort();
    }

    #[tokio::test]
    async fn relay_tunnel_client_can_host_a_multiplexed_session() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let client_ws = WebSocketStream::from_raw_socket(
            Box::new(client_io) as Box<dyn AsyncIo>,
            Role::Client,
            None,
        )
        .await;
        let server_ws = WebSocketStream::from_raw_socket(
            Box::new(server_io) as Box<dyn AsyncIo>,
            Role::Server,
            None,
        )
        .await;

        let session = RelayTunnelSession {
            cluster_id: Uuid::now_v7(),
            session_id: "relay-session-test".to_string(),
            source: PeerIdentity::Device(Uuid::now_v7()),
            target: PeerIdentity::Node(Uuid::now_v7()),
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
        };
        let client = RelayTunnelClient {
            session: session.clone(),
            websocket: client_ws,
        };

        let (returned_session, client_mux) = client
            .into_multiplexed_session(MultiplexMode::Client, MultiplexConfig::default())
            .expect("client multiplexed session should build");
        let mut server_mux = MultiplexedSession::spawn(
            WebSocketByteStream::new(server_ws),
            MultiplexMode::Server,
            MultiplexConfig::default(),
        )
        .expect("server multiplexed session should build");

        assert_eq!(returned_session, session);

        let mut outbound = client_mux
            .open_stream()
            .await
            .expect("outbound multiplexed stream should open");
        outbound
            .write_all(b"relay-mux")
            .await
            .expect("outbound stream write should succeed");
        outbound
            .close()
            .await
            .expect("outbound stream close should succeed");

        let mut inbound = server_mux
            .accept_stream()
            .await
            .expect("accepting multiplexed relay stream should succeed")
            .expect("multiplexed relay stream should exist");
        let mut payload = Vec::new();
        inbound
            .read_to_end(&mut payload)
            .await
            .expect("inbound multiplexed relay stream should read");

        assert_eq!(payload, b"relay-mux");

        client_mux
            .close()
            .await
            .expect("client multiplexed relay session should close");
        server_mux
            .close()
            .await
            .expect("server multiplexed relay session should close");
    }

    #[tokio::test]
    async fn accept_target_times_out_when_websocket_handshake_stalls() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have a local address");
        let server_task = tokio::spawn(async move {
            let (_socket, _peer) = listener
                .accept()
                .await
                .expect("test server should accept the client TCP connection");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let request = RelayTunnelAcceptRequest {
            cluster_id: Uuid::now_v7(),
            target: PeerIdentity::Node(Uuid::now_v7()),
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
            wait_timeout_ms: Some(15_000),
        };

        let started_at = Instant::now();
        let error =
            match RelayTunnelClient::accept_target(&format!("ws://{addr}"), None, None, request)
                .await
            {
                Ok(_) => panic!("stalled websocket handshake should fail"),
                Err(error) => error,
            };

        server_task.abort();

        assert!(
            started_at.elapsed() < Duration::from_secs(7),
            "relay tunnel handshake should fail within the timeout window"
        );
        assert!(
            error
                .to_string()
                .contains("relay tunnel websocket handshake timed out"),
            "unexpected relay tunnel error: {error:#}"
        );
    }
}
