use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use reqwest::Url;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::client_async;
use tokio_tungstenite::tungstenite::Message;

use crate::mux::{MultiplexConfig, MultiplexMode, MultiplexedSession};
use crate::peer::PeerIdentity;
use crate::relay::RelayTicket;
use crate::ws_stream::WebSocketByteStream;
use common::ClusterId;

trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTunnelAcceptRequest {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    #[serde(default)]
    pub wait_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTunnelSession {
    pub cluster_id: ClusterId,
    pub session_id: String,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
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

    pub async fn send_data(&mut self, bytes: &[u8]) -> Result<()> {
        self.websocket
            .send(Message::Binary(bytes.to_vec().into()))
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
        let (mut websocket, _response) = client_async(ws_url.as_str(), stream)
            .await
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
        .send(Message::Text(payload.into()))
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
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("failed connecting relay tunnel TCP stream to {host}:{port}"))?;

    match url.scheme() {
        "ws" => Ok(Box::new(tcp)),
        "wss" => {
            let server_name = ServerName::try_from(host.to_string())
                .context("failed building relay tunnel TLS server name")?;
            let tls_stream = TlsConnector::from(std::sync::Arc::new(build_tls_client_config(
                server_ca_pem,
                client_identity_pem,
            )?))
            .connect(server_name, tcp)
            .await
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
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::protocol::Role;
    use uuid::Uuid;

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
}
