use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use iroh::endpoint::{RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey, TransportAddr};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::candidates::{CandidateKind, ConnectionCandidate, ConnectionCandidateTransportHints};
use crate::mux::{MultiplexConfig, MultiplexMode, MultiplexedSession};

const DIRECT_QUIC_ENDPOINT_SCHEME: &str = "iroh";
pub const DEFAULT_DIRECT_QUIC_ALPN: &str = "ironmesh/transport/1";

#[derive(Debug, Clone)]
pub struct DirectQuicEndpointConfig {
    pub secret_key: SecretKey,
    pub relay_urls: Vec<String>,
    pub alpn: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectQuicEndpointSnapshot {
    pub endpoint_id: String,
    pub relay_url: Option<String>,
    pub direct_socket_addrs: Vec<String>,
    pub observed_socket_addrs: Vec<String>,
    pub alpn: String,
}

#[derive(Clone)]
pub struct DirectQuicEndpoint {
    endpoint: Endpoint,
    alpn: String,
}

pub struct DirectQuicSession {
    pub connection: iroh::endpoint::Connection,
    pub session: MultiplexedSession,
    pub remote_endpoint_id: String,
}

struct IrohBiStream {
    recv: RecvStream,
    send: SendStream,
}

impl DirectQuicEndpointConfig {
    pub fn new(secret_key: SecretKey) -> Self {
        Self {
            secret_key,
            relay_urls: Vec::new(),
            alpn: DEFAULT_DIRECT_QUIC_ALPN.to_string(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.alpn.trim().is_empty() {
            bail!("direct QUIC ALPN must not be blank");
        }
        for relay_url in &self.relay_urls {
            relay_url
                .trim()
                .parse::<RelayUrl>()
                .with_context(|| format!("invalid direct QUIC relay URL {relay_url}"))?;
        }
        Ok(())
    }
}

impl DirectQuicEndpoint {
    pub async fn bind(config: DirectQuicEndpointConfig) -> Result<Self> {
        config.validate()?;

        let relay_mode = if config.relay_urls.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::custom(
                config
                    .relay_urls
                    .iter()
                    .map(|value| value.trim().parse::<RelayUrl>())
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("failed parsing direct QUIC relay URLs")?,
            )
        };

        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(config.secret_key)
            .relay_mode(relay_mode)
            .alpns(vec![config.alpn.as_bytes().to_vec()])
            .bind()
            .await
            .context("failed binding direct QUIC endpoint")?;

        Ok(Self {
            endpoint,
            alpn: config.alpn,
        })
    }

    pub async fn wait_until_online(&self) {
        self.endpoint.online().await;
    }

    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    pub fn snapshot(&self) -> DirectQuicEndpointSnapshot {
        let addr = self.endpoint.addr();
        let relay_url = addr.relay_urls().next().map(ToString::to_string);
        let observed_socket_addrs = addr.ip_addrs().map(ToString::to_string).collect::<Vec<_>>();
        let direct_socket_addrs = self
            .endpoint
            .bound_sockets()
            .into_iter()
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();

        DirectQuicEndpointSnapshot {
            endpoint_id: addr.id.to_string(),
            relay_url,
            direct_socket_addrs,
            observed_socket_addrs,
            alpn: self.alpn.clone(),
        }
    }

    pub fn candidate(&self) -> ConnectionCandidate {
        self.snapshot().to_candidate()
    }

    pub async fn connect_session(
        &self,
        candidate: &ConnectionCandidate,
        config: MultiplexConfig,
    ) -> Result<DirectQuicSession> {
        let endpoint_addr = endpoint_addr_from_candidate(candidate)?;
        let remote_endpoint_id = endpoint_addr.id.to_string();
        let alpn = candidate
            .transport_hints
            .as_ref()
            .and_then(|hints| hints.alpn.as_deref())
            .unwrap_or(self.alpn.as_str())
            .as_bytes()
            .to_vec();

        let connection = self
            .endpoint
            .connect(endpoint_addr, &alpn)
            .await
            .with_context(|| {
                format!("failed opening direct QUIC connection to {remote_endpoint_id}")
            })?;
        let (send, recv) = connection.open_bi().await.with_context(|| {
            format!("failed opening direct QUIC bi-stream to {remote_endpoint_id}")
        })?;
        let session = MultiplexedSession::spawn(
            IrohBiStream::new(recv, send).compat(),
            MultiplexMode::Client,
            config,
        )
        .with_context(|| {
            format!("failed creating direct QUIC multiplex session to {remote_endpoint_id}")
        })?;

        Ok(DirectQuicSession {
            connection,
            session,
            remote_endpoint_id,
        })
    }

    pub async fn accept_session(
        &self,
        config: MultiplexConfig,
    ) -> Result<Option<DirectQuicSession>> {
        let Some(incoming) = self.endpoint.accept().await else {
            return Ok(None);
        };
        let connection = incoming
            .accept()
            .context("failed accepting direct QUIC connection")?
            .await
            .context("direct QUIC connection handshake failed")?;
        let remote_endpoint_id = connection.remote_id().to_string();
        let (send, recv) = connection.accept_bi().await.with_context(|| {
            format!("failed accepting direct QUIC bi-stream from {remote_endpoint_id}")
        })?;
        let session = MultiplexedSession::spawn(
            IrohBiStream::new(recv, send).compat(),
            MultiplexMode::Server,
            config,
        )
        .with_context(|| {
            format!("failed creating direct QUIC multiplex session from {remote_endpoint_id}")
        })?;

        Ok(Some(DirectQuicSession {
            connection,
            session,
            remote_endpoint_id,
        }))
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

impl DirectQuicEndpointSnapshot {
    pub fn to_candidate(&self) -> ConnectionCandidate {
        ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: direct_quic_endpoint_url(&self.endpoint_id),
            rtt_ms: None,
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some(self.endpoint_id.clone()),
                relay_url: self.relay_url.clone(),
                alpn: Some(self.alpn.clone()),
                direct_socket_addrs: self.direct_socket_addrs.clone(),
                observed_socket_addrs: self.observed_socket_addrs.clone(),
            }),
        }
    }
}

impl IrohBiStream {
    fn new(recv: RecvStream, send: SendStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for IrohBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for IrohBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(write_error_to_io_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

pub fn direct_quic_endpoint_url(endpoint_id: &str) -> String {
    format!("{DIRECT_QUIC_ENDPOINT_SCHEME}://{endpoint_id}")
}

pub fn endpoint_id_from_candidate(candidate: &ConnectionCandidate) -> Result<String> {
    if let Some(transport_id) = candidate
        .transport_hints
        .as_ref()
        .and_then(|hints| hints.transport_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(transport_id.to_string());
    }

    let url = reqwest::Url::parse(candidate.endpoint.trim())
        .with_context(|| format!("invalid direct QUIC endpoint {}", candidate.endpoint))?;
    if url.scheme() != DIRECT_QUIC_ENDPOINT_SCHEME {
        bail!("direct QUIC candidate endpoint must use {DIRECT_QUIC_ENDPOINT_SCHEME}:// scheme");
    }

    url.host_str()
        .map(ToString::to_string)
        .or_else(|| {
            let value = candidate
                .endpoint
                .trim()
                .strip_prefix(&format!("{DIRECT_QUIC_ENDPOINT_SCHEME}://"))?
                .trim_matches('/');
            (!value.is_empty()).then_some(value.to_string())
        })
        .ok_or_else(|| anyhow!("direct QUIC candidate endpoint is missing endpoint id"))
}

pub fn endpoint_addr_from_candidate(candidate: &ConnectionCandidate) -> Result<EndpointAddr> {
    let endpoint_id = endpoint_id_from_candidate(candidate)?;
    let endpoint_id = endpoint_id
        .parse()
        .with_context(|| format!("invalid direct QUIC endpoint id {endpoint_id}"))?;

    let mut addrs = Vec::new();
    if let Some(hints) = candidate.transport_hints.as_ref() {
        if let Some(relay_url) = hints.relay_url.as_deref() {
            addrs.push(TransportAddr::Relay(
                relay_url
                    .parse::<RelayUrl>()
                    .with_context(|| format!("invalid direct QUIC relay URL {relay_url}"))?,
            ));
        }
        addrs.extend(socket_addrs_to_transport_addrs(&hints.direct_socket_addrs)?);
        addrs.extend(socket_addrs_to_transport_addrs(
            &hints.observed_socket_addrs,
        )?);
    }

    Ok(EndpointAddr::from_parts(endpoint_id, addrs))
}

pub fn read_secret_key_from_path(path: &Path) -> Result<SecretKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading direct QUIC secret key {}", path.display()))?;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(raw.trim())
        .with_context(|| format!("failed decoding direct QUIC secret key {}", path.display()))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow!(
            "direct QUIC secret key {} must decode to exactly 32 bytes",
            path.display()
        )
    })?;
    Ok(SecretKey::from_bytes(&bytes))
}

pub fn write_secret_key_to_path(path: &Path, secret_key: &SecretKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating direct QUIC secret key directory {}",
                parent.display()
            )
        })?;
    }
    let payload = base64::engine::general_purpose::STANDARD_NO_PAD.encode(secret_key.to_bytes());
    fs::write(path, format!("{payload}\n"))
        .with_context(|| format!("failed writing direct QUIC secret key {}", path.display()))
}

pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        return read_secret_key_from_path(path);
    }
    let secret_key = SecretKey::generate();
    write_secret_key_to_path(path, &secret_key)?;
    Ok(secret_key)
}

fn socket_addrs_to_transport_addrs(values: &[String]) -> Result<Vec<TransportAddr>> {
    let mut addrs = Vec::new();
    for value in values {
        let addr = value
            .trim()
            .parse::<SocketAddr>()
            .with_context(|| format!("invalid direct QUIC socket address {value}"))?;
        if !addrs.contains(&TransportAddr::Ip(addr)) {
            addrs.push(TransportAddr::Ip(addr));
        }
    }
    Ok(addrs)
}

fn write_error_to_io_error(error: iroh::endpoint::WriteError) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_serializes_to_direct_quic_candidate() {
        let candidate = DirectQuicEndpointSnapshot {
            endpoint_id: "peer-key-1".to_string(),
            relay_url: Some("https://relay.example".to_string()),
            direct_socket_addrs: vec!["127.0.0.1:7000".to_string()],
            observed_socket_addrs: vec!["203.0.113.10:40000".to_string()],
            alpn: DEFAULT_DIRECT_QUIC_ALPN.to_string(),
        }
        .to_candidate();

        assert_eq!(candidate.kind, CandidateKind::DirectQuic);
        assert_eq!(candidate.endpoint, "iroh://peer-key-1");
        assert_eq!(
            candidate
                .transport_hints
                .as_ref()
                .and_then(|hints| hints.transport_id.as_deref()),
            Some("peer-key-1")
        );
    }

    #[test]
    fn secret_key_roundtrip_persists_exact_key() {
        let path =
            std::env::temp_dir().join(format!("ironmesh-iroh-key-{}.txt", uuid::Uuid::now_v7()));
        let secret_key = SecretKey::generate();

        write_secret_key_to_path(&path, &secret_key).expect("secret key should persist");
        let loaded = read_secret_key_from_path(&path).expect("secret key should load");
        std::fs::remove_file(&path).expect("temp secret key should be removed");

        assert_eq!(secret_key.to_bytes(), loaded.to_bytes());
    }
}
