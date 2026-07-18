use anyhow::{Context, Result, anyhow, bail};
use common::NodeId;
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use transport_sdk::{
    ClientIdentityMaterial, ConnectionCandidate, DEFAULT_DIRECT_QUIC_ALPN, DirectQuicEndpoint,
    DirectQuicEndpointConfig, MultiplexConfig, MultiplexMode, MultiplexedSession, PeerIdentity,
    RelayTicketRequest, RelayTunnelSession, RelayTunnelSessionKind,
    RelayTunnelSourceSecurityConfig, RendezvousControlClient, TRANSPORT_PROTOCOL_VERSION,
    TransportSessionControlMessage, TransportSessionRole, WebSocketByteStream,
    build_signed_request_headers, connect_websocket, perform_transport_client_handshake,
    websocket_url,
};

#[derive(Clone)]
pub(crate) struct TransportSessionPool {
    target: SessionPoolTarget,
    cached_session: Arc<Mutex<Option<CachedTransportSession>>>,
    stats: Arc<TransportSessionPoolStats>,
}

#[derive(Clone)]
enum SessionPoolTarget {
    DirectHttps {
        server_base_url: String,
        server_ca_pem: Option<String>,
    },
    DirectQuic {
        candidate: ConnectionCandidate,
        target_node_id: Option<NodeId>,
        endpoint: Arc<Mutex<Option<DirectQuicEndpoint>>>,
    },
    Relay {
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
        source_security: RelayTunnelSourceSecurityConfig,
    },
}

struct CachedTransportSession {
    session: Arc<MultiplexedSession>,
    _relay_session: Option<RelayTunnelSession>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportSessionPoolSnapshot {
    pub connect_count: u64,
    pub reuse_count: u64,
    pub reset_count: u64,
}

#[derive(Default)]
struct TransportSessionPoolStats {
    connect_count: AtomicU64,
    reuse_count: AtomicU64,
    reset_count: AtomicU64,
}

impl TransportSessionPool {
    pub(crate) fn new_direct(
        server_base_url: impl Into<String>,
        server_ca_pem: Option<String>,
    ) -> Self {
        Self {
            target: SessionPoolTarget::DirectHttps {
                server_base_url: server_base_url.into().trim_end_matches('/').to_string(),
                server_ca_pem,
            },
            cached_session: Arc::new(Mutex::new(None)),
            stats: Arc::new(TransportSessionPoolStats::default()),
        }
    }

    pub(crate) fn new_direct_quic(
        candidate: ConnectionCandidate,
        target_node_id: Option<NodeId>,
    ) -> Self {
        Self {
            target: SessionPoolTarget::DirectQuic {
                candidate,
                target_node_id,
                endpoint: Arc::new(Mutex::new(None)),
            },
            cached_session: Arc::new(Mutex::new(None)),
            stats: Arc::new(TransportSessionPoolStats::default()),
        }
    }

    pub(crate) fn new_relay(
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
        source_security: RelayTunnelSourceSecurityConfig,
    ) -> Self {
        Self {
            target: SessionPoolTarget::Relay {
                rendezvous,
                target_node_id,
                source_security,
            },
            cached_session: Arc::new(Mutex::new(None)),
            stats: Arc::new(TransportSessionPoolStats::default()),
        }
    }

    pub(crate) fn snapshot(&self) -> TransportSessionPoolSnapshot {
        TransportSessionPoolSnapshot {
            connect_count: self.stats.connect_count.load(Ordering::Relaxed),
            reuse_count: self.stats.reuse_count.load(Ordering::Relaxed),
            reset_count: self.stats.reset_count.load(Ordering::Relaxed),
        }
    }

    pub(crate) async fn invalidate(&self) {
        let mut guard = self.cached_session.lock().await;
        if guard.take().is_some() {
            self.stats.reset_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) async fn ensure_direct_session(
        &self,
        identity: &ClientIdentityMaterial,
        connection_name: Option<&str>,
    ) -> Result<Arc<MultiplexedSession>> {
        let mut guard = self.cached_session.lock().await;
        if let Some(existing) = guard.as_ref() {
            self.stats.reuse_count.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(&existing.session));
        }

        let (multiplexed, handshake_context, target) = match &self.target {
            SessionPoolTarget::DirectHttps {
                server_base_url,
                server_ca_pem,
            } => {
                let ws_url = websocket_url(server_base_url, "transport/ws").with_context(|| {
                    format!("failed building direct transport websocket URL from {server_base_url}")
                })?;
                let ws_headers = websocket_auth_headers(identity, connection_name)?;
                let websocket =
                    connect_websocket(&ws_url, server_ca_pem.as_deref(), None, &ws_headers)
                        .await
                        .with_context(|| {
                            format!("failed opening direct transport websocket {}", ws_url)
                        })?;
                let transport = WebSocketByteStream::new(websocket);
                (
                    MultiplexedSession::spawn(
                        transport,
                        MultiplexMode::Client,
                        MultiplexConfig::default(),
                    )
                    .context("failed creating direct multiplexed transport session")?,
                    format!("failed performing direct transport handshake for {server_base_url}"),
                    None,
                )
            }
            SessionPoolTarget::DirectQuic {
                candidate,
                target_node_id,
                endpoint,
            } => {
                let target_node_id = target_node_id.ok_or_else(|| {
                    anyhow!("direct QUIC transport target is missing target node id")
                })?;
                let target_label = candidate.endpoint.clone();
                let endpoint = ensure_direct_quic_endpoint(endpoint, candidate).await?;
                let direct_quic = endpoint
                    .connect_session(candidate, MultiplexConfig::default())
                    .await
                    .with_context(|| {
                        format!("failed opening direct QUIC transport session to {target_label}")
                    })?;
                (
                    direct_quic.session,
                    format!("failed performing direct QUIC transport handshake for {target_label}"),
                    Some(PeerIdentity::Node(target_node_id)),
                )
            }
            SessionPoolTarget::Relay { .. } => {
                bail!("attempted to open a direct session from a relay transport session pool");
            }
        };

        perform_transport_client_handshake(
            &multiplexed,
            TransportSessionControlMessage::Hello {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                cluster_id: identity.cluster_id,
                role: TransportSessionRole::Client,
                peer: PeerIdentity::Device(identity.device_id),
                connection_name: connection_name.map(ToString::to_string),
                target,
            },
        )
        .await
        .with_context(|| handshake_context)?;

        let session = Arc::new(multiplexed);
        *guard = Some(CachedTransportSession {
            session: Arc::clone(&session),
            _relay_session: None,
        });
        self.stats.connect_count.fetch_add(1, Ordering::Relaxed);
        Ok(session)
    }

    pub(crate) async fn ensure_relay_session(
        &self,
        source: PeerIdentity,
        connection_name: Option<&str>,
    ) -> Result<Arc<MultiplexedSession>> {
        let SessionPoolTarget::Relay {
            rendezvous,
            target_node_id,
            source_security,
        } = &self.target
        else {
            bail!("attempted to open a relay session from a direct transport session pool");
        };

        let mut guard = self.cached_session.lock().await;
        if let Some(existing) = guard.as_ref() {
            self.stats.reuse_count.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(&existing.session));
        }

        let ticket = rendezvous
            .issue_relay_ticket(&RelayTicketRequest {
                cluster_id: rendezvous.config().cluster_id,
                source: source.clone(),
                target: PeerIdentity::Node(*target_node_id),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(300),
            })
            .await
            .with_context(|| {
                format!(
                    "failed issuing multiplex relay ticket for client target node {}",
                    target_node_id
                )
            })?;
        let relay_tunnel = rendezvous
            .connect_relay_tunnel_source(&ticket)
            .await
            .with_context(|| {
                format!(
                    "failed opening relay tunnel source for client target node {}",
                    target_node_id
                )
            })?;
        let (relay_session, multiplexed) = relay_tunnel
            .into_secure_multiplexed_source_session(
                source_security.clone(),
                MultiplexConfig::default(),
            )
            .await
            .with_context(|| {
                format!(
                    "failed establishing inner mTLS relay session for client target node {}",
                    target_node_id
                )
            })?;

        perform_transport_client_handshake(
            &multiplexed,
            TransportSessionControlMessage::Hello {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                cluster_id: rendezvous.config().cluster_id,
                role: relay_session_role_for_source(&source),
                peer: source,
                connection_name: connection_name.map(ToString::to_string),
                target: Some(PeerIdentity::Node(*target_node_id)),
            },
        )
        .await
        .with_context(|| {
            format!(
                "failed performing multiplex relay transport handshake for target node {}",
                target_node_id
            )
        })?;

        let session = Arc::new(multiplexed);
        *guard = Some(CachedTransportSession {
            session: Arc::clone(&session),
            _relay_session: Some(relay_session),
        });
        self.stats.connect_count.fetch_add(1, Ordering::Relaxed);
        Ok(session)
    }
}

fn relay_session_role_for_source(source: &PeerIdentity) -> TransportSessionRole {
    match source {
        PeerIdentity::Node(_) => TransportSessionRole::Node,
        PeerIdentity::Device(_) => TransportSessionRole::Client,
    }
}

async fn ensure_direct_quic_endpoint(
    endpoint: &Arc<Mutex<Option<DirectQuicEndpoint>>>,
    candidate: &ConnectionCandidate,
) -> Result<DirectQuicEndpoint> {
    let mut guard = endpoint.lock().await;
    if let Some(endpoint) = guard.as_ref() {
        return Ok(endpoint.clone());
    }

    let mut config = DirectQuicEndpointConfig::new(SecretKey::generate());
    config.alpn = candidate
        .transport_hints
        .as_ref()
        .and_then(|hints| hints.alpn.clone())
        .unwrap_or_else(|| DEFAULT_DIRECT_QUIC_ALPN.to_string());
    if let Some(relay_url) = candidate
        .transport_hints
        .as_ref()
        .and_then(|hints| hints.relay_url.clone())
    {
        config.relay_urls.push(relay_url);
    }

    let endpoint = DirectQuicEndpoint::bind(config).await.with_context(|| {
        format!(
            "failed binding local direct QUIC endpoint for remote candidate {}",
            candidate.endpoint
        )
    })?;
    *guard = Some(endpoint.clone());
    Ok(endpoint)
}

fn websocket_auth_headers(
    identity: &ClientIdentityMaterial,
    connection_name: Option<&str>,
) -> Result<Vec<(String, String)>> {
    let signed_headers =
        build_signed_request_headers(identity, "GET", "/transport/ws", unix_ts(), None)?;
    let mut headers = vec![
        (
            transport_sdk::HEADER_CLUSTER_ID.to_string(),
            signed_headers.cluster_id.to_string(),
        ),
        (
            transport_sdk::HEADER_DEVICE_ID.to_string(),
            signed_headers.device_id,
        ),
        (
            transport_sdk::HEADER_CREDENTIAL_FINGERPRINT.to_string(),
            signed_headers.credential_fingerprint,
        ),
        (
            transport_sdk::HEADER_AUTH_TIMESTAMP.to_string(),
            signed_headers.timestamp_unix.to_string(),
        ),
        (
            transport_sdk::HEADER_AUTH_NONCE.to_string(),
            signed_headers.nonce,
        ),
        (
            transport_sdk::HEADER_AUTH_SIGNATURE.to_string(),
            signed_headers.signature_base64,
        ),
    ];
    if let Some(connection_name) = connection_name {
        headers.push((
            transport_sdk::HEADER_CONNECTION_NAME.to_string(),
            connection_name.to_string(),
        ));
    }
    Ok(headers)
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_quic_pool_snapshot_starts_empty() {
        let pool = TransportSessionPool::new_direct_quic(
            ConnectionCandidate {
                kind: transport_sdk::CandidateKind::DirectQuic,
                endpoint: "iroh://peer-key-1".to_string(),
                rtt_ms: None,
                transport_hints: None,
            },
            Some(NodeId::new_v4()),
        );

        assert_eq!(pool.snapshot(), TransportSessionPoolSnapshot::default());
    }
}
