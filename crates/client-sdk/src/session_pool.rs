use anyhow::{Context, Result, bail};
use common::NodeId;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;
use transport_sdk::{
    ClientIdentityMaterial, MultiplexConfig, MultiplexMode, MultiplexedSession, PeerIdentity,
    RelayTicketRequest, RelayTunnelSession, RelayTunnelSessionKind, RendezvousControlClient,
    TRANSPORT_PROTOCOL_VERSION, TransportSessionControlMessage, TransportSessionRole,
    WebSocketByteStream, build_signed_request_headers, connect_websocket,
    perform_transport_client_handshake, websocket_url,
};

#[derive(Clone)]
pub(crate) struct TransportSessionPool {
    target: SessionPoolTarget,
    cached_session: Arc<Mutex<Option<CachedTransportSession>>>,
    stats: Arc<TransportSessionPoolStats>,
}

#[derive(Clone)]
enum SessionPoolTarget {
    Direct {
        server_base_url: String,
        server_ca_pem: Option<String>,
    },
    Relay {
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
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
            target: SessionPoolTarget::Direct {
                server_base_url: server_base_url.into().trim_end_matches('/').to_string(),
                server_ca_pem,
            },
            cached_session: Arc::new(Mutex::new(None)),
            stats: Arc::new(TransportSessionPoolStats::default()),
        }
    }

    pub(crate) fn new_relay(rendezvous: RendezvousControlClient, target_node_id: NodeId) -> Self {
        Self {
            target: SessionPoolTarget::Relay {
                rendezvous,
                target_node_id,
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
    ) -> Result<Arc<MultiplexedSession>> {
        let SessionPoolTarget::Direct {
            server_base_url,
            server_ca_pem,
        } = &self.target
        else {
            bail!("attempted to open a direct session from a relay transport session pool");
        };

        let mut guard = self.cached_session.lock().await;
        if let Some(existing) = guard.as_ref() {
            self.stats.reuse_count.fetch_add(1, Ordering::Relaxed);
            return Ok(Arc::clone(&existing.session));
        }

        let ws_url = websocket_url(server_base_url, "transport/ws").with_context(|| {
            format!("failed building direct transport websocket URL from {server_base_url}")
        })?;
        let ws_headers = websocket_auth_headers(identity)?;
        let websocket = connect_websocket(&ws_url, server_ca_pem.as_deref(), None, &ws_headers)
            .await
            .with_context(|| format!("failed opening direct transport websocket {}", ws_url))?;
        let transport = WebSocketByteStream::new(websocket);
        let multiplexed =
            MultiplexedSession::spawn(transport, MultiplexMode::Client, MultiplexConfig::default())
                .context("failed creating direct multiplexed transport session")?;
        perform_transport_client_handshake(
            &multiplexed,
            TransportSessionControlMessage::Hello {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                cluster_id: identity.cluster_id,
                role: TransportSessionRole::Client,
                peer: PeerIdentity::Device(identity.device_id),
                target: None,
            },
        )
        .await
        .context("failed performing direct transport handshake")?;

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
    ) -> Result<Arc<MultiplexedSession>> {
        let SessionPoolTarget::Relay {
            rendezvous,
            target_node_id,
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
        let (relay_session, multiplexed) = rendezvous
            .connect_relay_multiplex_source(&ticket, MultiplexConfig::default())
            .await
            .with_context(|| {
                format!(
                    "failed opening multiplex relay session for client target node {}",
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

fn websocket_auth_headers(identity: &ClientIdentityMaterial) -> Result<Vec<(String, String)>> {
    let signed_headers =
        build_signed_request_headers(identity, "GET", "/transport/ws", unix_ts(), None)?;
    Ok(vec![
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
    ])
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
