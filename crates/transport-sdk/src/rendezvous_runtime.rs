use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use common::NodeId;
use futures_util::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, mpsc, oneshot};
use uuid::Uuid;

use crate::bootstrap::ClientBootstrap;
use crate::bootstrap_claim::{
    ClientBootstrapClaimPublishRequest, ClientBootstrapClaimPublishResponse,
};
use crate::mux::{MultiplexConfig, MultiplexMode, MultiplexedSession};
use crate::peer::PeerIdentity;
use crate::relay::{RelayTicket, RelayTicketRequest, RelayTunnelSessionKind};
use crate::relay_tunnel::{RelayTunnelAcceptRequest, RelayTunnelSession};
use crate::rendezvous::{PresenceEntry, PresenceRegistration};

#[derive(Clone, Default)]
pub struct PresenceRegistry {
    entries: Arc<StdMutex<HashMap<String, PresenceEntry>>>,
}

impl PresenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, registration: PresenceRegistration) -> PresenceEntry {
        let entry = PresenceEntry {
            updated_at_unix: registration.connected_at_unix,
            registration,
        };
        let key = entry.registration.identity.to_string();
        let mut entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.insert(key, entry.clone());
        entry
    }

    pub fn list(&self) -> Vec<PresenceEntry> {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        let mut values = entries.values().cloned().collect::<Vec<_>>();
        values.sort_by(|left, right| {
            left.registration
                .identity
                .to_string()
                .cmp(&right.registration.identity.to_string())
        });
        values
    }

    pub fn entry_for_identity(&self, identity: &PeerIdentity) -> Option<PresenceEntry> {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.get(&identity.to_string()).cloned()
    }

    pub fn contains_identity(&self, identity: &PeerIdentity) -> bool {
        self.entry_for_identity(identity).is_some()
    }

    pub fn len(&self) -> usize {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.len()
    }

    pub fn is_empty(&self) -> bool {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.is_empty()
    }
}

#[derive(Clone, Default)]
pub struct BootstrapClaimBroker {
    inner: Arc<Mutex<HashMap<String, BootstrapClaimRecord>>>,
}

#[derive(Debug, Clone)]
pub struct BootstrapClaimRecord {
    pub issuer: PeerIdentity,
    pub target_node_id: NodeId,
    pub expires_at_unix: u64,
    pub bootstrap: ClientBootstrap,
}

impl BootstrapClaimBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn publish(
        &self,
        request: ClientBootstrapClaimPublishRequest,
    ) -> Result<ClientBootstrapClaimPublishResponse> {
        request.validate()?;
        let mut state = self.inner.lock().await;
        retain_active_claims(&mut state);
        state.insert(
            request.claim_secret_hash.clone(),
            BootstrapClaimRecord {
                issuer: request.issuer,
                target_node_id: request.target_node_id,
                expires_at_unix: request.expires_at_unix,
                bootstrap: request.bootstrap,
            },
        );
        Ok(ClientBootstrapClaimPublishResponse {
            accepted: true,
            expires_at_unix: request.expires_at_unix,
        })
    }

    pub async fn take_for_redeem(&self, claim_token: &str) -> Result<BootstrapClaimRecord> {
        let claim_token = claim_token.trim();
        if claim_token.is_empty() {
            bail!("bootstrap claim token must not be empty");
        }

        let mut state = self.inner.lock().await;
        retain_active_claims(&mut state);
        state
            .remove(&hash_token(claim_token))
            .ok_or_else(|| anyhow!("bootstrap claim was not found or has expired"))
    }

    pub async fn restore(&self, claim_token: &str, record: BootstrapClaimRecord) {
        let mut state = self.inner.lock().await;
        if record.expires_at_unix > unix_ts() {
            state.insert(hash_token(claim_token), record);
        }
    }
}

pub fn issue_relay_ticket(
    request: RelayTicketRequest,
    relay_public_urls: &[String],
) -> RelayTicket {
    let now = unix_ts();
    let expires_at_unix = now
        + request
            .requested_expires_in_secs
            .unwrap_or(300)
            .clamp(60, 60 * 60);

    RelayTicket {
        cluster_id: request.cluster_id,
        session_id: Uuid::now_v7().to_string(),
        source: request.source,
        target: request.target,
        session_kind: request.session_kind,
        relay_urls: relay_public_urls.to_vec(),
        issued_at_unix: now,
        expires_at_unix,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayTunnelFrame {
    Data(Vec<u8>),
    CloseWrite,
}

pub struct RelayTunnelEndpoint {
    session: RelayTunnelSession,
    inbound: mpsc::Receiver<RelayTunnelFrame>,
    outbound: mpsc::Sender<RelayTunnelFrame>,
}

impl RelayTunnelEndpoint {
    pub fn session(&self) -> &RelayTunnelSession {
        &self.session
    }

    pub fn into_multiplexed_session(
        self,
        mode: MultiplexMode,
        config: MultiplexConfig,
    ) -> Result<(RelayTunnelSession, MultiplexedSession)> {
        let RelayTunnelEndpoint {
            session,
            inbound,
            outbound,
        } = self;
        let multiplexed = MultiplexedSession::spawn(
            RelayTunnelEndpointByteStream::new(inbound, outbound),
            mode,
            config,
        )
        .map_err(|err| anyhow!("failed creating multiplexed relay endpoint session: {err:#}"))?;
        Ok((session, multiplexed))
    }

    pub async fn send(&self, frame: RelayTunnelFrame) -> Result<()> {
        self.outbound
            .send(frame)
            .await
            .map_err(|_| anyhow!("relay tunnel peer disconnected before frame delivery"))
    }

    pub async fn recv(&mut self) -> Option<RelayTunnelFrame> {
        self.inbound.recv().await
    }
}

#[derive(Clone, Copy)]
enum PendingRelayTunnelSendKind {
    Data(usize),
    Close,
}

struct PendingRelayTunnelSend {
    future: Pin<
        Box<
            dyn Future<Output = std::result::Result<(), mpsc::error::SendError<RelayTunnelFrame>>>
                + Send,
        >,
    >,
    kind: PendingRelayTunnelSendKind,
}

struct RelayTunnelEndpointByteStream {
    inbound: mpsc::Receiver<RelayTunnelFrame>,
    outbound: mpsc::Sender<RelayTunnelFrame>,
    read_buffer: Vec<u8>,
    read_offset: usize,
    read_closed: bool,
    write_closed: bool,
    pending_send: Option<PendingRelayTunnelSend>,
}

impl RelayTunnelEndpointByteStream {
    fn new(
        inbound: mpsc::Receiver<RelayTunnelFrame>,
        outbound: mpsc::Sender<RelayTunnelFrame>,
    ) -> Self {
        Self {
            inbound,
            outbound,
            read_buffer: Vec::new(),
            read_offset: 0,
            read_closed: false,
            write_closed: false,
            pending_send: None,
        }
    }

    fn start_pending_send(&mut self, frame: RelayTunnelFrame, kind: PendingRelayTunnelSendKind) {
        let outbound = self.outbound.clone();
        self.pending_send = Some(PendingRelayTunnelSend {
            future: Box::pin(async move { outbound.send(frame).await }),
            kind,
        });
    }

    fn poll_pending_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Option<PendingRelayTunnelSendKind>>> {
        let Some(pending) = self.pending_send.as_mut() else {
            return Poll::Ready(Ok(None));
        };

        match pending.future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let kind = self
                    .pending_send
                    .take()
                    .expect("pending relay tunnel send should exist")
                    .kind;
                Poll::Ready(Ok(Some(kind)))
            }
            Poll::Ready(Err(_)) => {
                self.pending_send = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "relay tunnel peer disconnected before frame delivery",
                )))
            }
        }
    }
}

impl AsyncRead for RelayTunnelEndpointByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            if self.read_offset < self.read_buffer.len() {
                let available = self.read_buffer.len() - self.read_offset;
                let to_copy = available.min(buf.len());
                buf[..to_copy].copy_from_slice(
                    &self.read_buffer[self.read_offset..self.read_offset + to_copy],
                );
                self.read_offset += to_copy;
                if self.read_offset >= self.read_buffer.len() {
                    self.read_buffer.clear();
                    self.read_offset = 0;
                }
                return Poll::Ready(Ok(to_copy));
            }

            if self.read_closed {
                return Poll::Ready(Ok(0));
            }

            match self.inbound.poll_recv(cx) {
                Poll::Ready(Some(RelayTunnelFrame::Data(bytes))) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    self.read_buffer = bytes;
                    self.read_offset = 0;
                }
                Poll::Ready(Some(RelayTunnelFrame::CloseWrite)) | Poll::Ready(None) => {
                    self.read_closed = true;
                    return Poll::Ready(Ok(0));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for RelayTunnelEndpointByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "relay tunnel write side is already closed",
            )));
        }

        if self.pending_send.is_none() {
            self.start_pending_send(
                RelayTunnelFrame::Data(buf.to_vec()),
                PendingRelayTunnelSendKind::Data(buf.len()),
            );
        }

        match self.poll_pending_send(cx) {
            Poll::Ready(Ok(Some(PendingRelayTunnelSendKind::Data(len)))) => Poll::Ready(Ok(len)),
            Poll::Ready(Ok(Some(PendingRelayTunnelSendKind::Close))) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(0)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending_send(cx) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return self.poll_flush(cx);
        }

        if self.pending_send.is_none() {
            self.start_pending_send(
                RelayTunnelFrame::CloseWrite,
                PendingRelayTunnelSendKind::Close,
            );
        }

        match self.poll_pending_send(cx) {
            Poll::Ready(Ok(Some(PendingRelayTunnelSendKind::Close))) | Poll::Ready(Ok(None)) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Some(PendingRelayTunnelSendKind::Data(_)))) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Clone, Default)]
pub struct RelayTunnelBroker {
    inner: Arc<Mutex<RelayTunnelBrokerState>>,
}

#[derive(Default)]
struct RelayTunnelBrokerState {
    pending_sources_by_target: HashMap<String, VecDeque<PendingRelayTunnelSource>>,
    waiting_targets_by_key: HashMap<String, VecDeque<WaitingRelayTunnelTarget>>,
}

struct PendingRelayTunnelSource {
    session: RelayTunnelSession,
    waiter: oneshot::Sender<RelayTunnelEndpoint>,
}

struct WaitingRelayTunnelTarget {
    waiter: oneshot::Sender<RelayTunnelEndpoint>,
}

impl RelayTunnelBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn connect_source(&self, ticket: RelayTicket) -> Result<RelayTunnelEndpoint> {
        ticket.validate()?;
        if ticket.expires_at_unix <= unix_ts() {
            bail!("relay tunnel ticket has expired");
        }

        let session = RelayTunnelSession {
            cluster_id: ticket.cluster_id,
            session_id: ticket.session_id.clone(),
            source: ticket.source.clone(),
            target: ticket.target.clone(),
            session_kind: ticket.session_kind,
        };
        session.validate()?;

        let target_key = relay_target_key(ticket.cluster_id, &ticket.target, ticket.session_kind);
        let (waiter_tx, waiter_rx) = oneshot::channel();
        let source = PendingRelayTunnelSource {
            session: session.clone(),
            waiter: waiter_tx,
        };

        let paired = {
            let mut state = self.inner.lock().await;
            let mut paired = None;
            while let Some(waiting) =
                pop_waiting_target(&mut state.waiting_targets_by_key, &target_key)
            {
                let (source_endpoint, target_endpoint) = paired_tunnel_endpoints(session.clone());
                if waiting.waiter.send(target_endpoint).is_ok() {
                    paired = Some(source_endpoint);
                    break;
                }
            }
            if paired.is_none() {
                state
                    .pending_sources_by_target
                    .entry(target_key.clone())
                    .or_default()
                    .push_back(source);
            }
            paired
        };

        if let Some(endpoint) = paired {
            return Ok(endpoint);
        }

        let wait_secs = ticket
            .expires_at_unix
            .saturating_sub(unix_ts())
            .clamp(5, 60);
        match tokio::time::timeout(Duration::from_secs(wait_secs), waiter_rx).await {
            Ok(Ok(endpoint)) => Ok(endpoint),
            Ok(Err(_)) => {
                self.remove_pending_source(&target_key, &ticket.session_id)
                    .await;
                Err(anyhow!(
                    "relay tunnel target disconnected before session pairing"
                ))
            }
            Err(_) => {
                self.remove_pending_source(&target_key, &ticket.session_id)
                    .await;
                bail!("timed out waiting for relay tunnel target acceptance")
            }
        }
    }

    pub async fn accept_target(
        &self,
        request: RelayTunnelAcceptRequest,
    ) -> Result<RelayTunnelEndpoint> {
        request.validate()?;
        let target_key =
            relay_target_key(request.cluster_id, &request.target, request.session_kind);
        let timeout =
            Duration::from_millis(request.wait_timeout_ms.unwrap_or(15_000).clamp(100, 30_000));

        if let Some(endpoint) = self.try_pair_target(&target_key).await? {
            return Ok(endpoint);
        }

        let (waiter_tx, waiter_rx) = oneshot::channel();
        {
            let mut state = self.inner.lock().await;
            state
                .waiting_targets_by_key
                .entry(target_key.clone())
                .or_default()
                .push_back(WaitingRelayTunnelTarget { waiter: waiter_tx });
        }

        match tokio::time::timeout(timeout, waiter_rx).await {
            Ok(Ok(endpoint)) => Ok(endpoint),
            Ok(Err(_)) => {
                self.remove_waiting_target(&target_key).await;
                Err(anyhow!(
                    "relay tunnel source disconnected before session pairing"
                ))
            }
            Err(_) => {
                self.remove_waiting_target(&target_key).await;
                bail!("timed out waiting for relay tunnel source")
            }
        }
    }

    async fn try_pair_target(&self, target_key: &str) -> Result<Option<RelayTunnelEndpoint>> {
        let mut state = self.inner.lock().await;
        while let Some(source) =
            pop_pending_source(&mut state.pending_sources_by_target, target_key)
        {
            let (source_endpoint, target_endpoint) = paired_tunnel_endpoints(source.session);
            if source.waiter.send(source_endpoint).is_ok() {
                return Ok(Some(target_endpoint));
            }
        }
        Ok(None)
    }

    async fn remove_pending_source(&self, target_key: &str, session_id: &str) {
        let mut state = self.inner.lock().await;
        if let Some(queue) = state.pending_sources_by_target.get_mut(target_key) {
            queue.retain(|pending| pending.session.session_id != session_id);
            if queue.is_empty() {
                state.pending_sources_by_target.remove(target_key);
            }
        }
    }

    async fn remove_waiting_target(&self, target_key: &str) {
        let mut state = self.inner.lock().await;
        if let Some(queue) = state.waiting_targets_by_key.get_mut(target_key) {
            if !queue.is_empty() {
                queue.pop_front();
            }
            if queue.is_empty() {
                state.waiting_targets_by_key.remove(target_key);
            }
        }
    }
}

fn paired_tunnel_endpoints(
    session: RelayTunnelSession,
) -> (RelayTunnelEndpoint, RelayTunnelEndpoint) {
    let (source_to_target_tx, source_to_target_rx) = mpsc::channel(16);
    let (target_to_source_tx, target_to_source_rx) = mpsc::channel(16);
    (
        RelayTunnelEndpoint {
            session: session.clone(),
            inbound: target_to_source_rx,
            outbound: source_to_target_tx,
        },
        RelayTunnelEndpoint {
            session,
            inbound: source_to_target_rx,
            outbound: target_to_source_tx,
        },
    )
}

fn pop_pending_source(
    pending_by_target: &mut HashMap<String, VecDeque<PendingRelayTunnelSource>>,
    target_key: &str,
) -> Option<PendingRelayTunnelSource> {
    loop {
        let pending = pending_by_target
            .get_mut(target_key)
            .and_then(|queue| queue.pop_front());
        if pending_by_target
            .get(target_key)
            .map(|queue| queue.is_empty())
            .unwrap_or(false)
        {
            pending_by_target.remove(target_key);
        }
        let pending = pending?;
        if !pending.waiter.is_closed() {
            return Some(pending);
        }
    }
}

fn pop_waiting_target(
    waiting_targets_by_key: &mut HashMap<String, VecDeque<WaitingRelayTunnelTarget>>,
    target_key: &str,
) -> Option<WaitingRelayTunnelTarget> {
    loop {
        let waiting = waiting_targets_by_key
            .get_mut(target_key)
            .and_then(|queue| queue.pop_front());
        if waiting_targets_by_key
            .get(target_key)
            .map(|queue| queue.is_empty())
            .unwrap_or(false)
        {
            waiting_targets_by_key.remove(target_key);
        }
        let waiting = waiting?;
        if !waiting.waiter.is_closed() {
            return Some(waiting);
        }
    }
}

fn relay_target_key(
    cluster_id: uuid::Uuid,
    target: &PeerIdentity,
    session_kind: RelayTunnelSessionKind,
) -> String {
    format!("{cluster_id}:{target}:{session_kind:?}")
}

fn retain_active_claims(state: &mut HashMap<String, BootstrapClaimRecord>) {
    let now = unix_ts();
    state.retain(|_, record| record.expires_at_unix > now);
}

fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multiplex_transport::{
        BufferedTransportRequest, BufferedTransportResponse, perform_transport_client_handshake,
        perform_transport_server_handshake, read_buffered_transport_request,
        write_buffered_transport_request, write_buffered_transport_response,
    };
    use crate::transport_protocol::{
        TRANSPORT_PROTOCOL_VERSION, TransportSessionControlMessage, TransportSessionRole,
        TransportStreamKind,
    };

    #[tokio::test]
    async fn relay_tunnel_broker_pairs_source_and_target_and_relays_frames() {
        let broker = RelayTunnelBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source: source.clone(),
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_source = broker.clone();
        let source_task = tokio::spawn(async move {
            let mut endpoint = broker_for_source
                .connect_source(ticket)
                .await
                .expect("source should pair");
            endpoint
                .send(RelayTunnelFrame::Data(b"hello".to_vec()))
                .await
                .expect("source data should send");
            endpoint
                .send(RelayTunnelFrame::CloseWrite)
                .await
                .expect("source close_write should send");
            let response = endpoint
                .recv()
                .await
                .expect("target response should arrive");
            assert_eq!(response, RelayTunnelFrame::Data(b"world".to_vec()));
            assert_eq!(endpoint.recv().await, Some(RelayTunnelFrame::CloseWrite));
        });

        let mut target_endpoint = broker
            .accept_target(RelayTunnelAcceptRequest {
                cluster_id,
                target,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                wait_timeout_ms: Some(500),
            })
            .await
            .expect("target should pair");
        assert_eq!(target_endpoint.session().cluster_id, cluster_id);
        assert_eq!(target_endpoint.session().source, source);
        assert_eq!(
            target_endpoint.recv().await,
            Some(RelayTunnelFrame::Data(b"hello".to_vec()))
        );
        assert_eq!(
            target_endpoint.recv().await,
            Some(RelayTunnelFrame::CloseWrite)
        );
        target_endpoint
            .send(RelayTunnelFrame::Data(b"world".to_vec()))
            .await
            .expect("target data should send");
        target_endpoint
            .send(RelayTunnelFrame::CloseWrite)
            .await
            .expect("target close_write should send");

        source_task.await.expect("source task should join");
    }

    #[tokio::test]
    async fn relay_tunnel_endpoint_supports_multiplexed_sessions() {
        let broker = RelayTunnelBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source: source.clone(),
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_source = broker.clone();
        let source_for_task = source.clone();
        let source_task = tokio::spawn(async move {
            let (relay_session, session) = broker_for_source
                .connect_source(ticket)
                .await
                .expect("source should pair")
                .into_multiplexed_session(MultiplexMode::Client, MultiplexConfig::default())
                .expect("source multiplex session should spawn");
            assert_eq!(relay_session.source, source_for_task);

            perform_transport_client_handshake(
                &session,
                TransportSessionControlMessage::Hello {
                    protocol_version: TRANSPORT_PROTOCOL_VERSION,
                    cluster_id,
                    role: TransportSessionRole::Node,
                    peer: relay_session.source.clone(),
                    target: Some(relay_session.target.clone()),
                },
            )
            .await
            .expect("source transport handshake should succeed");

            let request = BufferedTransportRequest::new(
                TransportStreamKind::Diagnostics,
                "GET",
                "/diagnostics/latency",
                Vec::new(),
                Vec::new(),
            );
            let mut stream = session
                .open_stream()
                .await
                .expect("source stream should open");
            write_buffered_transport_request(&mut stream, &request)
                .await
                .expect("source request should write");
            let response =
                crate::multiplex_transport::read_buffered_transport_response(&mut stream)
                    .await
                    .expect("source response should read");
            assert_eq!(response.status, 200);
            assert_eq!(response.body, br#"{"ok":true}"#);

            session.close().await.expect("source session should close");
        });

        let (relay_session, mut session) = broker
            .accept_target(RelayTunnelAcceptRequest {
                cluster_id,
                target,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                wait_timeout_ms: Some(500),
            })
            .await
            .expect("target should pair")
            .into_multiplexed_session(MultiplexMode::Server, MultiplexConfig::default())
            .expect("target multiplex session should spawn");
        assert_eq!(relay_session.source, source);
        let hello = perform_transport_server_handshake(
            &mut session,
            TransportSessionControlMessage::Ready {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                session_id: relay_session.session_id.clone(),
                max_concurrent_streams: MultiplexConfig::default().max_num_streams,
            },
        )
        .await
        .expect("target handshake should succeed");
        assert!(matches!(
            hello,
            TransportSessionControlMessage::Hello {
                role: TransportSessionRole::Node,
                ..
            }
        ));

        let mut stream = session
            .accept_stream()
            .await
            .expect("target stream accept should succeed")
            .expect("target stream should exist");
        let request = read_buffered_transport_request(&mut stream)
            .await
            .expect("target request should decode");
        assert_eq!(request.path, "/diagnostics/latency");
        write_buffered_transport_response(
            &mut stream,
            &BufferedTransportResponse {
                request_id: request.request_id,
                status: 200,
                headers: Vec::new(),
                body: br#"{"ok":true}"#.to_vec(),
            },
        )
        .await
        .expect("target response should write");

        session.close().await.expect("target session should close");
        source_task.await.expect("source task should join");
    }
}
