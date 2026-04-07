use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow, bail};
use common::NodeId;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use uuid::Uuid;

use crate::bootstrap::ClientBootstrap;
use crate::bootstrap_claim::{
    ClientBootstrapClaimPublishRequest, ClientBootstrapClaimPublishResponse,
};
use crate::peer::PeerIdentity;
use crate::relay::{
    PendingRelayHttpRequest, RelayHttpPollRequest, RelayHttpPollResponse, RelayHttpRequest,
    RelayHttpResponse, RelayTicket, RelayTicketRequest, RelayTunnelSessionKind,
};
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

#[derive(Clone, Default)]
pub struct RelayBroker {
    inner: Arc<RelayBrokerInner>,
}

#[derive(Default)]
struct RelayBrokerInner {
    state: Mutex<RelayBrokerState>,
    notify: Notify,
}

#[derive(Default)]
struct RelayBrokerState {
    pending_by_target: HashMap<String, VecDeque<PendingRelayHttpRequest>>,
    inflight: HashMap<String, InflightRelayRequest>,
    stats: RelayBrokerStats,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayBrokerStats {
    pub submitted_requests: u64,
    pub delivered_requests: u64,
    pub completed_responses: u64,
}

struct InflightRelayRequest {
    response_tx: oneshot::Sender<RelayHttpResponse>,
    cluster_id: uuid::Uuid,
    session_id: String,
    expected_responder: PeerIdentity,
}

struct SubmitAwaitCleanup {
    inner: Arc<RelayBrokerInner>,
    request_id: String,
    active: bool,
}

impl SubmitAwaitCleanup {
    fn new(inner: Arc<RelayBrokerInner>, request_id: String) -> Self {
        Self {
            inner,
            request_id,
            active: true,
        }
    }

    fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for SubmitAwaitCleanup {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        let inner = self.inner.clone();
        let request_id = self.request_id.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        handle.spawn(async move {
            let mut state = inner.state.lock().await;
            state.inflight.remove(&request_id);
            remove_pending_request(&mut state.pending_by_target, &request_id);
        });
    }
}

impl RelayBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn stats(&self) -> RelayBrokerStats {
        let state = self.inner.state.lock().await;
        state.stats
    }

    pub async fn submit_and_await(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        request.validate()?;
        request.ticket.validate()?;
        if request.ticket.expires_at_unix <= unix_ts() {
            bail!("relay ticket has expired");
        }

        let target_key = relay_target_key(
            request.ticket.cluster_id,
            &request.ticket.target,
            RelayTunnelSessionKind::LegacyHttpTunnel,
        );
        let request_id = request.request_id.clone();
        let pending = PendingRelayHttpRequest {
            cluster_id: request.ticket.cluster_id,
            session_id: request.ticket.session_id.clone(),
            request_id: request.request_id.clone(),
            source: request.ticket.source.clone(),
            target: request.ticket.target.clone(),
            method: request.method,
            path_and_query: request.path_and_query,
            headers: request.headers,
            body_base64: request.body_base64,
        };
        pending.validate()?;

        let wait_timeout = request
            .ticket
            .expires_at_unix
            .saturating_sub(unix_ts())
            .clamp(5, 60);
        let (tx, rx) = oneshot::channel();

        {
            let mut state = self.inner.state.lock().await;
            state
                .pending_by_target
                .entry(target_key)
                .or_default()
                .push_back(pending);
            state.inflight.insert(
                request_id.clone(),
                InflightRelayRequest {
                    response_tx: tx,
                    cluster_id: request.ticket.cluster_id,
                    session_id: request.ticket.session_id.clone(),
                    expected_responder: request.ticket.target.clone(),
                },
            );
            state.stats.submitted_requests = state.stats.submitted_requests.saturating_add(1);
        }
        self.inner.notify.notify_waiters();
        let mut cleanup = SubmitAwaitCleanup::new(self.inner.clone(), request_id.clone());

        match tokio::time::timeout(Duration::from_secs(wait_timeout), rx).await {
            Ok(Ok(response)) => {
                cleanup.disarm();
                response.validate()?;
                Ok(response)
            }
            Ok(Err(_)) => {
                let mut state = self.inner.state.lock().await;
                state.inflight.remove(&request_id);
                remove_pending_request(&mut state.pending_by_target, &request_id);
                cleanup.disarm();
                Err(anyhow!("relay response channel closed before completion"))
            }
            Err(_) => {
                let mut state = self.inner.state.lock().await;
                state.inflight.remove(&request_id);
                remove_pending_request(&mut state.pending_by_target, &request_id);
                cleanup.disarm();
                bail!("timed out waiting for relayed HTTP response")
            }
        }
    }

    pub async fn poll(&self, request: RelayHttpPollRequest) -> Result<RelayHttpPollResponse> {
        request.validate()?;
        let target_key = relay_target_key(
            request.cluster_id,
            &request.target,
            RelayTunnelSessionKind::LegacyHttpTunnel,
        );
        let timeout =
            Duration::from_millis(request.wait_timeout_ms.unwrap_or(15_000).clamp(100, 30_000));

        if let Some(pending) = self.try_pop_pending(&target_key).await? {
            return Ok(RelayHttpPollResponse {
                request: Some(pending),
            });
        }

        let notified = self.inner.notify.notified();
        let _ = tokio::time::timeout(timeout, notified).await;

        Ok(RelayHttpPollResponse {
            request: self.try_pop_pending(&target_key).await?,
        })
    }

    pub async fn respond(&self, response: RelayHttpResponse) -> Result<bool> {
        response.validate()?;
        let inflight = {
            let mut state = self.inner.state.lock().await;
            state.inflight.remove(&response.request_id)
        };
        match inflight {
            Some(inflight) => {
                if inflight.cluster_id != response.cluster_id {
                    bail!("relay response cluster_id does not match the in-flight request");
                }
                if inflight.session_id != response.session_id {
                    bail!("relay response session_id does not match the in-flight request");
                }
                if inflight.expected_responder != response.responder {
                    bail!("relay response responder does not match the in-flight request target");
                }
                let _ = inflight.response_tx.send(response);
                let mut state = self.inner.state.lock().await;
                state.stats.completed_responses = state.stats.completed_responses.saturating_add(1);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn try_pop_pending(&self, target_key: &str) -> Result<Option<PendingRelayHttpRequest>> {
        let mut state = self.inner.state.lock().await;
        let pending = state
            .pending_by_target
            .get_mut(target_key)
            .and_then(|queue| queue.pop_front());
        if state
            .pending_by_target
            .get(target_key)
            .map(|queue| queue.is_empty())
            .unwrap_or(false)
        {
            state.pending_by_target.remove(target_key);
        }
        if let Some(pending) = pending.as_ref() {
            state.stats.delivered_requests = state.stats.delivered_requests.saturating_add(1);
            pending.validate()?;
        }
        Ok(pending)
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

fn remove_pending_request(
    pending_by_target: &mut HashMap<String, VecDeque<PendingRelayHttpRequest>>,
    request_id: &str,
) {
    let keys = pending_by_target.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        if let Some(queue) = pending_by_target.get_mut(&key) {
            queue.retain(|request| request.request_id != request_id);
            if queue.is_empty() {
                pending_by_target.remove(&key);
            }
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
    use crate::relay::encode_optional_body_base64;

    #[tokio::test]
    async fn relay_broker_round_trips_http_request() {
        let broker = RelayBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source: source.clone(),
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::LegacyHttpTunnel,
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_submit = broker.clone();
        let submit = tokio::spawn(async move {
            broker_for_submit
                .submit_and_await(RelayHttpRequest {
                    ticket,
                    request_id: "req-1".to_string(),
                    method: "GET".to_string(),
                    path_and_query: "/health".to_string(),
                    headers: Vec::new(),
                    body_base64: None,
                })
                .await
                .expect("relay request should complete")
        });

        let pending = broker
            .poll(RelayHttpPollRequest {
                cluster_id,
                target,
                wait_timeout_ms: Some(100),
            })
            .await
            .expect("relay poll should succeed")
            .request
            .expect("poll should return a pending request");
        assert_eq!(pending.request_id, "req-1");
        assert_eq!(pending.path_and_query, "/health");

        let accepted = broker
            .respond(RelayHttpResponse {
                cluster_id,
                session_id: pending.session_id.clone(),
                request_id: pending.request_id.clone(),
                responder: pending.target.clone(),
                status: 200,
                headers: Vec::new(),
                body_base64: encode_optional_body_base64(br#"{"ok":true}"#),
            })
            .await
            .expect("relay response should be accepted");
        assert!(accepted);

        let response = submit.await.expect("submit task should join");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body_bytes().expect("body should decode"),
            br#"{"ok":true}"#
        );
    }

    #[tokio::test]
    async fn relay_broker_rejects_response_from_wrong_responder() {
        let broker = RelayBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let wrong_target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source,
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::LegacyHttpTunnel,
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_submit = broker.clone();
        let submit = tokio::spawn(async move {
            broker_for_submit
                .submit_and_await(RelayHttpRequest {
                    ticket,
                    request_id: "req-2".to_string(),
                    method: "GET".to_string(),
                    path_and_query: "/health".to_string(),
                    headers: Vec::new(),
                    body_base64: None,
                })
                .await
        });

        let pending = broker
            .poll(RelayHttpPollRequest {
                cluster_id,
                target,
                wait_timeout_ms: Some(100),
            })
            .await
            .expect("relay poll should succeed")
            .request
            .expect("poll should return a pending request");

        let error = broker
            .respond(RelayHttpResponse {
                cluster_id,
                session_id: pending.session_id,
                request_id: pending.request_id,
                responder: wrong_target,
                status: 200,
                headers: Vec::new(),
                body_base64: None,
            })
            .await
            .expect_err("wrong responder should be rejected");
        assert!(error.to_string().contains("does not match"));

        submit.abort();
        let _ = submit.await;
    }

    #[tokio::test]
    async fn relay_broker_removes_pending_request_when_submitter_is_dropped() {
        let broker = RelayBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source,
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::LegacyHttpTunnel,
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_submit = broker.clone();
        let submit = tokio::spawn(async move {
            broker_for_submit
                .submit_and_await(RelayHttpRequest {
                    ticket,
                    request_id: "req-drop".to_string(),
                    method: "GET".to_string(),
                    path_and_query: "/health".to_string(),
                    headers: Vec::new(),
                    body_base64: None,
                })
                .await
        });

        tokio::task::yield_now().await;
        submit.abort();
        let _ = submit.await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pending = broker
            .poll(RelayHttpPollRequest {
                cluster_id,
                target,
                wait_timeout_ms: Some(50),
            })
            .await
            .expect("relay poll should succeed")
            .request;
        assert!(pending.is_none(), "abandoned request should be removed");
    }

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
                session_kind: RelayTunnelSessionKind::LegacyHttpTunnel,
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
                session_kind: RelayTunnelSessionKind::LegacyHttpTunnel,
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
}
