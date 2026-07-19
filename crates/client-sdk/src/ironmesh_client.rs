use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use common::{NodeId, StorageObjectMeta};
use futures_util::future::join_all;
use futures_util::io::{
    AsyncRead, AsyncReadExt as FuturesAsyncReadExt, AsyncWrite,
    AsyncWriteExt as FuturesAsyncWriteExt,
};
use futures_util::stream::{Stream, StreamExt};
use reqwest::Client as HttpClient;
use reqwest::Method;
use reqwest::RequestBuilder;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderMap, HeaderName, HeaderValue,
    IF_RANGE, RANGE,
};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_core::{NamespaceEntry, SyncSnapshot};
use transport_sdk::{
    BufferedTransportRequest, BufferedTransportResponse as MultiplexBufferedTransportResponse,
    ClientIdentityMaterial, ConnectionCandidate, PeerIdentity, RelayHttpHeader,
    RelayTunnelSourceSecurityConfig, RendezvousControlClient, TransportHeader, TransportPathKind,
    TransportRequestHead, TransportStreamKind, build_signed_request_headers,
    read_buffered_transport_response, read_transport_response_head,
    write_buffered_transport_request, write_transport_request_head,
};
use uuid::Uuid;

use crate::session_pool::{TransportSessionPool, TransportSessionPoolSnapshot};

const LARGE_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;
const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;
const DOWNLOAD_SEGMENT_SIZE_BYTES: usize = 1024 * 1024;
const STAGED_DOWNLOAD_COPY_BUFFER_SIZE_BYTES: usize = 64 * 1024;
const TRANSPORT_STREAM_COPY_BUFFER_SIZE_BYTES: usize = 64 * 1024;
const CLIENT_ROUTE_UNKNOWN_LATENCY_MS: f64 = 75.0;
const CLIENT_ROUTE_RELAY_PENALTY_MS: f64 = 25.0;
const CLIENT_ROUTE_FAILURE_PENALTY_MS: f64 = 250.0;
const CLIENT_ROUTE_ACTIVE_BONUS_MS: f64 = 5.0;
const CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS: u64 = 1_500;
const CLIENT_ROUTE_CIRCUIT_MAX_BACKOFF_MS: u64 = 30_000;
const CLIENT_ROUTE_BACKGROUND_REFRESH_STALE_MS: u64 = 30_000;
const CLIENT_ROUTE_BACKGROUND_REFRESH_MIN_INTERVAL_MS: u64 = 5_000;
const CLIENT_ROUTE_BACKGROUND_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CLIENT_ROUTE_RECENT_ATTEMPT_LIMIT: usize = 8;
const CLIENT_DIRECT_MULTIPLEX_STALL_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const CLIENT_API_V1_PREFIX: &str = "/api/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedRange {
    pub offset: u64,
    pub length: u64,
}

impl std::fmt::Display for RequestedRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}+{}", self.offset, self.length)
    }
}

#[derive(Clone)]
pub struct IronMeshClient {
    transport_router: ClientEndpointRouter,
    auth: ClientRequestAuth,
    connection_name: Option<String>,
    upload_session_affinities: Arc<Mutex<HashMap<String, UploadSessionAffinity>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientConnectionAttempt {
    pub started_unix_ms: u64,
    pub finished_unix_ms: Option<u64>,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    pub outcome: String,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientEndpointDiagnostics {
    pub path_kind: String,
    #[serde(default)]
    pub transport_path_kind: Option<String>,
    pub locator: String,
    pub request_base_url: String,
    pub active: bool,
    pub consecutive_failures: u32,
    pub total_failures: u64,
    pub total_successes: u64,
    #[serde(default)]
    pub last_attempt_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_success_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_failure_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub recent_attempts: Vec<ClientConnectionAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClientConnectionDiagnostics {
    #[serde(default)]
    pub endpoints: Vec<ClientEndpointDiagnostics>,
    #[serde(default)]
    pub last_success_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct ClientConnectionDiagnosticsEvent {
    pub connection_name: Option<String>,
    pub diagnostics: ClientConnectionDiagnostics,
}

#[derive(Clone)]
enum ClientRequestAuth {
    None,
    SignedIdentity(ClientIdentityMaterial),
}

#[derive(Clone)]
enum ClientTransport {
    DirectHttp {
        http: HttpClient,
        server_base_url: String,
        target_node_id: Option<NodeId>,
        session_pool: TransportSessionPool,
    },
    DirectQuic {
        request_base_url: String,
        target_node_id: Option<NodeId>,
        session_pool: TransportSessionPool,
    },
    Relay(ClientRelayTransport),
}

#[derive(Debug, Clone)]
struct UploadSessionAffinity {
    target_node_id: Option<NodeId>,
    preferred_request_base_url: Option<String>,
}

#[derive(Clone)]
struct ClientRelayTransport {
    rendezvous: RendezvousControlClient,
    request_base_url: String,
    target_node_id: NodeId,
    session_pool: TransportSessionPool,
}

#[derive(Clone)]
struct ClientEndpointRouter {
    endpoints: Arc<Vec<ClientEndpoint>>,
    active_index: Arc<AtomicUsize>,
}

#[derive(Clone, Copy)]
struct ClientRequestAttemptContext<'a> {
    method: &'a Method,
    url: &'a Url,
    timeout: Option<Duration>,
    started_unix_ms: u64,
}

#[derive(Clone)]
struct ClientEndpoint {
    descriptor: ClientEndpointDescriptor,
    transport: ClientTransport,
    state: Arc<std::sync::Mutex<ClientEndpointState>>,
}

#[derive(Debug, Clone)]
struct ClientEndpointDescriptor {
    path_kind: ClientEndpointPathKind,
    transport_path_kind: TransportPathKind,
    locator: String,
    bootstrap_rank: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientEndpointPathKind {
    Direct,
    Relay,
}

impl ClientEndpointPathKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

#[derive(Debug, Default)]
struct ClientEndpointState {
    ewma_latency_ms: Option<f64>,
    ewma_throughput_bytes_per_sec: Option<f64>,
    consecutive_failures: u32,
    total_failures: u64,
    total_successes: u64,
    last_measurement_unix_ms: Option<u64>,
    last_success_unix_ms: Option<u64>,
    last_failure_unix_ms: Option<u64>,
    circuit_open_until_unix_ms: Option<u64>,
    background_probe_in_flight: bool,
    last_background_probe_unix_ms: Option<u64>,
    last_error: Option<String>,
    recent_attempts: Vec<ClientConnectionAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConnectionRouteSnapshot {
    pub generated_at_unix_ms: u64,
    #[serde(default)]
    pub active_index: Option<usize>,
    #[serde(default)]
    pub ranked_indices: Vec<usize>,
    #[serde(default)]
    pub endpoints: Vec<ClientConnectionRouteEndpointSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientConnectionRouteEndpointSnapshot {
    pub index: usize,
    pub path_kind: TransportPathKind,
    pub locator: String,
    pub bootstrap_rank: usize,
    #[serde(default)]
    pub target_node_id: Option<NodeId>,
    #[serde(default)]
    pub active: bool,
    pub score: f64,
    #[serde(default)]
    pub ewma_latency_ms: Option<f64>,
    #[serde(default)]
    pub ewma_throughput_bytes_per_sec: Option<f64>,
    pub consecutive_failures: u32,
    pub total_failures: u64,
    pub total_successes: u64,
    #[serde(default)]
    pub last_measurement_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_success_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_failure_unix_ms: Option<u64>,
    #[serde(default)]
    pub circuit_open_until_unix_ms: Option<u64>,
    pub background_probe_in_flight: bool,
    #[serde(default)]
    pub last_background_probe_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct BufferedTransportResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Debug)]
struct RoutedBufferedTransportResponse {
    route_index: usize,
    response: BufferedTransportResponse,
}

impl ClientTransport {
    fn path_kind(&self) -> ClientEndpointPathKind {
        match self {
            Self::DirectHttp { .. } | Self::DirectQuic { .. } => ClientEndpointPathKind::Direct,
            Self::Relay(_) => ClientEndpointPathKind::Relay,
        }
    }

    fn transport_path_kind(&self) -> TransportPathKind {
        match self {
            Self::DirectHttp { .. } => TransportPathKind::DirectHttps,
            Self::DirectQuic { .. } => TransportPathKind::DirectQuic,
            Self::Relay(_) => TransportPathKind::RelayTunnel,
        }
    }

    fn request_base_url(&self) -> &str {
        match self {
            Self::DirectHttp {
                server_base_url, ..
            } => server_base_url.as_str(),
            Self::DirectQuic {
                request_base_url, ..
            } => request_base_url.as_str(),
            Self::Relay(relay) => relay.request_base_url.as_str(),
        }
    }

    fn endpoint_locator(&self) -> String {
        match self {
            Self::DirectHttp {
                server_base_url, ..
            } => server_base_url.clone(),
            Self::DirectQuic {
                request_base_url, ..
            } => request_base_url.clone(),
            Self::Relay(relay) => {
                let rendezvous_hint = relay
                    .rendezvous
                    .config()
                    .rendezvous_urls
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "rendezvous".to_string());
                format!(
                    "relay://{}@{}",
                    relay.target_node_id,
                    rendezvous_hint.trim_end_matches('/')
                )
            }
        }
    }

    fn direct_server_base_url(&self) -> Option<&str> {
        match self {
            Self::DirectHttp {
                server_base_url, ..
            } => Some(server_base_url.as_str()),
            Self::DirectQuic { .. } => None,
            Self::Relay(_) => None,
        }
    }

    fn target_node_id(&self) -> Option<NodeId> {
        match self {
            Self::DirectHttp { target_node_id, .. } | Self::DirectQuic { target_node_id, .. } => {
                *target_node_id
            }
            Self::Relay(relay) => Some(relay.target_node_id),
        }
    }

    fn relay_target_node_id(&self) -> Option<NodeId> {
        match self {
            Self::DirectHttp { .. } | Self::DirectQuic { .. } => None,
            Self::Relay(relay) => Some(relay.target_node_id),
        }
    }

    fn rendezvous_client(&self) -> Option<RendezvousControlClient> {
        match self {
            Self::DirectHttp { .. } | Self::DirectQuic { .. } => None,
            Self::Relay(relay) => Some(relay.rendezvous.clone()),
        }
    }

    fn session_pool_snapshot(&self) -> TransportSessionPoolSnapshot {
        match self {
            Self::DirectHttp { session_pool, .. } | Self::DirectQuic { session_pool, .. } => {
                session_pool.snapshot()
            }
            Self::Relay(relay) => relay.session_pool.snapshot(),
        }
    }

    fn rewrite_url(&self, url: &Url) -> Result<Url> {
        let base_url = Url::parse(self.request_base_url())
            .with_context(|| format!("invalid endpoint base URL: {}", self.request_base_url()))?;
        base_url
            .join(path_and_query(url).trim_start_matches('/'))
            .with_context(|| {
                format!(
                    "failed to rewrite request URL for endpoint {}",
                    self.endpoint_locator()
                )
            })
    }
}

impl ClientEndpoint {
    fn new(transport: ClientTransport, bootstrap_rank: usize) -> Self {
        Self {
            descriptor: ClientEndpointDescriptor {
                path_kind: transport.path_kind(),
                transport_path_kind: transport.transport_path_kind(),
                locator: transport.endpoint_locator(),
                bootstrap_rank,
            },
            transport,
            state: Arc::new(std::sync::Mutex::new(ClientEndpointState::default())),
        }
    }

    fn rewrite_url(&self, url: &Url) -> Result<Url> {
        self.transport.rewrite_url(url)
    }

    fn with_bootstrap_rank(&self, bootstrap_rank: usize) -> Self {
        Self {
            descriptor: ClientEndpointDescriptor {
                bootstrap_rank,
                ..self.descriptor.clone()
            },
            transport: self.transport.clone(),
            state: self.state.clone(),
        }
    }
}

type ConnectionDiagnosticsObserver =
    Arc<dyn Fn(ClientConnectionDiagnosticsEvent) + Send + Sync + 'static>;
type ConnectionDiagnosticsObserverSlot = RwLock<Option<ConnectionDiagnosticsObserver>>;

fn connection_diagnostics_observer() -> &'static ConnectionDiagnosticsObserverSlot {
    static OBSERVER: OnceLock<ConnectionDiagnosticsObserverSlot> = OnceLock::new();
    OBSERVER.get_or_init(|| RwLock::new(None))
}

pub fn set_connection_diagnostics_observer(observer: Option<ConnectionDiagnosticsObserver>) {
    let mut slot = connection_diagnostics_observer()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *slot = observer;
}

impl UploadSessionAffinity {
    fn from_endpoint(endpoint: &ClientEndpoint) -> Self {
        Self {
            target_node_id: endpoint.transport.target_node_id(),
            preferred_request_base_url: Some(endpoint.transport.request_base_url().to_string()),
        }
    }

    fn matches_endpoint(&self, endpoint: &ClientEndpoint) -> bool {
        if let Some(target_node_id) = self.target_node_id
            && endpoint.transport.target_node_id() == Some(target_node_id)
        {
            return true;
        }

        self.preferred_request_base_url
            .as_deref()
            .is_some_and(|base_url| endpoint.transport.request_base_url() == base_url)
    }
}

impl ClientEndpointRouter {
    fn new(endpoints: Vec<ClientEndpoint>) -> Self {
        let initial_active = if endpoints.is_empty() { usize::MAX } else { 0 };
        Self {
            endpoints: Arc::new(endpoints),
            active_index: Arc::new(AtomicUsize::new(initial_active)),
        }
    }

    fn endpoint(&self, index: usize) -> Option<&ClientEndpoint> {
        self.endpoints.get(index)
    }

    fn active_index(&self) -> Option<usize> {
        let active_index = self.active_index.load(Ordering::Relaxed);
        (active_index < self.endpoints.len()).then_some(active_index)
    }

    fn current_endpoint(&self) -> Option<&ClientEndpoint> {
        self.active_index()
            .and_then(|index| self.endpoints.get(index))
            .or_else(|| {
                self.best_ranked_index()
                    .and_then(|index| self.endpoints.get(index))
            })
            .or_else(|| self.endpoints.first())
    }

    fn set_active_index(&self, index: usize) {
        self.active_index.store(index, Ordering::Relaxed);
    }

    fn best_ranked_index(&self) -> Option<usize> {
        self.rank_indices().into_iter().next()
    }

    fn rank_indices(&self) -> Vec<usize> {
        let now_unix_ms = unix_ts_ms();
        let active_index = self.active_index();
        let mut available = Vec::new();
        let mut cooling = Vec::new();

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            let state = lock_endpoint_state(&endpoint.state);
            let score = endpoint_score(index, active_index, &endpoint.descriptor, &state);
            if let Some(until_unix_ms) = state
                .circuit_open_until_unix_ms
                .filter(|until_unix_ms| *until_unix_ms > now_unix_ms)
            {
                cooling.push((index, until_unix_ms, score));
            } else {
                available.push((index, score));
            }
        }

        available.sort_by(|left, right| compare_scores(left.1, right.1, left.0, right.0));
        cooling.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));

        if available.is_empty() {
            return cooling.into_iter().map(|(index, _, _)| index).collect();
        }

        available
            .into_iter()
            .map(|(index, _)| index)
            .chain(cooling.into_iter().map(|(index, _, _)| index))
            .collect()
    }

    fn claim_background_probe_candidates(&self) -> Vec<(usize, ClientEndpoint)> {
        if self.endpoints.len() <= 1 {
            return Vec::new();
        }

        let now_unix_ms = unix_ts_ms();
        let active_index = self.active_index();
        let mut claimed = Vec::new();

        for (index, endpoint) in self.endpoints.iter().enumerate() {
            if Some(index) == active_index {
                continue;
            }
            let mut state = lock_endpoint_state(&endpoint.state);
            if !background_probe_due(&state, now_unix_ms) {
                continue;
            }
            state.background_probe_in_flight = true;
            state.last_background_probe_unix_ms = Some(now_unix_ms);
            claimed.push((index, endpoint.clone()));
        }

        claimed
    }

    fn record_failure(&self, index: usize, error: &str) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_failure_sample(&mut state, error, false);
    }

    fn record_background_probe_success(&self, index: usize, latency_ms: f64) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_success_sample(&mut state, latency_ms, 0, true);
    }

    fn record_background_probe_failure(&self, index: usize, error: &str) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_failure_sample(&mut state, error, true);
    }

    fn snapshot(&self) -> ClientConnectionRouteSnapshot {
        let active_index = self.active_index();
        let ranked_indices = self.rank_indices();
        let endpoints = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let state = lock_endpoint_state(&endpoint.state);
                ClientConnectionRouteEndpointSnapshot {
                    index,
                    path_kind: endpoint.transport.transport_path_kind(),
                    locator: endpoint.descriptor.locator.clone(),
                    bootstrap_rank: endpoint.descriptor.bootstrap_rank,
                    target_node_id: endpoint.transport.target_node_id(),
                    active: active_index == Some(index),
                    score: endpoint_score(index, active_index, &endpoint.descriptor, &state),
                    ewma_latency_ms: state.ewma_latency_ms,
                    ewma_throughput_bytes_per_sec: state.ewma_throughput_bytes_per_sec,
                    consecutive_failures: state.consecutive_failures,
                    total_failures: state.total_failures,
                    total_successes: state.total_successes,
                    last_measurement_unix_ms: state.last_measurement_unix_ms,
                    last_success_unix_ms: state.last_success_unix_ms,
                    last_failure_unix_ms: state.last_failure_unix_ms,
                    circuit_open_until_unix_ms: state.circuit_open_until_unix_ms,
                    background_probe_in_flight: state.background_probe_in_flight,
                    last_background_probe_unix_ms: state.last_background_probe_unix_ms,
                    last_error: state.last_error.clone(),
                }
            })
            .collect();

        ClientConnectionRouteSnapshot {
            generated_at_unix_ms: unix_ts_ms(),
            active_index,
            ranked_indices,
            endpoints,
        }
    }

    fn record_request_success(
        &self,
        index: usize,
        attempt: ClientRequestAttemptContext<'_>,
        latency_ms: f64,
        bytes_transferred: usize,
    ) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_success_sample(&mut state, latency_ms, bytes_transferred, false);
        record_endpoint_attempt(
            &mut state,
            ClientConnectionAttempt {
                started_unix_ms: attempt.started_unix_ms,
                finished_unix_ms: Some(unix_ts_ms()),
                method: attempt.method.to_string(),
                url: attempt_display_url(endpoint, attempt.url),
                timeout_ms: attempt.timeout.and_then(duration_to_u64_ms),
                outcome: "success".to_string(),
                error: None,
            },
        );
        drop(state);
        self.set_active_index(index);
    }

    fn record_request_failure(
        &self,
        index: usize,
        attempt: ClientRequestAttemptContext<'_>,
        error: &str,
    ) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_failure_sample(&mut state, error, false);
        record_endpoint_attempt(
            &mut state,
            ClientConnectionAttempt {
                started_unix_ms: attempt.started_unix_ms,
                finished_unix_ms: Some(unix_ts_ms()),
                method: attempt.method.to_string(),
                url: attempt_display_url(endpoint, attempt.url),
                timeout_ms: attempt.timeout.and_then(duration_to_u64_ms),
                outcome: "failure".to_string(),
                error: Some(error.to_string()),
            },
        );
    }

    fn diagnostics_snapshot(&self) -> ClientConnectionDiagnostics {
        let active_index = self.active_index();
        let endpoints = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(index, endpoint)| {
                let state = lock_endpoint_state(&endpoint.state);
                ClientEndpointDiagnostics {
                    path_kind: endpoint.descriptor.path_kind.as_str().to_string(),
                    transport_path_kind: Some(
                        transport_path_kind_label(endpoint.descriptor.transport_path_kind)
                            .to_string(),
                    ),
                    locator: endpoint.descriptor.locator.clone(),
                    request_base_url: endpoint.transport.request_base_url().to_string(),
                    active: active_index == Some(index),
                    consecutive_failures: state.consecutive_failures,
                    total_failures: state.total_failures,
                    total_successes: state.total_successes,
                    last_attempt_unix_ms: state.last_measurement_unix_ms,
                    last_success_unix_ms: state.last_success_unix_ms,
                    last_failure_unix_ms: state.last_failure_unix_ms,
                    last_error: state.last_error.clone(),
                    recent_attempts: state.recent_attempts.clone(),
                }
            })
            .collect::<Vec<_>>();
        let last_success_unix_ms = endpoints
            .iter()
            .filter_map(|endpoint| endpoint.last_success_unix_ms)
            .max();
        ClientConnectionDiagnostics {
            endpoints,
            last_success_unix_ms,
        }
    }
}

fn lock_endpoint_state(
    state: &std::sync::Mutex<ClientEndpointState>,
) -> std::sync::MutexGuard<'_, ClientEndpointState> {
    match state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn endpoint_score(
    index: usize,
    active_index: Option<usize>,
    descriptor: &ClientEndpointDescriptor,
    state: &ClientEndpointState,
) -> f64 {
    let mut score = descriptor.bootstrap_rank as f64;
    score += state
        .ewma_latency_ms
        .unwrap_or(CLIENT_ROUTE_UNKNOWN_LATENCY_MS);
    if descriptor.path_kind == ClientEndpointPathKind::Relay {
        score += CLIENT_ROUTE_RELAY_PENALTY_MS;
    }
    score += state.consecutive_failures as f64 * CLIENT_ROUTE_FAILURE_PENALTY_MS;
    if let Some(throughput_bytes_per_sec) = state.ewma_throughput_bytes_per_sec {
        score -= (throughput_bytes_per_sec / 250_000.0).min(50.0);
    }
    if active_index == Some(index) {
        score -= CLIENT_ROUTE_ACTIVE_BONUS_MS;
    }
    score
}

fn compare_scores(
    left_score: f64,
    right_score: f64,
    left_index: usize,
    right_index: usize,
) -> std::cmp::Ordering {
    left_score
        .partial_cmp(&right_score)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| left_index.cmp(&right_index))
}

fn transport_path_kind_label(path_kind: TransportPathKind) -> &'static str {
    match path_kind {
        TransportPathKind::DirectHttps => "direct_https",
        TransportPathKind::DirectQuic => "direct_quic",
        TransportPathKind::RelayTunnel => "relay_tunnel",
    }
}

fn update_ewma(current: Option<f64>, sample: f64) -> f64 {
    const ALPHA: f64 = 0.35;
    match current {
        Some(current) => current + ALPHA * (sample - current),
        None => sample,
    }
}

fn endpoint_failure_backoff_ms(consecutive_failures: u32) -> u64 {
    let shift = consecutive_failures.saturating_sub(1).min(8);
    let multiplier = 1_u64 << shift;
    (CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS * multiplier).min(CLIENT_ROUTE_CIRCUIT_MAX_BACKOFF_MS)
}

fn record_endpoint_success_sample(
    state: &mut ClientEndpointState,
    latency_ms: f64,
    bytes_transferred: usize,
    background_probe: bool,
) {
    state.ewma_latency_ms = Some(update_ewma(state.ewma_latency_ms, latency_ms));
    if latency_ms > 0.0 && bytes_transferred > 0 {
        let throughput_bytes_per_sec = bytes_transferred as f64 / (latency_ms / 1000.0);
        state.ewma_throughput_bytes_per_sec = Some(update_ewma(
            state.ewma_throughput_bytes_per_sec,
            throughput_bytes_per_sec,
        ));
    }
    let now_unix_ms = unix_ts_ms();
    state.consecutive_failures = 0;
    state.total_successes = state.total_successes.saturating_add(1);
    state.last_measurement_unix_ms = Some(now_unix_ms);
    state.last_success_unix_ms = Some(now_unix_ms);
    state.circuit_open_until_unix_ms = None;
    state.last_error = None;
    if background_probe {
        state.background_probe_in_flight = false;
    }
}

fn record_endpoint_failure_sample(
    state: &mut ClientEndpointState,
    error: &str,
    background_probe: bool,
) {
    let now_unix_ms = unix_ts_ms();
    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
    state.total_failures = state.total_failures.saturating_add(1);
    state.last_measurement_unix_ms = Some(now_unix_ms);
    state.last_failure_unix_ms = Some(now_unix_ms);
    state.circuit_open_until_unix_ms =
        Some(now_unix_ms + endpoint_failure_backoff_ms(state.consecutive_failures));
    state.last_error = Some(error.to_string());
    if background_probe {
        state.background_probe_in_flight = false;
    }
}

fn record_endpoint_attempt(state: &mut ClientEndpointState, attempt: ClientConnectionAttempt) {
    if state.recent_attempts.len() >= CLIENT_ROUTE_RECENT_ATTEMPT_LIMIT {
        let drop_count = state
            .recent_attempts
            .len()
            .saturating_sub(CLIENT_ROUTE_RECENT_ATTEMPT_LIMIT - 1);
        state.recent_attempts.drain(0..drop_count);
    }
    state.recent_attempts.push(attempt);
}

fn attempt_display_url(endpoint: &ClientEndpoint, url: &Url) -> String {
    match endpoint.descriptor.path_kind {
        ClientEndpointPathKind::Direct => url.to_string(),
        ClientEndpointPathKind::Relay => {
            format!("{}{}", endpoint.descriptor.locator, path_and_query(url))
        }
    }
}

fn duration_to_u64_ms(duration: Duration) -> Option<u64> {
    duration.as_millis().try_into().ok()
}

fn background_probe_due(state: &ClientEndpointState, now_unix_ms: u64) -> bool {
    if state.background_probe_in_flight {
        return false;
    }
    if state
        .circuit_open_until_unix_ms
        .is_some_and(|until_unix_ms| until_unix_ms > now_unix_ms)
    {
        return false;
    }
    if state
        .last_background_probe_unix_ms
        .is_some_and(|last_probe_unix_ms| {
            now_unix_ms.saturating_sub(last_probe_unix_ms)
                < CLIENT_ROUTE_BACKGROUND_REFRESH_MIN_INTERVAL_MS
        })
    {
        return false;
    }

    state.last_measurement_unix_ms.is_none()
        || state.consecutive_failures > 0
        || state
            .last_measurement_unix_ms
            .is_some_and(|last_measurement_unix_ms| {
                now_unix_ms.saturating_sub(last_measurement_unix_ms)
                    >= CLIENT_ROUTE_BACKGROUND_REFRESH_STALE_MS
            })
}

fn is_retryable_transport_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    )
}

fn header_value_for_log(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| "<none>".to_string())
}

fn normalize_connection_name(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(trimmed.len().min(128));
    let mut previous_was_dash = false;
    for ch in trimmed.chars() {
        if normalized.len() >= 128 {
            break;
        }

        let mapped = if ch.is_ascii_alphanumeric() {
            previous_was_dash = false;
            ch.to_ascii_lowercase()
        } else if matches!(ch, '/' | '.' | '_' | '-') {
            previous_was_dash = false;
            ch
        } else {
            if previous_was_dash || normalized.is_empty() {
                continue;
            }
            previous_was_dash = true;
            '-'
        };
        normalized.push(mapped);
    }

    let normalized = normalized
        .trim_matches(|ch| matches!(ch, '-' | '/' | '.' | '_'))
        .to_string();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn lock_upload_session_affinities(
    affinities: &Mutex<HashMap<String, UploadSessionAffinity>>,
) -> std::sync::MutexGuard<'_, HashMap<String, UploadSessionAffinity>> {
    match affinities.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn upload_session_affinity_from_resumable_state(
    state: &ResumableUploadFileState,
) -> Option<UploadSessionAffinity> {
    if state.target_node_id.is_none() && state.preferred_request_base_url.is_none() {
        return None;
    }

    Some(UploadSessionAffinity {
        target_node_id: state.target_node_id,
        preferred_request_base_url: state.preferred_request_base_url.clone(),
    })
}

fn connection_name_header(connection_name: &str) -> RelayHttpHeader {
    RelayHttpHeader {
        name: transport_sdk::HEADER_CONNECTION_NAME.to_string(),
        value: connection_name.to_string(),
    }
}

fn build_identity_request_auth_headers(
    identity: &ClientIdentityMaterial,
    method: &str,
    path_and_query: &str,
) -> Result<Vec<RelayHttpHeader>> {
    let signed_headers =
        build_signed_request_headers(identity, method, path_and_query, unix_ts(), None)?;
    Ok(vec![
        RelayHttpHeader {
            name: transport_sdk::HEADER_CLUSTER_ID.to_string(),
            value: signed_headers.cluster_id.to_string(),
        },
        RelayHttpHeader {
            name: transport_sdk::HEADER_DEVICE_ID.to_string(),
            value: signed_headers.device_id,
        },
        RelayHttpHeader {
            name: transport_sdk::HEADER_CREDENTIAL_FINGERPRINT.to_string(),
            value: signed_headers.credential_fingerprint,
        },
        RelayHttpHeader {
            name: transport_sdk::HEADER_AUTH_TIMESTAMP.to_string(),
            value: signed_headers.timestamp_unix.to_string(),
        },
        RelayHttpHeader {
            name: transport_sdk::HEADER_AUTH_NONCE.to_string(),
            value: signed_headers.nonce,
        },
        RelayHttpHeader {
            name: transport_sdk::HEADER_AUTH_SIGNATURE.to_string(),
            value: signed_headers.signature_base64,
        },
    ])
}

fn request_auth_headers_for_auth(
    auth: &ClientRequestAuth,
    method: &Method,
    url: &Url,
    connection_name: Option<&str>,
) -> Result<Vec<RelayHttpHeader>> {
    let mut headers = match auth {
        ClientRequestAuth::None => Ok(Vec::new()),
        ClientRequestAuth::SignedIdentity(identity) => {
            build_identity_request_auth_headers(identity, method.as_str(), &path_and_query(url))
        }
    }?;
    if let Some(connection_name) = connection_name {
        headers.push(connection_name_header(connection_name));
    }
    Ok(headers)
}

fn method_uses_operation_id(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    )
}

fn ensure_operation_id_header(method: &Method, headers: &mut Vec<RelayHttpHeader>) {
    if !method_uses_operation_id(method) {
        return;
    }

    if let Some(header) = headers.iter_mut().find(|header| {
        header
            .name
            .eq_ignore_ascii_case(transport_sdk::HEADER_OPERATION_ID)
    }) {
        if header.value.trim().is_empty() {
            header.value = Uuid::now_v7().to_string();
        }
        return;
    }

    headers.push(RelayHttpHeader {
        name: transport_sdk::HEADER_OPERATION_ID.to_string(),
        value: Uuid::now_v7().to_string(),
    });
}

fn direct_multiplex_failover_timeout(url: &Url, allow_failover_timeout: bool) -> Option<Duration> {
    if !allow_failover_timeout || direct_multiplex_request_is_long_running(url) {
        return None;
    }
    Some(CLIENT_DIRECT_MULTIPLEX_STALL_TIMEOUT)
}

fn direct_multiplex_request_is_long_running(url: &Url) -> bool {
    match strip_client_api_v1_prefix(url.path()) {
        "/store/index/changes/wait" => true,
        "/diagnostics/latency" => url
            .query_pairs()
            .find_map(|(name, value)| {
                (name == "server_delay_ms")
                    .then(|| value.parse::<u64>().ok())
                    .flatten()
            })
            .is_some_and(|server_delay_ms| server_delay_ms > 0),
        _ => false,
    }
}

fn relay_source_identity_for_auth(auth: &ClientRequestAuth) -> Result<PeerIdentity> {
    match auth {
        ClientRequestAuth::SignedIdentity(identity) => Ok(PeerIdentity::Device(identity.device_id)),
        ClientRequestAuth::None => {
            bail!("relay-backed client transport requires signed client identity material")
        }
    }
}

fn apply_headers_to_request(
    request: RequestBuilder,
    headers: &[RelayHttpHeader],
) -> RequestBuilder {
    headers.iter().fold(request, |request, header| {
        request.header(header.name.as_str(), header.value.as_str())
    })
}

#[derive(Clone, Copy)]
struct TransportRequestOptions<'a> {
    connection_name: Option<&'a str>,
    direct_failover_timeout: Option<Duration>,
}

impl<'a> TransportRequestOptions<'a> {
    const fn new(
        connection_name: Option<&'a str>,
        direct_failover_timeout: Option<Duration>,
    ) -> Self {
        Self {
            connection_name,
            direct_failover_timeout,
        }
    }

    const fn without_direct_failover_timeout(self) -> Self {
        Self {
            connection_name: self.connection_name,
            direct_failover_timeout: None,
        }
    }
}

async fn execute_buffered_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    options: TransportRequestOptions<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    match transport {
        ClientTransport::DirectHttp {
            http,
            server_base_url,
            session_pool,
            ..
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                let direct = DirectMultiplexSessionContext {
                    transport_locator: server_base_url,
                    session_pool,
                    identity,
                    connection_name: options.connection_name,
                };
                return execute_direct_multiplex_buffered_request(
                    direct,
                    method,
                    url,
                    headers,
                    body,
                    options.direct_failover_timeout,
                )
                .await
                .with_context(|| format!("failed to execute multiplexed {} {}", method, url));
            }

            let mut request =
                apply_headers_to_request(http.request(method.clone(), url.clone()), headers);
            if !body.is_empty() {
                request = request.body(body.to_vec());
            }
            let response = request
                .send()
                .await
                .with_context(|| format!("failed to execute {} {}", method, url))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response
                .bytes()
                .await
                .with_context(|| format!("failed to read response body for {} {}", method, url))?;
            Ok(BufferedTransportResponse {
                status,
                headers,
                body,
            })
        }
        ClientTransport::DirectQuic {
            request_base_url,
            session_pool,
            ..
        } => {
            let ClientRequestAuth::SignedIdentity(identity) = auth else {
                bail!("direct QUIC client transport requires signed client identity material");
            };
            let direct = DirectMultiplexSessionContext {
                transport_locator: request_base_url,
                session_pool,
                identity,
                connection_name: options.connection_name,
            };
            execute_direct_multiplex_buffered_request(
                direct,
                method,
                url,
                headers,
                body,
                options.direct_failover_timeout,
            )
            .await
            .with_context(|| format!("failed to execute multiplexed {} {}", method, url))
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_buffered_request(
                relay,
                source,
                options.connection_name,
                method,
                url,
                headers,
                body,
            )
            .await
            .with_context(|| format!("failed to relay {} {}", method, url))
        }
    }
}

async fn execute_streaming_read_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
) -> Result<StreamedRelativePathResponse> {
    match transport {
        ClientTransport::DirectHttp {
            http,
            server_base_url,
            session_pool,
            ..
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                return execute_direct_multiplex_streaming_read_request(
                    server_base_url,
                    session_pool,
                    identity,
                    connection_name,
                    method,
                    url,
                    headers,
                )
                .await
                .with_context(|| format!("failed to execute streamed {} {}", method, url));
            }

            execute_direct_http_streaming_read_request(http, method, url, headers).await
        }
        ClientTransport::DirectQuic {
            request_base_url,
            session_pool,
            ..
        } => {
            let ClientRequestAuth::SignedIdentity(identity) = auth else {
                bail!("direct QUIC client transport requires signed client identity material");
            };
            execute_direct_multiplex_streaming_read_request(
                request_base_url,
                session_pool,
                identity,
                connection_name,
                method,
                url,
                headers,
            )
            .await
            .with_context(|| format!("failed to execute streamed {} {}", method, url))
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_streaming_read_request(
                relay,
                source,
                connection_name,
                method,
                url,
                headers,
            )
            .await
            .with_context(|| format!("failed to relay streamed {} {}", method, url))
        }
    }
}

async fn execute_streaming_object_read_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
    let mut response = execute_streaming_read_request_for_transport(
        transport,
        auth,
        connection_name,
        &Method::GET,
        url,
        headers,
    )
    .await?;
    let mut bytes_written = 0_u64;
    while let Some(chunk) = response.body.next().await {
        let chunk = chunk.context("failed reading streamed transport response body")?;
        if !chunk.is_empty() {
            writer
                .write_all(chunk.as_ref())
                .context("failed writing streamed transport response body")?;
            bytes_written += chunk.len() as u64;
        }
    }
    writer
        .flush()
        .context("failed flushing streamed transport response body")?;

    Ok(StreamedTransportResponseMeta {
        status: response.status,
        headers: response.headers,
        bytes_written,
    })
}

async fn execute_streaming_object_write_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    options: TransportRequestOptions<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    match transport {
        ClientTransport::DirectHttp {
            server_base_url,
            session_pool,
            ..
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                let direct = DirectMultiplexSessionContext {
                    transport_locator: server_base_url,
                    session_pool,
                    identity,
                    connection_name: options.connection_name,
                };
                return execute_direct_multiplex_streaming_object_write_request(
                    direct,
                    method,
                    url,
                    headers,
                    body,
                    options.direct_failover_timeout,
                )
                .await
                .with_context(|| format!("failed to execute streamed {} {}", method, url));
            }

            execute_buffered_request_for_transport(
                transport,
                auth,
                options.without_direct_failover_timeout(),
                method,
                url,
                headers,
                body,
            )
            .await
        }
        ClientTransport::DirectQuic {
            request_base_url,
            session_pool,
            ..
        } => {
            let ClientRequestAuth::SignedIdentity(identity) = auth else {
                bail!("direct QUIC client transport requires signed client identity material");
            };
            let direct = DirectMultiplexSessionContext {
                transport_locator: request_base_url,
                session_pool,
                identity,
                connection_name: options.connection_name,
            };
            execute_direct_multiplex_streaming_object_write_request(
                direct,
                method,
                url,
                headers,
                body,
                options.direct_failover_timeout,
            )
            .await
            .with_context(|| format!("failed to execute streamed {} {}", method, url))
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_streaming_object_write_request(
                relay,
                source,
                options.connection_name,
                method,
                url,
                headers,
                body,
            )
            .await
            .with_context(|| format!("failed to relay streamed {} {}", method, url))
        }
    }
}

async fn execute_streaming_write_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body_stream: RequestBodyStream,
) -> Result<BufferedTransportResponse> {
    match transport {
        ClientTransport::DirectHttp {
            http,
            server_base_url,
            session_pool,
            ..
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                let direct = DirectMultiplexSessionContext {
                    transport_locator: server_base_url,
                    session_pool,
                    identity,
                    connection_name,
                };
                return execute_direct_multiplex_streaming_write_request(
                    direct,
                    method,
                    url,
                    headers,
                    body_stream,
                )
                .await
                .with_context(|| format!("failed to execute streamed {} {}", method, url));
            }

            let mut payload = Vec::new();
            let mut body_stream = body_stream;
            while let Some(chunk) = body_stream.next().await {
                let chunk = chunk.context("failed reading streamed request body chunk")?;
                payload.extend_from_slice(chunk.as_ref());
            }
            let request =
                apply_headers_to_request(http.request(method.clone(), url.clone()), headers)
                    .body(payload);
            let response = request
                .send()
                .await
                .with_context(|| format!("failed to execute streamed {} {}", method, url))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.with_context(|| {
                format!(
                    "failed to read streamed response body for {} {}",
                    method, url
                )
            })?;
            Ok(BufferedTransportResponse {
                status,
                headers,
                body,
            })
        }
        ClientTransport::DirectQuic {
            request_base_url,
            session_pool,
            ..
        } => {
            let ClientRequestAuth::SignedIdentity(identity) = auth else {
                bail!("direct QUIC client transport requires signed client identity material");
            };
            let direct = DirectMultiplexSessionContext {
                transport_locator: request_base_url,
                session_pool,
                identity,
                connection_name,
            };
            execute_direct_multiplex_streaming_write_request(
                direct,
                method,
                url,
                headers,
                body_stream,
            )
            .await
            .with_context(|| format!("failed to execute streamed {} {}", method, url))
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_streaming_write_request(
                relay,
                source,
                connection_name,
                method,
                url,
                headers,
                body_stream,
            )
            .await
            .with_context(|| format!("failed to relay streamed {} {}", method, url))
        }
    }
}

async fn probe_endpoint_background_quality(
    endpoint: &ClientEndpoint,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
) -> Result<f64> {
    let base_url = Url::parse(endpoint.transport.request_base_url()).with_context(|| {
        format!(
            "invalid background probe base URL for endpoint {}",
            endpoint.descriptor.locator
        )
    })?;
    let method = Method::GET;
    let url = base_url
        .join(normalize_client_api_path("/health").trim_start_matches('/'))
        .with_context(|| {
            format!(
                "failed to build background health probe URL for endpoint {}",
                endpoint.descriptor.locator
            )
        })?;
    let headers = request_auth_headers_for_auth(auth, &method, &url, connection_name)?;
    let started_at = std::time::Instant::now();
    let response = tokio::time::timeout(
        CLIENT_ROUTE_BACKGROUND_PROBE_TIMEOUT,
        execute_buffered_request_for_transport(
            &endpoint.transport,
            auth,
            TransportRequestOptions::new(connection_name, None),
            &method,
            &url,
            &headers,
            &[],
        ),
    )
    .await
    .map_err(|_| {
        anyhow!(
            "background health probe timed out after {} ms for {}",
            CLIENT_ROUTE_BACKGROUND_PROBE_TIMEOUT.as_millis(),
            endpoint.descriptor.locator
        )
    })??;
    if !response.status.is_success() {
        bail!(
            "background health probe returned {} from {}",
            response.status,
            endpoint.descriptor.locator
        );
    }
    Ok(started_at.elapsed().as_secs_f64() * 1000.0)
}

fn blocking_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

    match RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("ironmesh-client-blocking")
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(anyhow!(
            "failed to initialize shared blocking runtime: {error}"
        )),
    }
}

#[derive(Debug, Clone)]
pub struct RelativePathResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

pub struct StreamedRelativePathResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: ResponseBodyStream,
}

type RequestBodyStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>>;
pub type ResponseBodyStream =
    Pin<Box<dyn Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadMode {
    Direct,
    Chunked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub meta: StorageObjectMeta,
    pub upload_mode: UploadMode,
    pub chunk_size_bytes: Option<usize>,
    pub chunk_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionStatus {
    pub upload_id: String,
    pub key: String,
    pub total_size_bytes: u64,
    pub chunk_size_bytes: usize,
    pub chunk_count: usize,
    pub received_indexes: Vec<usize>,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionChunkRef {
    pub hash: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionChunkStatus {
    pub stored: bool,
    pub received_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionCompleteInfo {
    pub snapshot_id: String,
    pub version_id: String,
    pub manifest_hash: String,
    pub state: String,
    pub new_chunks: usize,
    pub dedup_reused_chunks: usize,
    pub created_new_version: bool,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHeadInfo {
    pub total_size_bytes: u64,
    pub etag: Option<String>,
    pub accept_ranges: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub object_size_bytes: u64,
    pub range: RequestedRange,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadRangeResult {
    pub object_size_bytes: u64,
    pub range: RequestedRange,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadRangeRequest<'a> {
    pub key: &'a str,
    pub snapshot: Option<&'a str>,
    pub version: Option<&'a str>,
    pub range: RequestedRange,
}

#[derive(Debug, Serialize, Deserialize)]
struct UploadSessionStartRequest {
    key: String,
    total_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    chunk_refs: Vec<UploadSessionChunkRef>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UploadSessionView {
    upload_id: String,
    key: String,
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    #[serde(default, alias = "received_chunks")]
    received_indexes: Vec<usize>,
    completed: bool,
    #[serde(default)]
    completed_result: Option<UploadSessionCompleteResponse>,
    #[allow(dead_code)]
    expires_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UploadSessionChunkResponse {
    #[allow(dead_code)]
    stored: bool,
    received_index: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UploadSessionCompleteResponse {
    snapshot_id: String,
    version_id: String,
    manifest_hash: String,
    state: String,
    new_chunks: usize,
    dedup_reused_chunks: usize,
    created_new_version: bool,
    total_size_bytes: u64,
}

#[derive(Debug, Clone)]
struct ObjectHeadResponse {
    total_size_bytes: u64,
    etag: Option<String>,
    accept_ranges: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumableUploadFileState {
    upload_id: String,
    key: String,
    source_size_bytes: u64,
    source_modified_unix_ms: u128,
    chunk_size_bytes: usize,
    #[serde(default)]
    target_node_id: Option<NodeId>,
    #[serde(default)]
    preferred_request_base_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ResumableDownloadFileState {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    expected_size_bytes: u64,
    etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexEntry {
    pub path: String,
    pub entry_type: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub modified_at_unix: Option<u64>,
    #[serde(default)]
    pub content_fingerprint: Option<String>,
    #[serde(default)]
    pub media: Option<StoreIndexMedia>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexResponse {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub depth: usize,
    #[serde(default)]
    pub entry_count: usize,
    #[serde(default)]
    pub total_entry_count: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub media_summary: StoreIndexMediaSummary,
    #[serde(default)]
    pub entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionConsistencyState {
    Provisional,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreferredHeadReason {
    ConfirmedPreferredOverProvisional,
    ProvisionalFallbackNoConfirmed,
    DeterministicTiebreakVersionId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionRecordSummary {
    pub version_id: String,
    pub logical_path: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub created_at_unix: u64,
    pub copied_from_object_id: Option<String>,
    pub copied_from_version_id: Option<String>,
    pub copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionGraphSummary {
    pub key: String,
    pub object_id: String,
    #[serde(default)]
    pub preferred_head_version_id: Option<String>,
    #[serde(default)]
    pub preferred_head_reason: Option<PreferredHeadReason>,
    #[serde(default)]
    pub head_version_ids: Vec<String>,
    #[serde(default)]
    pub versions: Vec<VersionRecordSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreIndexView {
    Raw,
    Tree,
}

impl StoreIndexView {
    fn as_query_value(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Tree => "tree",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIndexSortOrder {
    PathAsc,
    PathDesc,
    CapturedAsc,
    CapturedDesc,
}

impl StoreIndexSortOrder {
    fn as_query_value(self) -> &'static str {
        match self {
            Self::PathAsc => "path_asc",
            Self::PathDesc => "path_desc",
            Self::CapturedAsc => "captured_asc",
            Self::CapturedDesc => "captured_desc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIndexMediaFilter {
    All,
    Image,
    Video,
}

impl StoreIndexMediaFilter {
    fn as_query_value(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Image => "image",
            Self::Video => "video",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StoreIndexMediaSummary {
    #[serde(default)]
    pub ready_count: usize,
    #[serde(default)]
    pub pending_count: usize,
    #[serde(default)]
    pub incomplete_count: usize,
    #[serde(default)]
    pub image_count: usize,
    #[serde(default)]
    pub video_count: usize,
    #[serde(default)]
    pub geotagged_count: usize,
}

#[derive(Debug, Clone)]
pub struct StoreIndexRequestOptions {
    pub view: Option<StoreIndexView>,
    pub cursor: Option<String>,
    pub page_size: Option<usize>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub sort: Option<StoreIndexSortOrder>,
    pub media_filter: Option<StoreIndexMediaFilter>,
    pub synthesize_missing_folder_markers: bool,
}

impl Default for StoreIndexRequestOptions {
    fn default() -> Self {
        Self {
            view: None,
            cursor: None,
            page_size: None,
            offset: None,
            limit: None,
            sort: None,
            media_filter: None,
            synthesize_missing_folder_markers: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreIndexChangeWaitResponse {
    pub sequence: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexMedia {
    pub status: String,
    pub content_fingerprint: String,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub orientation: Option<u16>,
    #[serde(default)]
    pub taken_at_unix: Option<u64>,
    #[serde(default)]
    pub gps: Option<StoreIndexGps>,
    #[serde(default)]
    pub thumbnail: Option<StoreIndexThumbnail>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexGps {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexThumbnail {
    pub url: String,
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PathMutationRequest {
    from_path: String,
    to_path: String,
    overwrite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<String>,
}

#[derive(Debug, Serialize)]
struct SnapshotRestoreRequest {
    snapshot: String,
    from_path: String,
    to_path: String,
    recursive: bool,
    overwrite: bool,
}

#[derive(Debug, Serialize)]
struct VersionRestoreRequest {
    to_path: String,
    overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRestoreResponse {
    pub snapshot_id: String,
    pub source_path: String,
    pub target_path: String,
    pub recursive: bool,
    pub restored_count: usize,
}

impl IronMeshClient {
    pub fn from_direct_base_url(server_base_url: impl Into<String>) -> Self {
        Self::from_direct_http_client(server_base_url, HttpClient::new())
    }

    pub fn from_direct_http_client(server_base_url: impl Into<String>, http: HttpClient) -> Self {
        Self::from_direct_http_client_with_ca_pem(server_base_url, http, None)
    }

    pub fn from_direct_http_client_with_ca_pem(
        server_base_url: impl Into<String>,
        http: HttpClient,
        server_ca_pem: Option<String>,
    ) -> Self {
        Self::from_direct_http_client_with_target_node_id_and_ca_pem(
            server_base_url,
            http,
            None,
            server_ca_pem,
        )
    }

    pub(crate) fn from_direct_http_client_with_target_node_id_and_ca_pem(
        server_base_url: impl Into<String>,
        http: HttpClient,
        target_node_id: Option<NodeId>,
        server_ca_pem: Option<String>,
    ) -> Self {
        let server_base_url = server_base_url.into().trim_end_matches('/').to_string();
        Self {
            transport_router: ClientEndpointRouter::new(vec![ClientEndpoint::new(
                ClientTransport::DirectHttp {
                    http,
                    target_node_id,
                    session_pool: TransportSessionPool::new_direct(
                        server_base_url.clone(),
                        server_ca_pem,
                    ),
                    server_base_url,
                },
                0,
            )]),
            auth: ClientRequestAuth::None,
            connection_name: None,
            upload_session_affinities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn from_direct_quic_candidate_with_target_node_id(
        candidate: ConnectionCandidate,
        target_node_id: Option<NodeId>,
    ) -> Self {
        let request_base_url = candidate.endpoint.trim().trim_end_matches('/').to_string();
        Self {
            transport_router: ClientEndpointRouter::new(vec![ClientEndpoint::new(
                ClientTransport::DirectQuic {
                    request_base_url,
                    target_node_id,
                    session_pool: TransportSessionPool::new_direct_quic(candidate, target_node_id),
                },
                0,
            )]),
            auth: ClientRequestAuth::None,
            connection_name: None,
            upload_session_affinities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_relay_transport(
        request_base_url: impl Into<String>,
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
        source_security: RelayTunnelSourceSecurityConfig,
    ) -> Self {
        let request_base_url = request_base_url.into().trim_end_matches('/').to_string();
        let session_pool =
            TransportSessionPool::new_relay(rendezvous.clone(), target_node_id, source_security);
        Self {
            transport_router: ClientEndpointRouter::new(vec![ClientEndpoint::new(
                ClientTransport::Relay(ClientRelayTransport {
                    rendezvous,
                    request_base_url,
                    target_node_id,
                    session_pool,
                }),
                0,
            )]),
            auth: ClientRequestAuth::None,
            connection_name: None,
            upload_session_affinities: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn combine(clients: Vec<Self>) -> Result<Self> {
        if clients.is_empty() {
            bail!("cannot combine zero client transport endpoints");
        }

        let mut combined_auth = None;
        let mut endpoints = Vec::with_capacity(clients.len());

        for (bootstrap_rank, client) in clients.into_iter().enumerate() {
            match (&combined_auth, &client.auth) {
                (None, auth) => combined_auth = Some(auth.clone()),
                (Some(ClientRequestAuth::None), ClientRequestAuth::None)
                | (
                    Some(ClientRequestAuth::SignedIdentity(_)),
                    ClientRequestAuth::SignedIdentity(_),
                ) => {}
                _ => bail!("cannot combine client transports with incompatible auth modes"),
            }

            let endpoint = client
                .transport_router
                .endpoints
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("cannot combine an empty client transport router"))?;
            endpoints.push(endpoint.with_bootstrap_rank(bootstrap_rank));
        }

        Ok(Self {
            transport_router: ClientEndpointRouter::new(endpoints),
            auth: combined_auth.unwrap_or(ClientRequestAuth::None),
            connection_name: None,
            upload_session_affinities: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn with_client_identity(mut self, identity: ClientIdentityMaterial) -> Self {
        self.auth = ClientRequestAuth::SignedIdentity(identity);
        self
    }

    pub fn with_connection_name(mut self, connection_name: impl Into<String>) -> Self {
        self.connection_name = normalize_connection_name(&connection_name.into());
        self
    }

    pub fn connection_route_snapshot(&self) -> ClientConnectionRouteSnapshot {
        self.transport_router.snapshot()
    }

    pub async fn refresh_connection_route_snapshot(&self) -> ClientConnectionRouteSnapshot {
        let tasks = self
            .transport_router
            .endpoints
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, endpoint)| {
                let auth = self.auth.clone();
                let connection_name = self.connection_name.clone();
                async move {
                    let result = probe_endpoint_background_quality(
                        &endpoint,
                        &auth,
                        connection_name.as_deref(),
                    )
                    .await;
                    (index, result)
                }
            });

        for (index, result) in join_all(tasks).await {
            match result {
                Ok(latency_ms) => self
                    .transport_router
                    .record_background_probe_success(index, latency_ms),
                Err(error) => self
                    .transport_router
                    .record_background_probe_failure(index, &error.to_string()),
            }
        }

        self.connection_route_snapshot()
    }

    pub fn connection_diagnostics(&self) -> ClientConnectionDiagnostics {
        self.transport_router.diagnostics_snapshot()
    }

    fn publish_connection_diagnostics(&self) {
        let observer = connection_diagnostics_observer()
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(observer) = observer else {
            return;
        };
        observer(ClientConnectionDiagnosticsEvent {
            connection_name: self.connection_name.clone(),
            diagnostics: self.connection_diagnostics(),
        });
    }

    pub fn uses_relay_transport(&self) -> bool {
        self.transport_router
            .current_endpoint()
            .map(|endpoint| matches!(endpoint.transport, ClientTransport::Relay(_)))
            .unwrap_or(false)
    }

    pub fn relay_target_node_id(&self) -> Option<NodeId> {
        self.transport_router
            .current_endpoint()
            .and_then(|endpoint| endpoint.transport.relay_target_node_id())
    }

    pub fn direct_server_base_url(&self) -> Option<&str> {
        self.transport_router
            .current_endpoint()
            .and_then(|endpoint| endpoint.transport.direct_server_base_url())
    }

    pub fn rendezvous_client(&self) -> Option<RendezvousControlClient> {
        self.transport_router
            .current_endpoint()
            .and_then(|endpoint| endpoint.transport.rendezvous_client())
    }

    pub fn transport_session_pool_snapshot(&self) -> TransportSessionPoolSnapshot {
        self.transport_router
            .current_endpoint()
            .map(|endpoint| endpoint.transport.session_pool_snapshot())
            .unwrap_or_default()
    }

    fn server_base_url(&self) -> &str {
        self.transport_router
            .current_endpoint()
            .map(|endpoint| endpoint.transport.request_base_url())
            .expect("ironmesh client must contain at least one transport endpoint")
    }

    fn request_auth_headers(&self, method: &Method, url: &Url) -> Result<Vec<RelayHttpHeader>> {
        request_auth_headers_for_auth(&self.auth, method, url, self.connection_name.as_deref())
    }

    fn maybe_spawn_background_quality_refresh(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }

        for (index, endpoint) in self.transport_router.claim_background_probe_candidates() {
            let transport_router = self.transport_router.clone();
            let auth = self.auth.clone();
            let connection_name = self.connection_name.clone();
            tokio::spawn(async move {
                match probe_endpoint_background_quality(
                    &endpoint,
                    &auth,
                    connection_name.as_deref(),
                )
                .await
                {
                    Ok(latency_ms) => {
                        transport_router.record_background_probe_success(index, latency_ms);
                    }
                    Err(error) => {
                        transport_router.record_background_probe_failure(index, &error.to_string());
                    }
                }
            });
        }
    }

    fn route_indices_for_upload_session(&self, upload_id: &str) -> Vec<usize> {
        let affinity = {
            let affinities = lock_upload_session_affinities(&self.upload_session_affinities);
            affinities.get(upload_id).cloned()
        };
        self.route_indices_for_affinity(affinity.as_ref())
    }

    fn route_indices_for_affinity(&self, affinity: Option<&UploadSessionAffinity>) -> Vec<usize> {
        let ranked = self.transport_router.rank_indices();
        let Some(affinity) = affinity else {
            return ranked;
        };

        let matching = ranked
            .iter()
            .copied()
            .filter(|index| {
                self.transport_router
                    .endpoint(*index)
                    .is_some_and(|endpoint| affinity.matches_endpoint(endpoint))
            })
            .collect::<Vec<_>>();

        if matching.is_empty() {
            ranked
        } else {
            matching
        }
    }

    fn upload_session_affinity(&self, upload_id: &str) -> Option<UploadSessionAffinity> {
        let affinities = lock_upload_session_affinities(&self.upload_session_affinities);
        affinities.get(upload_id).cloned()
    }

    fn remember_upload_session_affinity(&self, upload_id: &str, affinity: UploadSessionAffinity) {
        let mut affinities = lock_upload_session_affinities(&self.upload_session_affinities);
        affinities.insert(upload_id.to_string(), affinity);
    }

    fn remember_upload_session_affinity_from_route(&self, upload_id: &str, route_index: usize) {
        let Some(endpoint) = self.transport_router.endpoint(route_index) else {
            return;
        };

        self.remember_upload_session_affinity(
            upload_id,
            UploadSessionAffinity::from_endpoint(endpoint),
        );
    }

    fn clear_upload_session_affinity(&self, upload_id: &str) {
        let mut affinities = lock_upload_session_affinities(&self.upload_session_affinities);
        affinities.remove(upload_id);
    }

    async fn execute_buffered_request_on_route_indices(
        &self,
        method: Method,
        url: Url,
        mut headers: Vec<RelayHttpHeader>,
        body: Option<Vec<u8>>,
        route_indices: &[usize],
    ) -> Result<RoutedBufferedTransportResponse> {
        ensure_operation_id_header(&method, &mut headers);
        let direct_failover_timeout =
            direct_multiplex_failover_timeout(&url, route_indices.len() > 1);
        self.maybe_spawn_background_quality_refresh();

        let mut auth_headers = self.request_auth_headers(&method, &url)?;
        auth_headers.append(&mut headers);

        let mut last_error = None;
        for &index in route_indices {
            let Some(endpoint) = self.transport_router.endpoint(index).cloned() else {
                continue;
            };
            let endpoint_context = self.endpoint_context_for_route(index);
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite {} {}", method, url));
            let endpoint_url = match endpoint_url {
                Ok(endpoint_url) => endpoint_url,
                Err(error) => {
                    let error = error.context(endpoint_context);
                    self.transport_router
                        .record_failure(index, &format!("{error:#}"));
                    last_error = Some(error);
                    continue;
                }
            };
            let started_at = std::time::Instant::now();
            let started_unix_ms = unix_ts_ms();
            match execute_buffered_request_for_transport(
                &endpoint.transport,
                &self.auth,
                TransportRequestOptions::new(
                    self.connection_name.as_deref(),
                    direct_failover_timeout,
                ),
                &method,
                &endpoint_url,
                &auth_headers,
                body.as_deref().unwrap_or_default(),
            )
            .await
            {
                Ok(response) if is_retryable_transport_status(response.status) => {
                    self.transport_router.record_request_failure(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        &format!("retryable HTTP {} ({endpoint_context})", response.status,),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(anyhow!(
                        "retryable transport response {} ({endpoint_context})",
                        response.status,
                    ));
                }
                Ok(response) => {
                    self.transport_router.record_request_success(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        response.body.len(),
                    );
                    self.publish_connection_diagnostics();
                    return Ok(RoutedBufferedTransportResponse {
                        route_index: index,
                        response,
                    });
                }
                Err(error) => {
                    let error = error.context(endpoint_context);
                    self.transport_router.record_request_failure(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        &format!("{error:#}"),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "no client transport endpoints are available for {} {}",
                method,
                url
            )
        }))
    }

    async fn execute_upload_session_chunk_on_route_indices(
        &self,
        upload_id: &str,
        index: usize,
        url: Url,
        payload: Vec<u8>,
        route_indices: &[usize],
    ) -> Result<RoutedBufferedTransportResponse> {
        let mut operation_headers = Vec::new();
        ensure_operation_id_header(&Method::PUT, &mut operation_headers);
        let direct_failover_timeout =
            direct_multiplex_failover_timeout(&url, route_indices.len() > 1);
        if matches!(self.auth, ClientRequestAuth::None) {
            return self
                .execute_buffered_request_on_route_indices(
                    Method::PUT,
                    url,
                    operation_headers,
                    Some(payload),
                    route_indices,
                )
                .await;
        }

        self.maybe_spawn_background_quality_refresh();

        let mut auth_headers = self.request_auth_headers(&Method::PUT, &url)?;
        auth_headers.append(&mut operation_headers);
        let mut last_error = None;
        for &route_index in route_indices {
            let Some(endpoint) = self.transport_router.endpoint(route_index).cloned() else {
                continue;
            };
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite streamed PUT {}", url));
            let endpoint_url = match endpoint_url {
                Ok(endpoint_url) => endpoint_url,
                Err(error) => {
                    self.transport_router
                        .record_failure(route_index, &error.to_string());
                    last_error = Some(error);
                    continue;
                }
            };
            let started_at = std::time::Instant::now();
            let started_unix_ms = unix_ts_ms();
            match execute_streaming_object_write_request_for_transport(
                &endpoint.transport,
                &self.auth,
                TransportRequestOptions::new(
                    self.connection_name.as_deref(),
                    direct_failover_timeout,
                ),
                &Method::PUT,
                &endpoint_url,
                &auth_headers,
                &payload,
            )
            .await
            {
                Ok(candidate_response)
                    if is_retryable_transport_status(candidate_response.status) =>
                {
                    self.transport_router.record_request_failure(
                        route_index,
                        ClientRequestAttemptContext {
                            method: &Method::PUT,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        &format!(
                            "retryable HTTP {} from {}",
                            candidate_response.status, endpoint.descriptor.locator
                        ),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(anyhow!(
                        "retryable transport response {} from {}",
                        candidate_response.status,
                        endpoint.descriptor.locator
                    ));
                }
                Ok(candidate_response) => {
                    self.transport_router.record_request_success(
                        route_index,
                        ClientRequestAttemptContext {
                            method: &Method::PUT,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        candidate_response.body.len(),
                    );
                    self.publish_connection_diagnostics();
                    return Ok(RoutedBufferedTransportResponse {
                        route_index,
                        response: candidate_response,
                    });
                }
                Err(error) => {
                    self.transport_router.record_request_failure(
                        route_index,
                        ClientRequestAttemptContext {
                            method: &Method::PUT,
                            url: &endpoint_url,
                            timeout: direct_failover_timeout,
                            started_unix_ms,
                        },
                        &error.to_string(),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "no client transport endpoints accepted streamed upload for session={} index={}",
                upload_id,
                index
            )
        }))
    }

    async fn execute_buffered_request(
        &self,
        method: Method,
        url: Url,
        headers: Vec<RelayHttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<BufferedTransportResponse> {
        let routed = self
            .execute_buffered_request_with_route(method, url, headers, body)
            .await?;
        Ok(routed.response)
    }

    async fn execute_buffered_request_with_route(
        &self,
        method: Method,
        url: Url,
        headers: Vec<RelayHttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<RoutedBufferedTransportResponse> {
        self.execute_buffered_request_on_route_indices(
            method,
            url,
            headers,
            body,
            &self.transport_router.rank_indices(),
        )
        .await
    }

    fn endpoint_context_for_route(&self, route_index: usize) -> String {
        let Some(endpoint) = self.transport_router.endpoint(route_index) else {
            return format!(
                "endpoint_index={route_index} endpoint_locator=<unknown> target_node_id=<unknown>"
            );
        };

        let target_node_id = endpoint
            .transport
            .target_node_id()
            .map(|node_id| node_id.to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        format!(
            "endpoint_index={route_index} endpoint_locator={} target_node_id={target_node_id} transport_path_kind={}",
            endpoint.descriptor.locator,
            transport_path_kind_label(endpoint.descriptor.transport_path_kind),
        )
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        self.put_with_expected_revision(key, data, None).await
    }

    pub async fn put_with_expected_revision(
        &self,
        key: impl Into<String>,
        data: Bytes,
        expected_revision: Option<&str>,
    ) -> Result<StorageObjectMeta> {
        let key = key.into();
        let mut url = self.store_key_url(&key)?;
        append_optional_query(&mut url, "expected_revision", expected_revision);

        let response = self
            .execute_buffered_request(Method::PUT, url, Vec::new(), Some(data.to_vec()))
            .await
            .with_context(|| format!("failed to PUT object key={key}"))?;
        if !response.status.is_success() {
            bail!("server rejected PUT for key={key}: {}", response.status);
        }

        Ok(StorageObjectMeta {
            key,
            size_bytes: data.len(),
        })
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        self.get_with_selector(key, None, None).await
    }

    pub async fn get_with_selector(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<Bytes> {
        let key = key.as_ref();
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let routed = self
            .execute_buffered_request_with_route(Method::GET, url, Vec::new(), None)
            .await
            .map_err(|error| anyhow!("failed to GET object key={key}: {error:#}"))?;
        let endpoint_context = self.endpoint_context_for_route(routed.route_index);
        let response = routed.response;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {} ({endpoint_context})",
                response.status,
            );
        }
        Ok(response.body)
    }

    pub async fn rename_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        self.rename_path_with_expected_revision(from_path, to_path, overwrite, None)
            .await
    }

    pub async fn rename_path_with_expected_revision(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
        expected_revision: Option<&str>,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_rename_url()?;
        let payload = serde_json::to_vec(&PathMutationRequest {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            overwrite,
            expected_revision: expected_revision.map(str::to_string),
        })
        .context("failed to encode rename request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to rename {from_path} -> {to_path}"))?;

        match response.status {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => bail!("rename source path not found: {from_path}"),
            StatusCode::CONFLICT => bail!("rename target path already exists: {to_path}"),
            status => Err(anyhow!(
                "rename failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn copy_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_copy_url()?;
        let payload = serde_json::to_vec(&PathMutationRequest {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            overwrite,
            expected_revision: None,
        })
        .context("failed to encode copy request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to copy {from_path} -> {to_path}"))?;

        match response.status {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => bail!("copy source path not found: {from_path}"),
            StatusCode::CONFLICT => bail!("copy target path already exists: {to_path}"),
            status => Err(anyhow!(
                "copy failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn restore_path_from_snapshot(
        &self,
        snapshot: impl Into<String>,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        recursive: bool,
        overwrite: bool,
    ) -> Result<SnapshotRestoreResponse> {
        let snapshot = snapshot.into();
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_restore_url()?;
        let payload = serde_json::to_vec(&SnapshotRestoreRequest {
            snapshot: snapshot.clone(),
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            recursive,
            overwrite,
        })
        .context("failed to encode snapshot restore request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to restore snapshot={} path {} -> {}",
                    snapshot, from_path, to_path
                )
            })?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<SnapshotRestoreResponse>(&response.body)
                .context("failed to parse snapshot restore response"),
            StatusCode::NOT_FOUND => {
                bail!("snapshot restore source path not found in snapshot={snapshot}: {from_path}")
            }
            StatusCode::CONFLICT => {
                bail!("snapshot restore target path already exists: {to_path}")
            }
            status => Err(anyhow!(
                "snapshot restore failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn delete_path(&self, key: impl AsRef<str>) -> Result<()> {
        self.delete_path_with_expected_revision(key, None).await
    }

    pub async fn delete_path_with_expected_revision(
        &self,
        key: impl AsRef<str>,
        expected_revision: Option<&str>,
    ) -> Result<()> {
        let key = key.as_ref();
        let mut url = self.store_delete_url()?;
        url.query_pairs_mut().append_pair("key", key);
        append_optional_query(&mut url, "expected_revision", expected_revision);
        if key.ends_with('/') {
            url.query_pairs_mut().append_pair("recursive", "true");
        }

        let response = self
            .execute_buffered_request(Method::POST, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to delete path {key}"))?;

        match response.status {
            StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(()),
            status => Err(anyhow!("delete failed for {key}: {status}")),
        }
    }

    pub async fn list_versions(&self, key: impl AsRef<str>) -> Result<Option<VersionGraphSummary>> {
        let key = key.as_ref();
        let url = self.store_versions_url(key)?;

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request /versions/{key}"))?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<VersionGraphSummary>(&response.body)
                .map(Some)
                .context("failed to parse /versions response"),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(anyhow!("versions lookup failed for {key}: {status}")),
        }
    }

    pub async fn restore_version_path(
        &self,
        key: impl Into<String>,
        version_id: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let key = key.into();
        let version_id = version_id.into();
        let to_path = to_path.into();
        let url = self.store_version_restore_url(&key, &version_id)?;
        let payload = serde_json::to_vec(&VersionRestoreRequest {
            to_path: to_path.clone(),
            overwrite,
        })
        .context("failed to encode version restore request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to restore version {} for {} -> {}",
                    version_id, key, to_path
                )
            })?;

        match response.status {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => bail!(
                "version restore source not found for {}@{}",
                key,
                version_id
            ),
            StatusCode::CONFLICT => {
                bail!("version restore target path already exists: {to_path}")
            }
            status => Err(anyhow!(
                "version restore failed for {}@{} -> {}: {status}",
                key,
                version_id,
                to_path
            )),
        }
    }

    pub fn list_versions_blocking(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<VersionGraphSummary>> {
        let key = key.as_ref().to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.list_versions(key))
    }

    pub async fn store_index(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_options(prefix, depth, snapshot, StoreIndexRequestOptions::default())
            .await
    }

    pub async fn store_index_with_view(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_options(
            prefix,
            depth,
            snapshot,
            StoreIndexRequestOptions {
                view,
                ..StoreIndexRequestOptions::default()
            },
        )
        .await
    }

    pub async fn store_index_with_options(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        options: StoreIndexRequestOptions,
    ) -> Result<StoreIndexResponse> {
        let mut url = self.store_index_url()?;
        url.query_pairs_mut()
            .append_pair("depth", &depth.max(1).to_string());
        append_optional_query(&mut url, "prefix", prefix);
        append_optional_query(&mut url, "snapshot", snapshot);
        if let Some(view) = options.view {
            url.query_pairs_mut()
                .append_pair("view", view.as_query_value());
        }
        if let Some(cursor) = options.cursor.as_deref() {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        if let Some(page_size) = options.page_size {
            url.query_pairs_mut()
                .append_pair("page_size", &page_size.max(1).to_string());
        }
        if let Some(offset) = options.offset {
            url.query_pairs_mut()
                .append_pair("offset", &offset.to_string());
        }
        if let Some(limit) = options.limit {
            url.query_pairs_mut()
                .append_pair("limit", &limit.max(1).to_string());
        }
        if let Some(sort) = options.sort {
            url.query_pairs_mut()
                .append_pair("sort", sort.as_query_value());
        }
        if let Some(media_filter) = options.media_filter {
            url.query_pairs_mut()
                .append_pair("media_filter", media_filter.as_query_value());
        }

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .context("failed to request /store/index")?;
        if !response.status.is_success() {
            bail!(
                "/store/index returned non-success status: {}",
                response.status
            );
        }

        let mut result = serde_json::from_slice::<StoreIndexResponse>(&response.body)
            .context("failed to parse /store/index response");

        if let Ok(ref mut response) = result
            && options.synthesize_missing_folder_markers
        {
            ensure_missing_folder_markers(&mut response.entries);
            response.entry_count = response.entries.len();
            response.total_entry_count = response.total_entry_count.max(response.entry_count);
        }

        result
    }

    pub fn store_index_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_options_blocking(
            prefix,
            depth,
            snapshot,
            StoreIndexRequestOptions::default(),
        )
    }

    pub fn store_index_with_view_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_options_blocking(
            prefix,
            depth,
            snapshot,
            StoreIndexRequestOptions {
                view,
                ..StoreIndexRequestOptions::default()
            },
        )
    }

    pub fn store_index_with_options_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        options: StoreIndexRequestOptions,
    ) -> Result<StoreIndexResponse> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.store_index_with_options(prefix, depth, snapshot, options))
    }

    pub async fn wait_for_store_index_change(
        &self,
        since: u64,
        timeout_ms: u64,
    ) -> Result<StoreIndexChangeWaitResponse> {
        let mut url = self.store_index_change_wait_url()?;
        url.query_pairs_mut()
            .append_pair("since", &since.to_string())
            .append_pair("timeout_ms", &timeout_ms.max(250).to_string());

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .context("failed to request /store/index/changes/wait")?;
        if !response.status.is_success() {
            bail!(
                "/store/index/changes/wait returned non-success status: {}",
                response.status
            );
        }
        serde_json::from_slice::<StoreIndexChangeWaitResponse>(&response.body)
            .context("failed to parse /store/index/changes/wait response")
    }

    pub fn wait_for_store_index_change_blocking(
        &self,
        since: u64,
        timeout_ms: u64,
    ) -> Result<StoreIndexChangeWaitResponse> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.wait_for_store_index_change(since, timeout_ms))
    }

    pub async fn request_relative_path(
        &self,
        method: Method,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<RelativePathResponse> {
        let url = self.relative_url(path)?;
        let headers = headers
            .into_iter()
            .map(|(name, value)| RelayHttpHeader { name, value })
            .collect::<Vec<_>>();
        let response = self
            .execute_buffered_request(method, url, headers, body)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        Ok(RelativePathResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    pub async fn request_relative_path_streaming_response(
        &self,
        method: Method,
        path: &str,
        headers: Vec<(String, String)>,
    ) -> Result<StreamedRelativePathResponse> {
        if method != Method::GET {
            bail!(
                "streamed relative-path responses only support GET, received {}",
                method
            );
        }

        let normalized_path = normalize_client_api_path(path);
        let path_only = normalized_path
            .split_once('?')
            .map(|(path, _)| path)
            .unwrap_or(normalized_path.as_ref());
        let stream_path = strip_client_api_v1_prefix(path_only);
        let supports_s3_streaming =
            stream_path == "/s3" || stream_path == "/s3/" || stream_path.starts_with("/s3/");
        if !stream_path.starts_with("/store/") && !supports_s3_streaming {
            bail!(
                "streamed relative-path responses currently support only /store/* or /s3/* paths, received {}",
                path
            );
        }

        self.maybe_spawn_background_quality_refresh();

        let url = self.relative_url(path)?;
        let mut headers = headers
            .into_iter()
            .map(|(name, value)| RelayHttpHeader { name, value })
            .collect::<Vec<_>>();
        let mut auth_headers = self.request_auth_headers(&method, &url)?;
        auth_headers.append(&mut headers);
        let mut last_error = None;

        for index in self.transport_router.rank_indices() {
            let Some(endpoint) = self.transport_router.endpoint(index).cloned() else {
                continue;
            };
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite streamed {} {}", method, url));
            let endpoint_url = match endpoint_url {
                Ok(endpoint_url) => endpoint_url,
                Err(error) => {
                    self.transport_router
                        .record_failure(index, &error.to_string());
                    last_error = Some(error);
                    continue;
                }
            };
            let started_at = std::time::Instant::now();
            let started_unix_ms = unix_ts_ms();
            match execute_streaming_read_request_for_transport(
                &endpoint.transport,
                &self.auth,
                self.connection_name.as_deref(),
                &method,
                &endpoint_url,
                &auth_headers,
            )
            .await
            {
                Ok(response) => {
                    let bytes_hint = response
                        .headers
                        .get(CONTENT_LENGTH)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or_default();
                    self.transport_router.record_request_success(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        bytes_hint,
                    );
                    self.publish_connection_diagnostics();
                    return Ok(response);
                }
                Err(error) => {
                    self.transport_router.record_request_failure(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        &error.to_string(),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "no client transport endpoints are available for streamed {} {}",
                method,
                url
            )
        }))
    }

    pub async fn request_relative_path_streaming_body<S>(
        &self,
        method: Method,
        path: &str,
        headers: Vec<(String, String)>,
        body_stream: S,
    ) -> Result<RelativePathResponse>
    where
        S: Stream<Item = std::result::Result<Bytes, std::io::Error>> + Send + 'static,
    {
        self.maybe_spawn_background_quality_refresh();

        let url = self.relative_url(path)?;
        let mut headers = headers
            .into_iter()
            .map(|(name, value)| RelayHttpHeader { name, value })
            .collect::<Vec<_>>();
        let mut auth_headers = self.request_auth_headers(&method, &url)?;
        auth_headers.append(&mut headers);
        let mut last_error = None;
        let mut body_stream = Some(Box::pin(body_stream) as RequestBodyStream);

        for index in self.transport_router.rank_indices() {
            let Some(endpoint) = self.transport_router.endpoint(index).cloned() else {
                continue;
            };
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite streamed {} {}", method, url));
            let endpoint_url = match endpoint_url {
                Ok(endpoint_url) => endpoint_url,
                Err(error) => {
                    self.transport_router
                        .record_failure(index, &error.to_string());
                    last_error = Some(error);
                    continue;
                }
            };
            let started_at = std::time::Instant::now();
            let started_unix_ms = unix_ts_ms();
            let Some(request_body_stream) = body_stream.take() else {
                bail!("streamed relative-path request body was already consumed");
            };
            match execute_streaming_write_request_for_transport(
                &endpoint.transport,
                &self.auth,
                self.connection_name.as_deref(),
                &method,
                &endpoint_url,
                &auth_headers,
                request_body_stream,
            )
            .await
            {
                Ok(response) => {
                    self.transport_router.record_request_success(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        response.body.len(),
                    );
                    self.publish_connection_diagnostics();
                    return Ok(RelativePathResponse {
                        status: response.status,
                        headers: response.headers,
                        body: response.body,
                    });
                }
                Err(error) => {
                    self.transport_router.record_request_failure(
                        index,
                        ClientRequestAttemptContext {
                            method: &method,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        &error.to_string(),
                    );
                    self.publish_connection_diagnostics();
                    return Err(error);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!(
                "no client transport endpoints are available for streamed {} {}",
                method,
                url
            )
        }))
    }

    pub fn request_relative_path_blocking(
        &self,
        method: Method,
        path: &str,
        headers: Vec<(String, String)>,
        body: Option<Vec<u8>>,
    ) -> Result<RelativePathResponse> {
        let path = path.to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.request_relative_path(method, &path, headers, body))
    }

    pub async fn get_json_path(&self, path: &str) -> Result<serde_json::Value> {
        let url = self.relative_url(path)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        if !response.status.is_success() {
            bail!("{path} returned non-success status: {}", response.status);
        }
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .with_context(|| format!("failed to parse JSON response from {path}"))
    }

    pub fn get_json_path_blocking(&self, path: &str) -> Result<serde_json::Value> {
        let path = path.to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_json_path(&path))
    }

    pub async fn get_relative_path(&self, path: &str) -> Result<RelativePathResponse> {
        let url = self.relative_url(path)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        Ok(RelativePathResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    pub fn get_relative_path_blocking(&self, path: &str) -> Result<RelativePathResponse> {
        let path = path.to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_relative_path(&path))
    }

    pub async fn post_relative_path(&self, path: &str) -> Result<RelativePathResponse> {
        let url = self.relative_url(path)?;
        let response = self
            .execute_buffered_request(Method::POST, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        Ok(RelativePathResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    async fn start_upload_session(
        &self,
        key: &str,
        total_size_bytes: u64,
    ) -> Result<UploadSessionView> {
        self.start_upload_session_with_chunk_refs(key, total_size_bytes, Vec::new())
            .await
    }

    async fn start_upload_session_with_chunk_refs(
        &self,
        key: &str,
        total_size_bytes: u64,
        chunk_refs: Vec<UploadSessionChunkRef>,
    ) -> Result<UploadSessionView> {
        let url = self.store_upload_session_start_url()?;
        let payload = serde_json::to_vec(&UploadSessionStartRequest {
            key: key.to_string(),
            total_size_bytes,
            state: None,
            parent: Vec::new(),
            version_id: None,
            chunk_refs,
        })
        .context("failed to encode upload session start payload")?;

        let routed = self
            .execute_buffered_request_on_route_indices(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
                &self.transport_router.rank_indices(),
            )
            .await
            .with_context(|| format!("failed to start upload session for key={key}"))?;
        let response = routed.response;
        if !response.status.is_success() {
            bail!(
                "server rejected upload session start for key={key}: {}",
                response.status
            );
        }

        let view = serde_json::from_slice::<UploadSessionView>(&response.body)
            .with_context(|| format!("failed to parse upload session start response for {key}"))?;
        self.remember_upload_session_affinity_from_route(&view.upload_id, routed.route_index);
        Ok(view)
    }

    pub async fn begin_upload_session(
        &self,
        key: impl AsRef<str>,
        total_size_bytes: u64,
    ) -> Result<UploadSessionStatus> {
        self.begin_upload_session_with_chunk_refs(key, total_size_bytes, Vec::new())
            .await
    }

    pub async fn begin_upload_session_with_chunk_refs(
        &self,
        key: impl AsRef<str>,
        total_size_bytes: u64,
        chunk_refs: Vec<UploadSessionChunkRef>,
    ) -> Result<UploadSessionStatus> {
        let view = self
            .start_upload_session_with_chunk_refs(key.as_ref(), total_size_bytes, chunk_refs)
            .await?;
        Ok(upload_session_status_from_view(view))
    }

    async fn get_upload_session(&self, upload_id: &str) -> Result<Option<UploadSessionView>> {
        let url = self.store_upload_session_url(upload_id)?;
        let routed = self
            .execute_buffered_request_on_route_indices(
                Method::GET,
                url,
                Vec::new(),
                None,
                &self.route_indices_for_upload_session(upload_id),
            )
            .await
            .with_context(|| format!("failed to query upload session {upload_id}"))?;
        let response = routed.response;

        match response.status {
            StatusCode::OK => {
                let view = serde_json::from_slice::<UploadSessionView>(&response.body)
                    .with_context(|| format!("failed to parse upload session {upload_id}"))?;
                self.remember_upload_session_affinity_from_route(upload_id, routed.route_index);
                Ok(Some(view))
            }
            StatusCode::NOT_FOUND => {
                self.clear_upload_session_affinity(upload_id);
                Ok(None)
            }
            StatusCode::FORBIDDEN => Ok(None),
            status => Err(anyhow!(
                "upload session query failed for {upload_id}: {status}"
            )),
        }
    }

    async fn upload_session_chunk(
        &self,
        upload_id: &str,
        index: usize,
        payload: Vec<u8>,
    ) -> Result<UploadSessionChunkResponse> {
        let url = self.store_upload_session_chunk_url(upload_id, index)?;
        let routed = self
            .execute_upload_session_chunk_on_route_indices(
                upload_id,
                index,
                url,
                payload,
                &self.route_indices_for_upload_session(upload_id),
            )
            .await
            .with_context(|| format!("failed to upload chunk {index} for session={upload_id}"))?;
        let response = routed.response;
        if !response.status.is_success() {
            bail!(
                "upload session chunk rejected for session={upload_id} index={index}: {}",
                response.status
            );
        }

        self.remember_upload_session_affinity_from_route(upload_id, routed.route_index);

        serde_json::from_slice::<UploadSessionChunkResponse>(&response.body).with_context(|| {
            format!("failed to parse upload session chunk response for session={upload_id}")
        })
    }

    pub async fn upload_session_chunk_bytes(
        &self,
        upload_id: &str,
        index: usize,
        payload: Vec<u8>,
    ) -> Result<UploadSessionChunkStatus> {
        let response = self.upload_session_chunk(upload_id, index, payload).await?;
        Ok(UploadSessionChunkStatus {
            stored: response.stored,
            received_index: response.received_index,
        })
    }

    async fn complete_upload_session(
        &self,
        upload_id: &str,
    ) -> Result<UploadSessionCompleteResponse> {
        let url = self.store_upload_session_complete_url(upload_id)?;
        let routed = self
            .execute_buffered_request_on_route_indices(
                Method::POST,
                url,
                Vec::new(),
                None,
                &self.route_indices_for_upload_session(upload_id),
            )
            .await
            .with_context(|| format!("failed to complete upload session {upload_id}"))?;
        let response = routed.response;

        if !response.status.is_success() {
            bail!(
                "upload session completion rejected for session={upload_id}: {}",
                response.status
            );
        }

        let completed = serde_json::from_slice::<UploadSessionCompleteResponse>(&response.body)
            .with_context(|| {
                format!("failed to parse upload session completion response for {upload_id}")
            })?;
        self.remember_upload_session_affinity_from_route(upload_id, routed.route_index);
        self.clear_upload_session_affinity(upload_id);
        Ok(completed)
    }

    pub async fn finalize_upload_session(
        &self,
        upload_id: &str,
    ) -> Result<UploadSessionCompleteInfo> {
        let response = self.complete_upload_session(upload_id).await?;
        Ok(upload_session_complete_info_from_response(response))
    }

    async fn head_object_response(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadResponse> {
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let routed = self
            .execute_buffered_request_with_route(Method::HEAD, url, Vec::new(), None)
            .await
            .map_err(|error| anyhow!("failed to HEAD object key={key}: {error:#}"))?;
        let endpoint_context = self.endpoint_context_for_route(routed.route_index);
        let response = routed.response;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {} ({endpoint_context})",
                response.status,
            );
        }

        let total_size_bytes = response
            .headers
            .get("x-ironmesh-object-size")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| {
                response
                    .headers
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(0);

        let head_response = ObjectHeadResponse {
            total_size_bytes,
            etag: response
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string),
            accept_ranges: response
                .headers
                .get(ACCEPT_RANGES)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.eq_ignore_ascii_case("bytes"))
                .unwrap_or(false),
        };

        tracing::info!(
            "client head-object response: key={} snapshot={} version={} status={} content_length={} object_size={} etag={} accept_ranges={}",
            key,
            snapshot.unwrap_or("<none>"),
            version.unwrap_or("<none>"),
            response.status,
            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
            head_response.total_size_bytes,
            head_response.etag.as_deref().unwrap_or("<none>"),
            head_response.accept_ranges
        );

        Ok(head_response)
    }

    async fn stream_object_request_to_writer(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
        range: Option<(u64, u64)>,
        if_range: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<StreamedTransportResponseMeta> {
        self.maybe_spawn_background_quality_refresh();

        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let mut headers = Vec::new();
        if let Some((start, end_inclusive)) = range {
            headers.push(range_header(start, end_inclusive));
        }
        if let Some(if_range) = if_range {
            headers.push(simple_header(IF_RANGE, if_range)?);
        }
        let mut auth_headers = self.request_auth_headers(&Method::GET, &url)?;
        auth_headers.append(&mut headers);

        let mut last_error = None;
        let mut response = None;
        for index in self.transport_router.rank_indices() {
            let Some(endpoint) = self.transport_router.endpoint(index).cloned() else {
                continue;
            };
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite streamed GET {}", url));
            let endpoint_url = match endpoint_url {
                Ok(endpoint_url) => endpoint_url,
                Err(error) => {
                    self.transport_router
                        .record_failure(index, &error.to_string());
                    last_error = Some(error);
                    continue;
                }
            };
            let started_at = std::time::Instant::now();
            let started_unix_ms = unix_ts_ms();
            match execute_streaming_object_read_request_for_transport(
                &endpoint.transport,
                &self.auth,
                self.connection_name.as_deref(),
                &endpoint_url,
                &auth_headers,
                writer,
            )
            .await
            {
                Ok(candidate_response) => {
                    self.transport_router.record_request_success(
                        index,
                        ClientRequestAttemptContext {
                            method: &Method::GET,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        candidate_response.bytes_written as usize,
                    );
                    self.publish_connection_diagnostics();
                    response = Some(candidate_response);
                    break;
                }
                Err(error) => {
                    self.transport_router.record_request_failure(
                        index,
                        ClientRequestAttemptContext {
                            method: &Method::GET,
                            url: &endpoint_url,
                            timeout: None,
                            started_unix_ms,
                        },
                        &error.to_string(),
                    );
                    self.publish_connection_diagnostics();
                    last_error = Some(error);
                }
            }
        }

        let response = response.ok_or_else(|| {
            last_error.unwrap_or_else(|| {
                anyhow!(
                    "no client transport endpoints are available for streamed GET {}",
                    url
                )
            })
        })?;

        tracing::info!(
            "client streamed object-read: key={} snapshot={} version={} range_start={} range_end={} status={} content_length={} content_range={} object_size={} etag={} accept_ranges={} bytes_written={}",
            key,
            snapshot.unwrap_or("<none>"),
            version.unwrap_or("<none>"),
            range
                .map(|(start, _)| start.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            range
                .map(|(_, end)| end.to_string())
                .unwrap_or_else(|| "<none>".to_string()),
            response.status,
            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
            header_value_for_log(&response.headers, CONTENT_RANGE.as_str()),
            header_value_for_log(&response.headers, "x-ironmesh-object-size"),
            header_value_for_log(&response.headers, ETAG.as_str()),
            header_value_for_log(&response.headers, ACCEPT_RANGES.as_str()),
            response.bytes_written
        );

        Ok(response)
    }

    async fn download_with_range_requests(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let head = self.head_object_response(key, snapshot, version).await?;
        if head.total_size_bytes == 0 {
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(());
        }

        if !head.accept_ranges {
            let response = self
                .stream_object_request_to_writer(key, snapshot, version, None, None, writer)
                .await?;
            if response.status != StatusCode::OK {
                bail!(
                    "server rejected object download for key={key}: {}",
                    response.status
                );
            }
            return Ok(());
        }

        let mut offset = 0_u64;
        while offset < head.total_size_bytes {
            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                head.total_size_bytes - 1,
            );
            let response = self
                .stream_object_request_to_writer(
                    key,
                    snapshot,
                    version,
                    Some((offset, end_inclusive)),
                    head.etag.as_deref(),
                    writer,
                )
                .await?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.bytes_written != expected_len as u64 {
                        tracing::info!(
                            "client range-response length mismatch: key={} range_start={} range_end={} expected_len={} actual_len={} status={} content_length={} content_range={} object_size={} etag={}",
                            key,
                            offset,
                            end_inclusive,
                            expected_len,
                            response.bytes_written,
                            response.status,
                            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
                            header_value_for_log(&response.headers, CONTENT_RANGE.as_str()),
                            header_value_for_log(&response.headers, "x-ironmesh-object-size"),
                            header_value_for_log(&response.headers, ETAG.as_str())
                        );
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.bytes_written
                        );
                    }
                    offset = end_inclusive + 1;
                }
                StatusCode::OK if offset == 0 => {
                    offset = head.total_size_bytes;
                }
                status => {
                    bail!("server rejected ranged download for key={key}: {status}");
                }
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(())
    }

    async fn download_range_to_writer_with_progress(
        &self,
        request: DownloadRangeRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(DownloadProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<DownloadRangeResult> {
        let key = request.key;
        let snapshot = request.snapshot;
        let version = request.version;
        let head = await_download_with_cancellation(
            self.head_object_response(key, snapshot, version),
            should_cancel,
            format!("download canceled for key={key}"),
        )
        .await?;
        let range_start = request.range.offset.min(head.total_size_bytes);
        let range_end_exclusive = range_start
            .saturating_add(request.range.length)
            .min(head.total_size_bytes);
        let range_length = range_end_exclusive.saturating_sub(range_start);

        on_progress(DownloadProgress {
            object_size_bytes: head.total_size_bytes,
            range: RequestedRange {
                offset: range_start,
                length: range_length,
            },
            bytes_downloaded: 0,
        });

        if range_length == 0 {
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(DownloadRangeResult {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded: 0,
            });
        }

        if !head.accept_ranges {
            if range_start != 0 || range_length != head.total_size_bytes {
                bail!(
                    "server does not support byte ranges for key={key}, cannot satisfy requested range start={range_start} length={range_length}"
                );
            }

            if should_cancel() {
                bail!("download canceled for key={key}");
            }

            let response = await_download_with_cancellation(
                self.stream_object_request_to_writer(key, snapshot, version, None, None, writer),
                should_cancel,
                format!("download canceled for key={key}"),
            )
            .await?;
            if response.status != StatusCode::OK {
                bail!(
                    "server rejected object download for key={key}: {}",
                    response.status
                );
            }

            let bytes_downloaded = response.bytes_written;
            on_progress(DownloadProgress {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded,
            });

            return Ok(DownloadRangeResult {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded,
            });
        }

        let mut offset = range_start;
        let mut bytes_downloaded = 0_u64;
        while offset < range_end_exclusive {
            if should_cancel() {
                bail!("download canceled for key={key}");
            }

            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                range_end_exclusive - 1,
            );
            let response = await_download_with_cancellation(
                self.stream_object_request_to_writer(
                    key,
                    snapshot,
                    version,
                    Some((offset, end_inclusive)),
                    head.etag.as_deref(),
                    writer,
                ),
                should_cancel,
                format!("download canceled for key={key}"),
            )
            .await?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.bytes_written != expected_len as u64 {
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.bytes_written
                        );
                    }
                    bytes_downloaded += response.bytes_written;
                    offset = end_inclusive + 1;
                    on_progress(DownloadProgress {
                        object_size_bytes: head.total_size_bytes,
                        range: RequestedRange {
                            offset: range_start,
                            length: range_length,
                        },
                        bytes_downloaded,
                    });
                }
                StatusCode::OK if offset == 0 && range_length == head.total_size_bytes => {
                    bytes_downloaded = response.bytes_written;
                    offset = range_end_exclusive;
                    on_progress(DownloadProgress {
                        object_size_bytes: head.total_size_bytes,
                        range: RequestedRange {
                            offset: range_start,
                            length: range_length,
                        },
                        bytes_downloaded,
                    });
                }
                status => {
                    bail!("server rejected ranged download for key={key}: {status}");
                }
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(DownloadRangeResult {
            object_size_bytes: head.total_size_bytes,
            range: RequestedRange {
                offset: range_start,
                length: range_length,
            },
            bytes_downloaded,
        })
    }

    pub fn put_file_resumable(
        &self,
        key: impl Into<String>,
        source_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
    ) -> Result<UploadResult> {
        let key = key.into();
        let source_path = source_path.as_ref();
        let state_path = state_path.as_ref();
        let metadata = fs::metadata(source_path).with_context(|| {
            format!("failed to inspect upload source {}", source_path.display())
        })?;
        let source_size_bytes = metadata.len();
        let source_modified_unix_ms = file_modified_unix_ms(&metadata);

        if source_size_bytes <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            let mut file = File::open(source_path).with_context(|| {
                format!("failed to open upload source {}", source_path.display())
            })?;
            return self.put_large_aware_reader(key, &mut file, source_size_bytes);
        }

        let runtime = blocking_runtime()?;

        let persisted = load_json_file::<ResumableUploadFileState>(state_path)?.filter(|state| {
            state.key == key
                && state.source_size_bytes == source_size_bytes
                && state.source_modified_unix_ms == source_modified_unix_ms
        });

        let mut session = match persisted {
            Some(state) => {
                if let Some(affinity) = upload_session_affinity_from_resumable_state(&state) {
                    self.remember_upload_session_affinity(&state.upload_id, affinity);
                }

                match runtime.block_on(self.get_upload_session(&state.upload_id))? {
                    Some(session)
                        if session.key == key && session.total_size_bytes == source_size_bytes =>
                    {
                        session
                    }
                    _ => {
                        self.clear_upload_session_affinity(&state.upload_id);
                        remove_file_if_exists(state_path)?;
                        let chunk_refs =
                            upload_session_chunk_refs_for_file(source_path, source_size_bytes)?;
                        runtime.block_on(self.start_upload_session_with_chunk_refs(
                            &key,
                            source_size_bytes,
                            chunk_refs,
                        ))?
                    }
                }
            }
            None => {
                let chunk_refs =
                    upload_session_chunk_refs_for_file(source_path, source_size_bytes)?;
                runtime.block_on(self.start_upload_session_with_chunk_refs(
                    &key,
                    source_size_bytes,
                    chunk_refs,
                ))?
            }
        };

        persist_json_file_atomic(
            state_path,
            &ResumableUploadFileState {
                upload_id: session.upload_id.clone(),
                key: key.clone(),
                source_size_bytes,
                source_modified_unix_ms,
                chunk_size_bytes: session.chunk_size_bytes,
                target_node_id: self
                    .upload_session_affinity(&session.upload_id)
                    .and_then(|affinity| affinity.target_node_id),
                preferred_request_base_url: self
                    .upload_session_affinity(&session.upload_id)
                    .and_then(|affinity| affinity.preferred_request_base_url),
            },
        )?;
        maybe_abort_after_resumable_upload_state_persist(&key, state_path);

        if session.completed {
            self.clear_upload_session_affinity(&session.upload_id);
            remove_file_if_exists(state_path)?;
            if let Some(ref completed) = session.completed_result {
                return Ok(upload_result_from_session_complete(
                    &key, &session, completed,
                ));
            }
        }

        let received = session
            .received_indexes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut file = File::open(source_path)
            .with_context(|| format!("failed to open upload source {}", source_path.display()))?;
        let mut buffer = vec![0_u8; session.chunk_size_bytes];

        for index in 0..session.chunk_count {
            if received.contains(&index) {
                continue;
            }

            let offset = (index as u64)
                .checked_mul(session.chunk_size_bytes as u64)
                .context("upload chunk offset overflow")?;
            file.seek(SeekFrom::Start(offset)).with_context(|| {
                format!("failed to seek upload source {}", source_path.display())
            })?;

            let expected_size = expected_chunk_size(
                session.total_size_bytes,
                session.chunk_size_bytes,
                session.chunk_count,
                index,
            )
            .context("failed to determine expected upload chunk size")?;
            file.read_exact(&mut buffer[..expected_size])
                .with_context(|| {
                    format!(
                        "failed to read upload chunk index={index} from {}",
                        source_path.display()
                    )
                })?;

            let response = runtime.block_on(self.upload_session_chunk(
                &session.upload_id,
                index,
                buffer[..expected_size].to_vec(),
            ))?;
            if response.received_index != index {
                bail!(
                    "server acknowledged unexpected upload chunk index={} expected={index}",
                    response.received_index
                );
            }
        }

        let completed = runtime.block_on(self.complete_upload_session(&session.upload_id))?;
        self.clear_upload_session_affinity(&session.upload_id);
        remove_file_if_exists(state_path)?;
        session.completed_result = Some(completed.clone());
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    fn put_sized_reader_via_upload_session(
        &self,
        key: impl Into<String>,
        reader: &mut dyn Read,
        total_size_bytes: u64,
    ) -> Result<UploadResult> {
        let key = key.into();
        let runtime = blocking_runtime()?;
        let session = runtime.block_on(self.start_upload_session(&key, total_size_bytes))?;
        let mut buffer = vec![0_u8; session.chunk_size_bytes];

        for index in 0..session.chunk_count {
            let expected_size = expected_chunk_size(
                total_size_bytes,
                session.chunk_size_bytes,
                session.chunk_count,
                index,
            )
            .context("failed to determine expected upload chunk size")?;
            reader
                .read_exact(&mut buffer[..expected_size])
                .with_context(|| {
                    format!("failed reading upload chunk index={index} for key={key}")
                })?;
            let response = runtime.block_on(self.upload_session_chunk(
                &session.upload_id,
                index,
                buffer[..expected_size].to_vec(),
            ))?;
            if response.received_index != index {
                bail!(
                    "server acknowledged unexpected upload chunk index={} expected={index}",
                    response.received_index
                );
            }
        }

        let completed = runtime.block_on(self.complete_upload_session(&session.upload_id))?;
        self.clear_upload_session_affinity(&session.upload_id);
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    pub fn download_file_resumable(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        target_path: impl AsRef<Path>,
        temp_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
    ) -> Result<()> {
        let key = key.as_ref();
        let target_path = target_path.as_ref();
        let temp_path = temp_path.as_ref();
        let state_path = state_path.as_ref();
        let snapshot_owned = snapshot.map(ToString::to_string);
        let version_owned = version.map(ToString::to_string);

        let runtime = blocking_runtime()?;
        let head = runtime.block_on(self.head_object_response(
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
        ))?;

        if head.total_size_bytes == 0 {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create target directory {}", parent.display())
                })?;
            }
            fs::write(target_path, []).with_context(|| {
                format!("failed to write empty object {}", target_path.display())
            })?;
            remove_file_if_exists(temp_path)?;
            remove_file_if_exists(state_path)?;
            return Ok(());
        }

        if !head.accept_ranges {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(temp_path)
                .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
            runtime.block_on(self.download_with_range_requests(
                key,
                snapshot_owned.as_deref(),
                version_owned.as_deref(),
                &mut file,
            ))?;
            file.sync_all()
                .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;
            place_downloaded_file(temp_path, target_path)?;
            remove_file_if_exists(state_path)?;
            return Ok(());
        }

        let Some(current_etag) = head.etag.clone() else {
            bail!("server omitted ETag for resumable download key={key}");
        };

        let expected_state = ResumableDownloadFileState {
            key: key.to_string(),
            snapshot: snapshot_owned.clone(),
            version: version_owned.clone(),
            expected_size_bytes: head.total_size_bytes,
            etag: current_etag.clone(),
        };

        let should_reset = load_json_file::<ResumableDownloadFileState>(state_path)?
            .is_some_and(|persisted| persisted != expected_state);
        if should_reset {
            remove_file_if_exists(temp_path)?;
            remove_file_if_exists(state_path)?;
        }

        persist_json_file_atomic(state_path, &expected_state)?;
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create temp directory {}", parent.display()))?;
        }
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create target directory {}", parent.display())
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(temp_path)
            .with_context(|| {
                format!("failed to open temp download file {}", temp_path.display())
            })?;

        let mut offset = file
            .metadata()
            .with_context(|| format!("failed to inspect temp file {}", temp_path.display()))?
            .len();
        if offset > head.total_size_bytes {
            file.set_len(0)
                .with_context(|| format!("failed to reset temp file {}", temp_path.display()))?;
            offset = 0;
        }
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek temp file {}", temp_path.display()))?;
        if offset == 0 {
            file.set_len(0)
                .with_context(|| format!("failed to reset temp file {}", temp_path.display()))?;
            file.seek(SeekFrom::Start(0))
                .with_context(|| format!("failed to seek temp file {}", temp_path.display()))?;
        }

        while offset < head.total_size_bytes {
            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                head.total_size_bytes - 1,
            );
            let response = runtime.block_on(self.stream_object_request_to_writer(
                key,
                snapshot_owned.as_deref(),
                version_owned.as_deref(),
                Some((offset, end_inclusive)),
                Some(current_etag.as_str()),
                &mut file,
            ))?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.bytes_written != expected_len as u64 {
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.bytes_written
                        );
                    }
                    file.sync_data().with_context(|| {
                        format!(
                            "failed to persist temp download file {}",
                            temp_path.display()
                        )
                    })?;
                    offset = end_inclusive + 1;
                }
                StatusCode::OK if offset == 0 => {
                    file.sync_data().with_context(|| {
                        format!(
                            "failed to persist temp download file {}",
                            temp_path.display()
                        )
                    })?;
                    offset = response.bytes_written;
                }
                status => {
                    bail!("server rejected resumable download for key={key}: {status}");
                }
            }
        }

        file.sync_all()
            .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;
        place_downloaded_file(temp_path, target_path)?;
        remove_file_if_exists(state_path)?;
        Ok(())
    }

    pub fn download_to_writer_resumable_staged(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
        staging_root: impl AsRef<Path>,
    ) -> Result<()> {
        let key = key.as_ref();
        let snapshot_owned = snapshot.map(ToString::to_string);
        let version_owned = version.map(ToString::to_string);
        let staging_root = staging_root.as_ref();

        let (target_path, temp_path, state_path) = staged_download_paths(
            staging_root,
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
        );
        self.download_file_resumable(
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
            &target_path,
            &temp_path,
            &state_path,
        )?;
        stream_staged_download_and_cleanup(&target_path, &temp_path, &state_path, writer, key)
    }

    pub async fn load_snapshot_from_server(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let response = self.store_index(prefix, depth, snapshot).await?;
        Ok(snapshot_from_store_index_entries(response.entries))
    }

    pub fn load_snapshot_from_server_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.load_snapshot_from_server(prefix, depth, snapshot))
    }

    pub fn delete_path_blocking(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref().to_string();

        let runtime = blocking_runtime()?;
        runtime.block_on(self.delete_path(key))
    }

    pub fn rename_path_blocking(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();

        let runtime = blocking_runtime()?;
        runtime.block_on(self.rename_path(from_path, to_path, overwrite))
    }

    pub async fn put_large_aware(
        &self,
        key: impl Into<String>,
        data: Bytes,
    ) -> Result<UploadResult> {
        let key = key.into();
        let length = data.len();

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES {
            let meta = self.put(key, data).await?;
            return Ok(UploadResult {
                meta,
                upload_mode: UploadMode::Direct,
                chunk_size_bytes: None,
                chunk_count: None,
            });
        }
        let session = self
            .start_upload_session_with_chunk_refs(
                &key,
                length as u64,
                upload_session_chunk_refs_for_bytes(&data),
            )
            .await?;
        let received = session
            .received_indexes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        for (index, chunk) in data.chunks(CHUNK_UPLOAD_SIZE_BYTES).enumerate() {
            if received.contains(&index) {
                continue;
            }
            self.upload_session_chunk(&session.upload_id, index, chunk.to_vec())
                .await?;
        }
        let completed = self.complete_upload_session(&session.upload_id).await?;
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    pub fn put_large_aware_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadResult> {
        let key = key.into();

        tracing::info!("starting upload for key={key} with length={length} bytes");

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            tracing::info!("using direct upload for key={key} with length={length} bytes");

            let mut buf = Vec::with_capacity(std::cmp::min(length as usize, 8192));
            let mut limited = reader.take(length);
            std::io::Read::read_to_end(&mut limited, &mut buf)
                .with_context(|| format!("failed reading payload for key={key}"))?;

            let runtime = blocking_runtime()?;
            return runtime.block_on(async {
                let meta = self.put(key, Bytes::from(buf)).await?;
                Ok(UploadResult {
                    meta,
                    upload_mode: UploadMode::Direct,
                    chunk_size_bytes: None,
                    chunk_count: None,
                })
            });
        }

        tracing::info!("using chunked upload for key={key} with length={length} bytes");

        self.put_sized_reader_via_upload_session(key, reader, length)
    }

    pub fn get_with_selector_writer(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let key = key.as_ref();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.download_with_range_requests(key, snapshot, version, writer))
    }

    pub fn download_range_to_writer_with_progress_blocking(
        &self,
        request: DownloadRangeRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(DownloadProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<DownloadRangeResult> {
        let key_owned = request.key.to_string();
        let snapshot_owned = request.snapshot.map(ToString::to_string);
        let version_owned = request.version.map(ToString::to_string);
        let runtime = blocking_runtime()?;
        runtime.block_on(self.download_range_to_writer_with_progress(
            DownloadRangeRequest {
                key: key_owned.as_str(),
                snapshot: snapshot_owned.as_deref(),
                version: version_owned.as_deref(),
                range: request.range,
            },
            writer,
            on_progress,
            should_cancel,
        ))
    }

    pub async fn get_object_size(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<u64> {
        let key = key.as_ref();
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let response = self.head_object_response(key, snapshot, version).await?;

        Ok(response.total_size_bytes)
    }

    pub async fn head_object(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadInfo> {
        let key = key.as_ref();
        let response = self.head_object_response(key, snapshot, version).await?;
        Ok(ObjectHeadInfo {
            total_size_bytes: response.total_size_bytes,
            etag: response.etag,
            accept_ranges: response.accept_ranges,
        })
    }

    pub fn head_object_blocking(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadInfo> {
        let key = key.as_ref().to_string();
        let snapshot = snapshot.map(|value| value.to_string());
        let version = version.map(|value| value.to_string());
        let runtime = blocking_runtime()?;
        runtime.block_on(self.head_object(&key, snapshot.as_deref(), version.as_deref()))
    }

    pub fn get_object_size_blocking(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<u64> {
        let key = key.as_ref().to_string();
        let snapshot = snapshot.map(|value| value.to_string());
        let version = version.map(|value| value.to_string());

        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_object_size(&key, snapshot.as_deref(), version.as_deref()))
    }

    fn client_api_base_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("api");
            segments.push("v1");
        }

        Ok(url)
    }

    fn store_key_url(&self, key: &str) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("server URL cannot be a base"))?;
        segments.push("store");
        segments.push(key);
        drop(segments);

        Ok(url)
    }

    fn relative_url(&self, path: &str) -> Result<Url> {
        let path = path.trim();
        if path.is_empty() {
            bail!("relative request path is empty");
        }

        let normalized_path = normalize_client_api_path(path);
        let base_url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;
        base_url
            .join(normalized_path.trim_start_matches('/'))
            .with_context(|| {
                format!(
                    "failed to build request URL from {} and {}",
                    base_url, normalized_path
                )
            })
    }

    fn store_index_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("index");
        }

        Ok(url)
    }

    fn store_versions_url(&self, key: &str) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("versions");
            segments.push(key);
        }

        Ok(url)
    }

    fn store_version_restore_url(&self, key: &str, version_id: &str) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("versions");
            segments.push(key);
            segments.push("restore");
            segments.push(version_id);
        }

        Ok(url)
    }

    fn store_index_change_wait_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("index");
            segments.push("changes");
            segments.push("wait");
        }

        Ok(url)
    }

    fn store_rename_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("rename");
        }

        Ok(url)
    }

    fn store_copy_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("copy");
        }

        Ok(url)
    }

    fn store_delete_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("delete");
        }

        Ok(url)
    }

    fn store_restore_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("restore");
        }

        Ok(url)
    }

    fn store_upload_session_start_url(&self) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push("start");
        }

        Ok(url)
    }

    fn store_upload_session_url(&self, upload_id: &str) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
        }

        Ok(url)
    }

    fn store_upload_session_chunk_url(&self, upload_id: &str, index: usize) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
            segments.push("chunk");
            segments.push(&index.to_string());
        }

        Ok(url)
    }

    fn store_upload_session_complete_url(&self, upload_id: &str) -> Result<Url> {
        let mut url = self.client_api_base_url()?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
            segments.push("complete");
        }

        Ok(url)
    }
}

async fn await_download_with_cancellation<T, F>(
    future: F,
    should_cancel: &dyn Fn() -> bool,
    cancel_message: String,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    if should_cancel() {
        bail!("{cancel_message}");
    }

    tokio::select! {
        result = future => result,
        _ = wait_for_download_cancellation(should_cancel) => bail!("{cancel_message}"),
    }
}

async fn wait_for_download_cancellation(should_cancel: &dyn Fn() -> bool) {
    loop {
        if should_cancel() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn buffered_response_from_multiplex(
    response: MultiplexBufferedTransportResponse,
) -> Result<BufferedTransportResponse> {
    let status = StatusCode::from_u16(response.status)
        .with_context(|| format!("invalid multiplexed transport status {}", response.status))?;
    let mut headers = HeaderMap::new();
    for header in response.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .with_context(|| format!("invalid multiplexed header name {}", header.name))?;
        let value = HeaderValue::from_str(&header.value)
            .with_context(|| format!("invalid multiplexed header value for {}", header.name))?;
        headers.append(name, value);
    }
    Ok(BufferedTransportResponse {
        status,
        headers,
        body: Bytes::from(response.body),
    })
}

fn transport_headers_from_relay_headers(headers: &[RelayHttpHeader]) -> Vec<TransportHeader> {
    headers
        .iter()
        .map(|header| TransportHeader {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect()
}

#[derive(Debug, Clone)]
struct StreamedTransportResponseMeta {
    status: StatusCode,
    headers: HeaderMap,
    bytes_written: u64,
}

fn header_map_from_transport_headers(headers: &[TransportHeader]) -> Result<HeaderMap> {
    let mut header_map = HeaderMap::new();
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .with_context(|| format!("invalid multiplexed header name {}", header.name))?;
        let value = HeaderValue::from_str(&header.value)
            .with_context(|| format!("invalid multiplexed header value for {}", header.name))?;
        header_map.append(name, value);
    }
    Ok(header_map)
}

async fn read_streaming_transport_response_head<S>(
    stream: &mut S,
) -> Result<(StatusCode, HeaderMap)>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    let response_head = read_transport_response_head(stream)
        .await
        .context("failed reading streamed transport response head")?;
    let status = StatusCode::from_u16(response_head.status).with_context(|| {
        format!(
            "invalid multiplexed transport status {}",
            response_head.status
        )
    })?;
    let headers = header_map_from_transport_headers(&response_head.headers)?;
    Ok((status, headers))
}

fn multiplex_body_stream<S>(stream: S) -> ResponseBodyStream
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin + Send + 'static,
{
    Box::pin(futures_util::stream::try_unfold(
        (stream, vec![0_u8; TRANSPORT_STREAM_COPY_BUFFER_SIZE_BYTES]),
        |(mut stream, mut buffer)| async move {
            let bytes_read = stream.read(&mut buffer).await.map_err(|err| {
                io::Error::other(format!(
                    "failed reading streamed transport response body: {err}"
                ))
            })?;
            if bytes_read == 0 {
                Ok(None)
            } else {
                Ok(Some((
                    Bytes::copy_from_slice(&buffer[..bytes_read]),
                    (stream, buffer),
                )))
            }
        },
    ))
}

async fn read_streaming_transport_response<S>(mut stream: S) -> Result<StreamedRelativePathResponse>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin + Send + 'static,
{
    let (status, headers) = read_streaming_transport_response_head(&mut stream).await?;
    Ok(StreamedRelativePathResponse {
        status,
        headers,
        body: multiplex_body_stream(stream),
    })
}

fn transport_stream_kind_for_path(path: &str) -> TransportStreamKind {
    let path = strip_client_api_v1_prefix(path);
    if path == "/health" || path.starts_with("/diagnostics/") {
        TransportStreamKind::Diagnostics
    } else {
        TransportStreamKind::Rpc
    }
}

async fn execute_multiplex_streaming_read_request(
    session: &transport_sdk::MultiplexedSession,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
) -> Result<StreamedRelativePathResponse> {
    let request_path = path_and_query(url);
    let mut stream = session
        .open_stream()
        .await
        .context("failed opening streamed object-read transport stream")?;
    write_transport_request_head(
        &mut stream,
        &TransportRequestHead {
            request_id: Uuid::now_v7().to_string(),
            kind: TransportStreamKind::ObjectRead,
            method: method.as_str().to_string(),
            path: request_path,
            headers: transport_headers_from_relay_headers(headers),
            end_of_stream: true,
        },
    )
    .await
    .context("failed writing streamed object-read request head")?;
    stream
        .close()
        .await
        .context("failed closing streamed object-read request body")?;
    read_streaming_transport_response(stream).await
}

async fn execute_multiplex_streaming_object_write_request(
    session: &transport_sdk::MultiplexedSession,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
    response_head_timeout: Option<Duration>,
) -> Result<BufferedTransportResponse> {
    let request_path = path_and_query(url);
    let mut stream = session
        .open_stream()
        .await
        .context("failed opening streamed object-write transport stream")?;
    write_transport_request_head(
        &mut stream,
        &TransportRequestHead {
            request_id: Uuid::now_v7().to_string(),
            kind: TransportStreamKind::ObjectWrite,
            method: method.as_str().to_string(),
            path: request_path,
            headers: transport_headers_from_relay_headers(headers),
            end_of_stream: body.is_empty(),
        },
    )
    .await
    .context("failed writing streamed object-write request head")?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .context("failed writing streamed object-write request body")?;
    }
    stream
        .close()
        .await
        .context("failed closing streamed object-write request body")?;
    read_direct_multiplex_buffered_response(&mut stream, method, url, response_head_timeout)
        .await
        .context("failed reading streamed object-write response")
}

async fn execute_multiplex_streaming_write_request(
    session: &transport_sdk::MultiplexedSession,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    mut body_stream: RequestBodyStream,
) -> Result<BufferedTransportResponse> {
    let request_path = path_and_query(url);
    let mut stream = session
        .open_stream()
        .await
        .context("failed opening streamed transport request stream")?;
    write_transport_request_head(
        &mut stream,
        &TransportRequestHead {
            request_id: Uuid::now_v7().to_string(),
            kind: TransportStreamKind::ObjectWrite,
            method: method.as_str().to_string(),
            path: request_path,
            headers: transport_headers_from_relay_headers(headers),
            end_of_stream: false,
        },
    )
    .await
    .context("failed writing streamed transport request head")?;
    while let Some(chunk) = body_stream.next().await {
        let chunk = chunk.context("failed reading streamed request body chunk")?;
        if !chunk.is_empty() {
            stream
                .write_all(chunk.as_ref())
                .await
                .context("failed writing streamed transport request body chunk")?;
        }
    }
    stream
        .close()
        .await
        .context("failed closing streamed transport request body")?;
    let response = read_buffered_transport_response(&mut stream)
        .await
        .context("failed reading streamed transport response")?;
    buffered_response_from_multiplex(response)
}

async fn execute_direct_http_streaming_read_request(
    http: &HttpClient,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
) -> Result<StreamedRelativePathResponse> {
    let mut request = http.request(method.clone(), url.clone());
    for header in headers {
        request = request.header(header.name.as_str(), header.value.as_str());
    }
    let response = request
        .send()
        .await
        .with_context(|| format!("failed to execute streaming {} {}", method, url))?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let url_for_errors = url.clone();
    let body = Box::pin(futures_util::stream::try_unfold(
        response,
        move |mut response| {
            let url_for_errors = url_for_errors.clone();
            async move {
                let chunk = response.chunk().await.map_err(|err| {
                    io::Error::other(format!(
                        "failed reading streaming response chunk for {}: {err}",
                        url_for_errors
                    ))
                })?;
                Ok(chunk.map(|chunk| (chunk, response)))
            }
        },
    ));
    Ok(StreamedRelativePathResponse {
        status,
        headers: response_headers,
        body,
    })
}

#[derive(Clone, Copy)]
struct DirectMultiplexSessionContext<'a> {
    transport_locator: &'a str,
    session_pool: &'a TransportSessionPool,
    identity: &'a ClientIdentityMaterial,
    connection_name: Option<&'a str>,
}

#[derive(Debug)]
struct DirectMultiplexRequestTimeout {
    method: String,
    url: String,
    timeout: Duration,
}

impl std::fmt::Display for DirectMultiplexRequestTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "direct multiplex {} {} timed out after {:?}",
            self.method, self.url, self.timeout
        )
    }
}

impl std::error::Error for DirectMultiplexRequestTimeout {}

fn is_direct_multiplex_request_timeout(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<DirectMultiplexRequestTimeout>()
            .is_some()
    })
}

async fn read_direct_multiplex_buffered_response<T>(
    reader: &mut T,
    method: &Method,
    url: &Url,
    response_head_timeout: Option<Duration>,
) -> Result<BufferedTransportResponse>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let response_head = match response_head_timeout {
        Some(timeout) => tokio::time::timeout(timeout, read_transport_response_head(reader))
            .await
            .map_err(|_| DirectMultiplexRequestTimeout {
                method: method.to_string(),
                url: url.to_string(),
                timeout,
            })?,
        None => read_transport_response_head(reader).await,
    }
    .context("failed reading direct multiplex response head")?;

    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .await
        .context("failed reading direct multiplex response body")?;
    buffered_response_from_multiplex(MultiplexBufferedTransportResponse {
        request_id: response_head.request_id,
        status: response_head.status,
        headers: response_head.headers,
        body,
    })
}

async fn execute_direct_multiplex_streaming_read_request(
    transport_locator: &str,
    session_pool: &TransportSessionPool,
    identity: &ClientIdentityMaterial,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
) -> Result<StreamedRelativePathResponse> {
    for attempt in 0..2 {
        let session = session_pool
            .ensure_direct_session(identity, connection_name)
            .await
            .context("failed ensuring direct multiplex session")?;
        let result =
            execute_multiplex_streaming_read_request(session.as_ref(), method, url, headers).await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    transport_locator,
                    "retrying streamed direct object read after resetting cached session"
                );
            }
            Err(err) => {
                session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "streamed direct object read retried without producing a response for {}",
        transport_locator
    )
}

async fn execute_relay_multiplex_streaming_read_request(
    relay: &ClientRelayTransport,
    source: PeerIdentity,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
) -> Result<StreamedRelativePathResponse> {
    for attempt in 0..2 {
        let session = relay
            .session_pool
            .ensure_relay_session(source.clone(), connection_name)
            .await
            .with_context(|| {
                format!(
                    "failed ensuring multiplex relay session for target node {}",
                    relay.target_node_id
                )
            })?;
        let result =
            execute_multiplex_streaming_read_request(session.as_ref(), method, url, headers).await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                relay.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    target_node_id = %relay.target_node_id,
                    "retrying streamed relay object read after resetting cached session"
                );
            }
            Err(err) => {
                relay.session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "streamed relay object read retried without producing a response for target node {}",
        relay.target_node_id
    )
}

async fn execute_direct_multiplex_streaming_object_write_request(
    direct: DirectMultiplexSessionContext<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
    response_head_timeout: Option<Duration>,
) -> Result<BufferedTransportResponse> {
    for attempt in 0..2 {
        let session = direct
            .session_pool
            .ensure_direct_session(direct.identity, direct.connection_name)
            .await
            .context("failed ensuring direct multiplex session")?;
        let result = execute_multiplex_streaming_object_write_request(
            session.as_ref(),
            method,
            url,
            headers,
            body,
            response_head_timeout,
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 && !is_direct_multiplex_request_timeout(&err) => {
                direct.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    transport_locator = direct.transport_locator,
                    "retrying streamed direct object write after resetting cached session"
                );
            }
            Err(err) => {
                direct.session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "streamed direct object write retried without producing a response for {}",
        direct.transport_locator
    )
}

async fn execute_relay_multiplex_streaming_object_write_request(
    relay: &ClientRelayTransport,
    source: PeerIdentity,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    for attempt in 0..2 {
        let session = relay
            .session_pool
            .ensure_relay_session(source.clone(), connection_name)
            .await
            .with_context(|| {
                format!(
                    "failed ensuring multiplex relay session for target node {}",
                    relay.target_node_id
                )
            })?;
        let result = execute_multiplex_streaming_object_write_request(
            session.as_ref(),
            method,
            url,
            headers,
            body,
            None,
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                relay.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    target_node_id = %relay.target_node_id,
                    "retrying streamed relay object write after resetting cached session"
                );
            }
            Err(err) => {
                relay.session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "streamed relay object write retried without producing a response for target node {}",
        relay.target_node_id
    )
}

async fn execute_direct_multiplex_streaming_write_request(
    direct: DirectMultiplexSessionContext<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body_stream: RequestBodyStream,
) -> Result<BufferedTransportResponse> {
    let session = direct
        .session_pool
        .ensure_direct_session(direct.identity, direct.connection_name)
        .await
        .context("failed ensuring direct multiplex session")?;
    execute_multiplex_streaming_write_request(session.as_ref(), method, url, headers, body_stream)
        .await
}

async fn execute_relay_multiplex_streaming_write_request(
    relay: &ClientRelayTransport,
    source: PeerIdentity,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body_stream: RequestBodyStream,
) -> Result<BufferedTransportResponse> {
    let session = relay
        .session_pool
        .ensure_relay_session(source, connection_name)
        .await
        .with_context(|| {
            format!(
                "failed ensuring streamed relay session for target node {}",
                relay.target_node_id
            )
        })?;
    execute_multiplex_streaming_write_request(session.as_ref(), method, url, headers, body_stream)
        .await
}

async fn execute_direct_multiplex_buffered_request(
    direct: DirectMultiplexSessionContext<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
    response_head_timeout: Option<Duration>,
) -> Result<BufferedTransportResponse> {
    let request_path = path_and_query(url);
    let request_headers = transport_headers_from_relay_headers(headers);

    for attempt in 0..2 {
        let session = direct
            .session_pool
            .ensure_direct_session(direct.identity, direct.connection_name)
            .await
            .context("failed ensuring direct multiplex session")?;
        let request = BufferedTransportRequest::new(
            transport_stream_kind_for_path(&request_path),
            method.as_str(),
            request_path.clone(),
            request_headers.clone(),
            body.to_vec(),
        );

        let result = async {
            let mut stream = session
                .open_stream()
                .await
                .context("failed opening direct multiplex request stream")?;
            write_buffered_transport_request(&mut stream, &request)
                .await
                .context("failed writing direct multiplex request")?;
            read_direct_multiplex_buffered_response(&mut stream, method, url, response_head_timeout)
                .await
        }
        .await;

        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 && !is_direct_multiplex_request_timeout(&err) => {
                direct.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    transport_locator = direct.transport_locator,
                    "retrying direct multiplex request after resetting cached session"
                );
            }
            Err(err) => {
                direct.session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "direct multiplex request retried without producing a response for {}",
        direct.transport_locator
    )
}

async fn execute_relay_multiplex_buffered_request(
    relay: &ClientRelayTransport,
    source: PeerIdentity,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    let request_path = path_and_query(url);
    let request_headers = transport_headers_from_relay_headers(headers);

    for attempt in 0..2 {
        let session = relay
            .session_pool
            .ensure_relay_session(source.clone(), connection_name)
            .await
            .with_context(|| {
                format!(
                    "failed ensuring multiplex relay session for target node {}",
                    relay.target_node_id
                )
            })?;
        let request = BufferedTransportRequest::new(
            transport_stream_kind_for_path(&request_path),
            method.as_str(),
            request_path.clone(),
            request_headers.clone(),
            body.to_vec(),
        );

        let result = async {
            let mut stream = session
                .open_stream()
                .await
                .context("failed opening multiplex relay request stream")?;
            write_buffered_transport_request(&mut stream, &request)
                .await
                .context("failed writing multiplex relay request")?;
            let response = read_buffered_transport_response(&mut stream)
                .await
                .context("failed reading multiplex relay response")?;
            buffered_response_from_multiplex(response)
        }
        .await;

        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                relay.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    target_node_id = %relay.target_node_id,
                    "retrying multiplex relay request after resetting cached session"
                );
            }
            Err(err) => {
                relay.session_pool.invalidate().await;
                return Err(err);
            }
        }
    }

    bail!(
        "multiplex relay request retried without producing a response for target node {}",
        relay.target_node_id
    )
}

fn json_content_type_header() -> RelayHttpHeader {
    RelayHttpHeader {
        name: "content-type".to_string(),
        value: "application/json".to_string(),
    }
}

fn range_header(start: u64, end_inclusive: u64) -> RelayHttpHeader {
    RelayHttpHeader {
        name: RANGE.as_str().to_string(),
        value: format!("bytes={start}-{end_inclusive}"),
    }
}

fn simple_header(name: HeaderName, value: &str) -> Result<RelayHttpHeader> {
    let header_value =
        HeaderValue::from_str(value).with_context(|| format!("invalid header value for {name}"))?;
    Ok(RelayHttpHeader {
        name: name.as_str().to_string(),
        value: header_value
            .to_str()
            .context("header value must be valid utf-8")?
            .to_string(),
    })
}

fn expected_chunk_size(
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    index: usize,
) -> Option<usize> {
    if index >= chunk_count {
        return None;
    }
    if total_size_bytes == 0 {
        return Some(0);
    }
    if index + 1 == chunk_count {
        let remainder = total_size_bytes as usize % chunk_size_bytes;
        return Some(if remainder == 0 {
            chunk_size_bytes
        } else {
            remainder
        });
    }
    Some(chunk_size_bytes)
}

fn upload_session_chunk_refs_for_bytes(data: &[u8]) -> Vec<UploadSessionChunkRef> {
    data.chunks(CHUNK_UPLOAD_SIZE_BYTES)
        .map(|chunk| UploadSessionChunkRef {
            hash: hash_hex(chunk),
            size_bytes: chunk.len(),
        })
        .collect()
}

fn upload_session_chunk_refs_for_file(
    source_path: &Path,
    total_size_bytes: u64,
) -> Result<Vec<UploadSessionChunkRef>> {
    if total_size_bytes == 0 {
        return Ok(Vec::new());
    }

    let mut file = File::open(source_path)
        .with_context(|| format!("failed to open upload source {}", source_path.display()))?;
    let mut remaining = total_size_bytes;
    let mut buffer = vec![0_u8; CHUNK_UPLOAD_SIZE_BYTES];
    let mut chunk_refs = Vec::new();

    while remaining > 0 {
        let next_chunk_size = remaining.min(CHUNK_UPLOAD_SIZE_BYTES as u64) as usize;
        file.read_exact(&mut buffer[..next_chunk_size])
            .with_context(|| {
                format!(
                    "failed to hash upload chunk from source {}",
                    source_path.display()
                )
            })?;
        chunk_refs.push(UploadSessionChunkRef {
            hash: hash_hex(&buffer[..next_chunk_size]),
            size_bytes: next_chunk_size,
        });
        remaining -= next_chunk_size as u64;
    }

    Ok(chunk_refs)
}

fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn upload_result_from_session_complete(
    key: &str,
    session: &UploadSessionView,
    completed: &UploadSessionCompleteResponse,
) -> UploadResult {
    let _ = (
        &completed.snapshot_id,
        &completed.version_id,
        &completed.manifest_hash,
        &completed.state,
        completed.new_chunks,
        completed.dedup_reused_chunks,
        completed.created_new_version,
    );
    UploadResult {
        meta: StorageObjectMeta {
            key: key.to_string(),
            size_bytes: completed.total_size_bytes as usize,
        },
        upload_mode: UploadMode::Chunked,
        chunk_size_bytes: Some(session.chunk_size_bytes),
        chunk_count: Some(session.chunk_count),
    }
}

fn maybe_abort_after_resumable_upload_state_persist(key: &str, state_path: &Path) {
    if !cfg!(debug_assertions) {
        return;
    }

    let crash_key = std::env::var("IRONMESH_TEST_CRASH_AFTER_UPLOAD_STATE_KEY").ok();
    if crash_key.as_deref() == Some(key) && state_path.is_file() {
        std::process::abort();
    }
}

fn upload_session_status_from_view(view: UploadSessionView) -> UploadSessionStatus {
    UploadSessionStatus {
        upload_id: view.upload_id,
        key: view.key,
        total_size_bytes: view.total_size_bytes,
        chunk_size_bytes: view.chunk_size_bytes,
        chunk_count: view.chunk_count,
        received_indexes: view.received_indexes,
        completed: view.completed,
    }
}

fn upload_session_complete_info_from_response(
    response: UploadSessionCompleteResponse,
) -> UploadSessionCompleteInfo {
    UploadSessionCompleteInfo {
        snapshot_id: response.snapshot_id,
        version_id: response.version_id,
        manifest_hash: response.manifest_hash,
        state: response.state,
        new_chunks: response.new_chunks,
        dedup_reused_chunks: response.dedup_reused_chunks,
        created_new_version: response.created_new_version,
        total_size_bytes: response.total_size_bytes,
    }
}

fn staged_download_paths(
    staging_root: &Path,
    key: &str,
    snapshot: Option<&str>,
    version: Option<&str>,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let stem = staged_download_stem(key, snapshot, version);
    (
        staging_root.join(format!("{stem}.bin")),
        staging_root.join(format!("{stem}.part")),
        staging_root.join(format!("{stem}.json")),
    )
}

fn staged_download_stem(key: &str, snapshot: Option<&str>, version: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(&[0]);
    hasher.update(snapshot.unwrap_or_default().as_bytes());
    hasher.update(&[0]);
    hasher.update(version.unwrap_or_default().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn stream_staged_download_and_cleanup(
    target_path: &Path,
    temp_path: &Path,
    state_path: &Path,
    writer: &mut dyn Write,
    key: &str,
) -> Result<()> {
    let stream_result = (|| -> Result<()> {
        let mut file = File::open(target_path)
            .with_context(|| format!("failed to open staged download {}", target_path.display()))?;
        let mut buffer = vec![0_u8; STAGED_DOWNLOAD_COPY_BUFFER_SIZE_BYTES];
        loop {
            let read = file.read(&mut buffer).with_context(|| {
                format!("failed to read staged download {}", target_path.display())
            })?;
            if read == 0 {
                break;
            }
            writer
                .write_all(&buffer[..read])
                .with_context(|| format!("failed to write staged download output for key={key}"))?;
        }
        writer
            .flush()
            .with_context(|| format!("failed to flush staged download output for key={key}"))?;
        Ok(())
    })();

    if stream_result.is_ok() {
        remove_file_if_exists(target_path)?;
        remove_file_if_exists(temp_path)?;
        remove_file_if_exists(state_path)?;
    }

    stream_result
}

fn load_json_file<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(payload) => serde_json::from_slice(&payload)
            .with_context(|| format!("failed to parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn persist_json_file_atomic<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, payload)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to place transfer state {} into {}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn place_downloaded_file(temp_path: &Path, target_path: &Path) -> Result<()> {
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create download target directory {}",
                parent.display()
            )
        })?;
    }
    match fs::remove_file(target_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to replace {}", target_path.display()));
        }
    }
    fs::rename(temp_path, target_path).with_context(|| {
        format!(
            "failed to place downloaded file {} into {}",
            temp_path.display(),
            target_path.display()
        )
    })
}

fn file_modified_unix_ms(metadata: &fs::Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis())
        .unwrap_or(0)
}

pub fn normalize_server_base_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("server base URL is empty"));
    }

    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let mut normalized =
        Url::parse(&with_scheme).with_context(|| format!("invalid server base URL: {input}"))?;
    if !normalized.path().ends_with('/') {
        let path = format!("{}/", normalized.path());
        normalized.set_path(&path);
    }

    Ok(normalized)
}

fn ensure_missing_folder_markers(entries: &mut Vec<StoreIndexEntry>) {
    let mut existing = BTreeSet::new();
    for entry in entries.iter() {
        existing.insert(entry.path.clone());
    }

    let mut to_add = BTreeSet::new();
    for entry in entries.iter() {
        let path = entry.path.trim_end_matches('/');
        if path.is_empty() {
            continue;
        }

        let segments: Vec<&str> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.len() < 2 {
            continue;
        }

        for index in 1..segments.len() {
            let marker = format!("{}/", segments[..index].join("/"));
            if !existing.contains(&marker) {
                to_add.insert(marker);
            }
        }
    }

    for marker in to_add {
        if existing.insert(marker.clone()) {
            entries.push(StoreIndexEntry {
                path: marker,
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            });
        }
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
}

fn append_optional_query(url: &mut Url, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair(key, value);
    }
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn normalize_client_api_path(path: &str) -> Cow<'_, str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Cow::Borrowed(trimmed);
    }

    if trimmed == CLIENT_API_V1_PREFIX || trimmed.starts_with(&format!("{CLIENT_API_V1_PREFIX}/")) {
        return Cow::Borrowed(trimmed);
    }

    let path_with_slash = if trimmed.starts_with('/') {
        trimmed
    } else {
        return Cow::Owned(format!("{CLIENT_API_V1_PREFIX}/{trimmed}"));
    };

    let path_only = path_with_slash
        .split_once('?')
        .map(|(value, _)| value)
        .unwrap_or(path_with_slash);

    if path_only == "/health"
        || path_only.starts_with("/diagnostics/")
        || path_only.starts_with("/transport/")
        || path_only.starts_with("/snapshots")
        || path_only.starts_with("/store/")
        || path_only.starts_with("/versions/")
        || path_only.starts_with("/cluster/")
        || path_only.starts_with("/auth/")
        || path_only.starts_with("/storage/")
        || path_only.starts_with("/media/")
        || path_only.starts_with("/maintenance/")
    {
        Cow::Owned(format!("{CLIENT_API_V1_PREFIX}{path_with_slash}"))
    } else {
        Cow::Borrowed(path_with_slash)
    }
}

fn strip_client_api_v1_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix(CLIENT_API_V1_PREFIX)
        && !rest.is_empty()
        && (rest.starts_with('/') || rest.starts_with('?'))
    {
        rest
    } else {
        path
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn snapshot_from_store_index_entries(entries: Vec<StoreIndexEntry>) -> SyncSnapshot {
    let mut remote = Vec::with_capacity(entries.len());

    for entry in entries {
        if (entry.entry_type == "prefix") || entry.path.ends_with('/') {
            let directory_path = entry.path.trim_end_matches('/').to_string();
            if !directory_path.is_empty() {
                remote.push(NamespaceEntry::directory(directory_path));
            }
            continue;
        }

        let version = entry.version.unwrap_or_else(|| "server-head".to_string());
        let content_hash = entry
            .content_hash
            .unwrap_or_else(|| format!("server-head:{}", entry.path));
        let mut remote_entry =
            NamespaceEntry::file_sized(entry.path.clone(), version, content_hash, entry.size_bytes);
        remote_entry.content_fingerprint = entry.content_fingerprint;
        remote.push(remote_entry);
    }

    SyncSnapshot {
        local: Vec::new(),
        remote,
    }
}

#[cfg(test)]
#[path = "ironmesh_client/tests.rs"]
mod tests;
