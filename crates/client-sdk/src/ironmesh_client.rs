use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use common::{NodeId, StorageObjectMeta};
use futures_util::io::{
    AsyncReadExt as FuturesAsyncReadExt, AsyncWriteExt as FuturesAsyncWriteExt,
};
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
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_core::{NamespaceEntry, SyncSnapshot};
use transport_sdk::{
    BufferedTransportRequest, BufferedTransportResponse as MultiplexBufferedTransportResponse,
    ClientIdentityMaterial, PeerIdentity, RelayHttpHeader, RendezvousControlClient,
    TransportHeader, TransportRequestHead, TransportStreamKind, build_signed_request_headers,
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
}

#[derive(Clone)]
enum ClientRequestAuth {
    None,
    SignedIdentity(ClientIdentityMaterial),
}

#[derive(Clone)]
enum ClientTransport {
    Direct {
        http: HttpClient,
        server_base_url: String,
        session_pool: TransportSessionPool,
    },
    Relay(ClientRelayTransport),
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

#[derive(Clone)]
struct ClientEndpoint {
    descriptor: ClientEndpointDescriptor,
    transport: ClientTransport,
    state: Arc<std::sync::Mutex<ClientEndpointState>>,
}

#[derive(Debug, Clone)]
struct ClientEndpointDescriptor {
    path_kind: ClientEndpointPathKind,
    locator: String,
    bootstrap_rank: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientEndpointPathKind {
    Direct,
    Relay,
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
}

#[derive(Debug)]
struct BufferedTransportResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl ClientTransport {
    fn path_kind(&self) -> ClientEndpointPathKind {
        match self {
            Self::Direct { .. } => ClientEndpointPathKind::Direct,
            Self::Relay(_) => ClientEndpointPathKind::Relay,
        }
    }

    fn request_base_url(&self) -> &str {
        match self {
            Self::Direct {
                server_base_url, ..
            } => server_base_url.as_str(),
            Self::Relay(relay) => relay.request_base_url.as_str(),
        }
    }

    fn endpoint_locator(&self) -> String {
        match self {
            Self::Direct {
                server_base_url, ..
            } => server_base_url.clone(),
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
            Self::Direct {
                server_base_url, ..
            } => Some(server_base_url.as_str()),
            Self::Relay(_) => None,
        }
    }

    fn relay_target_node_id(&self) -> Option<NodeId> {
        match self {
            Self::Direct { .. } => None,
            Self::Relay(relay) => Some(relay.target_node_id),
        }
    }

    fn rendezvous_client(&self) -> Option<RendezvousControlClient> {
        match self {
            Self::Direct { .. } => None,
            Self::Relay(relay) => Some(relay.rendezvous.clone()),
        }
    }

    fn session_pool_snapshot(&self) -> TransportSessionPoolSnapshot {
        match self {
            Self::Direct { session_pool, .. } => session_pool.snapshot(),
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

    fn record_success(&self, index: usize, latency_ms: f64, bytes_transferred: usize) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_success_sample(&mut state, latency_ms, bytes_transferred, false);
        drop(state);
        self.set_active_index(index);
    }

    fn record_failure(&self, index: usize, error: &str) {
        let Some(endpoint) = self.endpoints.get(index) else {
            return;
        };
        let mut state = lock_endpoint_state(&endpoint.state);
        record_endpoint_failure_sample(&mut state, error, false);
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

async fn execute_buffered_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    match transport {
        ClientTransport::Direct {
            http,
            server_base_url,
            session_pool,
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                let direct = DirectMultiplexSessionContext {
                    server_base_url,
                    session_pool,
                    identity,
                    connection_name,
                };
                return execute_direct_multiplex_buffered_request(
                    direct, method, url, headers, body,
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
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_buffered_request(
                relay,
                source,
                connection_name,
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

async fn execute_streaming_object_read_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
    match transport {
        ClientTransport::Direct {
            http,
            server_base_url,
            session_pool,
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                return execute_direct_multiplex_streaming_object_read_request(
                    server_base_url,
                    session_pool,
                    identity,
                    connection_name,
                    url,
                    headers,
                    writer,
                )
                .await
                .with_context(|| format!("failed to execute streamed GET {}", url));
            }

            execute_direct_http_streaming_object_read_request(http, url, headers, writer).await
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_streaming_object_read_request(
                relay,
                source,
                connection_name,
                url,
                headers,
                writer,
            )
            .await
            .with_context(|| format!("failed to relay streamed GET {}", url))
        }
    }
}

async fn execute_streaming_object_write_request_for_transport(
    transport: &ClientTransport,
    auth: &ClientRequestAuth,
    connection_name: Option<&str>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<BufferedTransportResponse> {
    match transport {
        ClientTransport::Direct {
            server_base_url,
            session_pool,
            ..
        } => {
            if let ClientRequestAuth::SignedIdentity(identity) = auth {
                let direct = DirectMultiplexSessionContext {
                    server_base_url,
                    session_pool,
                    identity,
                    connection_name,
                };
                return execute_direct_multiplex_streaming_object_write_request(
                    direct, method, url, headers, body,
                )
                .await
                .with_context(|| format!("failed to execute streamed {} {}", method, url));
            }

            execute_buffered_request_for_transport(
                transport,
                auth,
                connection_name,
                method,
                url,
                headers,
                body,
            )
            .await
        }
        ClientTransport::Relay(relay) => {
            let source = relay_source_identity_for_auth(auth)?;
            execute_relay_multiplex_streaming_object_write_request(
                relay,
                source,
                connection_name,
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
    let response = execute_buffered_request_for_transport(
        &endpoint.transport,
        auth,
        connection_name,
        &method,
        &url,
        &headers,
        &[],
    )
    .await?;
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

#[derive(Debug, Serialize)]
struct UploadSessionStartRequest {
    key: String,
    total_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
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
}

#[derive(Debug, Serialize)]
struct SnapshotRestoreRequest {
    snapshot: String,
    from_path: String,
    to_path: String,
    recursive: bool,
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
        let server_base_url = server_base_url.into().trim_end_matches('/').to_string();
        Self {
            transport_router: ClientEndpointRouter::new(vec![ClientEndpoint::new(
                ClientTransport::Direct {
                    http,
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
        }
    }

    pub fn with_relay_transport(
        request_base_url: impl Into<String>,
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
    ) -> Self {
        let request_base_url = request_base_url.into().trim_end_matches('/').to_string();
        let session_pool = TransportSessionPool::new_relay(rendezvous.clone(), target_node_id);
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

            let transport = client
                .transport_router
                .endpoints
                .first()
                .map(|endpoint| endpoint.transport.clone())
                .ok_or_else(|| anyhow!("cannot combine an empty client transport router"))?;
            endpoints.push(ClientEndpoint::new(transport, bootstrap_rank));
        }

        Ok(Self {
            transport_router: ClientEndpointRouter::new(endpoints),
            auth: combined_auth.unwrap_or(ClientRequestAuth::None),
            connection_name: None,
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

    async fn execute_buffered_request(
        &self,
        method: Method,
        url: Url,
        mut headers: Vec<RelayHttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<BufferedTransportResponse> {
        self.maybe_spawn_background_quality_refresh();

        let mut auth_headers = self.request_auth_headers(&method, &url)?;
        auth_headers.append(&mut headers);

        let mut last_error = None;
        for index in self.transport_router.rank_indices() {
            let Some(endpoint) = self.transport_router.endpoint(index).cloned() else {
                continue;
            };
            let endpoint_url = endpoint
                .rewrite_url(&url)
                .with_context(|| format!("failed to rewrite {} {}", method, url));
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
            match execute_buffered_request_for_transport(
                &endpoint.transport,
                &self.auth,
                self.connection_name.as_deref(),
                &method,
                &endpoint_url,
                &auth_headers,
                body.as_deref().unwrap_or_default(),
            )
            .await
            {
                Ok(response) if is_retryable_transport_status(response.status) => {
                    self.transport_router.record_failure(
                        index,
                        &format!(
                            "retryable HTTP {} from {}",
                            response.status, endpoint.descriptor.locator
                        ),
                    );
                    last_error = Some(anyhow!(
                        "retryable transport response {} from {}",
                        response.status,
                        endpoint.descriptor.locator
                    ));
                }
                Ok(response) => {
                    self.transport_router.record_success(
                        index,
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        response.body.len(),
                    );
                    return Ok(response);
                }
                Err(error) => {
                    self.transport_router
                        .record_failure(index, &error.to_string());
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

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let url = self.store_key_url(&key)?;

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

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to GET object key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {}",
                response.status
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
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_rename_url()?;
        let payload = serde_json::to_vec(&PathMutationRequest {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            overwrite,
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
        let key = key.as_ref();
        let mut url = self.store_delete_url()?;
        url.query_pairs_mut().append_pair("key", key);
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
        self.store_index_with_view(prefix, depth, snapshot, None)
            .await
    }

    pub async fn store_index_with_view(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        let mut url = self.store_index_url()?;
        url.query_pairs_mut()
            .append_pair("depth", &depth.max(1).to_string());
        append_optional_query(&mut url, "prefix", prefix);
        append_optional_query(&mut url, "snapshot", snapshot);
        if let Some(view) = view {
            url.query_pairs_mut()
                .append_pair("view", view.as_query_value());
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

        if let Ok(ref mut response) = result {
            ensure_missing_folder_markers(&mut response.entries);
            response.entry_count = response.entries.len();
        }

        result
    }

    pub fn store_index_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_view_blocking(prefix, depth, snapshot, None)
    }

    pub fn store_index_with_view_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.store_index_with_view(prefix, depth, snapshot, view))
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

    async fn start_upload_session(
        &self,
        key: &str,
        total_size_bytes: u64,
    ) -> Result<UploadSessionView> {
        let url = self.store_upload_session_start_url()?;
        let payload = serde_json::to_vec(&UploadSessionStartRequest {
            key: key.to_string(),
            total_size_bytes,
            state: None,
            parent: Vec::new(),
            version_id: None,
        })
        .context("failed to encode upload session start payload")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to start upload session for key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "server rejected upload session start for key={key}: {}",
                response.status
            );
        }

        serde_json::from_slice::<UploadSessionView>(&response.body)
            .with_context(|| format!("failed to parse upload session start response for {key}"))
    }

    pub async fn begin_upload_session(
        &self,
        key: impl AsRef<str>,
        total_size_bytes: u64,
    ) -> Result<UploadSessionStatus> {
        let view = self
            .start_upload_session(key.as_ref(), total_size_bytes)
            .await?;
        Ok(upload_session_status_from_view(view))
    }

    async fn get_upload_session(&self, upload_id: &str) -> Result<Option<UploadSessionView>> {
        let url = self.store_upload_session_url(upload_id)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to query upload session {upload_id}"))?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<UploadSessionView>(&response.body)
                .with_context(|| format!("failed to parse upload session {upload_id}"))
                .map(Some),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => Ok(None),
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
        self.maybe_spawn_background_quality_refresh();

        let url = self.store_upload_session_chunk_url(upload_id, index)?;
        let response = if matches!(self.auth, ClientRequestAuth::None) {
            self.execute_buffered_request(Method::PUT, url.clone(), Vec::new(), Some(payload))
                .await
                .with_context(|| {
                    format!("failed to upload chunk {index} for session={upload_id}")
                })?
        } else {
            let auth_headers = self.request_auth_headers(&Method::PUT, &url)?;
            let mut last_error = None;
            let mut response = None;
            for route_index in self.transport_router.rank_indices() {
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
                match execute_streaming_object_write_request_for_transport(
                    &endpoint.transport,
                    &self.auth,
                    self.connection_name.as_deref(),
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
                        self.transport_router.record_failure(
                            route_index,
                            &format!(
                                "retryable HTTP {} from {}",
                                candidate_response.status, endpoint.descriptor.locator
                            ),
                        );
                        last_error = Some(anyhow!(
                            "retryable transport response {} from {}",
                            candidate_response.status,
                            endpoint.descriptor.locator
                        ));
                    }
                    Ok(candidate_response) => {
                        self.transport_router.record_success(
                            route_index,
                            started_at.elapsed().as_secs_f64() * 1000.0,
                            candidate_response.body.len(),
                        );
                        response = Some(candidate_response);
                        break;
                    }
                    Err(error) => {
                        self.transport_router
                            .record_failure(route_index, &error.to_string());
                        last_error = Some(error);
                    }
                }
            }

            response.ok_or_else(|| {
                last_error.unwrap_or_else(|| {
                    anyhow!(
                        "no client transport endpoints accepted streamed upload for session={} index={}",
                        upload_id,
                        index
                    )
                })
            })?
        };
        if !response.status.is_success() {
            bail!(
                "upload session chunk rejected for session={upload_id} index={index}: {}",
                response.status
            );
        }

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
        let response = self
            .execute_buffered_request(Method::POST, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to complete upload session {upload_id}"))?;

        if !response.status.is_success() {
            bail!(
                "upload session completion rejected for session={upload_id}: {}",
                response.status
            );
        }

        serde_json::from_slice::<UploadSessionCompleteResponse>(&response.body).with_context(|| {
            format!("failed to parse upload session completion response for {upload_id}")
        })
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

        let response = self
            .execute_buffered_request(Method::HEAD, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to HEAD object key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {}",
                response.status
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
                    self.transport_router.record_success(
                        index,
                        started_at.elapsed().as_secs_f64() * 1000.0,
                        candidate_response.bytes_written as usize,
                    );
                    response = Some(candidate_response);
                    break;
                }
                Err(error) => {
                    self.transport_router
                        .record_failure(index, &error.to_string());
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
            Some(state) => match runtime.block_on(self.get_upload_session(&state.upload_id))? {
                Some(session)
                    if session.key == key && session.total_size_bytes == source_size_bytes =>
                {
                    session
                }
                _ => {
                    remove_file_if_exists(state_path)?;
                    runtime.block_on(self.start_upload_session(&key, source_size_bytes))?
                }
            },
            None => runtime.block_on(self.start_upload_session(&key, source_size_bytes))?,
        };

        persist_json_file_atomic(
            state_path,
            &ResumableUploadFileState {
                upload_id: session.upload_id.clone(),
                key: key.clone(),
                source_size_bytes,
                source_modified_unix_ms,
                chunk_size_bytes: session.chunk_size_bytes,
            },
        )?;
        maybe_abort_after_resumable_upload_state_persist(&key, state_path);

        if session.completed {
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
        let session = self.start_upload_session(&key, length as u64).await?;
        for (index, chunk) in data.chunks(CHUNK_UPLOAD_SIZE_BYTES).enumerate() {
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

async fn read_streaming_transport_response_to_writer<S>(
    stream: &mut S,
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta>
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

    let mut buffer = vec![0_u8; TRANSPORT_STREAM_COPY_BUFFER_SIZE_BYTES];
    let mut bytes_written = 0_u64;
    loop {
        let bytes_read = stream
            .read(&mut buffer)
            .await
            .context("failed reading streamed transport response body")?;
        if bytes_read == 0 {
            break;
        }
        writer
            .write_all(&buffer[..bytes_read])
            .context("failed writing streamed transport response body")?;
        bytes_written += bytes_read as u64;
    }
    writer
        .flush()
        .context("failed flushing streamed transport response body")?;

    Ok(StreamedTransportResponseMeta {
        status,
        headers,
        bytes_written,
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

async fn execute_multiplex_streaming_object_read_request(
    session: &transport_sdk::MultiplexedSession,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
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
            method: Method::GET.as_str().to_string(),
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
    read_streaming_transport_response_to_writer(&mut stream, writer).await
}

async fn execute_multiplex_streaming_object_write_request(
    session: &transport_sdk::MultiplexedSession,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
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
    let response = read_buffered_transport_response(&mut stream)
        .await
        .context("failed reading streamed object-write response")?;
    buffered_response_from_multiplex(response)
}

async fn execute_direct_http_streaming_object_read_request(
    http: &HttpClient,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
    let mut request = http.request(Method::GET, url.clone());
    for header in headers {
        request = request.header(header.name.as_str(), header.value.as_str());
    }
    let mut response = request
        .send()
        .await
        .with_context(|| format!("failed to execute streaming GET {}", url))?;
    let status = response.status();
    let response_headers = response.headers().clone();
    let mut bytes_written = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("failed reading streaming response chunk for {}", url))?
    {
        writer
            .write_all(chunk.as_ref())
            .with_context(|| format!("failed writing streamed response body for {}", url))?;
        bytes_written += chunk.len() as u64;
    }
    writer
        .flush()
        .with_context(|| format!("failed flushing streamed response for {}", url))?;
    Ok(StreamedTransportResponseMeta {
        status,
        headers: response_headers,
        bytes_written,
    })
}

#[derive(Clone, Copy)]
struct DirectMultiplexSessionContext<'a> {
    server_base_url: &'a str,
    session_pool: &'a TransportSessionPool,
    identity: &'a ClientIdentityMaterial,
    connection_name: Option<&'a str>,
}

async fn execute_direct_multiplex_streaming_object_read_request(
    server_base_url: &str,
    session_pool: &TransportSessionPool,
    identity: &ClientIdentityMaterial,
    connection_name: Option<&str>,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
    for attempt in 0..2 {
        let session = session_pool
            .ensure_direct_session(identity, connection_name)
            .await
            .context("failed ensuring direct multiplex session")?;
        let result =
            execute_multiplex_streaming_object_read_request(session.as_ref(), url, headers, writer)
                .await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    server_base_url,
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
        server_base_url
    )
}

async fn execute_relay_multiplex_streaming_object_read_request(
    relay: &ClientRelayTransport,
    source: PeerIdentity,
    connection_name: Option<&str>,
    url: &Url,
    headers: &[RelayHttpHeader],
    writer: &mut dyn Write,
) -> Result<StreamedTransportResponseMeta> {
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
            execute_multiplex_streaming_object_read_request(session.as_ref(), url, headers, writer)
                .await;
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
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                direct.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    server_base_url = direct.server_base_url,
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
        direct.server_base_url
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

async fn execute_direct_multiplex_buffered_request(
    direct: DirectMultiplexSessionContext<'_>,
    method: &Method,
    url: &Url,
    headers: &[RelayHttpHeader],
    body: &[u8],
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
            let response = read_buffered_transport_response(&mut stream)
                .await
                .context("failed reading direct multiplex response")?;
            buffered_response_from_multiplex(response)
        }
        .await;

        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                direct.session_pool.invalidate().await;
                tracing::debug!(
                    error = %err,
                    server_base_url = direct.server_base_url,
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
        direct.server_base_url
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
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        body::Body,
        extract::{
            Path as AxumPath, State,
            ws::{Message, WebSocket, WebSocketUpgrade},
        },
        http::{Response, header},
        response::IntoResponse,
        routing::{get, post},
    };
    use futures_util::{Sink, Stream};
    use std::pin::Pin;
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::sync::Mutex;
    use transport_sdk::{
        BufferedTransportResponse as MultiplexBufferedTransportResponse, DecodedWebSocketMessage,
        MultiplexConfig, MultiplexMode, MultiplexedSession, RelayHttpHeader, RelayTicket,
        RelayTicketRequest, RelayTunnelControlMessage, RelayTunnelSession, RelayTunnelSessionKind,
        RendezvousClientConfig, RendezvousControlClient, TRANSPORT_PROTOCOL_VERSION,
        TransportHeader, TransportResponseHead, TransportSessionControlMessage,
        TransportSessionRole, TransportStreamKind, WebSocketByteStream, WebSocketMessageCodec,
        perform_transport_server_handshake, read_buffered_transport_request,
        write_buffered_transport_response, write_transport_response_head,
    };

    #[test]
    fn object_url_builder_escapes_segments() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client
            .store_key_url("read me.txt")
            .expect("object url should build");
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:18080/api/v1/store/read%20me.txt"
        );
    }

    #[test]
    fn normalize_client_api_path_prefixes_known_public_routes() {
        assert_eq!(
            normalize_client_api_path("/cluster/status").as_ref(),
            "/api/v1/cluster/status"
        );
        assert_eq!(
            normalize_client_api_path("/api/v1/cluster/status").as_ref(),
            "/api/v1/cluster/status"
        );
        assert_eq!(
            normalize_client_api_path("/media/thumbnail?key=gallery%2Fcat.png").as_ref(),
            "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
        );
    }

    #[test]
    fn normalize_connection_name_preserves_readable_role_segments() {
        assert_eq!(
            normalize_connection_name(" Windows Cfapi / Upload Worker #1 ").as_deref(),
            Some("windows-cfapi-/-upload-worker-1")
        );
        assert_eq!(normalize_connection_name("   "), None);
    }

    #[test]
    fn transport_stream_kind_classification_accepts_versioned_public_routes() {
        assert_eq!(
            transport_stream_kind_for_path("/api/v1/health"),
            TransportStreamKind::Diagnostics
        );
        assert_eq!(
            transport_stream_kind_for_path("/api/v1/diagnostics/latency"),
            TransportStreamKind::Diagnostics
        );
        assert_eq!(
            transport_stream_kind_for_path("/api/v1/cluster/status"),
            TransportStreamKind::Rpc
        );
    }

    #[test]
    fn normalize_server_base_url_adds_scheme_and_trailing_slash() {
        let normalized = normalize_server_base_url("127.0.0.1:18080").expect("url should be valid");
        assert_eq!(normalized.as_str(), "http://127.0.0.1:18080/");
    }

    #[test]
    fn snapshot_conversion_maps_prefix_and_keys() {
        let snapshot = snapshot_from_store_index_entries(vec![
            StoreIndexEntry {
                path: "docs/".to_string(),
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(42),
                modified_at_unix: None,
                content_fingerprint: Some("cfp-readme".to_string()),
                media: None,
            },
        ]);

        assert_eq!(snapshot.local.len(), 0);
        assert_eq!(snapshot.remote.len(), 2);
        assert_eq!(snapshot.remote[0], NamespaceEntry::directory("docs"));
        assert_eq!(snapshot.remote[1].path, "docs/readme.txt");
        assert_eq!(snapshot.remote[1].version.as_deref(), Some("server-head"));
        assert_eq!(
            snapshot.remote[1].content_hash.as_deref(),
            Some("server-head:docs/readme.txt")
        );
        assert_eq!(
            snapshot.remote[1].content_fingerprint.as_deref(),
            Some("cfp-readme")
        );
        assert_eq!(snapshot.remote[1].size_bytes, Some(42));
    }

    #[test]
    fn ensure_missing_folder_markers_adds_nested_parents() {
        let mut entries = vec![StoreIndexEntry {
            path: "a/b/c.txt".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: None,
            size_bytes: Some(7),
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        }];

        ensure_missing_folder_markers(&mut entries);

        let paths = entries
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["a/", "a/b/", "a/b/c.txt"]);
    }

    #[test]
    fn ensure_missing_folder_markers_keeps_existing_markers_unique() {
        let mut entries = vec![
            StoreIndexEntry {
                path: "docs/".to_string(),
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/guides/readme.md".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(11),
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
        ];

        ensure_missing_folder_markers(&mut entries);

        let paths = entries
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec!["docs/", "docs/guides/", "docs/guides/readme.md"]
        );
    }

    #[test]
    fn place_downloaded_file_creates_missing_target_directory() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "ironmesh-place-downloaded-file-test-{}-{}",
            std::process::id(),
            nonce
        ));
        let source_dir = root.join("source");
        let target_dir = root.join("target").join("nested");
        fs::create_dir_all(&source_dir).unwrap();
        let temp_path = source_dir.join("download.part");
        let target_path = target_dir.join("download.bin");
        fs::write(&temp_path, b"hello").unwrap();

        place_downloaded_file(&temp_path, &target_path).unwrap();

        assert_eq!(fs::read(&target_path).unwrap(), b"hello");
        assert!(!temp_path.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_url_builder_builds_expected_path() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client.store_delete_url().expect("delete url should build");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/api/v1/store/delete");
    }

    #[test]
    fn versions_url_builder_builds_expected_path() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client.store_versions_url("docs/readme.txt").unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:18080/api/v1/versions/docs%2Freadme.txt"
        );
    }

    #[tokio::test]
    async fn list_versions_parses_version_graph_summary() {
        async fn versions(
            axum::extract::Path(key): axum::extract::Path<String>,
        ) -> axum::Json<VersionGraphSummary> {
            axum::Json(VersionGraphSummary {
                key,
                object_id: "obj-123".to_string(),
                preferred_head_version_id: Some("v2".to_string()),
                preferred_head_reason: Some(PreferredHeadReason::DeterministicTiebreakVersionId),
                head_version_ids: vec!["v2".to_string()],
                versions: vec![VersionRecordSummary {
                    version_id: "v2".to_string(),
                    logical_path: Some("docs/readme.txt".to_string()),
                    parent_version_ids: vec!["v1".to_string()],
                    state: VersionConsistencyState::Confirmed,
                    created_at_unix: 123,
                    copied_from_object_id: None,
                    copied_from_version_id: None,
                    copied_from_path: None,
                }],
            })
        }

        let app = axum::Router::new().route("/api/v1/versions/{key}", axum::routing::get(versions));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");
        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });

        let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
        let versions = client
            .list_versions("docs/readme.txt")
            .await
            .expect("versions should parse")
            .expect("versions should exist");

        assert_eq!(versions.object_id, "obj-123");
        assert_eq!(versions.preferred_head_version_id.as_deref(), Some("v2"));
        assert_eq!(versions.versions.len(), 1);
        assert_eq!(versions.versions[0].version_id, "v2");

        handle.abort();
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RelayTestCapturedRequest {
        kind: Option<TransportStreamKind>,
        method: String,
        path_and_query: String,
        headers: Vec<RelayHttpHeader>,
        body: Vec<u8>,
    }

    #[derive(Debug, Clone)]
    struct DirectHttpRouteState {
        cluster_status_hits: Arc<AtomicUsize>,
        health_hits: Arc<AtomicUsize>,
        response_delay_ms: u64,
        name: String,
    }

    async fn spawn_direct_http_route_server_at(
        bind_addr: std::net::SocketAddr,
        response_delay_ms: u64,
        name: &str,
    ) -> (String, DirectHttpRouteState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");
        let state = DirectHttpRouteState {
            cluster_status_hits: Arc::new(AtomicUsize::new(0)),
            health_hits: Arc::new(AtomicUsize::new(0)),
            response_delay_ms,
            name: name.to_string(),
        };
        let router = Router::new()
            .route(
                "/api/v1/cluster/status",
                get(|State(state): State<DirectHttpRouteState>| async move {
                    state.cluster_status_hits.fetch_add(1, Ordering::SeqCst);
                    if state.response_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
                    }
                    Json(serde_json::json!({
                        "status": "ok",
                        "route": state.name,
                    }))
                }),
            )
            .route(
                "/api/v1/health",
                get(|State(state): State<DirectHttpRouteState>| async move {
                    state.health_hits.fetch_add(1, Ordering::SeqCst);
                    if state.response_delay_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
                    }
                    StatusCode::OK
                }),
            )
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("direct http route server should run");
        });
        (format!("http://{addr}"), state, server)
    }

    async fn spawn_direct_http_route_server(
        response_delay_ms: u64,
        name: &str,
    ) -> (String, DirectHttpRouteState, tokio::task::JoinHandle<()>) {
        spawn_direct_http_route_server_at(
            "127.0.0.1:0".parse().expect("bind addr should parse"),
            response_delay_ms,
            name,
        )
        .await
    }

    #[derive(Clone)]
    struct RelayTestState {
        public_url: String,
        captured_request: Arc<Mutex<Option<RelayTestCapturedRequest>>>,
        issued_ticket_count: Arc<AtomicUsize>,
        paired_session_count: Arc<AtomicUsize>,
        object_write_failures_remaining: Arc<AtomicUsize>,
        response_delay_ms: u64,
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
    }

    async fn issue_ticket(
        State(state): State<RelayTestState>,
        Json(request): Json<RelayTicketRequest>,
    ) -> Json<RelayTicket> {
        state.issued_ticket_count.fetch_add(1, Ordering::SeqCst);
        Json(RelayTicket {
            cluster_id: request.cluster_id,
            session_id: format!("relay-session-{}", uuid::Uuid::now_v7()),
            source: request.source,
            target: request.target,
            session_kind: request.session_kind,
            relay_urls: vec![state.public_url],
            issued_at_unix: 1,
            expires_at_unix: 61,
        })
    }

    async fn relay_tunnel_ws(
        State(state): State<RelayTestState>,
        websocket: WebSocketUpgrade,
    ) -> impl axum::response::IntoResponse {
        websocket.on_upgrade(move |socket| async move {
            serve_relay_tunnel_test_socket(state, socket).await;
        })
    }

    async fn direct_transport_ws(
        State(state): State<RelayTestState>,
        websocket: WebSocketUpgrade,
    ) -> impl axum::response::IntoResponse {
        websocket.on_upgrade(move |socket| async move {
            state.paired_session_count.fetch_add(1, Ordering::SeqCst);
            serve_test_multiplex_socket(
                state,
                socket,
                format!("direct-session-{}", uuid::Uuid::now_v7()),
            )
            .await;
        })
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RelayTestWsMessage {
        Binary(Vec<u8>),
        Text(String),
        Ping(Vec<u8>),
        Pong(Vec<u8>),
        Close,
    }

    impl WebSocketMessageCodec for RelayTestWsMessage {
        fn decode(self) -> std::io::Result<DecodedWebSocketMessage> {
            Ok(match self {
                Self::Binary(bytes) => DecodedWebSocketMessage::Binary(bytes),
                Self::Text(_) => DecodedWebSocketMessage::Ignore,
                Self::Ping(payload) => DecodedWebSocketMessage::Ping(payload),
                Self::Pong(_) => DecodedWebSocketMessage::Pong,
                Self::Close => DecodedWebSocketMessage::Close,
            })
        }

        fn binary(bytes: Vec<u8>) -> Self {
            Self::Binary(bytes)
        }

        fn pong(bytes: Vec<u8>) -> Self {
            Self::Pong(bytes)
        }
    }

    struct RelayTestSocketAdapter {
        socket: WebSocket,
    }

    impl Stream for RelayTestSocketAdapter {
        type Item = Result<RelayTestWsMessage, axum::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this = self.get_mut();
            match Pin::new(&mut this.socket).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                    Poll::Ready(Some(Ok(RelayTestWsMessage::Binary(bytes.to_vec()))))
                }
                Poll::Ready(Some(Ok(Message::Text(text)))) => {
                    Poll::Ready(Some(Ok(RelayTestWsMessage::Text(text.to_string()))))
                }
                Poll::Ready(Some(Ok(Message::Ping(payload)))) => {
                    Poll::Ready(Some(Ok(RelayTestWsMessage::Ping(payload.to_vec()))))
                }
                Poll::Ready(Some(Ok(Message::Pong(payload)))) => {
                    Poll::Ready(Some(Ok(RelayTestWsMessage::Pong(payload.to_vec()))))
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) => {
                    Poll::Ready(Some(Ok(RelayTestWsMessage::Close)))
                }
                Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    impl Sink<RelayTestWsMessage> for RelayTestSocketAdapter {
        type Error = axum::Error;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.get_mut().socket).poll_ready(cx)
        }

        fn start_send(self: Pin<&mut Self>, item: RelayTestWsMessage) -> Result<(), Self::Error> {
            let message = match item {
                RelayTestWsMessage::Binary(bytes) => Message::Binary(bytes.into()),
                RelayTestWsMessage::Text(text) => Message::Text(text.into()),
                RelayTestWsMessage::Ping(payload) => Message::Ping(payload.into()),
                RelayTestWsMessage::Pong(payload) => Message::Pong(payload.into()),
                RelayTestWsMessage::Close => Message::Close(None),
            };
            Pin::new(&mut self.get_mut().socket).start_send(message)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.get_mut().socket).poll_flush(cx)
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Pin::new(&mut self.get_mut().socket).poll_close(cx)
        }
    }

    async fn serve_relay_tunnel_test_socket(state: RelayTestState, mut socket: WebSocket) {
        let initial = match socket.recv().await {
            Some(Ok(Message::Text(text))) => text,
            _ => return,
        };
        let RelayTunnelControlMessage::ConnectSource { ticket } =
            serde_json::from_str(&initial).expect("test relay tunnel control should parse")
        else {
            return;
        };

        let session = RelayTunnelSession {
            cluster_id: ticket.cluster_id,
            session_id: ticket.session_id.clone(),
            source: ticket.source.clone(),
            target: ticket.target.clone(),
            session_kind: ticket.session_kind,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&RelayTunnelControlMessage::Paired { session })
                    .expect("paired control should serialize")
                    .into(),
            ))
            .await
            .expect("paired response should send");

        state.paired_session_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            ticket.session_kind,
            RelayTunnelSessionKind::MultiplexTransport
        );
        serve_relay_multiplex_test_socket(state, socket, ticket).await;
    }

    async fn serve_test_multiplex_socket(
        state: RelayTestState,
        socket: WebSocket,
        session_id: String,
    ) {
        let transport = WebSocketByteStream::new(RelayTestSocketAdapter { socket });
        let mut session =
            MultiplexedSession::spawn(transport, MultiplexMode::Server, MultiplexConfig::default())
                .expect("multiplexed relay test session should spawn");

        let hello = perform_transport_server_handshake(
            &mut session,
            TransportSessionControlMessage::Ready {
                protocol_version: TRANSPORT_PROTOCOL_VERSION,
                session_id,
                max_concurrent_streams: MultiplexConfig::default().max_num_streams,
            },
        )
        .await
        .expect("multiplexed relay test handshake should succeed");
        assert!(matches!(
            hello,
            TransportSessionControlMessage::Hello {
                role: TransportSessionRole::Client,
                ..
            }
        ));

        while let Some(mut stream) = session
            .accept_stream()
            .await
            .expect("multiplexed relay test stream accept should succeed")
        {
            let request = read_buffered_transport_request(&mut stream)
                .await
                .expect("multiplexed relay test request should decode");
            *state.captured_request.lock().await = Some(RelayTestCapturedRequest {
                kind: Some(request.kind),
                method: request.method.clone(),
                path_and_query: request.path.clone(),
                headers: request
                    .headers
                    .iter()
                    .map(|header| RelayHttpHeader {
                        name: header.name.clone(),
                        value: header.value.clone(),
                    })
                    .collect(),
                body: request.body.clone(),
            });

            let fail_object_write = request.kind == TransportStreamKind::ObjectWrite
                && state
                    .object_write_failures_remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    .is_ok();
            if fail_object_write {
                return;
            }

            if state.response_delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
            }

            write_buffered_transport_response(
                &mut stream,
                &MultiplexBufferedTransportResponse {
                    request_id: request.request_id,
                    status: state.response_status,
                    headers: state
                        .response_headers
                        .iter()
                        .map(|header| TransportHeader {
                            name: header.name.clone(),
                            value: header.value.clone(),
                        })
                        .collect(),
                    body: state.response_body.clone(),
                },
            )
            .await
            .expect("multiplexed relay test response should write");
        }
    }

    async fn serve_relay_multiplex_test_socket(
        state: RelayTestState,
        socket: WebSocket,
        ticket: RelayTicket,
    ) {
        serve_test_multiplex_socket(state, socket, ticket.session_id).await;
    }

    async fn spawn_relay_test_server(
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        spawn_relay_test_server_with_object_write_failures(
            response_status,
            response_headers,
            response_body,
            0,
        )
        .await
    }

    async fn spawn_relay_test_server_with_object_write_failures(
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
        object_write_failures_remaining: usize,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        spawn_relay_test_server_with_delay_and_object_write_failures(
            response_status,
            response_headers,
            response_body,
            0,
            object_write_failures_remaining,
        )
        .await
    }

    async fn spawn_relay_test_server_with_delay(
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
        response_delay_ms: u64,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        spawn_relay_test_server_with_delay_and_object_write_failures(
            response_status,
            response_headers,
            response_body,
            response_delay_ms,
            0,
        )
        .await
    }

    async fn spawn_relay_test_server_with_delay_and_object_write_failures(
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
        response_delay_ms: u64,
        object_write_failures_remaining: usize,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        spawn_relay_test_server_at(
            "127.0.0.1:0".parse().expect("bind addr should parse"),
            response_status,
            response_headers,
            response_body,
            response_delay_ms,
            object_write_failures_remaining,
        )
        .await
    }

    async fn spawn_relay_test_server_at(
        bind_addr: std::net::SocketAddr,
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
        response_delay_ms: u64,
        object_write_failures_remaining: usize,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let state = RelayTestState {
            public_url: format!("http://{addr}"),
            captured_request: Arc::new(Mutex::new(None)),
            issued_ticket_count: Arc::new(AtomicUsize::new(0)),
            paired_session_count: Arc::new(AtomicUsize::new(0)),
            object_write_failures_remaining: Arc::new(AtomicUsize::new(
                object_write_failures_remaining,
            )),
            response_delay_ms,
            response_status,
            response_headers,
            response_body,
        };
        let router = Router::new()
            .route("/control/relay/ticket", post(issue_ticket))
            .route("/relay/tunnel/ws", get(relay_tunnel_ws))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("relay test server should run");
        });
        (state, server)
    }

    async fn spawn_direct_transport_test_server(
        response_status: u16,
        response_headers: Vec<RelayHttpHeader>,
        response_body: Vec<u8>,
    ) -> (RelayTestState, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let state = RelayTestState {
            public_url: format!("http://{addr}"),
            captured_request: Arc::new(Mutex::new(None)),
            issued_ticket_count: Arc::new(AtomicUsize::new(0)),
            paired_session_count: Arc::new(AtomicUsize::new(0)),
            object_write_failures_remaining: Arc::new(AtomicUsize::new(0)),
            response_delay_ms: 0,
            response_status,
            response_headers,
            response_body,
        };
        let router = Router::new()
            .route("/transport/ws", get(direct_transport_ws))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("direct transport test server should run");
        });
        (state, server)
    }

    async fn direct_mixed_workload_ws(
        websocket: WebSocketUpgrade,
        State(payload): State<Arc<Vec<u8>>>,
    ) -> impl IntoResponse {
        websocket.on_upgrade(move |socket| async move {
            let transport = WebSocketByteStream::new(RelayTestSocketAdapter { socket });
            let mut session = MultiplexedSession::spawn(
                transport,
                MultiplexMode::Server,
                MultiplexConfig::default(),
            )
            .expect("mixed workload session should spawn");
            let hello = perform_transport_server_handshake(
                &mut session,
                TransportSessionControlMessage::Ready {
                    protocol_version: TRANSPORT_PROTOCOL_VERSION,
                    session_id: format!("mixed-session-{}", uuid::Uuid::now_v7()),
                    max_concurrent_streams: MultiplexConfig::default().max_num_streams,
                },
            )
            .await
            .expect("mixed workload handshake should succeed");
            assert!(matches!(
                hello,
                TransportSessionControlMessage::Hello {
                    role: TransportSessionRole::Client,
                    ..
                }
            ));

            while let Some(mut stream) = session
                .accept_stream()
                .await
                .expect("mixed workload stream accept should succeed")
            {
                let payload = Arc::clone(&payload);
                tokio::spawn(async move {
                    let request = read_buffered_transport_request(&mut stream)
                        .await
                        .expect("mixed workload request should decode");

                    match (request.kind, request.method.as_str(), request.path.as_str()) {
                        (TransportStreamKind::Rpc, "HEAD", "/api/v1/store/large.bin") => {
                            write_buffered_transport_response(
                                &mut stream,
                                &MultiplexBufferedTransportResponse {
                                    request_id: request.request_id,
                                    status: StatusCode::OK.as_u16(),
                                    headers: vec![
                                        TransportHeader {
                                            name: ACCEPT_RANGES.as_str().to_string(),
                                            value: "bytes".to_string(),
                                        },
                                        TransportHeader {
                                            name: CONTENT_LENGTH.as_str().to_string(),
                                            value: payload.len().to_string(),
                                        },
                                        TransportHeader {
                                            name: ETAG.as_str().to_string(),
                                            value: "\"mixed-etag\"".to_string(),
                                        },
                                        TransportHeader {
                                            name: "x-ironmesh-object-size".to_string(),
                                            value: payload.len().to_string(),
                                        },
                                    ],
                                    body: Vec::new(),
                                },
                            )
                            .await
                            .expect("mixed workload HEAD response should write");
                        }
                        (TransportStreamKind::ObjectRead, "GET", "/api/v1/store/large.bin") => {
                            let range = request
                                .headers
                                .iter()
                                .find(|header| header.name.eq_ignore_ascii_case("range"))
                                .map(|header| header.value.clone())
                                .expect("range header should be present");
                            let (start, end_inclusive) = parse_range_header(&range, payload.len());
                            let selected = &payload[start..=end_inclusive];
                            write_transport_response_head(
                                &mut stream,
                                &TransportResponseHead {
                                    request_id: request.request_id,
                                    status: StatusCode::PARTIAL_CONTENT.as_u16(),
                                    headers: vec![
                                        TransportHeader {
                                            name: ACCEPT_RANGES.as_str().to_string(),
                                            value: "bytes".to_string(),
                                        },
                                        TransportHeader {
                                            name: CONTENT_LENGTH.as_str().to_string(),
                                            value: selected.len().to_string(),
                                        },
                                        TransportHeader {
                                            name: CONTENT_RANGE.as_str().to_string(),
                                            value: format!(
                                                "bytes {start}-{end_inclusive}/{}",
                                                payload.len()
                                            ),
                                        },
                                        TransportHeader {
                                            name: ETAG.as_str().to_string(),
                                            value: "\"mixed-etag\"".to_string(),
                                        },
                                        TransportHeader {
                                            name: "x-ironmesh-object-size".to_string(),
                                            value: payload.len().to_string(),
                                        },
                                    ],
                                },
                            )
                            .await
                            .expect("mixed workload object-read head should write");

                            for chunk in selected.chunks(16 * 1024) {
                                stream
                                    .write_all(chunk)
                                    .await
                                    .expect("mixed workload object-read body should write");
                                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                            }
                            stream
                                .close()
                                .await
                                .expect("mixed workload object-read stream should close");
                        }
                        (TransportStreamKind::Rpc, "GET", "/api/v1/cluster/status") => {
                            write_buffered_transport_response(
                                &mut stream,
                                &MultiplexBufferedTransportResponse {
                                    request_id: request.request_id,
                                    status: StatusCode::OK.as_u16(),
                                    headers: vec![
                                        TransportHeader {
                                            name: "content-type".to_string(),
                                            value: "application/json".to_string(),
                                        },
                                        TransportHeader {
                                            name: "content-length".to_string(),
                                            value: br#"{"status":"ok"}"#.len().to_string(),
                                        },
                                    ],
                                    body: br#"{"status":"ok"}"#.to_vec(),
                                },
                            )
                            .await
                            .expect("mixed workload RPC response should write");
                        }
                        _ => {
                            write_buffered_transport_response(
                                &mut stream,
                                &MultiplexBufferedTransportResponse {
                                    request_id: request.request_id,
                                    status: StatusCode::BAD_REQUEST.as_u16(),
                                    headers: vec![
                                        TransportHeader {
                                            name: "content-type".to_string(),
                                            value: "text/plain; charset=utf-8".to_string(),
                                        },
                                        TransportHeader {
                                            name: "content-length".to_string(),
                                            value: b"unsupported".len().to_string(),
                                        },
                                    ],
                                    body: b"unsupported".to_vec(),
                                },
                            )
                            .await
                            .expect("mixed workload error response should write");
                        }
                    }
                });
            }
        })
    }

    async fn spawn_direct_mixed_workload_test_server(
        payload: Arc<Vec<u8>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let router = Router::new()
            .route("/transport/ws", get(direct_mixed_workload_ws))
            .with_state(payload);
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("mixed workload server should run");
        });
        (format!("http://{addr}"), server)
    }

    fn relay_test_client_for_public_url(
        public_url: impl Into<String>,
        identity: ClientIdentityMaterial,
        target_node_id: NodeId,
    ) -> IronMeshClient {
        let rendezvous = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec![public_url.into()],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");
        IronMeshClient::with_relay_transport("https://relay.invalid/", rendezvous, target_node_id)
            .with_client_identity(identity)
    }

    fn direct_transport_test_client(
        state: &RelayTestState,
        identity: ClientIdentityMaterial,
    ) -> IronMeshClient {
        IronMeshClient::from_direct_base_url(state.public_url.clone())
            .with_client_identity(identity)
    }

    fn relay_test_client(
        state: &RelayTestState,
        identity: ClientIdentityMaterial,
        target_node_id: NodeId,
    ) -> IronMeshClient {
        relay_test_client_for_public_url(state.public_url.clone(), identity, target_node_id)
    }

    fn parse_range_header(range: &str, total_len: usize) -> (usize, usize) {
        let trimmed = range
            .strip_prefix("bytes=")
            .expect("range header should have bytes= prefix");
        let (start, end) = trimmed
            .split_once('-')
            .expect("range header should contain dash");
        let start = start.parse::<usize>().expect("range start should parse");
        let end = end.parse::<usize>().expect("range end should parse");
        assert!(start <= end, "range start must not exceed end");
        assert!(end < total_len, "range end must stay within payload");
        (start, end)
    }

    #[tokio::test]
    async fn relay_transport_executes_store_index_request_with_signed_device_identity() {
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: serde_json::to_vec(&StoreIndexResponse {
                        prefix: String::new(),
                        depth: 1,
                        entry_count: 1,
                        entries: vec![StoreIndexEntry {
                            path: "docs/readme.txt".to_string(),
                            entry_type: "key".to_string(),
                            version: Some("v1".to_string()),
                            content_hash: Some("hash-1".to_string()),
                            size_bytes: Some(42),
                            modified_at_unix: None,
                            content_fingerprint: None,
                            media: None,
                        }],
                    })
                    .expect("store index response should serialize")
                    .len()
                    .to_string(),
                },
            ],
            serde_json::to_vec(&StoreIndexResponse {
                prefix: String::new(),
                depth: 1,
                entry_count: 1,
                entries: vec![StoreIndexEntry {
                    path: "docs/readme.txt".to_string(),
                    entry_type: "key".to_string(),
                    version: Some("v1".to_string()),
                    content_hash: Some("hash-1".to_string()),
                    size_bytes: Some(42),
                    modified_at_unix: None,
                    content_fingerprint: None,
                    media: None,
                }],
            })
            .expect("store index response should serialize"),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

        let response = client
            .store_index(None, 1, None)
            .await
            .expect("store index over relay should succeed");

        assert_eq!(response.entry_count, 2);
        assert_eq!(response.entries[0].path, "docs/");
        assert_eq!(response.entries[1].path, "docs/readme.txt");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.method, "GET");
        assert_eq!(captured.path_and_query, "/api/v1/store/index?depth=1");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_executes_generic_json_get_request() {
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: br#"{"status":"ok"}"#.len().to_string(),
                },
            ],
            br#"{"status":"ok"}"#.to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

        let response = client
            .get_json_path("/cluster/status")
            .await
            .expect("generic JSON GET over relay should succeed");

        assert_eq!(response["status"], "ok");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.path_and_query, "/api/v1/cluster/status");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_executes_relative_path_get_request() {
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "image/jpeg".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: b"thumb-jpeg-bytes".len().to_string(),
                },
            ],
            b"thumb-jpeg-bytes".to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

        let response = client
            .get_relative_path("/media/thumbnail?key=gallery%2Fcat.png")
            .await
            .expect("relative GET over relay should succeed");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"thumb-jpeg-bytes");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(
            captured.path_and_query,
            "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
        );
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_preserves_head_response_headers() {
        let payload = b"head-only-payload";
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: ACCEPT_RANGES.as_str().to_string(),
                    value: "bytes".to_string(),
                },
                RelayHttpHeader {
                    name: CONTENT_LENGTH.as_str().to_string(),
                    value: payload.len().to_string(),
                },
                RelayHttpHeader {
                    name: ETAG.as_str().to_string(),
                    value: "\"relay-head-etag\"".to_string(),
                },
            ],
            Vec::new(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

        let response = client
            .head_object("gallery/cat.png", None, None)
            .await
            .expect("HEAD over relay should succeed");

        assert_eq!(response.total_size_bytes, payload.len() as u64);
        assert!(response.accept_ranges);
        assert_eq!(response.etag.as_deref(), Some("\"relay-head-etag\""));

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.method, "HEAD");
        assert_eq!(captured.path_and_query, "/api/v1/store/gallery%2Fcat.png");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_reuses_multiplexed_session_for_multiple_requests() {
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: br#"{"status":"ok"}"#.len().to_string(),
                },
            ],
            br#"{"status":"ok"}"#.to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity, target_node_id);

        let first = client
            .get_json_path("/cluster/status")
            .await
            .expect("first multiplex relay request should succeed");
        let second = client
            .get_json_path("/cluster/status")
            .await
            .expect("second multiplex relay request should succeed");

        assert_eq!(first["status"], "ok");
        assert_eq!(second["status"], "ok");
        assert_eq!(relay_state.issued_ticket_count.load(Ordering::SeqCst), 1);
        assert_eq!(relay_state.paired_session_count.load(Ordering::SeqCst), 1);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_streams_upload_session_chunks_over_object_write() {
        let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
            stored: true,
            received_index: 2,
        })
        .expect("upload chunk response should serialize");
        let (relay_state, server) = spawn_relay_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: response_body.len().to_string(),
                },
            ],
            response_body,
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-upload-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity, target_node_id);

        let response = client
            .upload_session_chunk_bytes("upload-123", 2, b"chunk-body".to_vec())
            .await
            .expect("relay upload chunk should succeed");

        assert!(response.stored);
        assert_eq!(response.received_index, 2);

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
        assert_eq!(captured.method, "PUT");
        assert_eq!(
            captured.path_and_query,
            "/api/v1/store/uploads/upload-123/chunk/2"
        );
        assert_eq!(captured.body, b"chunk-body".to_vec());

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_retries_streamed_upload_chunk_after_partial_session_failure() {
        let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
            stored: true,
            received_index: 4,
        })
        .expect("upload chunk response should serialize");
        let (relay_state, server) = spawn_relay_test_server_with_object_write_failures(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: response_body.len().to_string(),
                },
            ],
            response_body,
            1,
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-upload-retry-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let client = relay_test_client(&relay_state, identity, target_node_id);

        let response = client
            .upload_session_chunk_bytes("upload-retry", 4, b"retry-body".to_vec())
            .await
            .expect("relay upload chunk retry should succeed");

        assert!(response.stored);
        assert_eq!(response.received_index, 4);
        assert_eq!(relay_state.issued_ticket_count.load(Ordering::SeqCst), 2);
        assert_eq!(relay_state.paired_session_count.load(Ordering::SeqCst), 2);

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
        assert_eq!(
            captured.path_and_query,
            "/api/v1/store/uploads/upload-retry/chunk/4"
        );
        assert_eq!(captured.body, b"retry-body".to_vec());

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_executes_and_reuses_multiplexed_session() {
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: br#"{"status":"ok"}"#.len().to_string(),
                },
            ],
            br#"{"status":"ok"}"#.to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = direct_transport_test_client(&direct_state, identity.clone());

        let first = client
            .get_json_path("/cluster/status")
            .await
            .expect("first direct multiplex request should succeed");
        let second = client
            .get_json_path("/cluster/status")
            .await
            .expect("second direct multiplex request should succeed");

        assert_eq!(first["status"], "ok");
        assert_eq!(second["status"], "ok");
        assert_eq!(direct_state.paired_session_count.load(Ordering::SeqCst), 1);

        let captured = direct_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("direct request should be captured");
        assert_eq!(captured.path_and_query, "/api/v1/cluster/status");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_executes_store_index_request_with_signed_device_identity() {
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: serde_json::to_vec(&StoreIndexResponse {
                        prefix: String::new(),
                        depth: 1,
                        entry_count: 1,
                        entries: vec![StoreIndexEntry {
                            path: "docs/readme.txt".to_string(),
                            entry_type: "key".to_string(),
                            version: Some("v1".to_string()),
                            content_hash: Some("hash-1".to_string()),
                            size_bytes: Some(42),
                            modified_at_unix: None,
                            content_fingerprint: None,
                            media: None,
                        }],
                    })
                    .expect("store index response should serialize")
                    .len()
                    .to_string(),
                },
            ],
            serde_json::to_vec(&StoreIndexResponse {
                prefix: String::new(),
                depth: 1,
                entry_count: 1,
                entries: vec![StoreIndexEntry {
                    path: "docs/readme.txt".to_string(),
                    entry_type: "key".to_string(),
                    version: Some("v1".to_string()),
                    content_hash: Some("hash-1".to_string()),
                    size_bytes: Some(42),
                    modified_at_unix: None,
                    content_fingerprint: None,
                    media: None,
                }],
            })
            .expect("store index response should serialize"),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-store-index-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = direct_transport_test_client(&direct_state, identity.clone());

        let response = client
            .store_index(None, 1, None)
            .await
            .expect("store index over direct transport should succeed");

        assert_eq!(response.entry_count, 2);
        assert_eq!(response.entries[0].path, "docs/");
        assert_eq!(response.entries[1].path, "docs/readme.txt");

        let captured = direct_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("direct request should be captured");
        assert_eq!(captured.method, "GET");
        assert_eq!(captured.path_and_query, "/api/v1/store/index?depth=1");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn combined_direct_transports_fail_over_to_second_endpoint() {
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: br#"{"status":"ok"}"#.len().to_string(),
                },
            ],
            br#"{"status":"ok"}"#.to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-failover-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());

        let failing = IronMeshClient::from_direct_base_url("http://127.0.0.1:9")
            .with_client_identity(identity.clone());
        let healthy = direct_transport_test_client(&direct_state, identity);
        let client = IronMeshClient::combine(vec![failing, healthy])
            .expect("combined direct client should build");

        let first = client
            .get_json_path("/cluster/status")
            .await
            .expect("first combined direct request should succeed via fallback");
        let second = client
            .get_json_path("/cluster/status")
            .await
            .expect("second combined direct request should keep using the healthy route");

        assert_eq!(first["status"], "ok");
        assert_eq!(second["status"], "ok");
        assert_eq!(
            client.direct_server_base_url(),
            Some(direct_state.public_url.as_str())
        );
        assert_eq!(direct_state.paired_session_count.load(Ordering::SeqCst), 1);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_probe_reprioritizes_recovered_direct_endpoint() {
        let reserved_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let primary_addr = reserved_listener
            .local_addr()
            .expect("listener should have addr");
        drop(reserved_listener);

        let primary_url = format!("http://{primary_addr}");
        let (fallback_url, fallback_state, fallback_server) =
            spawn_direct_http_route_server(125, "fallback").await;

        let primary = IronMeshClient::from_direct_base_url(primary_url.clone());
        let fallback = IronMeshClient::from_direct_base_url(fallback_url.clone());
        let client = IronMeshClient::combine(vec![primary, fallback])
            .expect("combined direct client should build");

        let first = client
            .get_json_path("/cluster/status")
            .await
            .expect("first request should fall back to the healthy route");
        assert_eq!(first["route"], "fallback");
        assert_eq!(client.direct_server_base_url(), Some(fallback_url.as_str()));

        let (_primary_url, primary_state, primary_server) =
            spawn_direct_http_route_server_at(primary_addr, 0, "primary").await;

        tokio::time::sleep(Duration::from_millis(
            CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS + 100,
        ))
        .await;

        let second = client
            .get_json_path("/cluster/status")
            .await
            .expect("second request should still use the current fallback route");
        assert_eq!(second["route"], "fallback");

        tokio::time::sleep(Duration::from_millis(200)).await;

        let third = client
            .get_json_path("/cluster/status")
            .await
            .expect("third request should use the reprobed primary route");
        assert_eq!(third["route"], "primary");
        assert_eq!(client.direct_server_base_url(), Some(primary_url.as_str()));
        assert!(primary_state.health_hits.load(Ordering::SeqCst) >= 1);
        assert_eq!(primary_state.cluster_status_hits.load(Ordering::SeqCst), 1);
        assert_eq!(fallback_state.cluster_status_hits.load(Ordering::SeqCst), 2);

        primary_server.abort();
        let _ = primary_server.await;
        fallback_server.abort();
        let _ = fallback_server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_probe_reprioritizes_recovered_relay_endpoint() {
        let reserved_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let primary_addr = reserved_listener
            .local_addr()
            .expect("listener should have addr");
        drop(reserved_listener);

        let primary_url = format!("http://{primary_addr}");
        let fallback_body = serde_json::to_vec(&serde_json::json!({
            "status": "ok",
            "route": "fallback",
        }))
        .expect("fallback relay body should serialize");
        let (fallback_state, fallback_server) = spawn_relay_test_server_with_delay(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: fallback_body.len().to_string(),
                },
            ],
            fallback_body,
            125,
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-background-refresh-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let primary_target_node_id = NodeId::new_v4();
        let fallback_target_node_id = NodeId::new_v4();
        let primary = relay_test_client_for_public_url(
            primary_url.clone(),
            identity.clone(),
            primary_target_node_id,
        );
        let fallback =
            relay_test_client(&fallback_state, identity.clone(), fallback_target_node_id);
        let client = IronMeshClient::combine(vec![primary, fallback])
            .expect("combined relay client should build");

        let first = client
            .get_json_path("/cluster/status")
            .await
            .expect("first request should fall back to the healthy relay route");
        assert_eq!(first["route"], "fallback");
        assert_eq!(client.relay_target_node_id(), Some(fallback_target_node_id));
        assert!(client.uses_relay_transport());

        let primary_body = serde_json::to_vec(&serde_json::json!({
            "status": "ok",
            "route": "primary",
        }))
        .expect("primary relay body should serialize");
        let (primary_state, primary_server) = spawn_relay_test_server_at(
            primary_addr,
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: primary_body.len().to_string(),
                },
            ],
            primary_body,
            0,
            0,
        )
        .await;

        tokio::time::sleep(Duration::from_millis(
            CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS + 100,
        ))
        .await;

        let second = client
            .get_json_path("/cluster/status")
            .await
            .expect("second request should still use the fallback relay route");
        assert_eq!(second["route"], "fallback");

        let background_capture = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(captured) = primary_state.captured_request.lock().await.clone()
                    && captured.path_and_query == "/api/v1/health"
                {
                    break captured;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("background probe should hit the recovered relay route");
        assert_eq!(background_capture.path_and_query, "/api/v1/health");

        let third = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let response = client
                    .get_json_path("/cluster/status")
                    .await
                    .expect("request after background probe should succeed");
                if response["route"] == "primary" {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("client should eventually prefer the recovered relay route");
        assert_eq!(third["route"], "primary");
        assert_eq!(client.relay_target_node_id(), Some(primary_target_node_id));
        assert!(primary_state.issued_ticket_count.load(Ordering::SeqCst) >= 1);
        assert!(primary_state.paired_session_count.load(Ordering::SeqCst) >= 1);
        assert_eq!(fallback_state.issued_ticket_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            fallback_state.paired_session_count.load(Ordering::SeqCst),
            1
        );

        primary_server.abort();
        let _ = primary_server.await;
        fallback_server.abort();
        let _ = fallback_server.await;
    }

    #[tokio::test]
    async fn direct_transport_executes_relative_path_get_request() {
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "image/jpeg".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: b"thumb-jpeg-bytes".len().to_string(),
                },
            ],
            b"thumb-jpeg-bytes".to_vec(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-relative-path-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = direct_transport_test_client(&direct_state, identity.clone());

        let response = client
            .get_relative_path("/media/thumbnail?key=gallery%2Fcat.png")
            .await
            .expect("relative GET over direct transport should succeed");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"thumb-jpeg-bytes");

        let captured = direct_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("direct request should be captured");
        assert_eq!(
            captured.path_and_query,
            "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
        );
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_preserves_head_response_headers() {
        let payload = b"head-only-payload";
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: ACCEPT_RANGES.as_str().to_string(),
                    value: "bytes".to_string(),
                },
                RelayHttpHeader {
                    name: CONTENT_LENGTH.as_str().to_string(),
                    value: payload.len().to_string(),
                },
                RelayHttpHeader {
                    name: ETAG.as_str().to_string(),
                    value: "\"direct-head-etag\"".to_string(),
                },
            ],
            Vec::new(),
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-head-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = direct_transport_test_client(&direct_state, identity);

        let response = client
            .head_object("gallery/cat.png", None, None)
            .await
            .expect("HEAD over direct transport should succeed");

        assert_eq!(response.total_size_bytes, payload.len() as u64);
        assert!(response.accept_ranges);
        assert_eq!(response.etag.as_deref(), Some("\"direct-head-etag\""));

        let captured = direct_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("direct request should be captured");
        assert_eq!(captured.method, "HEAD");
        assert_eq!(captured.path_and_query, "/api/v1/store/gallery%2Fcat.png");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_streams_upload_session_chunks_over_object_write() {
        let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
            stored: true,
            received_index: 3,
        })
        .expect("upload chunk response should serialize");
        let (direct_state, server) = spawn_direct_transport_test_server(
            200,
            vec![
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: response_body.len().to_string(),
                },
            ],
            response_body,
        )
        .await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-upload-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = direct_transport_test_client(&direct_state, identity);

        let response = client
            .upload_session_chunk_bytes("upload-abc", 3, b"direct-chunk".to_vec())
            .await
            .expect("direct upload chunk should succeed");

        assert!(response.stored);
        assert_eq!(response.received_index, 3);

        let captured = direct_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("direct request should be captured");
        assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
        assert_eq!(captured.method, "PUT");
        assert_eq!(
            captured.path_and_query,
            "/api/v1/store/uploads/upload-abc/chunk/3"
        );
        assert_eq!(captured.body, b"direct-chunk".to_vec());

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_keeps_small_rpcs_responsive_during_streamed_downloads() {
        let payload = Arc::new(vec![0x5A; 1024 * 1024]);
        let payload_len = payload.len();
        let (base_url, server) =
            spawn_direct_mixed_workload_test_server(Arc::clone(&payload)).await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-mixed-workload-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = IronMeshClient::from_direct_base_url(base_url).with_client_identity(identity);

        let download_client = client.clone();
        let download_future = async move {
            let mut output = Vec::new();
            let mut progress = Vec::new();
            let mut on_progress = |update: DownloadProgress| {
                progress.push(update);
            };
            let result = download_client
                .download_range_to_writer_with_progress(
                    DownloadRangeRequest {
                        key: "large.bin",
                        snapshot: None,
                        version: None,
                        range: RequestedRange {
                            offset: 0,
                            length: payload_len as u64,
                        },
                    },
                    &mut output,
                    &mut on_progress,
                    &|| false,
                )
                .await
                .expect("streamed download should succeed");
            (output, progress, result)
        };
        let rpc_future = async {
            tokio::time::sleep(std::time::Duration::from_millis(40)).await;
            tokio::time::timeout(
                std::time::Duration::from_millis(250),
                client.get_json_path("/cluster/status"),
            )
            .await
            .expect("small RPC should not be blocked behind streamed download")
            .expect("small RPC should succeed")
        };
        let ((output, progress, result), rpc_response) = tokio::join!(download_future, rpc_future);

        assert_eq!(rpc_response["status"], "ok");
        assert_eq!(output.len(), payload_len);
        assert_eq!(result.bytes_downloaded, payload_len as u64);
        assert!(
            progress
                .last()
                .is_some_and(|entry| entry.bytes_downloaded == payload_len as u64)
        );
        let snapshot = client.transport_session_pool_snapshot();
        assert_eq!(snapshot.connect_count, 1);
        assert!(snapshot.reuse_count >= 2);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn direct_transport_cancels_streamed_download_promptly() {
        let payload = Arc::new(vec![0x3C; 1024 * 1024]);
        let payload_len = payload.len();
        let (base_url, server) =
            spawn_direct_mixed_workload_test_server(Arc::clone(&payload)).await;

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("direct-cancel-download-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let client = IronMeshClient::from_direct_base_url(base_url).with_client_identity(identity);

        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_for_task = Arc::clone(&cancel);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            cancel_for_task.store(true, Ordering::SeqCst);
        });

        let mut output = Vec::new();
        let result = client
            .download_range_to_writer_with_progress(
                DownloadRangeRequest {
                    key: "large.bin",
                    snapshot: None,
                    version: None,
                    range: RequestedRange {
                        offset: 0,
                        length: payload_len as u64,
                    },
                },
                &mut output,
                &mut |_| {},
                &|| cancel.load(Ordering::SeqCst),
            )
            .await;

        let error = result.expect_err("streamed download should cancel");
        assert!(error.to_string().contains("download canceled"));
        assert!(output.len() < payload_len);

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn blocking_range_download_handles_concurrent_overlapping_requests() {
        fn build_range_response(
            payload: &[u8],
            status: StatusCode,
            start: usize,
            end_inclusive: usize,
        ) -> Response<Body> {
            Response::builder()
                .status(status)
                .header("x-ironmesh-object-size", payload.len().to_string())
                .header(ETAG.as_str(), "\"test-etag\"")
                .header(ACCEPT_RANGES.as_str(), "bytes")
                .header(
                    CONTENT_LENGTH.as_str(),
                    (end_inclusive - start + 1).to_string(),
                )
                .header(
                    CONTENT_RANGE.as_str(),
                    format!("bytes {start}-{end_inclusive}/{}", payload.len()),
                )
                .body(Body::from(payload[start..=end_inclusive].to_vec()))
                .expect("range response should build")
        }

        fn parse_range_header(range: &str, total_len: usize) -> (usize, usize) {
            let trimmed = range
                .strip_prefix("bytes=")
                .expect("range header should have bytes= prefix");
            let (start, end) = trimmed
                .split_once('-')
                .expect("range header should contain dash");
            let start = start.parse::<usize>().expect("range start should parse");
            let end = end.parse::<usize>().expect("range end should parse");
            assert!(start <= end, "range start must not exceed end");
            assert!(end < total_len, "range end must stay within payload");
            (start, end)
        }

        async fn head_store(
            State(payload): State<Arc<Vec<u8>>>,
            AxumPath(_key): AxumPath<String>,
        ) -> Response<Body> {
            Response::builder()
                .status(StatusCode::OK)
                .header("x-ironmesh-object-size", payload.len().to_string())
                .header(ETAG.as_str(), "\"test-etag\"")
                .header(ACCEPT_RANGES.as_str(), "bytes")
                .header(CONTENT_LENGTH.as_str(), payload.len().to_string())
                .body(Body::empty())
                .expect("head response should build")
        }

        async fn get_store(
            State(payload): State<Arc<Vec<u8>>>,
            AxumPath(_key): AxumPath<String>,
            headers: HeaderMap,
        ) -> Response<Body> {
            tokio::time::sleep(Duration::from_millis(20)).await;

            match headers.get(RANGE).and_then(|value| value.to_str().ok()) {
                Some(range) => {
                    let (start, end_inclusive) = parse_range_header(range, payload.len());
                    build_range_response(
                        &payload,
                        StatusCode::PARTIAL_CONTENT,
                        start,
                        end_inclusive,
                    )
                }
                None => Response::builder()
                    .status(StatusCode::OK)
                    .header("x-ironmesh-object-size", payload.len().to_string())
                    .header(ETAG.as_str(), "\"test-etag\"")
                    .header(ACCEPT_RANGES.as_str(), "bytes")
                    .header(header::CONTENT_LENGTH, payload.len().to_string())
                    .body(Body::from(payload.as_ref().clone()))
                    .expect("full response should build"),
            }
        }

        let payload = Arc::new(
            (0..200_000)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
        );

        let app = Router::new()
            .route("/api/v1/store/{*key}", get(get_store).head(head_store))
            .with_state(payload.clone());
        let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("listener should bind");
                addr_tx
                    .send(listener.local_addr().expect("listener should have addr"))
                    .expect("server addr should send");
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("range server should run");
            });
        });

        let addr = addr_rx.recv().expect("server addr should arrive");
        let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
        let requests = [
            (0_u64, 65_536_u64),
            (65_536_u64, 4_096_u64),
            (69_632_u64, 61_440_u64),
            (131_072_u64, payload.len() as u64 - 131_072_u64),
        ];

        for _round in 0..8 {
            let barrier = Arc::new(Barrier::new(requests.len()));
            let mut handles = Vec::new();
            for (start, length) in requests {
                let client = client.clone();
                let barrier = barrier.clone();
                let expected = payload[start as usize..(start + length) as usize].to_vec();
                handles.push(std::thread::spawn(move || {
                    let mut writer = Vec::new();
                    let mut progress_updates = Vec::new();
                    barrier.wait();
                    let result = client
                        .download_range_to_writer_with_progress_blocking(
                            DownloadRangeRequest {
                                key: "photos/test.jpg",
                                snapshot: None,
                                version: None,
                                range: RequestedRange {
                                    offset: start,
                                    length,
                                },
                            },
                            &mut writer,
                            &mut |progress| progress_updates.push(progress),
                            &|| false,
                        )
                        .expect("blocking ranged download should succeed");
                    assert_eq!(writer, expected);
                    assert_eq!(result.range.offset, start);
                    assert_eq!(result.range.length, length);
                    assert_eq!(result.bytes_downloaded, length);
                    assert!(
                        progress_updates
                            .last()
                            .is_some_and(|progress| progress.bytes_downloaded == length),
                        "final progress update should report the completed byte count",
                    );
                }));
            }

            for handle in handles {
                handle.join().expect("download worker should complete");
            }
        }

        let _ = shutdown_tx.send(());
        server_thread.join().expect("server thread should stop");
    }
}
