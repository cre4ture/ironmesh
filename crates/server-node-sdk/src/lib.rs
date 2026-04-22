use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::ws::{Message as AxumWsMessage, WebSocket as AxumWebSocket};
use axum::extract::{Path, Query, Request, State, WebSocketUpgrade};
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_server::Handle;
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use bytes::Bytes;
use common::traced_rwlock::{
    TracedRwLock, TracedRwLockConfig, TracedRwLockReadGuard, TracedRwLockWriteGuard,
};
use common::{ClusterId, DeviceId, HealthStatus, NodeId};
use futures_util::io::{
    AsyncReadExt as FuturesAsyncReadExt, AsyncWriteExt as FuturesAsyncWriteExt,
};
use futures_util::{Sink, Stream};
use http_body_util::BodyExt;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SanType,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{OtherError, RootCertStore, SignatureScheme};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use time::OffsetDateTime;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use tower::Service;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use transport_sdk::{
    BootstrapClaimBroker, BootstrapEndpoint, BootstrapEndpointUse, BootstrapMutualTlsMaterial,
    BootstrapServerTlsFiles, BootstrapTlsFiles, BootstrapTlsMaterialMetadata, BootstrapTrustRoots,
    BufferedTransportRequest, BufferedTransportResponse, CLIENT_BOOTSTRAP_CLAIM_VERSION,
    CandidateKind, ClientBootstrap as TransportClientBootstrap, ClientBootstrapClaim,
    ClientBootstrapClaimIssueResponse, ClientBootstrapClaimPublishRequest,
    ClientBootstrapClaimRedeemRequest, ClientBootstrapClaimRedeemResponse,
    ClientBootstrapClaimTrust, ClientEnrollmentRequest, ConnectionCandidate, MultiplexConfig,
    MultiplexMode, MultiplexedSession, NodeBootstrap as TransportNodeBootstrap, NodeBootstrapMode,
    NodeEnrollmentPackage, NodeJoinRequest, PeerIdentity, PeerTransportClient,
    PeerTransportClientConfig, PresenceRegistration, RelayHttpHeader, RelayMode,
    RelayTicketRequest, RelayTunnelAcceptRequest, RelayTunnelSession, RelayTunnelSessionKind,
    RendezvousClientConfig, RendezvousControlClient, SignedRequestHeaders,
    TRANSPORT_PROTOCOL_VERSION, TransportCapability, TransportHeader, TransportPathKind,
    TransportRequestHead, TransportResponseHead, TransportSessionControlMessage,
    TransportSessionRole, TransportStreamKind, credential_fingerprint,
    perform_transport_client_handshake, perform_transport_server_handshake,
    read_buffered_transport_response, read_transport_request_head, verify_signed_request_headers,
    write_buffered_transport_request, write_buffered_transport_response,
    write_transport_response_head,
};
use uuid::Uuid;

const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_REVISION: &str =
    git_version::git_version!(fallback = "unknown", args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);
const STORAGE_STATS_REFRESH_INTERVAL_SECS: u64 = 300;
const STORAGE_STATS_CHANGE_DEBOUNCE_SECS: u64 = 15;
const LARGE_RELAY_HTTP_RESPONSE_LOG_THRESHOLD_BYTES: usize = 512 * 1024;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

mod cluster;
mod embedded_rendezvous;
mod replication;
mod setup;
mod storage;
mod transport_service;
mod ui;
mod web_maps;

const QUERY_COMPONENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'&')
    .add(b'+')
    .add(b'/')
    .add(b'=')
    .add(b'?');
const RENDEZVOUS_REGISTRATION_RETRY_INTERVAL_SECS: u64 = 1;
const RENDEZVOUS_REGISTRATION_REQUEST_TIMEOUT_SECS: u64 = 5;
const DIRECT_PEER_REQUEST_TIMEOUT_SECS: u64 = 30;
const DIRECT_PEER_REPAIR_REQUEST_TIMEOUT_SECS: u64 = 300;
const REPAIR_LOCAL_AVAILABILITY_SYNC_TIMEOUT_SECS: u64 = 30;
const OBJECT_RESPONSE_STREAM_CHUNK_SIZE_BYTES: usize = 64 * 1024;
const STORAGE_STATS_RECONCILE_INTERVAL_SECS: u64 = 60 * 60;
const STORAGE_STATS_HISTORY_RETENTION_SECS: u64 = 90 * 24 * 60 * 60;
const MAX_STORAGE_STATS_HISTORY_LIMIT: usize = 250_000;
const MAX_STORAGE_STATS_HISTORY_POINTS: usize = 4_096;
const DATA_SCRUB_INTERVAL_SECS: u64 = 7 * 24 * 60 * 60;
const DATA_SCRUB_HISTORY_RETENTION_SECS: u64 = 12 * 30 * 24 * 60 * 60;
const MAX_DATA_SCRUB_HISTORY_LIMIT: usize = 4_096;
const REPAIR_RUN_HISTORY_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;
const MAX_REPAIR_RUN_HISTORY_LIMIT: usize = 4_096;
const UPLOAD_SESSION_PERSIST_INACTIVITY_SECS: u64 = 60;
const DEFAULT_REPLICA_VIEW_SYNC_INTERVAL_SECS: u64 = 30;
const SLOW_UPLOAD_CHUNK_LOG_THRESHOLD_MS: u128 = 250;
const SLOW_UPLOAD_FINALIZE_LOG_THRESHOLD_MS: u128 = 500;
const SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS: u128 = 500;
const SLOW_STORE_LOCK_HOLD_LOG_THRESHOLD_MS: u128 = 500;
const SLOW_SERVER_STARTUP_PHASE_LOG_THRESHOLD_MS: u128 = 500;
const SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS: u128 = 250;
const SLOW_STORE_INDEX_PHASE_LOG_THRESHOLD_MS: u128 = 250;
const MAX_LATENCY_DIAGNOSTIC_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_LATENCY_DIAGNOSTIC_SERVER_DELAY_MS: u64 = 5_000;
pub(crate) const PUBLIC_API_V1_PREFIX: &str = "/api/v1";
const PUBLIC_API_V1_MEDIA_THUMBNAIL_ROUTE: &str = "/api/v1/media/thumbnail";
const PUBLIC_API_V1_ADMIN_MEDIA_THUMBNAIL_ROUTE: &str = "/api/v1/auth/media/thumbnail";
const ALLOW_INSECURE_PUBLIC_HTTP_ENV: &str = "IRONMESH_ALLOW_INSECURE_PUBLIC_HTTP";
const ALLOW_UNAUTHENTICATED_CLIENTS_ENV: &str = "IRONMESH_ALLOW_UNAUTHENTICATED_CLIENTS";

use cluster::{
    ClusterService, NodeCapabilities, NodeDescriptor, NodeReachability, NodeStorageStatsSummary,
    ReplicationPlan, ReplicationPolicy,
};
use setup::{
    ManagedRendezvousFailoverPackage, ManagedSignerBackup,
    export_managed_rendezvous_failover_package, export_managed_signer_backup,
    import_managed_rendezvous_failover_package, import_managed_signer_backup,
    issue_managed_rendezvous_tls_identity_from_ca, managed_rendezvous_cert_path,
    managed_rendezvous_key_path, managed_signer_ca_cert_path,
};
use storage::{
    AdminAuditEvent, ChunkIngestor, ClientCredentialRecord, ClientCredentialState, DataScrubReport,
    MediaCacheLookup, MediaCacheStatus, MediaGpsCoordinates, MetadataBackendKind,
    MetadataExportBundle, ObjectReadDescriptor, ObjectReadMode, ObjectStreamPlan,
    PairingAuthorizationRecord, PathMutationResult, PersistentStore, PutOptions,
    ReconcileVersionEntry, RepairAttemptRecord, ReplicationChunkInfo,
    SnapshotRestoreMutationResult, StorageStatsSample, StoreReadError, TOMBSTONE_MANIFEST_HASH,
    UploadChunkRef, VersionConsistencyState,
};
#[derive(Clone)]
struct ServerState {
    data_dir: PathBuf,
    cluster_id: ClusterId,
    node_id: NodeId,
    storage_stats_history_retention_secs: u64,
    data_scrub_enabled: bool,
    data_scrub_interval_secs: u64,
    data_scrub_history_retention_secs: u64,
    repair_run_history_retention_secs: u64,
    map_perf_logging_enabled: bool,
    map_glyphs_root: Option<PathBuf>,
    mbtiles_sources: Arc<RwLock<HashMap<String, Arc<web_maps::LogicalMbtilesSource>>>>,
    store: Arc<TracedRwLock<PersistentStore>>,
    upload_chunk_ingestor: ChunkIngestor,
    cluster: Arc<Mutex<ClusterService>>,
    client_credentials: Arc<Mutex<ClientCredentialState>>,
    bootstrap_claims: BootstrapClaimBroker,
    upload_sessions: Arc<TracedRwLock<UploadSessionStore>>,
    upload_sessions_dirty: Arc<AtomicUsize>,
    upload_sessions_persist_notify: Arc<Notify>,
    public_ca_pem: Option<String>,
    public_ca_key_pem: Option<String>,
    cluster_ca_pem: Option<String>,
    internal_ca_key_pem: Option<String>,
    public_tls_runtime: Option<PublicTlsRuntime>,
    internal_tls_runtime: Option<InternalTlsRuntime>,
    rendezvous_ca_pem: Option<String>,
    rendezvous_urls: Arc<StdMutex<Vec<String>>>,
    rendezvous_registration_enabled: bool,
    rendezvous_mtls_required: bool,
    managed_rendezvous_public_url: Option<String>,
    rendezvous_registration_state:
        Arc<Mutex<HashMap<String, RendezvousEndpointRegistrationRuntime>>>,
    relay_mode: RelayMode,
    enrollment_issuer_url: Option<String>,
    node_enrollment_path: Option<PathBuf>,
    node_enrollment_auto_renew_enabled: bool,
    node_enrollment_auto_renew_check_secs: u64,
    node_enrollment_auto_renew_state: Arc<Mutex<NodeEnrollmentAutoRenewState>>,
    outbound_clients: Arc<RwLock<OutboundClients>>,
    peer_relay_sessions: PeerRelaySessionPool,
    metadata_commit_mode: MetadataCommitMode,
    autonomous_replication_on_put_enabled: bool,
    inflight_requests: Arc<AtomicUsize>,
    peer_heartbeat_config: PeerHeartbeatConfig,
    repair_config: RepairConfig,
    log_buffer: Arc<LogBuffer>,
    startup_repair_status: Arc<Mutex<StartupRepairStatus>>,
    repair_state: Arc<Mutex<RepairExecutorState>>,
    repair_activity: Arc<Mutex<RepairActivityRuntime>>,
    data_scrub_activity: Arc<Mutex<DataScrubActivityRuntime>>,
    local_availability_refresh_lock: Arc<Mutex<()>>,
    local_availability_refresh_notify: Arc<Notify>,
    storage_stats_runtime: Arc<Mutex<StorageStatsRuntime>>,
    namespace_change_sequence: Arc<AtomicU64>,
    namespace_change_tx: watch::Sender<u64>,
    admin_control: AdminControl,
    admin_sessions: Arc<Mutex<AdminSessionStore>>,
    client_auth_control: ClientAuthControl,
    client_auth_replay_cache: Arc<Mutex<ClientAuthReplayCache>>,
}

fn new_store_rwlock(store: PersistentStore) -> Arc<TracedRwLock<PersistentStore>> {
    Arc::new(TracedRwLock::new(
        "store",
        store,
        TracedRwLockConfig::new(
            Duration::from_millis(SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS as u64),
            Duration::from_secs(1),
            Duration::from_millis(SLOW_STORE_LOCK_HOLD_LOG_THRESHOLD_MS as u64),
        ),
    ))
}

async fn lock_store<'a>(
    state: &'a ServerState,
    operation: &'static str,
) -> TracedRwLockWriteGuard<'a, PersistentStore> {
    state.store.write(operation).await
}

async fn read_store<'a>(
    state: &'a ServerState,
    operation: &'static str,
) -> TracedRwLockReadGuard<'a, PersistentStore> {
    state.store.read(operation).await
}

fn new_upload_sessions_rwlock(store: UploadSessionStore) -> Arc<TracedRwLock<UploadSessionStore>> {
    Arc::new(TracedRwLock::new(
        "upload_sessions",
        store,
        TracedRwLockConfig::new(
            Duration::from_millis(SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS as u64),
            Duration::from_secs(1),
            Duration::from_millis(SLOW_STORE_LOCK_HOLD_LOG_THRESHOLD_MS as u64),
        ),
    ))
}

async fn write_upload_sessions<'a>(
    state: &'a ServerState,
    operation: &'static str,
) -> TracedRwLockWriteGuard<'a, UploadSessionStore> {
    state.upload_sessions.write(operation).await
}

#[cfg(test)]
async fn read_upload_sessions<'a>(
    state: &'a ServerState,
    operation: &'static str,
) -> TracedRwLockReadGuard<'a, UploadSessionStore> {
    state.upload_sessions.read(operation).await
}

fn log_server_startup_phase_begin(phase: &'static str, startup_started_at: Instant) -> Instant {
    info!(
        phase,
        since_metadata_init_ms = startup_started_at.elapsed().as_millis(),
        "server startup phase begin"
    );
    Instant::now()
}

fn log_server_startup_phase_end(
    phase: &'static str,
    startup_started_at: Instant,
    phase_started_at: Instant,
) {
    let phase_ms = phase_started_at.elapsed().as_millis();
    let since_metadata_init_ms = startup_started_at.elapsed().as_millis();
    if phase_ms >= SLOW_SERVER_STARTUP_PHASE_LOG_THRESHOLD_MS {
        warn!(
            phase,
            phase_ms, since_metadata_init_ms, "slow server startup phase"
        );
    } else {
        info!(
            phase,
            phase_ms, since_metadata_init_ms, "server startup phase complete"
        );
    }
}

fn request_local_availability_refresh(state: &ServerState) {
    state.local_availability_refresh_notify.notify_one();
}

async fn run_local_availability_refresh(
    state: &ServerState,
    trigger: &'static str,
    startup_started_at: Option<Instant>,
) {
    let refresh_started_at = Instant::now();
    let subject_count = refresh_local_availability_view_once(state).await;
    let total_ms = refresh_started_at.elapsed().as_millis();

    if let Some(startup_started_at) = startup_started_at {
        let since_metadata_init_ms = startup_started_at.elapsed().as_millis();
        if total_ms >= SLOW_SERVER_STARTUP_PHASE_LOG_THRESHOLD_MS {
            warn!(
                trigger,
                subject_count,
                total_ms,
                since_metadata_init_ms,
                "slow background local availability refresh"
            );
        } else {
            info!(
                trigger,
                subject_count,
                total_ms,
                since_metadata_init_ms,
                "background local availability refresh complete"
            );
        }
    } else if total_ms >= SLOW_SERVER_STARTUP_PHASE_LOG_THRESHOLD_MS {
        warn!(
            trigger,
            subject_count, total_ms, "slow background local availability refresh"
        );
    } else {
        info!(
            trigger,
            subject_count, total_ms, "background local availability refresh complete"
        );
    }
}

fn spawn_local_availability_refresher(state: ServerState, startup_started_at: Instant) {
    tokio::spawn(async move {
        run_local_availability_refresh(&state, "startup", Some(startup_started_at)).await;

        loop {
            state.local_availability_refresh_notify.notified().await;
            run_local_availability_refresh(&state, "queued", None).await;
        }
    });
}

#[derive(Clone)]
struct PublicTlsRuntime {
    config: RustlsConfig,
    cert_path: PathBuf,
    key_path: PathBuf,
    metadata_path: Option<PathBuf>,
}

#[derive(Clone)]
struct OutboundClients {
    #[cfg(test)]
    internal_http: reqwest::Client,
    rendezvous_control: Option<RendezvousControlClient>,
    rendezvous_controls: Vec<RendezvousEndpointClient>,
}

#[derive(Clone, Default)]
struct PeerRelaySessionPool {
    sessions: Arc<Mutex<HashMap<NodeId, CachedPeerRelaySession>>>,
}

#[derive(Clone)]
struct CachedPeerRelaySession {
    session: Arc<MultiplexedSession>,
    relay_session: RelayTunnelSession,
}

struct EstablishedPeerRelaySession {
    session: MultiplexedSession,
    relay_session: RelayTunnelSession,
}

#[derive(Clone)]
struct RendezvousEndpointClient {
    url: String,
    control: RendezvousControlClient,
}

#[derive(Debug, Clone, Default)]
struct RendezvousEndpointRegistrationRuntime {
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    consecutive_failures: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RendezvousEndpointRegistrationStatus {
    Pending,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, Serialize)]
struct RendezvousEndpointRegistrationView {
    url: String,
    status: RendezvousEndpointRegistrationStatus,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    consecutive_failures: u64,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum RendezvousConfigPersistenceSource {
    NodeEnrollment,
    RuntimeOnly,
}

#[derive(Clone)]
struct LiveTrustMaterial {
    public_ca_pem: Option<String>,
    public_ca_key_pem: Option<String>,
    cluster_ca_pem: Option<String>,
    internal_ca_key_pem: Option<String>,
    rendezvous_ca_pem: Option<String>,
}

#[derive(Clone)]
struct InternalTlsRuntime {
    config: RustlsConfig,
    ca_cert_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    metadata_path: Option<PathBuf>,
}

pub(crate) fn publish_namespace_change(state: &ServerState) {
    let sequence = state
        .namespace_change_sequence
        .fetch_add(1, Ordering::SeqCst)
        .saturating_add(1);
    let _ = state.namespace_change_tx.send(sequence);
}

#[derive(Debug, Clone)]
struct InternalCaller {
    node_id: NodeId,
    cluster_id: ClusterId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCertificateIdentity {
    node_id: NodeId,
    cluster_id: Option<ClusterId>,
}

#[derive(Debug, Clone, Default)]
struct ClientAuthControl {
    require_client_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadSessionRecord {
    upload_id: String,
    owner_device_id: Option<String>,
    key: String,
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    state: VersionConsistencyState,
    parent_version_ids: Vec<String>,
    explicit_version_id: Option<String>,
    received_chunks: Vec<Option<UploadChunkRef>>,
    created_at_unix: u64,
    updated_at_unix: u64,
    expires_at_unix: u64,
    #[serde(default)]
    finalizing: bool,
    completed: bool,
    completed_result: Option<UploadSessionCompleteResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UploadSessionFile {
    #[serde(default)]
    sessions: HashMap<String, UploadSessionRecord>,
}

#[derive(Debug)]
struct UploadSessionStore {
    path: PathBuf,
    sessions: HashMap<String, UploadSessionRecord>,
}

#[derive(Debug, Deserialize)]
struct UploadSessionStartRequest {
    key: String,
    total_size_bytes: u64,
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    version_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LatencyDiagnosticQuery {
    response_bytes: Option<usize>,
    server_delay_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadSessionView {
    upload_id: String,
    key: String,
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    received_indexes: Vec<usize>,
    expires_at_unix: u64,
    completed: bool,
    completed_result: Option<UploadSessionCompleteResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadSessionChunkResponse {
    stored: bool,
    received_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UploadSessionCompleteResponse {
    snapshot_id: String,
    version_id: String,
    manifest_hash: String,
    state: VersionConsistencyState,
    new_chunks: usize,
    dedup_reused_chunks: usize,
    created_new_version: bool,
    total_size_bytes: u64,
}

#[derive(Debug, Default)]
struct ClientAuthReplayCache {
    seen_requests: HashMap<String, u64>,
}

#[derive(Debug, Default, Clone)]
struct NodeEnrollmentAutoRenewState {
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
    loaded_public_tls_fingerprint: Option<String>,
    loaded_internal_tls_fingerprint: Option<String>,
}

impl ClientAuthReplayCache {
    fn remember(&mut self, device_id: &str, nonce: &str, now: u64) -> bool {
        self.prune(now);
        self.seen_requests
            .insert(format!("{device_id}:{nonce}"), now)
            .is_none()
    }

    fn prune(&mut self, now: u64) {
        let oldest_allowed = now.saturating_sub(CLIENT_AUTH_MAX_CLOCK_SKEW_SECS * 2);
        self.seen_requests
            .retain(|_, seen_at| *seen_at >= oldest_allowed);
    }
}

fn upload_sessions_path(data_dir: &FsPath) -> PathBuf {
    data_dir.join("state").join("upload_sessions.json")
}

async fn load_upload_session_store(data_dir: &FsPath) -> Result<UploadSessionStore> {
    let path = upload_sessions_path(data_dir);
    if !tokio::fs::try_exists(&path).await? {
        return Ok(UploadSessionStore {
            path,
            sessions: HashMap::new(),
        });
    }

    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_slice::<UploadSessionFile>(&payload)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(UploadSessionStore {
        path,
        sessions: parsed.sessions,
    })
}

async fn persist_upload_session_store(store: &UploadSessionStore) -> Result<()> {
    let payload = serde_json::to_vec_pretty(&UploadSessionFile {
        sessions: store.sessions.clone(),
    })
    .context("failed encoding upload session state")?;
    write_json_atomic(&store.path, &payload).await
}

fn mark_upload_session_store_dirty(state: &ServerState) {
    state.upload_sessions_dirty.fetch_add(1, Ordering::SeqCst);
    state.upload_sessions_persist_notify.notify_one();
}

async fn persist_upload_session_store_after_mutation(state: &ServerState, context: &'static str) {
    if let Err(err) = persist_upload_session_store_now(state).await {
        warn!(error = %err, context, "failed to persist upload session state");
        mark_upload_session_store_dirty(state);
    }
}

async fn persist_upload_session_store_now(state: &ServerState) -> Result<()> {
    let now = unix_ts();
    let mut sessions =
        write_upload_sessions(state, "upload_sessions.persist_now.prune_and_persist").await;
    prune_expired_upload_sessions(&mut sessions, now);
    persist_upload_session_store(&sessions).await
}

fn spawn_upload_session_store_persister(state: ServerState) {
    tokio::spawn(async move {
        let mut persisted_generation = state.upload_sessions_dirty.load(Ordering::SeqCst);

        loop {
            state.upload_sessions_persist_notify.notified().await;

            loop {
                let observed_generation = state.upload_sessions_dirty.load(Ordering::SeqCst);
                let sleep =
                    tokio::time::sleep(Duration::from_secs(UPLOAD_SESSION_PERSIST_INACTIVITY_SECS));
                tokio::pin!(sleep);
                tokio::select! {
                    _ = &mut sleep => {}
                    _ = state.upload_sessions_persist_notify.notified() => {
                        continue;
                    }
                }
                let stable_generation = state.upload_sessions_dirty.load(Ordering::SeqCst);
                if stable_generation != observed_generation {
                    continue;
                }
                if stable_generation == persisted_generation {
                    break;
                }

                match persist_upload_session_store_now(&state).await {
                    Ok(()) => {
                        persisted_generation = stable_generation;
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to persist debounced upload session state");
                        state.upload_sessions_persist_notify.notify_one();
                    }
                }
                break;
            }
        }
    });
}

fn prune_expired_upload_sessions(store: &mut UploadSessionStore, now: u64) {
    store
        .sessions
        .retain(|_, session| session.expires_at_unix > now);
}

fn upload_session_view(session: &UploadSessionRecord) -> UploadSessionView {
    UploadSessionView {
        upload_id: session.upload_id.clone(),
        key: session.key.clone(),
        total_size_bytes: session.total_size_bytes,
        chunk_size_bytes: session.chunk_size_bytes,
        chunk_count: session.chunk_count,
        received_indexes: session
            .received_chunks
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| entry.as_ref().map(|_| index))
            .collect(),
        expires_at_unix: session.expires_at_unix,
        completed: session.completed,
        completed_result: session.completed_result.clone(),
    }
}

fn expected_upload_chunk_size(
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    index: usize,
) -> Option<usize> {
    if chunk_count == 0 {
        return None;
    }
    if index >= chunk_count {
        return None;
    }
    if index + 1 < chunk_count {
        return Some(chunk_size_bytes);
    }
    let consumed = (chunk_count.saturating_sub(1) as u64) * chunk_size_bytes as u64;
    Some(total_size_bytes.saturating_sub(consumed) as usize)
}

fn request_device_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(transport_sdk::HEADER_DEVICE_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

impl AdminSessionStore {
    fn create_session(&mut self, now: u64) -> (String, u64) {
        self.prune(now);
        let session_id = format!(
            "im-admin-{}-{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let expires_at_unix = now.saturating_add(ADMIN_SESSION_TTL_SECS);
        self.sessions.insert(session_id.clone(), expires_at_unix);
        (session_id, expires_at_unix)
    }

    fn is_valid(&mut self, session_id: &str, now: u64) -> Option<u64> {
        self.prune(now);
        self.sessions.get(session_id).copied()
    }

    fn revoke(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    fn prune(&mut self, now: u64) {
        self.sessions
            .retain(|_, expires_at_unix| *expires_at_unix > now);
    }
}

const CLIENT_AUTH_MAX_CLOCK_SKEW_SECS: u64 = 300;
const ADMIN_SESSION_TTL_SECS: u64 = 12 * 60 * 60;
const UPLOAD_SESSION_TTL_SECS: u64 = 24 * 60 * 60;

impl<S> FromRequestParts<S> for InternalCaller
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, &'static str);

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        std::future::ready(
            parts
                .extensions
                .get::<InternalCaller>()
                .cloned()
                .ok_or((StatusCode::UNAUTHORIZED, "missing internal caller identity")),
        )
    }
}

async fn require_internal_caller(
    State(_state): State<ServerState>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    if request.extensions().get::<InternalCaller>().is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

async fn require_client_auth(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    if !state.client_auth_control.require_client_auth {
        return Ok(next.run(request).await);
    }

    let request_headers = request.headers().clone();
    let request_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_string();
    let request_method = request.method().as_str().to_string();

    validate_client_auth_request(
        &state,
        &request_headers,
        &request_method,
        &request_path_and_query,
    )
    .await?;

    Ok(next.run(request).await)
}

async fn require_client_or_admin_auth(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    let request_headers = request.headers().clone();
    if request_has_admin_auth(&state, &request_headers).await {
        return Ok(next.run(request).await);
    }

    if !state.client_auth_control.require_client_auth {
        return Ok(next.run(request).await);
    }

    let request_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_string();
    let request_method = request.method().as_str().to_string();

    validate_client_auth_request(
        &state,
        &request_headers,
        &request_method,
        &request_path_and_query,
    )
    .await?;

    Ok(next.run(request).await)
}

async fn validate_client_auth_request(
    state: &ServerState,
    headers: &HeaderMap,
    request_method: &str,
    request_path_and_query: &str,
) -> std::result::Result<(), StatusCode> {
    let signed_headers = SignedRequestHeaders::from_header_lookup(|name| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
    })
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if signed_headers.cluster_id != state.cluster_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let now = unix_ts();
    if signed_headers.timestamp_unix < now.saturating_sub(CLIENT_AUTH_MAX_CLOCK_SKEW_SECS)
        || signed_headers.timestamp_unix > now.saturating_add(CLIENT_AUTH_MAX_CLOCK_SKEW_SECS)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let (public_key_pem, stored_credential_fingerprint) = {
        let auth_state = state.client_credentials.lock().await;
        let Some(device) = auth_state.credentials.iter().find(|device| {
            device.revoked_at_unix.is_none() && device.device_id == signed_headers.device_id
        }) else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let Some(public_key_pem) = device.public_key_pem.clone() else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let stored_credential_fingerprint = match (
            device.credential_fingerprint.as_deref(),
            device.issued_credential_pem.as_deref(),
        ) {
            (Some(fingerprint), _) if !fingerprint.trim().is_empty() => fingerprint.to_string(),
            (_, Some(issued_credential_pem)) => credential_fingerprint(issued_credential_pem)
                .map_err(|_| StatusCode::UNAUTHORIZED)?,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        (public_key_pem, stored_credential_fingerprint)
    };

    if stored_credential_fingerprint != signed_headers.credential_fingerprint {
        return Err(StatusCode::UNAUTHORIZED);
    }
    verify_signed_request_headers(
        &signed_headers,
        &public_key_pem,
        request_method,
        request_path_and_query,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut replay_cache = state.client_auth_replay_cache.lock().await;
    if !replay_cache.remember(&signed_headers.device_id, &signed_headers.nonce, now) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    drop(replay_cache);

    Ok(())
}

async fn request_has_admin_auth(state: &ServerState, headers: &HeaderMap) -> bool {
    state
        .admin_control
        .admin_token
        .as_deref()
        .map(|expected| {
            token_matches(
                expected,
                headers
                    .get(ADMIN_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok()),
            )
        })
        .unwrap_or(false)
        || current_admin_session_expiry(state, headers).await.is_some()
}

fn admin_auth_configured(state: &ServerState) -> bool {
    state.admin_control.admin_password_hash.is_some() || state.admin_control.admin_token.is_some()
}

fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

fn generate_pairing_token() -> String {
    format!(
        "im-pair-{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn generate_client_credential_pem(
    cluster_id: ClusterId,
    device_id: &str,
    public_key_pem: &str,
    issued_at_unix: u64,
    expires_at_unix: Option<u64>,
) -> String {
    let public_key_fingerprint = blake3::hash(public_key_pem.as_bytes()).to_hex().to_string();
    let expires_at_unix = expires_at_unix
        .map(|value| value.to_string())
        .unwrap_or_else(|| "never".to_string());
    format!(
        "-----BEGIN IRONMESH CLIENT CREDENTIAL-----\ncluster_id={cluster_id}\ndevice_id={device_id}\nissued_at_unix={issued_at_unix}\nexpires_at_unix={expires_at_unix}\npublic_key_fingerprint={public_key_fingerprint}\n-----END IRONMESH CLIENT CREDENTIAL-----\n"
    )
}

fn text_fingerprint(value: &str) -> String {
    blake3::hash(value.trim().as_bytes()).to_hex().to_string()
}

fn validate_rendezvous_client_identity_issuance(state: &ServerState) -> Result<()> {
    if !state.rendezvous_mtls_required {
        return Ok(());
    }
    if state.cluster_ca_pem.as_deref().is_none() {
        bail!("rendezvous mTLS client identity issuance requires cluster_ca_pem");
    }
    if state.internal_ca_key_pem.as_deref().is_none() {
        bail!("rendezvous mTLS client identity issuance requires internal_ca_key_pem");
    }
    Ok(())
}

fn ensure_client_enrollment_issuance_available(
    state: &ServerState,
) -> std::result::Result<(), (StatusCode, String)> {
    validate_rendezvous_client_identity_issuance(state).map_err(|err| {
        (
            StatusCode::PRECONDITION_FAILED,
            format!("client enrollment issuance is unavailable on this node: {err}"),
        )
    })
}

fn issue_client_rendezvous_identity_pem(
    state: &ServerState,
    device_id: &str,
    expires_at_unix: Option<u64>,
) -> Result<Option<String>> {
    if !state.rendezvous_mtls_required {
        return Ok(None);
    }

    validate_rendezvous_client_identity_issuance(state)?;

    let ca_cert_pem = state.cluster_ca_pem.as_deref().ok_or_else(|| {
        anyhow!("rendezvous mTLS client identity issuance requires cluster_ca_pem")
    })?;
    let ca_key_pem = state.internal_ca_key_pem.as_deref().ok_or_else(|| {
        anyhow!("rendezvous mTLS client identity issuance requires internal_ca_key_pem")
    })?;

    let issuer_key =
        KeyPair::from_pem(ca_key_pem).context("failed to parse rendezvous client CA key PEM")?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key)
        .context("failed to build rendezvous client certificate issuer")?;

    let issued_at_unix = unix_ts();
    let not_after_unix = expires_at_unix
        .filter(|value| *value > issued_at_unix)
        .unwrap_or_else(|| issued_at_unix + (30 * 24 * 60 * 60));

    let mut params =
        CertificateParams::new(Vec::new()).context("failed to initialize client cert params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("ironmesh-device-{device_id}"));
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(issued_at_unix as i64)
        .context("invalid rendezvous client cert not_before timestamp")?;
    params.not_after = OffsetDateTime::from_unix_timestamp(not_after_unix as i64)
        .context("invalid rendezvous client cert not_after timestamp")?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = vec![SanType::URI(
        format!("urn:ironmesh:device:{device_id}")
            .try_into()
            .context("invalid rendezvous client SAN URI")?,
    )];

    let key_pair = KeyPair::generate().context("failed generating rendezvous client key")?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .context("failed signing rendezvous client certificate")?;
    Ok(Some(format!("{}{}", cert.pem(), key_pair.serialize_pem())))
}

#[derive(Clone)]
struct WithInternalCaller<S> {
    inner: S,
    caller: InternalCaller,
}

impl<S> WithInternalCaller<S> {
    fn new(inner: S, caller: InternalCaller) -> Self {
        Self { inner, caller }
    }
}

impl<S, B> Service<axum::http::Request<B>> for WithInternalCaller<S>
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
        req.extensions_mut().insert(self.caller.clone());
        self.inner.call(req)
    }
}

#[derive(Clone)]
struct MtlsCallerAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl MtlsCallerAcceptor {
    fn new(config: RustlsConfig) -> Self {
        Self {
            inner: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> Accept<tokio::net::TcpStream, S> for MtlsCallerAcceptor
where
    axum_server::tls_rustls::RustlsAcceptor: Accept<
            tokio::net::TcpStream,
            S,
            Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        >,
    <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Service:
        Send + 'static,
    <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Future:
        Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Service = WithInternalCaller<
        <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Service,
    >;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls_stream, service) = fut.await?;
            let caller = internal_caller_from_tls_stream(&tls_stream)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err))?;
            Ok((tls_stream, WithInternalCaller::new(service, caller)))
        })
    }
}

fn internal_caller_from_tls_stream<T>(
    tls_stream: &tokio_rustls::server::TlsStream<T>,
) -> Result<InternalCaller> {
    let (_, conn) = tls_stream.get_ref();
    let certs = conn
        .peer_certificates()
        .context("missing peer certificate")?;

    let cert = certs
        .first()
        .context("missing end-entity peer certificate")?;
    let identity = parse_peer_certificate_identity(cert)?;
    let cluster_id = identity
        .cluster_id
        .context("missing urn:ironmesh:cluster:<uuid> SAN URI in peer certificate")?;
    Ok(InternalCaller {
        node_id: identity.node_id,
        cluster_id,
    })
}

fn parse_peer_certificate_identity(cert: &CertificateDer<'_>) -> Result<PeerCertificateIdentity> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("failed parsing peer certificate")?;

    let mut node_id = None;
    let mut cluster_id = None;

    for extension in parsed.extensions() {
        let parsed_extension = extension.parsed_extension();
        if let ParsedExtension::SubjectAlternativeName(san) = parsed_extension {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if node_id.is_none() {
                        node_id = parse_node_id_from_san_uri(uri);
                    }
                    if cluster_id.is_none() {
                        cluster_id = parse_cluster_id_from_san_uri(uri);
                    }
                }
            }
        }
    }

    let node_id =
        node_id.context("missing urn:ironmesh:node:<uuid> SAN URI in peer certificate")?;

    Ok(PeerCertificateIdentity {
        node_id,
        cluster_id,
    })
}

fn validate_expected_peer_certificate_identity(
    cert: &CertificateDer<'_>,
    expected_node_id: NodeId,
    expected_cluster_id: ClusterId,
) -> Result<()> {
    let identity = parse_peer_certificate_identity(cert)?;
    if identity.node_id != expected_node_id {
        bail!(
            "peer certificate presented node_id {} but expected {}",
            identity.node_id,
            expected_node_id
        );
    }

    let presented_cluster_id = identity
        .cluster_id
        .context("missing urn:ironmesh:cluster:<uuid> SAN URI in peer certificate")?;
    if presented_cluster_id != expected_cluster_id {
        bail!(
            "peer certificate presented cluster_id {} but expected {}",
            presented_cluster_id,
            expected_cluster_id
        );
    }

    Ok(())
}

fn parse_node_id_from_san_uri(uri: &str) -> Option<NodeId> {
    let prefix = "urn:ironmesh:node:";
    uri.strip_prefix(prefix)
        .and_then(|rest| rest.trim().parse::<NodeId>().ok())
}

fn parse_cluster_id_from_san_uri(uri: &str) -> Option<ClusterId> {
    let prefix = "urn:ironmesh:cluster:";
    uri.strip_prefix(prefix)
        .and_then(|rest| rest.trim().parse::<ClusterId>().ok())
}

fn peer_certificate_verifier_error(message: impl Into<String>) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(OtherError(Arc::new(
        io::Error::other(message.into()),
    ))))
}

#[derive(Debug)]
struct ExpectedPeerServerCertVerifier {
    roots: Arc<RootCertStore>,
    inner: Arc<WebPkiServerVerifier>,
    expected_node_id: NodeId,
    expected_cluster_id: ClusterId,
}

impl ExpectedPeerServerCertVerifier {
    fn new(
        roots: Arc<RootCertStore>,
        expected_node_id: NodeId,
        expected_cluster_id: ClusterId,
    ) -> Result<Self> {
        let inner = WebPkiServerVerifier::builder(roots.clone())
            .build()
            .context("failed building expected peer certificate verifier")?;

        Ok(Self {
            roots,
            inner,
            expected_node_id,
            expected_cluster_id,
        })
    }
}

impl ServerCertVerifier for ExpectedPeerServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|err| {
            peer_certificate_verifier_error(format!("failed parsing peer certificate: {err}"))
        })?;
        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            self.roots.roots.as_slice(),
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|err| {
            peer_certificate_verifier_error(format!(
                "peer certificate chain validation failed: {err}"
            ))
        })?;
        validate_expected_peer_certificate_identity(
            end_entity,
            self.expected_node_id,
            self.expected_cluster_id,
        )
        .map_err(|err| peer_certificate_verifier_error(err.to_string()))?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

struct LogBuffer {
    entries: StdMutex<VecDeque<String>>,
    max_entries: usize,
}

impl LogBuffer {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: StdMutex::new(VecDeque::with_capacity(max_entries.max(1))),
            max_entries: max_entries.max(1),
        }
    }

    fn push(&self, line: String) {
        let mut entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        entries.push_back(line);
        while entries.len() > self.max_entries {
            entries.pop_front();
        }
    }

    fn recent(&self, limit: usize) -> Vec<String> {
        let entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        let keep = limit.max(1);
        let skip = entries.len().saturating_sub(keep);
        entries.iter().skip(skip).cloned().collect()
    }
}

#[derive(Clone)]
struct LogCaptureLayer {
    buffer: Arc<LogBuffer>,
}

impl LogCaptureLayer {
    fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

struct EventFieldVisitor {
    fields: Vec<String>,
}

impl EventFieldVisitor {
    fn new() -> Self {
        Self { fields: Vec::new() }
    }
}

impl Visit for EventFieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.push(format!("{}={:?}", field.name(), value));
    }
}

impl<S> Layer<S> for LogCaptureLayer
where
    S: Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = EventFieldVisitor::new();
        event.record(&mut visitor);
        let metadata = event.metadata();

        let line = if visitor.fields.is_empty() {
            format!("{} {}", metadata.level(), metadata.target())
        } else {
            format!(
                "{} {} {}",
                metadata.level(),
                metadata.target(),
                visitor.fields.join(" ")
            )
        };

        self.buffer.push(line);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MetadataCommitMode {
    Local,
    Quorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerNodeMode {
    Cluster,
}

#[derive(Debug, Clone)]
pub struct InternalTlsConfig {
    pub bind_addr: SocketAddr,
    pub internal_url: Option<String>,
    pub ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub metadata_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PublicTlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub metadata_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct ManagedRendezvousConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub client_ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ServerNodeConfig {
    pub mode: ServerNodeMode,
    pub cluster_id: ClusterId,
    pub node_id: NodeId,
    pub data_dir: PathBuf,
    metadata_backend: MetadataBackendKind,
    pub bind_addr: SocketAddr,
    pub public_url: Option<String>,
    pub labels: HashMap<String, String>,
    pub public_tls: Option<PublicTlsConfig>,
    pub allow_insecure_public_http: bool,
    pub public_ca_cert_path: Option<PathBuf>,
    pub public_ca_key_path: Option<PathBuf>,
    bootstrap_trust_roots: Option<BootstrapTrustRoots>,
    pub public_peer_api_enabled: bool,
    pub internal_tls: Option<InternalTlsConfig>,
    pub internal_ca_key_path: Option<PathBuf>,
    pub rendezvous_ca_cert_path: Option<PathBuf>,
    pub rendezvous_urls: Vec<String>,
    pub rendezvous_registration_enabled: bool,
    pub rendezvous_mtls_required: bool,
    pub managed_rendezvous: Option<ManagedRendezvousConfig>,
    pub relay_mode: RelayMode,
    pub enrollment_issuer_url: Option<String>,
    pub node_enrollment_path: Option<PathBuf>,
    pub node_enrollment_auto_renew_enabled: bool,
    pub node_enrollment_auto_renew_check_secs: u64,
    pub heartbeat_timeout_secs: u64,
    pub audit_interval_secs: u64,
    pub replica_view_sync_interval_secs: u64,
    pub replication_factor: usize,
    pub accepted_over_replication_items: usize,
    pub metadata_commit_mode: MetadataCommitMode,
    pub autonomous_replication_on_put_enabled: bool,
    pub replication_repair_enabled: bool,
    pub replication_repair_batch_size: usize,
    pub replication_repair_max_retries: u32,
    pub replication_repair_backoff_secs: u64,
    pub repair_busy_throttle_enabled: bool,
    pub repair_busy_inflight_threshold: usize,
    pub repair_busy_wait_millis: u64,
    pub startup_repair_enabled: bool,
    pub startup_repair_delay_secs: u64,
    pub peer_heartbeat_enabled: bool,
    pub peer_heartbeat_interval_secs: u64,
    pub admin_token: Option<String>,
    pub admin_password_hash: Option<String>,
    pub require_client_auth: bool,
}

pub struct LocalNodeHandle {
    base_url: String,
    shutdown_tx: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| !matches!(value.as_str(), "0" | "false" | "no"))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Copy)]
struct RepairConfig {
    enabled: bool,
    batch_size: usize,
    max_retries: u32,
    backoff_secs: u64,
    busy_throttle_enabled: bool,
    busy_inflight_threshold: usize,
    busy_wait_millis: u64,
    startup_repair_enabled: bool,
    startup_repair_delay_secs: u64,
}

#[derive(Debug, Clone, Copy)]
struct PeerHeartbeatConfig {
    enabled: bool,
    interval_secs: u64,
}

#[derive(Debug, Clone, Default)]
struct AdminControl {
    admin_token: Option<String>,
    admin_password_hash: Option<String>,
}

#[derive(Debug, Default)]
struct AdminSessionStore {
    sessions: HashMap<String, u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StartupRepairStatus {
    Disabled,
    Scheduled,
    Running,
    SkippedNoGaps,
    Completed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RepairRunTrigger {
    ManualRequest,
    StartupRepair,
    BackgroundAudit,
    DataScrubAutoRepair,
    AutonomousPostWrite,
    PeerClusterRequest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RepairRunStatus {
    Completed,
    SkippedNoGaps,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RepairActivityState {
    Idle,
    Scheduled,
    Running,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairPlanSummary {
    generated_at_unix: u64,
    under_replicated: usize,
    over_replicated: usize,
    cleanup_deferred_items: usize,
    cleanup_deferred_extra_nodes: usize,
    item_count: usize,
}

impl RepairPlanSummary {
    fn from_plan(plan: &ReplicationPlan) -> Self {
        Self {
            generated_at_unix: plan.generated_at_unix,
            under_replicated: plan.under_replicated,
            over_replicated: plan.over_replicated,
            cleanup_deferred_items: plan.cleanup_deferred_items,
            cleanup_deferred_extra_nodes: plan.cleanup_deferred_extra_nodes,
            item_count: plan.items.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairRunSummary {
    attempted_transfers: usize,
    successful_transfers: usize,
    failed_transfers: usize,
    skipped_items: usize,
    skipped_backoff: usize,
    skipped_max_retries: usize,
    skipped_detail_count: usize,
    last_error: Option<String>,
    nodes_contacted: Option<usize>,
    failed_nodes: Option<usize>,
}

impl RepairRunSummary {
    fn from_local_report(report: &replication::ReplicationRepairReport) -> Self {
        Self {
            attempted_transfers: report.attempted_transfers,
            successful_transfers: report.successful_transfers,
            failed_transfers: report.failed_transfers,
            skipped_items: report.skipped_items,
            skipped_backoff: report.skipped_backoff,
            skipped_max_retries: report.skipped_max_retries,
            skipped_detail_count: report.skipped_details.len(),
            last_error: report.last_error.clone(),
            nodes_contacted: None,
            failed_nodes: None,
        }
    }

    fn from_cluster_report(report: &replication::ClusterReplicationRepairReport) -> Self {
        Self {
            attempted_transfers: report.totals.attempted_transfers,
            successful_transfers: report.totals.successful_transfers,
            failed_transfers: report.totals.failed_transfers,
            skipped_items: report.totals.skipped_items,
            skipped_backoff: report.totals.skipped_backoff,
            skipped_max_retries: report.totals.skipped_max_retries,
            skipped_detail_count: report.totals.skipped_details.len(),
            last_error: report.totals.last_error.clone(),
            nodes_contacted: Some(report.nodes_contacted),
            failed_nodes: Some(report.failed_nodes),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairRunRecord {
    run_id: String,
    reporting_node_id: NodeId,
    scope: replication::ReplicationRepairScope,
    trigger: RepairRunTrigger,
    status: RepairRunStatus,
    started_at_unix: u64,
    finished_at_unix: u64,
    duration_ms: u64,
    plan_summary: RepairPlanSummary,
    summary: Option<RepairRunSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairHistoryResponse {
    retention_secs: u64,
    runs: Vec<RepairRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairActiveRun {
    run_id: String,
    scope: replication::ReplicationRepairScope,
    trigger: RepairRunTrigger,
    started_at_unix: u64,
}

#[derive(Debug, Default, Clone)]
struct RepairActivityRuntime {
    active_runs: Vec<RepairActiveRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepairActivityStatusResponse {
    state: RepairActivityState,
    startup_status: StartupRepairStatus,
    active_runs: Vec<RepairActiveRun>,
    latest_run: Option<RepairRunRecord>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DataScrubScope {
    Local,
    Cluster,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DataScrubRunTrigger {
    ManualRequest,
    Scheduled,
    PeerClusterRequest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DataScrubRunStatus {
    Clean,
    IssuesDetected,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DataScrubActivityState {
    Idle,
    Running,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubRunRecord {
    run_id: String,
    reporting_node_id: NodeId,
    trigger: DataScrubRunTrigger,
    status: DataScrubRunStatus,
    started_at_unix: u64,
    finished_at_unix: u64,
    duration_ms: u64,
    summary: DataScrubReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubHistoryResponse {
    retention_secs: u64,
    runs: Vec<DataScrubRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubActiveRun {
    run_id: String,
    trigger: DataScrubRunTrigger,
    started_at_unix: u64,
}

#[derive(Debug, Clone, Default)]
struct DataScrubActivityRuntime {
    active_runs: Vec<DataScrubActiveRun>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubActivityStatusResponse {
    state: DataScrubActivityState,
    enabled: bool,
    interval_secs: u64,
    retention_secs: u64,
    active_runs: Vec<DataScrubActiveRun>,
    latest_run: Option<DataScrubRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubClusterNodeStatus {
    node_id: NodeId,
    state: DataScrubActivityState,
    enabled: bool,
    interval_secs: u64,
    retention_secs: u64,
    active_runs: Vec<DataScrubActiveRun>,
    latest_run: Option<DataScrubRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubClusterSkippedNode {
    node_id: NodeId,
    error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubClusterStatusResponse {
    nodes: Vec<DataScrubClusterNodeStatus>,
    skipped_nodes: Vec<DataScrubClusterSkippedNode>,
    runs: Vec<DataScrubRunRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubTriggerNodeResult {
    node_id: NodeId,
    started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_run: Option<DataScrubActiveRun>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DataScrubTriggerResponse {
    scope: DataScrubScope,
    nodes_contacted: usize,
    failed_nodes: usize,
    node_results: Vec<DataScrubTriggerNodeResult>,
}

#[derive(Debug, Default)]
struct RepairExecutorState {
    attempts: HashMap<String, RepairAttemptEntry>,
}

#[derive(Debug, Clone, Copy)]
struct RepairAttemptEntry {
    attempts: u32,
    last_failure_unix: u64,
}

#[derive(Debug, Clone, Default)]
struct StorageStatsRuntime {
    collecting: bool,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
}

impl MetadataCommitMode {
    fn parse(raw: &str) -> Result<Self> {
        match raw {
            "local" => Ok(Self::Local),
            "quorum" => Ok(Self::Quorum),
            _ => Err(anyhow::anyhow!(
                "invalid IRONMESH_METADATA_COMMIT_MODE '{raw}', expected 'local' or 'quorum'"
            )),
        }
    }
}

fn parse_relay_mode(raw: &str) -> Result<RelayMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "fallback" => Ok(RelayMode::Fallback),
        "disabled" => Ok(RelayMode::Disabled),
        "preferred" => Ok(RelayMode::Preferred),
        "required" => Ok(RelayMode::Required),
        other => bail!(
            "invalid IRONMESH_RELAY_MODE '{other}', expected disabled, fallback, preferred, or required"
        ),
    }
}

fn parse_metadata_backend(raw: &str) -> Result<MetadataBackendKind> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "sqlite" => Ok(MetadataBackendKind::Sqlite),
        "turso" => {
            #[cfg(feature = "turso-metadata")]
            {
                Ok(MetadataBackendKind::Turso)
            }
            #[cfg(not(feature = "turso-metadata"))]
            {
                bail!(
                    "IRONMESH_METADATA_BACKEND='turso' requires rebuilding server-node-sdk with the 'turso-metadata' feature enabled"
                )
            }
        }
        other => bail!(
            "invalid IRONMESH_METADATA_BACKEND '{other}', expected 'sqlite'{}",
            if cfg!(feature = "turso-metadata") {
                " or 'turso'"
            } else {
                ""
            }
        ),
    }
}

fn resolve_materialized_path(data_dir: &std::path::Path, raw_path: &str) -> PathBuf {
    let candidate = PathBuf::from(raw_path);
    if candidate.is_absolute() {
        candidate
    } else {
        data_dir.join(candidate)
    }
}

fn tls_metadata_sidecar_path(cert_path: &std::path::Path) -> PathBuf {
    let file_name = cert_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "certificate".to_string());
    cert_path.with_file_name(format!("{file_name}.metadata.json"))
}

fn existing_tls_metadata_sidecar_path(cert_path: &std::path::Path) -> Option<PathBuf> {
    let path = tls_metadata_sidecar_path(cert_path);
    path.exists().then_some(path)
}

fn env_flag_is_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn env_flag_or(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

fn env_u64_or(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(value) => match value.trim().parse::<u64>() {
            Ok(parsed) if parsed > 0 => parsed,
            _ => {
                warn!(
                    env_var = name,
                    value = %value,
                    fallback = default,
                    "invalid unsigned integer environment override; using default"
                );
                default
            }
        },
        Err(_) => default,
    }
}

fn write_tls_material_metadata_sidecar(
    cert_path: &std::path::Path,
    metadata: &BootstrapTlsMaterialMetadata,
) -> Result<()> {
    let metadata_path = tls_metadata_sidecar_path(cert_path);
    if let Some(parent) = metadata_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let payload = serde_json::to_string_pretty(metadata)
        .context("failed serializing TLS material metadata sidecar")?;
    std::fs::write(&metadata_path, payload)
        .with_context(|| format!("failed writing {}", metadata_path.display()))
}

#[derive(Debug, Clone)]
struct ParsedCertificateDetails {
    not_before_unix: u64,
    not_after_unix: u64,
    certificate_fingerprint: String,
}

fn parse_certificate_details_from_pem(cert_pem: &str) -> Result<ParsedCertificateDetails> {
    let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .context("failed parsing certificate PEM")?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .context("failed parsing certificate DER")?;
    Ok(ParsedCertificateDetails {
        not_before_unix: cert.validity().not_before.timestamp().max(0) as u64,
        not_after_unix: cert.validity().not_after.timestamp().max(0) as u64,
        certificate_fingerprint: blake3::hash(cert_der.as_ref()).to_hex().to_string(),
    })
}

fn parse_certificate_details_from_path(
    cert_path: &std::path::Path,
) -> Result<ParsedCertificateDetails> {
    let cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("failed reading {}", cert_path.display()))?;
    parse_certificate_details_from_pem(&cert_pem)
}

fn build_tls_issue_policy(
    tls_validity_secs: Option<u64>,
    tls_renewal_window_secs: Option<u64>,
) -> std::result::Result<NodeTlsIssuePolicy, StatusCode> {
    const MIN_VALIDITY_SECS: u64 = 60 * 60;
    const MAX_VALIDITY_SECS: u64 = 365 * 24 * 60 * 60;
    let issued_at_unix = unix_ts();
    let validity_secs = tls_validity_secs.unwrap_or(30 * 24 * 60 * 60);
    if !(MIN_VALIDITY_SECS..=MAX_VALIDITY_SECS).contains(&validity_secs) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let default_renewal_window_secs = (validity_secs / 5)
        .max(15 * 60)
        .min(validity_secs.saturating_sub(300));
    let renewal_window_secs = tls_renewal_window_secs.unwrap_or(default_renewal_window_secs);
    if renewal_window_secs < 300 || renewal_window_secs >= validity_secs {
        return Err(StatusCode::BAD_REQUEST);
    }

    let not_before_unix = issued_at_unix.saturating_sub(300);
    let not_after_unix = issued_at_unix.saturating_add(validity_secs);
    let renew_after_unix = not_after_unix.saturating_sub(renewal_window_secs);

    Ok(NodeTlsIssuePolicy {
        issued_at_unix,
        not_before_unix,
        not_after_unix,
        renew_after_unix,
    })
}

fn build_tls_material_metadata(
    cert_pem: &str,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<BootstrapTlsMaterialMetadata, StatusCode> {
    let parsed = parse_certificate_details_from_pem(cert_pem)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(BootstrapTlsMaterialMetadata {
        issued_at_unix: policy.issued_at_unix,
        not_before_unix: parsed.not_before_unix,
        not_after_unix: parsed.not_after_unix,
        renew_after_unix: policy.renew_after_unix,
        certificate_fingerprint: parsed.certificate_fingerprint,
    })
}

fn node_enrollment_due_for_renewal(package: &NodeEnrollmentPackage, now: u64) -> bool {
    [
        package.public_tls_material.as_ref(),
        package.internal_tls_material.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|material| material.metadata.renew_after_unix <= now)
}

async fn resolve_node_enrollment_issuer_descriptor(
    state: &ServerState,
    issuer_url: &str,
) -> Result<cluster::NodeDescriptor> {
    let expected_url = issuer_url.trim_end_matches('/');
    let cluster = state.cluster.lock().await;
    cluster
        .list_nodes()
        .into_iter()
        .find(|node| {
            node.public_api_url()
                .map(|value| value.trim_end_matches('/'))
                == Some(expected_url)
        })
        .with_context(|| {
            format!(
                "node enrollment auto-renew could not resolve issuer {expected_url} from current cluster membership"
            )
        })
}

async fn renew_node_enrollment_package_if_due(
    state: &ServerState,
    config: &ServerNodeConfig,
) -> Result<bool> {
    if !config.node_enrollment_auto_renew_enabled {
        return Ok(false);
    }
    let Some(enrollment_path) = config.node_enrollment_path.as_ref() else {
        return Ok(false);
    };
    if config.internal_tls.is_none() {
        bail!("node enrollment auto-renew requires configured internal TLS identity");
    }

    let package = NodeEnrollmentPackage::from_path(enrollment_path)?;
    if package.bootstrap.mode != NodeBootstrapMode::Cluster {
        bail!(
            "node enrollment auto-renew only supports cluster node enrollments in the first implementation"
        );
    }
    let now = unix_ts();
    if !node_enrollment_due_for_renewal(&package, now) {
        return Ok(false);
    }

    let issuer_url = package
        .bootstrap
        .enrollment_issuer_url
        .as_deref()
        .or(config.enrollment_issuer_url.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
        .context("node enrollment auto-renew requires bootstrap.enrollment_issuer_url")?;
    let issuer_node = resolve_node_enrollment_issuer_descriptor(state, &issuer_url).await?;
    let response = execute_peer_request(
        state,
        &issuer_node,
        reqwest::Method::POST,
        "/cluster/node-enrollments/renew",
        vec![RelayHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        serde_json::to_vec(&build_node_enrollment_renew_request(&package))
            .context("failed encoding automatic node enrollment renewal request")?,
    )
    .await
    .context("failed requesting automatic node enrollment renewal")?;
    if !response.is_success() {
        let error_body = String::from_utf8_lossy(&response.body).trim().to_string();
        if error_body.is_empty() {
            bail!(
                "automatic node enrollment renewal returned status {}",
                response.status
            );
        }
        bail!(
            "automatic node enrollment renewal returned status {}: {}",
            response.status,
            error_body
        );
    }
    let renewed = response
        .json::<NodeEnrollmentRenewResponse>()
        .context("failed decoding automatic node enrollment renewal response")?;
    let renewed = merge_node_enrollment_renew_response(package, renewed)?;
    renewed.validate()?;
    renewed.write_to_path(enrollment_path)?;
    let _ = materialize_node_enrollment_package(renewed)?;
    Ok(true)
}

fn build_node_enrollment_renew_request(
    package: &NodeEnrollmentPackage,
) -> NodeEnrollmentRenewRequest {
    NodeEnrollmentRenewRequest {
        current_public_tls_cert_pem: package
            .public_tls_material
            .as_ref()
            .map(|material| material.cert_pem.clone()),
    }
}

fn merge_node_enrollment_renew_response(
    mut package: NodeEnrollmentPackage,
    response: NodeEnrollmentRenewResponse,
) -> Result<NodeEnrollmentPackage> {
    if response.cluster_id != package.bootstrap.cluster_id {
        bail!(
            "renewed node enrollment response cluster_id {} does not match local cluster_id {}",
            response.cluster_id,
            package.bootstrap.cluster_id
        );
    }
    if response.node_id != package.bootstrap.node_id {
        bail!(
            "renewed node enrollment response node_id {} does not match local node_id {}",
            response.node_id,
            package.bootstrap.node_id
        );
    }

    if package.bootstrap.public_tls.is_some() != response.public_tls_material.is_some() {
        bail!(
            "renewed node enrollment response public TLS material does not match local public TLS configuration"
        );
    }

    package.bootstrap.trust_roots = response.trust_roots;
    package.bootstrap.enrollment_issuer_url = response.enrollment_issuer_url;
    package.internal_tls_material = Some(response.internal_tls_material);
    package.public_tls_material = response.public_tls_material;
    Ok(package)
}

fn load_tls_material_metadata_sidecar(
    metadata_path: Option<&std::path::Path>,
) -> Option<BootstrapTlsMaterialMetadata> {
    let path = metadata_path?;
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn default_renew_after_unix(not_before_unix: u64, not_after_unix: u64) -> u64 {
    let lifetime = not_after_unix.saturating_sub(not_before_unix);
    let renewal_window = (lifetime / 5).max(60 * 60);
    not_after_unix.saturating_sub(renewal_window)
}

fn inspect_node_certificate(
    name: &str,
    cert_path: Option<&std::path::Path>,
    metadata_path: Option<&std::path::Path>,
) -> NodeCertificateStatusView {
    let Some(cert_path) = cert_path else {
        return NodeCertificateStatusView {
            name: name.to_string(),
            configured: false,
            cert_path: None,
            metadata_path: None,
            issued_at_unix: None,
            renew_after_unix: None,
            expires_at_unix: None,
            seconds_until_expiry: None,
            certificate_fingerprint: None,
            metadata_matches_certificate: None,
            state: NodeCertificateLifecycleState::NotConfigured,
        };
    };

    let metadata = load_tls_material_metadata_sidecar(metadata_path);
    let parsed = match parse_certificate_details_from_path(cert_path) {
        Ok(parsed) => parsed,
        Err(_) => {
            return NodeCertificateStatusView {
                name: name.to_string(),
                configured: true,
                cert_path: Some(cert_path.display().to_string()),
                metadata_path: metadata_path.map(|path| path.display().to_string()),
                issued_at_unix: metadata.as_ref().map(|entry| entry.issued_at_unix),
                renew_after_unix: metadata.as_ref().map(|entry| entry.renew_after_unix),
                expires_at_unix: metadata.as_ref().map(|entry| entry.not_after_unix),
                seconds_until_expiry: None,
                certificate_fingerprint: metadata
                    .as_ref()
                    .map(|entry| entry.certificate_fingerprint.clone()),
                metadata_matches_certificate: None,
                state: NodeCertificateLifecycleState::Missing,
            };
        }
    };

    let now = unix_ts();
    let renew_after_unix = metadata
        .as_ref()
        .map(|entry| entry.renew_after_unix)
        .unwrap_or_else(|| default_renew_after_unix(parsed.not_before_unix, parsed.not_after_unix));
    let expires_at_unix = parsed.not_after_unix;
    let seconds_until_expiry = expires_at_unix as i64 - now as i64;
    let state = if expires_at_unix <= now {
        NodeCertificateLifecycleState::Expired
    } else if renew_after_unix <= now {
        NodeCertificateLifecycleState::RenewalDue
    } else {
        NodeCertificateLifecycleState::Valid
    };

    NodeCertificateStatusView {
        name: name.to_string(),
        configured: true,
        cert_path: Some(cert_path.display().to_string()),
        metadata_path: metadata_path.map(|path| path.display().to_string()),
        issued_at_unix: metadata
            .as_ref()
            .map(|entry| entry.issued_at_unix)
            .or(Some(parsed.not_before_unix)),
        renew_after_unix: Some(renew_after_unix),
        expires_at_unix: Some(expires_at_unix),
        seconds_until_expiry: Some(seconds_until_expiry),
        certificate_fingerprint: Some(parsed.certificate_fingerprint.clone()),
        metadata_matches_certificate: metadata
            .as_ref()
            .map(|entry| entry.certificate_fingerprint == parsed.certificate_fingerprint),
        state,
    }
}

fn collect_node_certificate_status(
    public_cert_path: Option<&std::path::Path>,
    public_metadata_path: Option<&std::path::Path>,
    internal_cert_path: Option<&std::path::Path>,
    internal_metadata_path: Option<&std::path::Path>,
    auto_renew: NodeCertificateAutoRenewStatusView,
) -> NodeCertificateStatusResponse {
    NodeCertificateStatusResponse {
        public_tls: inspect_node_certificate("public_tls", public_cert_path, public_metadata_path),
        internal_tls: inspect_node_certificate(
            "internal_tls",
            internal_cert_path,
            internal_metadata_path,
        ),
        auto_renew,
    }
}

fn node_certificate_restart_required(
    public_tls: &NodeCertificateStatusView,
    internal_tls: &NodeCertificateStatusView,
    loaded_public_fingerprint: Option<&str>,
    loaded_internal_fingerprint: Option<&str>,
) -> bool {
    loaded_public_fingerprint.is_some_and(|loaded| {
        public_tls
            .certificate_fingerprint
            .as_deref()
            .is_some_and(|current| current != loaded)
    }) || loaded_internal_fingerprint.is_some_and(|loaded| {
        internal_tls
            .certificate_fingerprint
            .as_deref()
            .is_some_and(|current| current != loaded)
    })
}

#[cfg(test)]
async fn current_internal_http(state: &ServerState) -> reqwest::Client {
    state.outbound_clients.read().await.internal_http.clone()
}

async fn current_rendezvous_control(state: &ServerState) -> Option<RendezvousControlClient> {
    state
        .outbound_clients
        .read()
        .await
        .rendezvous_control
        .clone()
}

async fn cached_peer_relay_session(
    state: &ServerState,
    node_id: NodeId,
) -> Option<CachedPeerRelaySession> {
    state
        .peer_relay_sessions
        .sessions
        .lock()
        .await
        .get(&node_id)
        .cloned()
}

async fn invalidate_peer_relay_session(state: &ServerState, node_id: NodeId) {
    let removed = state
        .peer_relay_sessions
        .sessions
        .lock()
        .await
        .remove(&node_id);
    if let Some(removed) = removed {
        tracing::debug!(
            peer_node_id = %node_id,
            session_id = %removed.relay_session.session_id,
            "invalidated cached relay peer session"
        );
    }
}

async fn clear_peer_relay_sessions(state: &ServerState) {
    let cleared = {
        let mut sessions = state.peer_relay_sessions.sessions.lock().await;
        let cleared = sessions.len();
        sessions.clear();
        cleared
    };
    if cleared > 0 {
        tracing::debug!(
            cleared_sessions = cleared,
            "cleared cached relay peer sessions after outbound client update"
        );
    }
}

async fn replace_outbound_clients(state: &ServerState, outbound_clients: OutboundClients) {
    *state.outbound_clients.write().await = outbound_clients;
    clear_peer_relay_sessions(state).await;
}

async fn current_rendezvous_endpoint_clients(state: &ServerState) -> Vec<RendezvousEndpointClient> {
    state
        .outbound_clients
        .read()
        .await
        .rendezvous_controls
        .clone()
}

fn current_rendezvous_urls(state: &ServerState) -> Vec<String> {
    state
        .rendezvous_urls
        .lock()
        .expect("rendezvous URL mutex poisoned")
        .clone()
}

fn replace_rendezvous_urls(state: &ServerState, urls: Vec<String>) {
    *state
        .rendezvous_urls
        .lock()
        .expect("rendezvous URL mutex poisoned") = urls;
}

async fn sync_rendezvous_registration_state(state: &ServerState) {
    let urls = current_rendezvous_urls(state);
    let desired = urls.iter().cloned().collect::<HashSet<_>>();
    let mut registration_state = state.rendezvous_registration_state.lock().await;
    registration_state.retain(|url, _| desired.contains(url));
    for url in urls {
        registration_state.entry(url).or_default();
    }
}

async fn record_rendezvous_registration_success(state: &ServerState, url: &str) -> bool {
    let now = unix_ts();
    let mut registration_state = state.rendezvous_registration_state.lock().await;
    let entry = registration_state.entry(url.to_string()).or_default();
    let recovered = entry.consecutive_failures > 0;
    entry.last_attempt_unix = Some(now);
    entry.last_success_unix = Some(now);
    entry.consecutive_failures = 0;
    entry.last_error = None;
    recovered
}

async fn record_rendezvous_registration_failure(
    state: &ServerState,
    url: &str,
    error: &str,
) -> u64 {
    let now = unix_ts();
    let mut registration_state = state.rendezvous_registration_state.lock().await;
    let entry = registration_state.entry(url.to_string()).or_default();
    entry.last_attempt_unix = Some(now);
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
    entry.last_error = Some(error.to_string());
    entry.consecutive_failures
}

async fn rendezvous_registration_views(
    state: &ServerState,
) -> Vec<RendezvousEndpointRegistrationView> {
    let urls = current_rendezvous_urls(state);
    let registration_state = state.rendezvous_registration_state.lock().await;
    urls.into_iter()
        .map(|url| {
            let runtime = registration_state.get(&url).cloned().unwrap_or_default();
            let status = if runtime.consecutive_failures > 0 {
                RendezvousEndpointRegistrationStatus::Disconnected
            } else if runtime.last_success_unix.is_some() {
                RendezvousEndpointRegistrationStatus::Connected
            } else {
                RendezvousEndpointRegistrationStatus::Pending
            };

            RendezvousEndpointRegistrationView {
                url,
                status,
                last_attempt_unix: runtime.last_attempt_unix,
                last_success_unix: runtime.last_success_unix,
                consecutive_failures: runtime.consecutive_failures,
                last_error: runtime.last_error,
            }
        })
        .collect()
}

fn current_editable_rendezvous_urls(state: &ServerState) -> Vec<String> {
    let urls = normalize_rendezvous_url_list(&current_rendezvous_urls(state))
        .unwrap_or_else(|_| current_rendezvous_urls(state));
    match state
        .managed_rendezvous_public_url
        .as_deref()
        .and_then(|url| canonicalize_rendezvous_url(url).ok())
    {
        Some(managed_url) => urls.into_iter().filter(|url| url != &managed_url).collect(),
        None => urls,
    }
}

async fn connected_rendezvous_registration_urls(
    state: &ServerState,
    candidate_urls: &[String],
) -> Vec<String> {
    let registration_state = state.rendezvous_registration_state.lock().await;
    candidate_urls
        .iter()
        .filter(|url| {
            registration_state.get(*url).is_some_and(|runtime| {
                runtime.last_success_unix.is_some() && runtime.consecutive_failures == 0
            })
        })
        .cloned()
        .collect()
}

fn current_bootstrap_trust_roots(state: &ServerState) -> Result<BootstrapTrustRoots> {
    // Enrollment packages are the supported production lifecycle source for trust roots.
    // Direct env/file CA wiring remains useful for development/testing or short-lived
    // manually managed setups, where restart-after-change is acceptable.
    if let Some(path) = state.node_enrollment_path.as_ref() {
        return Ok(NodeEnrollmentPackage::from_path(path)?
            .bootstrap
            .trust_roots);
    }

    Ok(BootstrapTrustRoots {
        cluster_ca_pem: state.cluster_ca_pem.clone(),
        public_api_ca_pem: state.public_ca_pem.clone(),
        rendezvous_ca_pem: state
            .rendezvous_ca_pem
            .clone()
            .or_else(|| state.public_ca_pem.clone())
            .or_else(|| state.cluster_ca_pem.clone()),
    })
}

fn load_live_trust_material(state: &ServerState) -> Result<LiveTrustMaterial> {
    let bootstrap_trust_roots = current_bootstrap_trust_roots(state)?;
    let cluster_ca_pem = state
        .internal_tls_runtime
        .as_ref()
        .map(|tls| {
            std::fs::read_to_string(&tls.ca_cert_path).with_context(|| {
                format!(
                    "failed reading cluster CA certificate {}",
                    tls.ca_cert_path.display()
                )
            })
        })
        .transpose()?
        .or(bootstrap_trust_roots.cluster_ca_pem.clone())
        .or(state.cluster_ca_pem.clone());
    let public_ca_pem = bootstrap_trust_roots
        .public_api_ca_pem
        .clone()
        .or(state.public_ca_pem.clone());
    let internal_ca_key_pem = state.internal_ca_key_pem.clone();
    let public_ca_key_pem = state.public_ca_key_pem.clone().or_else(|| {
        if public_ca_pem.is_none() || public_ca_pem == cluster_ca_pem {
            internal_ca_key_pem.clone()
        } else {
            None
        }
    });
    let rendezvous_ca_pem = bootstrap_trust_roots
        .rendezvous_ca_pem
        .clone()
        .or(state.rendezvous_ca_pem.clone())
        .or_else(|| public_ca_pem.clone())
        .or_else(|| cluster_ca_pem.clone());

    Ok(LiveTrustMaterial {
        public_ca_pem,
        public_ca_key_pem,
        cluster_ca_pem,
        internal_ca_key_pem,
        rendezvous_ca_pem,
    })
}

fn build_rendezvous_control_clients(
    cluster_id: ClusterId,
    rendezvous_urls: &[String],
    heartbeat_interval_secs: u64,
    rendezvous_ca_pem: Option<&str>,
    rendezvous_client_identity_pem: Option<&[u8]>,
) -> Result<(
    Option<RendezvousControlClient>,
    Vec<RendezvousEndpointClient>,
)> {
    if rendezvous_urls.is_empty() {
        return Ok((None, Vec::new()));
    }

    let shared_config = RendezvousClientConfig {
        cluster_id,
        rendezvous_urls: rendezvous_urls.to_vec(),
        heartbeat_interval_secs,
    };
    let shared = RendezvousControlClient::new(
        shared_config,
        rendezvous_ca_pem,
        rendezvous_client_identity_pem,
    )?;

    let mut endpoints = Vec::with_capacity(rendezvous_urls.len());
    for url in rendezvous_urls {
        let control = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id,
                rendezvous_urls: vec![url.clone()],
                heartbeat_interval_secs,
            },
            rendezvous_ca_pem,
            rendezvous_client_identity_pem,
        )?;
        endpoints.push(RendezvousEndpointClient {
            url: url.clone(),
            control,
        });
    }

    Ok((Some(shared), endpoints))
}

fn build_outbound_clients_with_urls(
    state: &ServerState,
    rendezvous_urls: &[String],
) -> Result<OutboundClients> {
    let trust_material = load_live_trust_material(state)?;
    #[cfg(test)]
    let internal_http = if let Some(internal_tls) = state.internal_tls_runtime.as_ref() {
        build_internal_mtls_http_client(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )?
    } else {
        reqwest::Client::new()
    };

    let (rendezvous_control, rendezvous_controls) =
        if state.rendezvous_registration_enabled && !rendezvous_urls.is_empty() {
            let rendezvous_client_identity_pem = state
                .internal_tls_runtime
                .as_ref()
                .map(|tls| build_identity_pem_from_paths(&tls.cert_path, &tls.key_path))
                .transpose()?;
            build_rendezvous_control_clients(
                state.cluster_id,
                rendezvous_urls,
                state.peer_heartbeat_config.interval_secs.max(5),
                trust_material
                    .rendezvous_ca_pem
                    .as_deref()
                    .or(trust_material.public_ca_pem.as_deref())
                    .or(trust_material.cluster_ca_pem.as_deref()),
                rendezvous_client_identity_pem.as_deref(),
            )?
        } else {
            (None, Vec::new())
        };

    Ok(OutboundClients {
        #[cfg(test)]
        internal_http,
        rendezvous_control,
        rendezvous_controls,
    })
}

fn build_outbound_clients(state: &ServerState) -> Result<OutboundClients> {
    let rendezvous_urls = normalize_rendezvous_url_list(&current_rendezvous_urls(state))?;
    build_outbound_clients_with_urls(state, &rendezvous_urls)
}

async fn reload_live_outbound_clients(state: &ServerState) -> Result<()> {
    let outbound_clients = build_outbound_clients(state)?;
    replace_outbound_clients(state, outbound_clients).await;
    Ok(())
}

async fn reload_live_tls_from_disk(state: &ServerState) -> Result<()> {
    let mut loaded_public_tls_fingerprint = None;
    let mut loaded_internal_tls_fingerprint = None;
    let mut reload_errors = Vec::new();

    if let Some(public_tls) = state.public_tls_runtime.as_ref() {
        match public_tls
            .config
            .reload_from_pem_file(&public_tls.cert_path, &public_tls.key_path)
            .await
            .with_context(|| {
                format!(
                    "failed reloading public TLS config from {} and {}",
                    public_tls.cert_path.display(),
                    public_tls.key_path.display()
                )
            }) {
            Ok(()) => {
                match parse_certificate_details_from_path(&public_tls.cert_path).with_context(
                    || {
                        format!(
                            "failed reading reloaded public TLS certificate {}",
                            public_tls.cert_path.display()
                        )
                    },
                ) {
                    Ok(details) => {
                        loaded_public_tls_fingerprint = Some(details.certificate_fingerprint);
                    }
                    Err(err) => reload_errors.push(err.to_string()),
                }
            }
            Err(err) => reload_errors.push(err.to_string()),
        }
    }

    if let Some(internal_tls) = state.internal_tls_runtime.as_ref() {
        match build_internal_mtls_server_config(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )
        .with_context(|| {
            format!(
                "failed rebuilding internal TLS config from {}, {}, and {}",
                internal_tls.ca_cert_path.display(),
                internal_tls.cert_path.display(),
                internal_tls.key_path.display()
            )
        }) {
            Ok(config) => {
                internal_tls.config.reload_from_config(Arc::new(config));
                match parse_certificate_details_from_path(&internal_tls.cert_path).with_context(
                    || {
                        format!(
                            "failed reading reloaded internal TLS certificate {}",
                            internal_tls.cert_path.display()
                        )
                    },
                ) {
                    Ok(details) => {
                        loaded_internal_tls_fingerprint = Some(details.certificate_fingerprint);
                    }
                    Err(err) => reload_errors.push(err.to_string()),
                }
            }
            Err(err) => reload_errors.push(err.to_string()),
        }
    }

    {
        let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
        if let Some(fingerprint) = loaded_public_tls_fingerprint {
            renewal_state.loaded_public_tls_fingerprint = Some(fingerprint);
        }
        if let Some(fingerprint) = loaded_internal_tls_fingerprint {
            renewal_state.loaded_internal_tls_fingerprint = Some(fingerprint);
        }
    }

    if let Err(err) = reload_live_outbound_clients(state).await {
        reload_errors.push(err.to_string());
    }

    if reload_errors.is_empty() {
        Ok(())
    } else {
        bail!(reload_errors.join("; "));
    }
}

fn log_certificate_lifecycle_status(status: &NodeCertificateStatusResponse) {
    for entry in [&status.public_tls, &status.internal_tls] {
        match entry.state {
            NodeCertificateLifecycleState::Expired => {
                tracing::warn!(
                    certificate = %entry.name,
                    cert_path = ?entry.cert_path,
                    expires_at_unix = entry.expires_at_unix,
                    "configured node certificate is expired"
                );
            }
            NodeCertificateLifecycleState::RenewalDue => {
                tracing::warn!(
                    certificate = %entry.name,
                    cert_path = ?entry.cert_path,
                    renew_after_unix = entry.renew_after_unix,
                    expires_at_unix = entry.expires_at_unix,
                    "configured node certificate is due for renewal"
                );
            }
            NodeCertificateLifecycleState::Missing => {
                tracing::warn!(
                    certificate = %entry.name,
                    cert_path = ?entry.cert_path,
                    "configured node certificate could not be loaded"
                );
            }
            NodeCertificateLifecycleState::NotConfigured | NodeCertificateLifecycleState::Valid => {
            }
        }
    }
}

fn materialize_node_enrollment_package(
    package: NodeEnrollmentPackage,
) -> Result<TransportNodeBootstrap> {
    package.validate()?;
    let mut bootstrap = package.bootstrap;
    let data_dir = PathBuf::from(&bootstrap.data_dir);
    let public_tls_material = package.public_tls_material;
    let internal_tls_material = package.internal_tls_material;

    if let (Some(internal_tls), Some(material)) = (
        bootstrap.internal_tls.as_mut(),
        internal_tls_material.as_ref(),
    ) {
        let ca_path = resolve_materialized_path(&data_dir, &internal_tls.ca_cert_path);
        let cert_path = resolve_materialized_path(&data_dir, &internal_tls.cert_path);
        let key_path = resolve_materialized_path(&data_dir, &internal_tls.key_path);

        for (path, contents) in [
            (&ca_path, material.ca_cert_pem.as_str()),
            (&cert_path, material.cert_pem.as_str()),
            (&key_path, material.key_pem.as_str()),
        ] {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed creating {}", parent.display()))?;
            }
            std::fs::write(path, contents)
                .with_context(|| format!("failed writing {}", path.display()))?;
        }
        write_tls_material_metadata_sidecar(&cert_path, &material.metadata)?;

        internal_tls.ca_cert_path = ca_path.to_string_lossy().into_owned();
        internal_tls.cert_path = cert_path.to_string_lossy().into_owned();
        internal_tls.key_path = key_path.to_string_lossy().into_owned();
    }

    if let (Some(public_tls), Some(material)) =
        (bootstrap.public_tls.as_mut(), public_tls_material.as_ref())
    {
        let cert_path = resolve_materialized_path(&data_dir, &public_tls.cert_path);
        let key_path = resolve_materialized_path(&data_dir, &public_tls.key_path);

        for (path, contents) in [
            (&cert_path, material.cert_pem.as_str()),
            (&key_path, material.key_pem.as_str()),
        ] {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed creating {}", parent.display()))?;
            }
            std::fs::write(path, contents)
                .with_context(|| format!("failed writing {}", path.display()))?;
        }
        write_tls_material_metadata_sidecar(&cert_path, &material.metadata)?;

        public_tls.cert_path = cert_path.to_string_lossy().into_owned();
        public_tls.key_path = key_path.to_string_lossy().into_owned();
    }

    if let Some(public_ca_pem) = public_tls_material
        .as_ref()
        .map(|material| material.ca_cert_pem.as_str())
        .or(bootstrap.trust_roots.public_api_ca_pem.as_deref())
        && let Some(public_ca_cert_path) = bootstrap.public_ca_cert_path.as_mut()
    {
        let public_ca_path = resolve_materialized_path(&data_dir, public_ca_cert_path);
        if let Some(parent) = public_ca_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::write(&public_ca_path, public_ca_pem)
            .with_context(|| format!("failed writing {}", public_ca_path.display()))?;
        *public_ca_cert_path = public_ca_path.to_string_lossy().into_owned();
    }

    Ok(bootstrap)
}

fn parse_enrollment_auto_renew_enabled(default_enabled: bool) -> bool {
    std::env::var("IRONMESH_NODE_ENROLLMENT_AUTO_RENEW_ENABLED")
        .ok()
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
        .unwrap_or(default_enabled)
}

fn default_node_enrollment_auto_renew_enabled(config: &ServerNodeConfig) -> bool {
    config.internal_tls.is_some()
        && config
            .enrollment_issuer_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some()
}

fn node_enrollment_auto_renew_check_secs() -> u64 {
    std::env::var("IRONMESH_NODE_ENROLLMENT_RENEWAL_CHECK_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(300)
}

impl ServerNodeConfig {
    pub fn from_enrollment_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let package = NodeEnrollmentPackage::from_path(path.as_ref())?;
        let mut config = Self::from_enrollment(package)?;
        config.node_enrollment_path = Some(path.as_ref().to_path_buf());
        config.node_enrollment_auto_renew_enabled = parse_enrollment_auto_renew_enabled(
            default_node_enrollment_auto_renew_enabled(&config),
        );
        config.node_enrollment_auto_renew_check_secs = node_enrollment_auto_renew_check_secs();
        Ok(config)
    }

    pub fn from_enrollment(package: NodeEnrollmentPackage) -> Result<Self> {
        let bootstrap = materialize_node_enrollment_package(package)?;
        Self::from_bootstrap(bootstrap)
    }

    pub fn from_bootstrap_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let bootstrap = TransportNodeBootstrap::from_path(path.as_ref())?;
        Self::from_bootstrap(bootstrap)
    }

    pub fn from_bootstrap(bootstrap: TransportNodeBootstrap) -> Result<Self> {
        bootstrap.validate()?;

        let mode = ServerNodeMode::Cluster;
        let allow_insecure_public_http = env_flag_enabled(ALLOW_INSECURE_PUBLIC_HTTP_ENV);
        let allow_unauthenticated_clients = env_flag_enabled(ALLOW_UNAUTHENTICATED_CLIENTS_ENV);
        let bind_addr: SocketAddr = bootstrap
            .bind_addr
            .parse()
            .context("invalid node bootstrap bind_addr")?;
        let internal_tls = match bootstrap.internal_tls {
            Some(internal_tls) => {
                let internal_bind_addr = bootstrap
                    .internal_bind_addr
                    .as_deref()
                    .context("node bootstrap internal_tls requires internal_bind_addr")?
                    .parse()
                    .context("invalid node bootstrap internal_bind_addr")?;
                let ca_cert_path = PathBuf::from(internal_tls.ca_cert_path);
                let cert_path = PathBuf::from(internal_tls.cert_path);
                let key_path = PathBuf::from(internal_tls.key_path);
                Some(InternalTlsConfig {
                    bind_addr: internal_bind_addr,
                    internal_url: bootstrap.internal_url.clone(),
                    metadata_path: existing_tls_metadata_sidecar_path(&cert_path),
                    ca_cert_path,
                    cert_path,
                    key_path,
                })
            }
            None => None,
        };
        let public_tls = bootstrap.public_tls.map(|public_tls| {
            let cert_path = PathBuf::from(public_tls.cert_path);
            let key_path = PathBuf::from(public_tls.key_path);
            PublicTlsConfig {
                metadata_path: existing_tls_metadata_sidecar_path(&cert_path),
                cert_path,
                key_path,
            }
        });
        let rendezvous_configured = !bootstrap.rendezvous_urls.is_empty();

        Ok(Self {
            mode,
            cluster_id: bootstrap.cluster_id,
            node_id: bootstrap.node_id,
            data_dir: PathBuf::from(bootstrap.data_dir),
            metadata_backend: parse_metadata_backend(
                std::env::var("IRONMESH_METADATA_BACKEND")
                    .unwrap_or_else(|_| "sqlite".to_string())
                    .as_str(),
            )?,
            bind_addr,
            public_url: bootstrap.public_url,
            labels: bootstrap.labels,
            public_tls,
            allow_insecure_public_http,
            public_ca_cert_path: bootstrap.public_ca_cert_path.map(PathBuf::from),
            public_ca_key_path: None,
            bootstrap_trust_roots: Some(bootstrap.trust_roots),
            public_peer_api_enabled: bootstrap.public_peer_api_enabled,
            internal_tls,
            internal_ca_key_path: None,
            rendezvous_ca_cert_path: None,
            rendezvous_urls: bootstrap.rendezvous_urls,
            rendezvous_registration_enabled: rendezvous_configured,
            rendezvous_mtls_required: bootstrap.rendezvous_mtls_required,
            managed_rendezvous: None,
            relay_mode: bootstrap.relay_mode,
            enrollment_issuer_url: bootstrap.enrollment_issuer_url,
            node_enrollment_path: None,
            node_enrollment_auto_renew_enabled: false,
            node_enrollment_auto_renew_check_secs: node_enrollment_auto_renew_check_secs(),
            heartbeat_timeout_secs: std::env::var("IRONMESH_HEARTBEAT_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(90),
            audit_interval_secs: std::env::var("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(3600),
            replica_view_sync_interval_secs: std::env::var(
                "IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS",
            )
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REPLICA_VIEW_SYNC_INTERVAL_SECS),
            replication_factor: std::env::var("IRONMESH_REPLICATION_FACTOR")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(3),
            accepted_over_replication_items: std::env::var(
                "IRONMESH_ACCEPTED_OVER_REPLICATION_ITEMS",
            )
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0),
            metadata_commit_mode: MetadataCommitMode::parse(
                std::env::var("IRONMESH_METADATA_COMMIT_MODE")
                    .unwrap_or_else(|_| "local".to_string())
                    .as_str(),
            )?,
            autonomous_replication_on_put_enabled: std::env::var(
                "IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED",
            )
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true),
            replication_repair_enabled: std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            replication_repair_batch_size: std::env::var("IRONMESH_REPLICATION_REPAIR_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(256),
            replication_repair_max_retries: std::env::var(
                "IRONMESH_REPLICATION_REPAIR_MAX_RETRIES",
            )
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3),
            replication_repair_backoff_secs: std::env::var(
                "IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS",
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30),
            repair_busy_throttle_enabled: std::env::var("IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            repair_busy_inflight_threshold: std::env::var(
                "IRONMESH_REPAIR_BUSY_INFLIGHT_THRESHOLD",
            )
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(32),
            repair_busy_wait_millis: std::env::var("IRONMESH_REPAIR_BUSY_WAIT_MILLIS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(100),
            startup_repair_enabled: std::env::var("IRONMESH_STARTUP_REPAIR_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            startup_repair_delay_secs: std::env::var("IRONMESH_STARTUP_REPAIR_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
            peer_heartbeat_enabled: std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            peer_heartbeat_interval_secs: std::env::var(
                "IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS",
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(15),
            admin_token: std::env::var("IRONMESH_ADMIN_TOKEN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            admin_password_hash: None,
            require_client_auth: !allow_unauthenticated_clients,
        })
    }

    pub fn from_env() -> Result<Self> {
        if let Some(path) = std::env::var("IRONMESH_NODE_ENROLLMENT_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Self::from_enrollment_path(path);
        }

        if let Some(path) = std::env::var("IRONMESH_NODE_BOOTSTRAP_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        {
            return Self::from_bootstrap_path(path);
        }

        let mode = ServerNodeMode::Cluster;
        let allow_insecure_public_http = env_flag_enabled(ALLOW_INSECURE_PUBLIC_HTTP_ENV);
        let allow_unauthenticated_clients = env_flag_enabled(ALLOW_UNAUTHENTICATED_CLIENTS_ENV);

        let node_id = std::env::var("IRONMESH_NODE_ID")
            .ok()
            .and_then(|value| value.parse::<NodeId>().ok())
            .unwrap_or_else(NodeId::new_v4);
        let cluster_id = std::env::var("IRONMESH_CLUSTER_ID")
            .ok()
            .and_then(|value| value.parse::<ClusterId>().ok())
            .unwrap_or_else(Uuid::now_v7);

        let data_dir = PathBuf::from(
            std::env::var("IRONMESH_DATA_DIR").unwrap_or_else(|_| "./data/server-node".to_string()),
        );
        let bind_addr: SocketAddr = std::env::var("IRONMESH_SERVER_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
            .parse()
            .context("invalid IRONMESH_SERVER_BIND")?;

        let public_tls = match (
            std::env::var("IRONMESH_PUBLIC_TLS_CERT").ok(),
            std::env::var("IRONMESH_PUBLIC_TLS_KEY").ok(),
        ) {
            (Some(cert), Some(key)) => {
                let cert_path = PathBuf::from(cert);
                let key_path = PathBuf::from(key);
                Some(PublicTlsConfig {
                    metadata_path: existing_tls_metadata_sidecar_path(&cert_path),
                    cert_path,
                    key_path,
                })
            }
            (None, None) => None,
            _ => {
                bail!("IRONMESH_PUBLIC_TLS_CERT and IRONMESH_PUBLIC_TLS_KEY must be set together")
            }
        };

        let public_url = std::env::var("IRONMESH_PUBLIC_URL").ok().or_else(|| {
            let scheme = if public_tls.is_some() {
                "https"
            } else {
                "http"
            };
            Some(format!("{scheme}://{bind_addr}"))
        });
        let explicit_rendezvous_urls = std::env::var("IRONMESH_RENDEZVOUS_URLS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|urls| !urls.is_empty());
        let rendezvous_registration_enabled = explicit_rendezvous_urls.is_some();
        let rendezvous_urls = explicit_rendezvous_urls
            .clone()
            .or_else(|| public_url.as_ref().map(|url| vec![url.clone()]))
            .unwrap_or_default();
        let rendezvous_ca_cert_path = std::env::var("IRONMESH_RENDEZVOUS_CA_CERT")
            .ok()
            .map(PathBuf::from);
        let rendezvous_mtls_required = std::env::var("IRONMESH_RENDEZVOUS_MTLS_REQUIRED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(false);
        let relay_mode = parse_relay_mode(
            std::env::var("IRONMESH_RELAY_MODE")
                .unwrap_or_else(|_| "fallback".to_string())
                .as_str(),
        )?;

        let internal_bind_addr: SocketAddr = std::env::var("IRONMESH_INTERNAL_BIND")
            .unwrap_or_else(|_| "127.0.0.1:18080".to_string())
            .parse()
            .context("invalid IRONMESH_INTERNAL_BIND")?;
        let ca_cert_path = PathBuf::from(
            std::env::var("IRONMESH_INTERNAL_TLS_CA_CERT")
                .context("missing IRONMESH_INTERNAL_TLS_CA_CERT")?,
        );
        let cert_path = PathBuf::from(
            std::env::var("IRONMESH_INTERNAL_TLS_CERT")
                .context("missing IRONMESH_INTERNAL_TLS_CERT")?,
        );
        let key_path = PathBuf::from(
            std::env::var("IRONMESH_INTERNAL_TLS_KEY")
                .context("missing IRONMESH_INTERNAL_TLS_KEY")?,
        );
        let internal_tls = Some(InternalTlsConfig {
            bind_addr: internal_bind_addr,
            internal_url: std::env::var("IRONMESH_INTERNAL_URL")
                .ok()
                .or_else(|| Some(format!("https://{internal_bind_addr}"))),
            metadata_path: existing_tls_metadata_sidecar_path(&cert_path),
            ca_cert_path,
            cert_path,
            key_path,
        });

        let mut labels = HashMap::new();
        labels.insert(
            "region".to_string(),
            std::env::var("IRONMESH_REGION").unwrap_or_else(|_| "local".to_string()),
        );
        labels.insert(
            "dc".to_string(),
            std::env::var("IRONMESH_DC").unwrap_or_else(|_| "local-dc".to_string()),
        );
        labels.insert(
            "rack".to_string(),
            std::env::var("IRONMESH_RACK").unwrap_or_else(|_| "local-rack".to_string()),
        );

        let default_replication_factor = 3;
        let public_peer_api_enabled = std::env::var("IRONMESH_PUBLIC_PEER_API_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(false);
        let default_audit_interval_secs = 3600;
        let default_replication_repair_backoff_secs = 30;

        Ok(Self {
            mode,
            cluster_id,
            node_id,
            data_dir,
            metadata_backend: parse_metadata_backend(
                std::env::var("IRONMESH_METADATA_BACKEND")
                    .unwrap_or_else(|_| "sqlite".to_string())
                    .as_str(),
            )?,
            bind_addr,
            public_url,
            labels,
            public_tls,
            allow_insecure_public_http,
            public_ca_cert_path: std::env::var("IRONMESH_PUBLIC_TLS_CA_CERT")
                .ok()
                .map(PathBuf::from),
            public_ca_key_path: std::env::var("IRONMESH_PUBLIC_TLS_CA_KEY")
                .ok()
                .map(PathBuf::from),
            bootstrap_trust_roots: None,
            public_peer_api_enabled,
            internal_tls,
            internal_ca_key_path: std::env::var("IRONMESH_INTERNAL_TLS_CA_KEY")
                .ok()
                .map(PathBuf::from),
            rendezvous_ca_cert_path,
            rendezvous_urls,
            rendezvous_registration_enabled,
            rendezvous_mtls_required,
            managed_rendezvous: None,
            relay_mode,
            enrollment_issuer_url: None,
            node_enrollment_path: None,
            node_enrollment_auto_renew_enabled: false,
            node_enrollment_auto_renew_check_secs: node_enrollment_auto_renew_check_secs(),
            heartbeat_timeout_secs: std::env::var("IRONMESH_HEARTBEAT_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(90),
            audit_interval_secs: std::env::var("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(default_audit_interval_secs),
            replica_view_sync_interval_secs: std::env::var(
                "IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS",
            )
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_REPLICA_VIEW_SYNC_INTERVAL_SECS),
            replication_factor: std::env::var("IRONMESH_REPLICATION_FACTOR")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(default_replication_factor),
            accepted_over_replication_items: std::env::var(
                "IRONMESH_ACCEPTED_OVER_REPLICATION_ITEMS",
            )
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0),
            metadata_commit_mode: MetadataCommitMode::parse(
                std::env::var("IRONMESH_METADATA_COMMIT_MODE")
                    .unwrap_or_else(|_| "local".to_string())
                    .as_str(),
            )?,
            autonomous_replication_on_put_enabled: std::env::var(
                "IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED",
            )
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true),
            replication_repair_enabled: std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            replication_repair_batch_size: std::env::var("IRONMESH_REPLICATION_REPAIR_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(256),
            replication_repair_max_retries: std::env::var(
                "IRONMESH_REPLICATION_REPAIR_MAX_RETRIES",
            )
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3),
            replication_repair_backoff_secs: std::env::var(
                "IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS",
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(default_replication_repair_backoff_secs),
            repair_busy_throttle_enabled: std::env::var("IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            repair_busy_inflight_threshold: std::env::var(
                "IRONMESH_REPAIR_BUSY_INFLIGHT_THRESHOLD",
            )
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(32),
            repair_busy_wait_millis: std::env::var("IRONMESH_REPAIR_BUSY_WAIT_MILLIS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(100),
            startup_repair_enabled: std::env::var("IRONMESH_STARTUP_REPAIR_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            startup_repair_delay_secs: std::env::var("IRONMESH_STARTUP_REPAIR_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
            peer_heartbeat_enabled: std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(true),
            peer_heartbeat_interval_secs: std::env::var(
                "IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS",
            )
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(15),
            admin_token: std::env::var("IRONMESH_ADMIN_TOKEN")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            admin_password_hash: None,
            require_client_auth: !allow_unauthenticated_clients,
        })
    }

    fn validate_public_listener_security(&self) -> Result<()> {
        if self.public_tls.is_some() || self.allow_insecure_public_http {
            return Ok(());
        }

        bail!(
            "ironmesh-server-node refuses insecure public HTTP startup without TLS; configure IRONMESH_PUBLIC_TLS_CERT plus IRONMESH_PUBLIC_TLS_KEY, or set {ALLOW_INSECURE_PUBLIC_HTTP_ENV}=true for local development/testing only"
        )
    }

    fn metadata_backend(&self) -> MetadataBackendKind {
        self.metadata_backend
    }

    fn repair_config(&self) -> RepairConfig {
        RepairConfig {
            enabled: self.replication_repair_enabled,
            batch_size: self.replication_repair_batch_size,
            max_retries: self.replication_repair_max_retries,
            backoff_secs: self.replication_repair_backoff_secs,
            busy_throttle_enabled: self.repair_busy_throttle_enabled,
            busy_inflight_threshold: self.repair_busy_inflight_threshold,
            busy_wait_millis: self.repair_busy_wait_millis,
            startup_repair_enabled: self.startup_repair_enabled,
            startup_repair_delay_secs: self.startup_repair_delay_secs,
        }
    }

    fn peer_heartbeat_config(&self) -> PeerHeartbeatConfig {
        PeerHeartbeatConfig {
            enabled: self.peer_heartbeat_enabled,
            interval_secs: self.peer_heartbeat_interval_secs,
        }
    }

    fn admin_control(&self) -> AdminControl {
        AdminControl {
            admin_token: self.admin_token.clone(),
            admin_password_hash: self.admin_password_hash.clone(),
        }
    }

    fn client_auth_control(&self) -> ClientAuthControl {
        ClientAuthControl {
            require_client_auth: self.require_client_auth,
        }
    }
}

impl LocalNodeHandle {
    pub fn start(config: ServerNodeConfig) -> Result<Self> {
        config.validate_public_listener_security()?;

        let base_url = config.public_url.clone().unwrap_or_else(|| {
            let scheme = if config.public_tls.is_some() {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{}", config.bind_addr)
        });

        let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel::<()>();
        let (result_tx, result_rx) = std::sync::mpsc::channel::<Result<()>>();

        let thread = thread::spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let _ = result_tx.send(Err(err).context("failed to build local node runtime"));
                    return;
                }
            };

            runtime.block_on(async move {
                let mut task = tokio::spawn(async move { run(config).await });

                tokio::select! {
                    outcome = &mut task => {
                        let outcome = match outcome {
                            Ok(result) => result,
                            Err(err) => Err(err).context("local node task failed"),
                        };
                        let _ = result_tx.send(outcome);
                    }
                    _ = async {
                        let _ = shutdown_rx.recv();
                    } => {
                        task.abort();
                        let _ = task.await;
                        let _ = result_tx.send(Ok(()));
                    }
                }
            });
        });

        wait_for_local_node_ready(base_url.as_str(), &result_rx)?;

        Ok(Self {
            base_url,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub fn base_url(&self) -> &str {
        self.base_url.as_str()
    }
}

impl Drop for LocalNodeHandle {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn wait_for_local_node_ready(
    base_url: &str,
    result_rx: &std::sync::mpsc::Receiver<Result<()>>,
) -> Result<()> {
    let health_url = format!("{}/health", base_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .context("failed to build local node health-check client")?;

    for _ in 0..50 {
        match result_rx.try_recv() {
            Ok(Ok(())) => bail!("local node exited before becoming healthy"),
            Ok(Err(err)) => return Err(err).context("local node failed during startup"),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                bail!("local node startup channel disconnected")
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }

        if let Ok(response) = client.get(&health_url).send()
            && response.status() == StatusCode::OK
        {
            return Ok(());
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    bail!("local node did not become healthy at {health_url}")
}

pub async fn run_from_env() -> Result<()> {
    let log_buffer = Arc::new(LogBuffer::new(500));
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new("info"))
        .with(common::logging::compact_fmt_layer())
        .with(LogCaptureLayer::new(log_buffer.clone()))
        .init();

    // Rustls 0.23 requires explicitly selecting a process-wide CryptoProvider when multiple
    // providers are enabled via transitive features (e.g. reqwest brings `ring`, axum-server may
    // bring `aws-lc-rs`). Installing once avoids startup panics.
    let _ = rustls::crypto::ring::default_provider().install_default();
    match setup::load_startup_mode_from_env()? {
        setup::StartupMode::Runtime(config) => run_inner(config, Some(log_buffer)).await,
        setup::StartupMode::Setup(config) => setup::run_setup_mode(config, log_buffer).await,
    }
}

pub async fn run(config: ServerNodeConfig) -> Result<()> {
    run_inner(config, None).await
}

async fn wait_for_shutdown_trigger(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }

    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            warn!(error = %err, "failed waiting for ctrl-c signal");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                let _ = signal.recv().await;
            }
            Err(err) => {
                warn!(error = %err, "failed installing SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

async fn run_inner(config: ServerNodeConfig, log_buffer: Option<Arc<LogBuffer>>) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    config.validate_public_listener_security()?;

    let public_tls_runtime = match config.public_tls.as_ref() {
        Some(public_tls) => Some(PublicTlsRuntime {
            config: RustlsConfig::from_pem_file(&public_tls.cert_path, &public_tls.key_path)
                .await
                .with_context(|| {
                    format!(
                        "failed building public TLS config from {} and {}",
                        public_tls.cert_path.display(),
                        public_tls.key_path.display()
                    )
                })?,
            cert_path: public_tls.cert_path.clone(),
            key_path: public_tls.key_path.clone(),
            metadata_path: public_tls.metadata_path.clone(),
        }),
        None => None,
    };
    let internal_tls_runtime = match config.internal_tls.as_ref() {
        Some(internal_tls) => Some(InternalTlsRuntime {
            config: build_internal_mtls_rustls_config(
                &internal_tls.ca_cert_path,
                &internal_tls.cert_path,
                &internal_tls.key_path,
            )?,
            ca_cert_path: internal_tls.ca_cert_path.clone(),
            cert_path: internal_tls.cert_path.clone(),
            key_path: internal_tls.key_path.clone(),
            metadata_path: internal_tls.metadata_path.clone(),
        }),
        None => None,
    };
    let tls_status = collect_node_certificate_status(
        public_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        public_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        internal_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        internal_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        NodeCertificateAutoRenewStatusView {
            enabled: config.node_enrollment_auto_renew_enabled,
            enrollment_path: config
                .node_enrollment_path
                .as_ref()
                .map(|path| path.display().to_string()),
            issuer_url: config.enrollment_issuer_url.clone(),
            check_interval_secs: config
                .node_enrollment_auto_renew_enabled
                .then_some(config.node_enrollment_auto_renew_check_secs),
            last_attempt_unix: None,
            last_success_unix: None,
            last_error: None,
            restart_required: false,
        },
    );
    log_certificate_lifecycle_status(&tls_status);

    let public_url = config.public_url.clone().unwrap_or_else(|| {
        let scheme = if config.public_tls.is_some() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{}", config.bind_addr)
    });
    let internal_url = config
        .internal_tls
        .as_ref()
        .and_then(|tls| tls.internal_url.clone())
        .unwrap_or_else(|| public_url.clone());

    let repair_config = config.repair_config();
    let peer_heartbeat_config = config.peer_heartbeat_config();
    let admin_control = config.admin_control();
    let client_auth_control = config.client_auth_control();
    let startup_repair_status = if repair_config.startup_repair_enabled {
        StartupRepairStatus::Scheduled
    } else {
        StartupRepairStatus::Disabled
    };

    let policy = ReplicationPolicy {
        replication_factor: config.replication_factor,
        accepted_over_replication_items: config.accepted_over_replication_items,
        ..ReplicationPolicy::default()
    };

    let mut cluster = ClusterService::new(config.node_id, policy, config.heartbeat_timeout_secs);
    cluster.register_node(NodeDescriptor {
        node_id: config.node_id,
        reachability: NodeReachability {
            public_api_url: Some(public_url.clone()),
            peer_api_url: Some(internal_url),
            relay_required: config.relay_mode == RelayMode::Required,
        },
        capabilities: NodeCapabilities {
            public_api: true,
            peer_api: true,
            relay_tunnel: config.rendezvous_registration_enabled
                && config.relay_mode != RelayMode::Disabled,
        },
        labels: config.labels.clone(),
        capacity_bytes: 0,
        free_bytes: 0,
        storage_stats: None,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    let store = new_store_rwlock(
        PersistentStore::init_with_metadata_backend(
            config.data_dir.clone(),
            config.metadata_backend(),
        )
        .await?,
    );
    let upload_chunk_ingestor = {
        let store_guard = store.read("server.init.chunk_ingestor").await;
        store_guard.chunk_ingestor()
    };
    info!(
        data_dir = %config.data_dir.display(),
        metadata_backend = ?config.metadata_backend(),
        "server node metadata backend initialized"
    );
    let startup_phase_anchor = Instant::now();

    #[cfg(test)]
    let internal_http = if let Some(internal_tls) = config.internal_tls.as_ref() {
        build_internal_mtls_http_client(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )?
    } else {
        reqwest::Client::new()
    };

    let load_cluster_replicas_phase_started_at =
        log_server_startup_phase_begin("load_cluster_replicas", startup_phase_anchor);
    let persisted_cluster_replicas = {
        let store_guard = store.read("server.init.load_cluster_replicas").await;
        match store_guard.load_cluster_replicas().await {
            Ok(replicas) => replicas,
            Err(err) => {
                warn!(error = %err, "failed to load cluster replica state; starting empty");
                HashMap::new()
            }
        }
    };
    log_server_startup_phase_end(
        "load_cluster_replicas",
        startup_phase_anchor,
        load_cluster_replicas_phase_started_at,
    );
    cluster.import_replicas_by_key(persisted_cluster_replicas);

    let load_client_credentials_phase_started_at =
        log_server_startup_phase_begin("load_client_credentials", startup_phase_anchor);
    let persisted_client_credentials = {
        let store_guard = store.read("server.init.load_client_credentials").await;
        match store_guard.load_client_credential_state().await {
            Ok(state) => state,
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to load client credential state; starting empty"
                );
                ClientCredentialState::default()
            }
        }
    };
    log_server_startup_phase_end(
        "load_client_credentials",
        startup_phase_anchor,
        load_client_credentials_phase_started_at,
    );

    let load_trust_and_rendezvous_phase_started_at =
        log_server_startup_phase_begin("load_trust_and_rendezvous", startup_phase_anchor);
    let embedded_trust_roots =
        config
            .bootstrap_trust_roots
            .clone()
            .unwrap_or(BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            });

    let internal_ca_key_pem = config
        .internal_ca_key_path
        .clone()
        .map(|path| {
            std::fs::read_to_string(&path).with_context(|| {
                format!("failed reading internal CA private key {}", path.display())
            })
        })
        .transpose()?;
    let configured_public_ca_key_pem = config
        .public_ca_key_path
        .clone()
        .map(|path| {
            std::fs::read_to_string(&path)
                .with_context(|| format!("failed reading public CA private key {}", path.display()))
        })
        .transpose()?;

    let public_ca_pem = config
        .public_ca_cert_path
        .clone()
        .map(|path| {
            std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "failed reading IRONMESH_PUBLIC_TLS_CA_CERT from {}",
                    path.display()
                )
            })
        })
        .transpose()?
        .or(embedded_trust_roots.public_api_ca_pem.clone());
    let cluster_ca_pem = config
        .internal_tls
        .as_ref()
        .map(|tls| tls.ca_cert_path.clone())
        .or_else(|| config.public_ca_cert_path.clone())
        .map(|path| {
            std::fs::read_to_string(&path).with_context(|| {
                format!("failed reading cluster CA certificate {}", path.display())
            })
        })
        .transpose()?
        .or(embedded_trust_roots.cluster_ca_pem.clone());
    let public_ca_key_pem = configured_public_ca_key_pem.or_else(|| {
        if public_ca_pem.is_none() || public_ca_pem == cluster_ca_pem {
            internal_ca_key_pem.clone()
        } else {
            None
        }
    });
    let rendezvous_ca_pem = config
        .rendezvous_ca_cert_path
        .clone()
        .map(|path| {
            std::fs::read_to_string(&path).with_context(|| {
                format!(
                    "failed reading rendezvous CA certificate {}",
                    path.display()
                )
            })
        })
        .transpose()?
        .or(embedded_trust_roots.rendezvous_ca_pem.clone())
        .or_else(|| public_ca_pem.clone())
        .or_else(|| cluster_ca_pem.clone());
    let rendezvous_client_identity_pem = config
        .internal_tls
        .as_ref()
        .map(|tls| build_identity_pem_from_paths(&tls.cert_path, &tls.key_path))
        .transpose()?;
    let normalized_rendezvous_urls = normalize_rendezvous_url_list(&config.rendezvous_urls)?;
    let (rendezvous_control, rendezvous_controls) = if config.rendezvous_registration_enabled {
        match build_rendezvous_control_clients(
            config.cluster_id,
            &normalized_rendezvous_urls,
            config.peer_heartbeat_interval_secs.max(5),
            rendezvous_ca_pem
                .as_deref()
                .or(public_ca_pem.as_deref())
                .or(cluster_ca_pem.as_deref()),
            rendezvous_client_identity_pem.as_deref(),
        ) {
            Ok(clients) => clients,
            Err(err) => {
                warn!(error = %err, "failed to initialize rendezvous control client");
                (None, Vec::new())
            }
        }
    } else {
        (None, Vec::new())
    };
    let rendezvous_registration_state = Arc::new(Mutex::new(
        config
            .rendezvous_urls
            .iter()
            .map(|url| canonicalize_rendezvous_url(url).unwrap_or_else(|_| url.clone()))
            .map(|url| (url, RendezvousEndpointRegistrationRuntime::default()))
            .collect(),
    ));
    log_server_startup_phase_end(
        "load_trust_and_rendezvous",
        startup_phase_anchor,
        load_trust_and_rendezvous_phase_started_at,
    );

    let load_upload_sessions_phase_started_at =
        log_server_startup_phase_begin("load_upload_sessions", startup_phase_anchor);
    let upload_session_store = match load_upload_session_store(&config.data_dir).await {
        Ok(mut store) => {
            prune_expired_upload_sessions(&mut store, unix_ts());
            if let Err(err) = persist_upload_session_store(&store).await {
                warn!(error = %err, "failed to persist pruned upload session state");
            }
            store
        }
        Err(err) => {
            warn!(error = %err, "failed to load upload session state; starting empty");
            UploadSessionStore {
                path: upload_sessions_path(&config.data_dir),
                sessions: HashMap::new(),
            }
        }
    };
    log_server_startup_phase_end(
        "load_upload_sessions",
        startup_phase_anchor,
        load_upload_sessions_phase_started_at,
    );

    let map_perf_logging_enabled = env_flag_is_truthy("IRONMESH_MAP_PERF_LOG");
    if map_perf_logging_enabled {
        info!("map performance logging enabled via IRONMESH_MAP_PERF_LOG");
    }
    let storage_stats_history_retention_secs = env_u64_or(
        "IRONMESH_STORAGE_STATS_HISTORY_RETENTION_SECS",
        STORAGE_STATS_HISTORY_RETENTION_SECS,
    );
    if storage_stats_history_retention_secs != STORAGE_STATS_HISTORY_RETENTION_SECS {
        info!(
            retention_secs = storage_stats_history_retention_secs,
            "storage stats history retention override enabled"
        );
    }
    let data_scrub_enabled = env_flag_or("IRONMESH_DATA_SCRUB_ENABLED", true);
    let data_scrub_interval_secs = env_u64_or(
        "IRONMESH_DATA_SCRUB_INTERVAL_SECS",
        DATA_SCRUB_INTERVAL_SECS,
    );
    if data_scrub_interval_secs != DATA_SCRUB_INTERVAL_SECS {
        info!(
            interval_secs = data_scrub_interval_secs,
            "data scrub interval override enabled"
        );
    }
    let data_scrub_history_retention_secs = env_u64_or(
        "IRONMESH_DATA_SCRUB_HISTORY_RETENTION_SECS",
        DATA_SCRUB_HISTORY_RETENTION_SECS,
    );
    if data_scrub_history_retention_secs != DATA_SCRUB_HISTORY_RETENTION_SECS {
        info!(
            retention_secs = data_scrub_history_retention_secs,
            "data scrub history retention override enabled"
        );
    }
    if !data_scrub_enabled {
        info!("background data scrubbing disabled via IRONMESH_DATA_SCRUB_ENABLED");
    }
    let repair_run_history_retention_secs = env_u64_or(
        "IRONMESH_REPAIR_RUN_HISTORY_RETENTION_SECS",
        REPAIR_RUN_HISTORY_RETENTION_SECS,
    );
    if repair_run_history_retention_secs != REPAIR_RUN_HISTORY_RETENTION_SECS {
        info!(
            retention_secs = repair_run_history_retention_secs,
            "repair run history retention override enabled"
        );
    }

    let state = ServerState {
        data_dir: config.data_dir.clone(),
        cluster_id: config.cluster_id,
        node_id: config.node_id,
        storage_stats_history_retention_secs,
        data_scrub_enabled,
        data_scrub_interval_secs,
        data_scrub_history_retention_secs,
        repair_run_history_retention_secs,
        map_perf_logging_enabled,
        map_glyphs_root: web_maps::resolve_map_glyphs_root(None),
        mbtiles_sources: Arc::new(RwLock::new(HashMap::new())),
        store,
        upload_chunk_ingestor,
        cluster: Arc::new(Mutex::new(cluster)),
        client_credentials: Arc::new(Mutex::new(persisted_client_credentials)),
        bootstrap_claims: BootstrapClaimBroker::new(),
        upload_sessions: new_upload_sessions_rwlock(upload_session_store),
        upload_sessions_dirty: Arc::new(AtomicUsize::new(0)),
        upload_sessions_persist_notify: Arc::new(Notify::new()),
        public_ca_pem,
        public_ca_key_pem,
        cluster_ca_pem,
        internal_ca_key_pem,
        public_tls_runtime,
        internal_tls_runtime,
        rendezvous_ca_pem,
        rendezvous_urls: Arc::new(StdMutex::new(normalized_rendezvous_urls)),
        rendezvous_registration_enabled: config.rendezvous_registration_enabled,
        rendezvous_mtls_required: config.rendezvous_mtls_required,
        managed_rendezvous_public_url: config
            .managed_rendezvous
            .as_ref()
            .map(|managed| managed.public_url.clone()),
        rendezvous_registration_state,
        relay_mode: config.relay_mode,
        enrollment_issuer_url: config.enrollment_issuer_url.clone(),
        node_enrollment_path: config.node_enrollment_path.clone(),
        node_enrollment_auto_renew_enabled: config.node_enrollment_auto_renew_enabled,
        node_enrollment_auto_renew_check_secs: config.node_enrollment_auto_renew_check_secs,
        node_enrollment_auto_renew_state: Arc::new(Mutex::new(NodeEnrollmentAutoRenewState {
            loaded_public_tls_fingerprint: tls_status.public_tls.certificate_fingerprint.clone(),
            loaded_internal_tls_fingerprint: tls_status
                .internal_tls
                .certificate_fingerprint
                .clone(),
            ..NodeEnrollmentAutoRenewState::default()
        })),
        outbound_clients: Arc::new(RwLock::new(OutboundClients {
            #[cfg(test)]
            internal_http,
            rendezvous_control,
            rendezvous_controls,
        })),
        peer_relay_sessions: PeerRelaySessionPool::default(),
        metadata_commit_mode: config.metadata_commit_mode,
        autonomous_replication_on_put_enabled: config.autonomous_replication_on_put_enabled,
        inflight_requests: Arc::new(AtomicUsize::new(0)),
        peer_heartbeat_config,
        repair_config,
        log_buffer: log_buffer.unwrap_or_else(|| Arc::new(LogBuffer::new(500))),
        startup_repair_status: Arc::new(Mutex::new(startup_repair_status)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
        repair_activity: Arc::new(Mutex::new(RepairActivityRuntime::default())),
        data_scrub_activity: Arc::new(Mutex::new(DataScrubActivityRuntime::default())),
        local_availability_refresh_lock: Arc::new(Mutex::new(())),
        local_availability_refresh_notify: Arc::new(Notify::new()),
        storage_stats_runtime: Arc::new(Mutex::new(StorageStatsRuntime::default())),
        namespace_change_sequence: Arc::new(AtomicU64::new(0)),
        namespace_change_tx: watch::channel(0).0,
        admin_control,
        admin_sessions: Arc::new(Mutex::new(AdminSessionStore::default())),
        client_auth_control,
        client_auth_replay_cache: Arc::new(Mutex::new(ClientAuthReplayCache::default())),
    };

    spawn_upload_session_store_persister(state.clone());
    let refresh_local_node_storage_phase_started_at =
        log_server_startup_phase_begin("refresh_local_node_storage", startup_phase_anchor);
    refresh_local_node_storage(&state).await;
    log_server_startup_phase_end(
        "refresh_local_node_storage",
        startup_phase_anchor,
        refresh_local_node_storage_phase_started_at,
    );
    info!(
        phase = "refresh_local_availability",
        since_metadata_init_ms = startup_phase_anchor.elapsed().as_millis(),
        "server startup phase deferred to background"
    );
    spawn_local_availability_refresher(state.clone(), startup_phase_anchor);
    spawn_storage_stats_refresher(state.clone());
    spawn_data_scrubber(state.clone());
    spawn_media_metadata_backfill(state.clone(), "startup");

    let load_repair_attempts_phase_started_at =
        log_server_startup_phase_begin("load_repair_attempts", startup_phase_anchor);
    let persisted_attempts = {
        let store = read_store(&state, "server.init.load_repair_attempts").await;
        match store.load_repair_attempts().await {
            Ok(attempts) => attempts,
            Err(err) => {
                warn!(error = %err, "failed to load repair attempts state; starting empty");
                HashMap::new()
            }
        }
    };
    log_server_startup_phase_end(
        "load_repair_attempts",
        startup_phase_anchor,
        load_repair_attempts_phase_started_at,
    );

    {
        let mut repair_state = state.repair_state.lock().await;
        repair_state.attempts = persisted_attempts
            .into_iter()
            .map(|(key, record)| {
                (
                    key,
                    RepairAttemptEntry {
                        attempts: record.attempts,
                        last_failure_unix: record.last_failure_unix,
                    },
                )
            })
            .collect();
    }

    if state.rendezvous_registration_enabled {
        spawn_rendezvous_peer_discovery(state.clone(), config.replica_view_sync_interval_secs);
        spawn_rendezvous_presence_heartbeat(
            state.clone(),
            Some(public_url.clone()),
            config
                .internal_tls
                .as_ref()
                .and_then(|tls| tls.internal_url.clone()),
            config.public_peer_api_enabled,
            config.peer_heartbeat_interval_secs,
        );

        if state.relay_mode != RelayMode::Disabled {
            spawn_rendezvous_relay_multiplex_agent(state.clone());
        }
    }

    spawn_replication_auditor(state.clone(), config.audit_interval_secs);
    spawn_replica_view_synchronizer(state.clone(), config.replica_view_sync_interval_secs);
    if state.repair_config.startup_repair_enabled {
        spawn_startup_replication_repair(
            state.clone(),
            state.repair_config.startup_repair_delay_secs,
        );
    }
    if peer_heartbeat_config.enabled {
        spawn_peer_heartbeat_emitter(state.clone(), peer_heartbeat_config.interval_secs);
    }

    if config.node_enrollment_auto_renew_enabled {
        spawn_node_enrollment_auto_renew(
            state.clone(),
            config.clone(),
            config.node_enrollment_auto_renew_check_secs,
        );
    }

    let build_http_routers_phase_started_at =
        log_server_startup_phase_begin("build_http_routers", startup_phase_anchor);
    let public_client_api = Router::new()
        .route("/transport/ws", get(client_transport_ws))
        .route("/diagnostics/latency", get(latency_diagnostic))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/store/uploads/start", post(start_upload_session))
        .route(
            "/store/uploads/{upload_id}",
            get(get_upload_session).delete(delete_upload_session),
        )
        .route(
            "/store/uploads/{upload_id}/chunk/{index}",
            put(upload_session_chunk),
        )
        .route(
            "/store/uploads/{upload_id}/complete",
            post(complete_upload_session_route),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store/restore", post(restore_snapshot_path))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .head(head_object)
                .delete(delete_object),
        )
        .route("/versions/{key}", get(list_versions))
        .route(
            "/versions/{key}/confirm/{version_id}",
            post(confirm_version),
        )
        .route("/versions/{key}/commit/{version_id}", post(commit_version))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_auth,
        ));

    let public_cluster_info_api = Router::new()
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route("/cluster/replication/plan", get(replication_plan))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_or_admin_auth,
        ));

    let public_admin_api = Router::new()
        .route("/auth/admin/session", get(get_admin_session_status))
        .route("/auth/admin/login", post(login_admin_session))
        .route("/auth/admin/logout", post(logout_admin_session))
        .route("/auth/repair/activity", get(repair_activity_status))
        .route("/auth/repair/history", get(repair_history))
        .route("/auth/scrub/activity", get(data_scrub_activity_status))
        .route("/auth/scrub/history", get(data_scrub_history))
        .route("/auth/scrub/cluster", get(data_scrub_cluster_status))
        .route("/auth/scrub/run", post(trigger_data_scrub_public))
        .route("/auth/store/snapshots", get(list_snapshots_admin))
        .route("/auth/store/index", get(list_store_index_admin))
        .route("/auth/versions/{key}", get(list_versions_admin))
        .route("/auth/store/delete", post(delete_object_by_query_admin))
        .route("/auth/store/rename", post(rename_object_path_admin))
        .route("/auth/media/thumbnail", get(get_media_thumbnail_admin))
        .route("/auth/media/cache/clear", post(clear_media_cache_admin))
        .route("/auth/store/{key}", get(get_object_admin))
        .route(
            "/auth/rendezvous-config",
            get(get_rendezvous_config).put(update_rendezvous_config),
        )
        .route("/auth/client-credentials", get(list_client_credentials))
        .route(
            "/auth/client-credentials/{device_id}",
            axum::routing::delete(revoke_client_credential),
        )
        .route(
            "/auth/bootstrap-bundles/issue",
            post(issue_bootstrap_bundle),
        )
        .route("/auth/bootstrap-claims/issue", post(issue_bootstrap_claim))
        .route("/auth/node-bootstraps/issue", post(issue_node_bootstrap))
        .route("/auth/node-enrollments/issue", post(issue_node_enrollment))
        .route(
            "/auth/managed-signer/backup/export",
            post(export_managed_signer_backup_handler),
        )
        .route(
            "/auth/managed-signer/backup/import",
            post(import_managed_signer_backup_handler),
        )
        .route(
            "/auth/managed-rendezvous/failover/export",
            post(export_managed_rendezvous_failover_handler),
        )
        .route(
            "/auth/managed-rendezvous/failover/import",
            post(import_managed_rendezvous_failover_handler),
        )
        .route(
            "/auth/managed-control-plane/promotion/export",
            post(export_managed_control_plane_promotion_handler),
        )
        .route(
            "/auth/managed-control-plane/promotion/import",
            post(import_managed_control_plane_promotion_handler),
        )
        .route(
            "/auth/node-join-requests/issue-enrollment",
            post(issue_node_enrollment_from_join_request),
        )
        .route(
            "/auth/node-certificates/status",
            get(node_certificate_status),
        )
        .route("/auth/pairing-tokens/issue", post(issue_pairing_token));

    let public_maps_api = Router::new()
        .route("/maps/mbtiles-metadata", get(web_maps::mbtiles_metadata))
        .route(
            "/maps/logical-file",
            get(web_maps::logical_file).head(web_maps::logical_file),
        )
        .route("/maps/tiles/{z}/{x}/{y}", get(web_maps::xyz_tile))
        .route("/maps/vector-tiles/{z}/{x}/{y}", get(web_maps::vector_tile))
        .route("/maps/fonts/{fontstack}/{range}", get(web_maps::font_range));

    let public_api_v1 = Router::new()
        .route("/health", get(health))
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route(
            "/cluster/nodes/{node_id}",
            put(register_node).delete(remove_node),
        )
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair_public),
        )
        .route(
            "/cluster/replication/cleanup",
            post(execute_replication_cleanup),
        )
        .route("/cluster/reconcile/{node_id}", post(reconcile_from_node))
        .route("/maintenance/cleanup", post(run_cleanup))
        .route(
            "/maintenance/tombstones/compact",
            post(run_tombstone_compaction),
        )
        .route(
            "/maintenance/tombstones/archive",
            get(list_tombstone_archives),
        )
        .route(
            "/maintenance/tombstones/archive/restore",
            post(run_tombstone_archive_restore),
        )
        .route(
            "/maintenance/tombstones/archive/purge",
            post(run_tombstone_archive_purge),
        )
        .merge(public_maps_api.clone())
        .merge(public_admin_api.clone())
        .merge(public_cluster_info_api.clone())
        .merge(public_client_api.clone());

    let legacy_public_api = Router::new()
        .route("/health", get(health))
        .route(
            "/api/maps/mbtiles-metadata",
            get(web_maps::mbtiles_metadata),
        )
        .route(
            "/api/maps/logical-file",
            get(web_maps::logical_file).head(web_maps::logical_file),
        )
        .route("/api/maps/tiles/{z}/{x}/{y}", get(web_maps::xyz_tile))
        .route(
            "/api/maps/vector-tiles/{z}/{x}/{y}",
            get(web_maps::vector_tile),
        )
        .route(
            "/api/maps/fonts/{fontstack}/{range}",
            get(web_maps::font_range),
        )
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route(
            "/cluster/nodes/{node_id}",
            put(register_node).delete(remove_node),
        )
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair_public),
        )
        .route(
            "/cluster/replication/cleanup",
            post(execute_replication_cleanup),
        )
        .route("/cluster/reconcile/{node_id}", post(reconcile_from_node))
        .route("/maintenance/cleanup", post(run_cleanup))
        .route(
            "/maintenance/tombstones/compact",
            post(run_tombstone_compaction),
        )
        .route(
            "/maintenance/tombstones/archive",
            get(list_tombstone_archives),
        )
        .route(
            "/maintenance/tombstones/archive/restore",
            post(run_tombstone_archive_restore),
        )
        .route(
            "/maintenance/tombstones/archive/purge",
            post(run_tombstone_archive_purge),
        )
        .merge(public_admin_api)
        .merge(public_cluster_info_api)
        .merge(public_client_api);

    let public_logs_api = Router::new()
        .route("/logs", get(ui::list_logs))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_or_admin_auth,
        ));

    let public_app = Router::new()
        .route("/", get(ui::index))
        .route("/ironmesh-favicon.svg", get(ui::favicon))
        .route("/assets/{*path}", get(ui::static_asset))
        .route("/ui/assets/{*path}", get(ui::static_asset))
        .route("/ui/app.css", get(ui::app_css))
        .route("/ui/app.js", get(ui::app_js))
        .merge(public_logs_api)
        .nest(PUBLIC_API_V1_PREFIX, public_api_v1)
        .merge(legacy_public_api);

    let public_app = public_app
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_inflight_requests,
        ));

    let internal_app = Router::new()
        .route("/health", get(health))
        .route("/diagnostics/latency", get(latency_diagnostic))
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route(
            "/cluster/scrub/activity",
            get(data_scrub_activity_status_internal),
        )
        .route("/cluster/scrub/history", get(data_scrub_history_internal))
        .route("/cluster/scrub/run", post(trigger_data_scrub_peer))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route("/cluster/replication/plan", get(replication_plan))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/store/uploads/start", post(start_upload_session))
        .route(
            "/store/uploads/{upload_id}",
            get(get_upload_session).delete(delete_upload_session),
        )
        .route(
            "/store/uploads/{upload_id}/chunk/{index}",
            put(upload_session_chunk),
        )
        .route(
            "/store/uploads/{upload_id}/complete",
            post(complete_upload_session_route),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store/restore", post(restore_snapshot_path))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .head(head_object)
                .delete(delete_object),
        )
        .route("/versions/{key}", get(list_versions))
        .route(
            "/versions/{key}/confirm/{version_id}",
            post(confirm_version),
        )
        .route("/versions/{key}/commit/{version_id}", post(commit_version))
        .merge(build_internal_peer_api())
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_internal_caller,
        ));
    log_server_startup_phase_end(
        "build_http_routers",
        startup_phase_anchor,
        build_http_routers_phase_started_at,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut internal_server_handle = None;
    let mut internal_server_task = None;

    if let Some(internal_tls) = config.internal_tls.as_ref() {
        let internal_bind_addr = internal_tls.bind_addr;
        let internal_tls = state
            .internal_tls_runtime
            .as_ref()
            .map(|runtime| runtime.config.clone())
            .context("internal TLS runtime missing for configured internal listener")?;
        let internal_state = state.clone();
        let handle = Handle::new();
        internal_server_handle = Some(handle.clone());
        internal_server_task = Some(tokio::spawn(async move {
            info!(
                bind_addr = %internal_bind_addr,
                node_id = %internal_state.node_id,
                "server node internal (mTLS) listener"
            );

            let acceptor = MtlsCallerAcceptor::new(internal_tls);
            axum_server::Server::bind(internal_bind_addr)
                .handle(handle)
                .acceptor(acceptor)
                .serve(internal_app.into_make_service())
                .await
                .context("internal server listener stopped")
        }));
    }

    if let Some(managed_rendezvous) = config.managed_rendezvous.clone() {
        let rendezvous_state = state.clone();
        tokio::spawn(async move {
            info!(
                bind_addr = %managed_rendezvous.bind_addr,
                public_url = %managed_rendezvous.public_url,
                node_id = %rendezvous_state.node_id,
                "server node embedded managed rendezvous listener"
            );

            if let Err(err) =
                embedded_rendezvous::run_listener(embedded_rendezvous::EmbeddedRendezvousConfig {
                    bind_addr: managed_rendezvous.bind_addr,
                    public_url: managed_rendezvous.public_url,
                    client_ca_cert_path: managed_rendezvous.client_ca_cert_path,
                    cert_path: managed_rendezvous.cert_path,
                    key_path: managed_rendezvous.key_path,
                })
                .await
            {
                warn!(error = %err, "embedded managed rendezvous listener stopped");
            }
        });
    }

    info!(
        bind_addr = %config.bind_addr,
        node_id = %config.node_id,
        tls_enabled = config.public_tls.is_some(),
        mode = ?config.mode,
        "server node listening"
    );

    let mut public_server_handle = None;
    let mut public_server_task = if config.public_tls.is_some() {
        let tls_config = state
            .public_tls_runtime
            .as_ref()
            .map(|runtime| runtime.config.clone())
            .context("public TLS runtime missing for configured public listener")?;
        let handle = Handle::new();
        public_server_handle = Some(handle.clone());
        tokio::spawn(async move {
            axum_server::bind_rustls(config.bind_addr, tls_config)
                .handle(handle)
                .serve(public_app.into_make_service())
                .await
                .context("public TLS server listener stopped")
        })
    } else {
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
            axum::serve(listener, public_app)
                .with_graceful_shutdown(wait_for_shutdown_trigger(shutdown_rx))
                .await
                .context("public HTTP server listener stopped")
        })
    };

    tokio::select! {
        outcome = &mut public_server_task => {
            outcome.context("public server task join failure")??;
        }
        _ = shutdown_signal() => {
            info!(node_id = %state.node_id, "shutdown signal received");
            let _ = shutdown_tx.send(true);
            if let Some(handle) = public_server_handle.as_ref() {
                handle.graceful_shutdown(Some(Duration::from_secs(5)));
            }
            if let Some(handle) = internal_server_handle.as_ref() {
                handle.graceful_shutdown(Some(Duration::from_secs(5)));
            }

            public_server_task
                .await
                .context("public server task join failure")??;
            if let Some(task) = internal_server_task.take() {
                task.await.context("internal server task join failure")??;
            }
            if let Err(err) = persist_upload_session_store_now(&state).await {
                warn!(error = %err, "failed to persist upload session state during shutdown");
            }
            return Ok(());
        }
    }

    let _ = shutdown_tx.send(true);
    if let Some(handle) = internal_server_handle.as_ref() {
        handle.graceful_shutdown(Some(Duration::from_secs(0)));
    }
    if let Some(task) = internal_server_task {
        task.await.context("internal server task join failure")??;
    }
    if let Err(err) = persist_upload_session_store_now(&state).await {
        warn!(error = %err, "failed to persist upload session state during shutdown");
    }

    Ok(())
}

fn storage_stats_for_path(path: &FsPath) -> Result<(u64, u64)> {
    let capacity_bytes = fs2::total_space(path)
        .with_context(|| format!("failed to read capacity for {}", path.display()))?;
    let free_bytes = fs2::available_space(path)
        .with_context(|| format!("failed to read free space for {}", path.display()))?;
    Ok((capacity_bytes, free_bytes.min(capacity_bytes)))
}

fn summarize_storage_stats(sample: &StorageStatsSample) -> NodeStorageStatsSummary {
    NodeStorageStatsSummary {
        collected_at_unix: sample.collected_at_unix,
        latest_snapshot_id: sample.latest_snapshot_id.clone(),
        latest_snapshot_created_at_unix: sample.latest_snapshot_created_at_unix,
        latest_snapshot_object_count: sample.latest_snapshot_object_count,
        chunk_store_bytes: sample.chunk_store_bytes,
        manifest_store_bytes: sample.manifest_store_bytes,
        metadata_db_bytes: sample.metadata_db_bytes,
        media_cache_bytes: sample.media_cache_bytes,
        latest_snapshot_logical_bytes: sample.latest_snapshot_logical_bytes,
        latest_snapshot_unique_chunk_bytes: sample.latest_snapshot_unique_chunk_bytes,
    }
}

async fn refresh_local_node_storage(state: &ServerState) {
    let (capacity_bytes, free_bytes) = match storage_stats_for_path(&state.data_dir) {
        Ok(stats) => stats,
        Err(err) => {
            warn!(
                path = %state.data_dir.display(),
                error = %err,
                "failed to refresh local node storage stats"
            );
            return;
        }
    };

    let mut cluster = state.cluster.lock().await;
    let _ = cluster.update_node_storage(state.node_id, free_bytes, capacity_bytes, None);
}

async fn refresh_storage_stats_once(state: &ServerState) {
    {
        let mut runtime = state.storage_stats_runtime.lock().await;
        runtime.collecting = true;
        runtime.last_attempt_unix = Some(unix_ts());
    }

    let storage_stats_collector = {
        let store = read_store(state, "storage_stats.clone_worker").await;
        store.storage_stats_collector()
    };

    let result: anyhow::Result<StorageStatsSample> = {
        match storage_stats_collector
            .current_chunk_store_bytes(Some(STORAGE_STATS_RECONCILE_INTERVAL_SECS))
            .await
        {
            Ok(_) => storage_stats_collector.collect_storage_stats_sample().await,
            Err(err) => Err(err),
        }
    };

    match result {
        Ok(sample) => {
            let persist_result: anyhow::Result<()> = {
                if let Err(err) = storage_stats_collector
                    .persist_storage_stats_sample(&sample)
                    .await
                {
                    Err(err)
                } else {
                    let retention_cutoff = sample
                        .collected_at_unix
                        .saturating_sub(state.storage_stats_history_retention_secs);
                    storage_stats_collector
                        .prune_storage_stats_history_before(retention_cutoff)
                        .await
                }
            };

            let mut runtime = state.storage_stats_runtime.lock().await;
            runtime.collecting = false;
            match persist_result {
                Ok(()) => {
                    {
                        let mut cluster = state.cluster.lock().await;
                        let _ = cluster.update_node_storage_stats(
                            state.node_id,
                            summarize_storage_stats(&sample),
                        );
                    }
                    runtime.last_success_unix = Some(sample.collected_at_unix);
                    runtime.last_error = None;
                }
                Err(err) => {
                    runtime.last_error = Some(err.to_string());
                    tracing::warn!(error = %err, "failed to persist storage stats sample");
                }
            }
        }
        Err(err) => {
            let mut runtime = state.storage_stats_runtime.lock().await;
            runtime.collecting = false;
            runtime.last_error = Some(err.to_string());
            tracing::warn!(error = %err, "failed to collect storage stats sample");
        }
    }
}

fn spawn_storage_stats_refresher(state: ServerState) {
    tokio::spawn(async move {
        refresh_storage_stats_once(&state).await;

        let mut ticker =
            tokio::time::interval(Duration::from_secs(STORAGE_STATS_REFRESH_INTERVAL_SECS));
        let mut namespace_changes = state.namespace_change_tx.subscribe();

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    refresh_storage_stats_once(&state).await;
                }
                changed = namespace_changes.changed() => {
                    if changed.is_err() {
                        break;
                    }

                    loop {
                        tokio::time::sleep(Duration::from_secs(STORAGE_STATS_CHANGE_DEBOUNCE_SECS)).await;
                        match namespace_changes.has_changed() {
                            Ok(true) => {
                                let _ = namespace_changes.borrow_and_update();
                                continue;
                            }
                            Ok(false) => break,
                            Err(_) => return,
                        }
                    }

                    refresh_storage_stats_once(&state).await;
                }
            }
        }
    });
}

fn spawn_data_scrubber(state: ServerState) {
    if !state.data_scrub_enabled {
        return;
    }

    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(state.data_scrub_interval_secs.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;

        loop {
            ticker.tick().await;
            let result = start_local_data_scrub(&state, DataScrubRunTrigger::Scheduled).await;
            if result.started {
                if let Some(active_run) = result.active_run.as_ref() {
                    info!(
                        run_id = %active_run.run_id,
                        interval_secs = state.data_scrub_interval_secs,
                        "scheduled data scrub queued"
                    );
                }
            } else if let Some(active_run) = result.active_run.as_ref() {
                info!(
                    run_id = %active_run.run_id,
                    interval_secs = state.data_scrub_interval_secs,
                    "scheduled data scrub skipped because a run is already active"
                );
            }
        }
    });
}

fn spawn_rendezvous_presence_heartbeat(
    state: ServerState,
    public_url: Option<String>,
    internal_peer_url: Option<String>,
    public_peer_api_enabled: bool,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let connected_interval = Duration::from_secs(interval_secs.max(5));
        let retry_interval = Duration::from_secs(RENDEZVOUS_REGISTRATION_RETRY_INTERVAL_SECS)
            .min(connected_interval);

        loop {
            refresh_local_node_storage(&state).await;

            let local_descriptor = {
                let cluster = state.cluster.lock().await;
                cluster
                    .list_nodes()
                    .into_iter()
                    .find(|node| node.node_id == state.node_id)
            };
            let registration = build_rendezvous_presence_registration(
                &state,
                public_url.as_deref(),
                internal_peer_url.as_deref(),
                public_peer_api_enabled,
                local_descriptor.as_ref(),
            );

            let clients = current_rendezvous_endpoint_clients(&state).await;
            if clients.is_empty() {
                tokio::time::sleep(connected_interval).await;
                continue;
            }

            let mut registrations = tokio::task::JoinSet::new();
            for endpoint in clients {
                let url = endpoint.url.clone();
                let client = endpoint.control.clone();
                let registration = registration.clone();
                registrations.spawn(async move {
                    let result = tokio::time::timeout(
                        Duration::from_secs(RENDEZVOUS_REGISTRATION_REQUEST_TIMEOUT_SECS),
                        client.register_presence(&registration),
                    )
                    .await;
                    (url, result)
                });
            }

            let mut all_registered = true;
            while let Some(result) = registrations.join_next().await {
                let Ok((url, result)) = result else {
                    all_registered = false;
                    continue;
                };
                match result {
                    Ok(Ok(response)) => {
                        let recovered = record_rendezvous_registration_success(&state, &url).await;
                        if recovered {
                            info!(
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                updated_at_unix = response.updated_at_unix,
                                "rendezvous presence registration recovered"
                            );
                        } else {
                            tracing::debug!(
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                updated_at_unix = response.updated_at_unix,
                                "registered rendezvous presence"
                            );
                        }
                    }
                    Ok(Err(err)) => {
                        all_registered = false;
                        let error_text = err.to_string();
                        let failures =
                            record_rendezvous_registration_failure(&state, &url, &error_text).await;
                        if failures == 1 || failures % 10 == 0 {
                            warn!(
                                error = %err,
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                consecutive_failures = failures,
                                "failed to register rendezvous presence"
                            );
                        } else {
                            tracing::debug!(
                                error = %err,
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                consecutive_failures = failures,
                                "failed to register rendezvous presence"
                            );
                        }
                    }
                    Err(_) => {
                        all_registered = false;
                        let error_text = format!(
                            "timed out contacting rendezvous endpoint {url} while registering presence"
                        );
                        let failures =
                            record_rendezvous_registration_failure(&state, &url, &error_text).await;
                        if failures == 1 || failures % 10 == 0 {
                            warn!(
                                error = %error_text,
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                consecutive_failures = failures,
                                "failed to register rendezvous presence"
                            );
                        } else {
                            tracing::debug!(
                                error = %error_text,
                                node_id = %state.node_id,
                                rendezvous_url = %url,
                                consecutive_failures = failures,
                                "failed to register rendezvous presence"
                            );
                        }
                    }
                }
            }

            tokio::time::sleep(if all_registered {
                connected_interval
            } else {
                retry_interval
            })
            .await;
        }
    })
}

fn build_rendezvous_presence_registration(
    state: &ServerState,
    public_url: Option<&str>,
    internal_peer_url: Option<&str>,
    _public_peer_api_enabled: bool,
    local_descriptor: Option<&NodeDescriptor>,
) -> PresenceRegistration {
    let mut direct_candidates = Vec::new();
    let mut seen_endpoints = BTreeSet::new();
    let public_api_url = normalize_optional_url(public_url);
    let peer_api_url = normalize_optional_url(internal_peer_url);

    push_rendezvous_direct_candidate(
        &mut direct_candidates,
        &mut seen_endpoints,
        internal_peer_url,
    );

    let mut capabilities = Vec::new();
    if !direct_candidates.is_empty() {
        capabilities.push(TransportCapability::DirectHttps);
    }
    if state.relay_mode != RelayMode::Disabled {
        capabilities.push(TransportCapability::RelayTunnel);
    }

    PresenceRegistration {
        cluster_id: state.cluster_id,
        identity: PeerIdentity::Node(state.node_id),
        public_api_url,
        peer_api_url,
        direct_candidates,
        labels: local_descriptor
            .map(|descriptor| descriptor.labels.clone())
            .unwrap_or_default(),
        capacity_bytes: local_descriptor.map(|descriptor| descriptor.capacity_bytes),
        free_bytes: local_descriptor.map(|descriptor| descriptor.free_bytes),
        capabilities,
        relay_mode: state.relay_mode,
        connected_at_unix: unix_ts(),
    }
}

fn push_rendezvous_direct_candidate(
    candidates: &mut Vec<ConnectionCandidate>,
    seen_endpoints: &mut BTreeSet<String>,
    endpoint: Option<&str>,
) {
    let Some(endpoint) = endpoint
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
    else {
        return;
    };

    if !seen_endpoints.insert(endpoint.clone()) {
        return;
    }

    candidates.push(ConnectionCandidate {
        kind: CandidateKind::DirectHttps,
        endpoint,
        rtt_ms: None,
    });
}

fn normalize_optional_url(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
}

fn spawn_rendezvous_peer_discovery(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
        ticker.tick().await;

        loop {
            let Some(client) = current_rendezvous_control(&state).await else {
                ticker.tick().await;
                continue;
            };
            match client.list_presence().await {
                Ok(response) => {
                    let discovered =
                        apply_rendezvous_presence_entries(&state, &response.entries).await;
                    tracing::debug!(
                        node_id = %state.node_id,
                        discovered_nodes = discovered,
                        registered_endpoints = response.registered_endpoints,
                        "refreshed rendezvous peer discovery"
                    );
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        node_id = %state.node_id,
                        rendezvous_urls = ?client.config().rendezvous_urls,
                        "failed to refresh rendezvous peer discovery"
                    );
                }
            }

            ticker.tick().await;
        }
    });
}

async fn apply_rendezvous_presence_entries(
    state: &ServerState,
    entries: &[transport_sdk::PresenceEntry],
) -> usize {
    let mut discovered = 0usize;
    let mut cluster = state.cluster.lock().await;

    for entry in entries {
        let transport_sdk::PeerIdentity::Node(node_id) = &entry.registration.identity else {
            continue;
        };
        if *node_id == state.node_id {
            continue;
        }

        let Some(descriptor) = node_descriptor_from_presence_entry(entry) else {
            tracing::debug!(
                node_id = %node_id,
                "skipping rendezvous peer without a usable transport path"
            );
            continue;
        };

        cluster.register_node(descriptor);
        discovered += 1;
    }

    discovered
}

fn node_descriptor_from_presence_entry(
    entry: &transport_sdk::PresenceEntry,
) -> Option<NodeDescriptor> {
    let transport_sdk::PeerIdentity::Node(node_id) = &entry.registration.identity else {
        return None;
    };

    let peer_api_url = entry
        .registration
        .peer_api_url
        .as_deref()
        .and_then(|value| normalize_optional_url(Some(value)))
        .or_else(|| {
            entry
                .registration
                .direct_candidates
                .iter()
                .find_map(|candidate| {
                    if candidate.kind == CandidateKind::DirectHttps {
                        normalize_optional_url(Some(candidate.endpoint.as_str()))
                    } else {
                        None
                    }
                })
        });
    let has_relay_capability = entry
        .registration
        .capabilities
        .contains(&TransportCapability::RelayTunnel)
        || entry.registration.relay_mode != RelayMode::Disabled;
    if peer_api_url.is_none() && !has_relay_capability {
        return None;
    }
    let public_api_url = entry
        .registration
        .public_api_url
        .as_deref()
        .and_then(|value| normalize_optional_url(Some(value)));

    Some(NodeDescriptor {
        node_id: *node_id,
        reachability: NodeReachability {
            public_api_url: public_api_url.clone(),
            peer_api_url: peer_api_url.clone(),
            relay_required: entry.registration.relay_mode == RelayMode::Required,
        },
        capabilities: NodeCapabilities {
            public_api: public_api_url.is_some(),
            peer_api: peer_api_url.is_some(),
            relay_tunnel: has_relay_capability,
        },
        labels: entry.registration.labels.clone(),
        capacity_bytes: entry.registration.capacity_bytes.unwrap_or(0),
        free_bytes: entry.registration.free_bytes.unwrap_or(0),
        storage_stats: None,
        last_heartbeat_unix: entry.updated_at_unix,
        status: cluster::NodeStatus::Online,
    })
}

fn peer_transport_client(state: &ServerState) -> Result<PeerTransportClient> {
    PeerTransportClient::new(PeerTransportClientConfig {
        cluster_id: state.cluster_id,
        prefer_direct: !matches!(state.relay_mode, RelayMode::Preferred | RelayMode::Required),
        allow_relay: state.relay_mode != RelayMode::Disabled,
    })
}

fn peer_connection_candidates(
    state: &ServerState,
    node: &NodeDescriptor,
) -> Vec<ConnectionCandidate> {
    let mut candidates = Vec::new();
    let mut seen_endpoints = BTreeSet::new();

    if state.relay_mode != RelayMode::Required && !node.relay_required() {
        push_ranked_peer_candidate(
            &mut candidates,
            &mut seen_endpoints,
            normalize_optional_url(node.peer_api_url()),
            Some(1),
        );
    }
    if state.relay_mode != RelayMode::Disabled && node.relay_capable() {
        for relay_url in current_rendezvous_urls(state) {
            let Some(endpoint) = normalize_optional_url(Some(relay_url.as_str())) else {
                continue;
            };
            if !seen_endpoints.insert(endpoint.clone()) {
                continue;
            }
            candidates.push(ConnectionCandidate {
                kind: CandidateKind::Relay,
                endpoint,
                rtt_ms: None,
            });
        }
    }

    candidates
}

fn push_ranked_peer_candidate(
    candidates: &mut Vec<ConnectionCandidate>,
    seen_endpoints: &mut BTreeSet<String>,
    endpoint: Option<String>,
    rtt_ms: Option<u32>,
) {
    let Some(endpoint) = endpoint else {
        return;
    };
    if !seen_endpoints.insert(endpoint.clone()) {
        return;
    }

    candidates.push(ConnectionCandidate {
        kind: CandidateKind::DirectHttps,
        endpoint,
        rtt_ms,
    });
}

fn plan_peer_transport(
    state: &ServerState,
    node: &NodeDescriptor,
) -> Result<transport_sdk::TransportSessionPlan> {
    let transport = peer_transport_client(state)?;
    let candidates = peer_connection_candidates(state, node);
    transport
        .plan_session(PeerIdentity::Node(node.node_id), &candidates)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "node {} does not expose any usable peer transport candidates",
                node.node_id
            )
        })
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn resolve_peer_base_url(state: &ServerState, node: &NodeDescriptor) -> Result<String> {
    let plan = plan_peer_transport(state, node)?;
    let candidate = plan
        .candidate
        .as_ref()
        .context("peer transport plan did not include a selected candidate")?;

    match plan.path_kind {
        TransportPathKind::DirectHttps | TransportPathKind::DirectQuic => {
            Ok(candidate.endpoint.trim_end_matches('/').to_string())
        }
        TransportPathKind::RelayTunnel => bail!(
            "node {} requires relay peer transport instead of a direct base URL",
            node.node_id
        ),
    }
}

fn build_direct_peer_http_client(
    state: &ServerState,
    node: &NodeDescriptor,
) -> Result<reqwest::Client> {
    if let Some(internal_tls) = state.internal_tls_runtime.as_ref() {
        build_internal_mtls_http_client_for_expected_peer(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
            node.node_id,
            state.cluster_id,
        )
    } else {
        Ok(reqwest::Client::new())
    }
}

pub(crate) fn build_internal_peer_api() -> Router<ServerState> {
    Router::new()
        .route("/cluster/nodes/{node_id}/heartbeat", post(node_heartbeat))
        .route(
            "/cluster/node-enrollments/renew",
            post(renew_node_enrollment_authenticated),
        )
        .route(
            "/cluster/availability/subjects/local",
            get(local_available_subjects),
        )
        .route(
            "/cluster/metadata/subjects/local",
            get(local_metadata_subjects),
        )
        .route(
            "/cluster/replication/export",
            get(export_replication_bundle),
        )
        .route("/cluster/metadata/export", get(export_metadata_bundle))
        .route(
            "/cluster/replication/chunk/{hash}",
            get(get_replication_chunk),
        )
        .route(
            "/cluster/replication/push/chunk/{hash}",
            post(push_replication_chunk),
        )
        .route(
            "/cluster/replication/push/manifest",
            post(push_replication_manifest),
        )
        .route("/cluster/replication/drop", post(drop_replication_subject))
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair_peer),
        )
        .route(
            "/cluster/reconcile/export/provisional",
            get(export_provisional_versions),
        )
}

#[derive(Debug, Clone)]
pub(crate) struct PeerHttpResponse {
    pub(crate) status: u16,
    #[allow(dead_code)]
    pub(crate) headers: Vec<RelayHttpHeader>,
    pub(crate) body: Bytes,
}

impl PeerHttpResponse {
    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub(crate) fn json<T>(&self) -> Result<T>
    where
        T: DeserializeOwned,
    {
        serde_json::from_slice(&self.body).with_context(|| {
            format!(
                "failed decoding peer JSON response with status {}",
                self.status
            )
        })
    }
}

async fn execute_peer_request(
    state: &ServerState,
    node: &NodeDescriptor,
    method: reqwest::Method,
    path_and_query: &str,
    headers: Vec<RelayHttpHeader>,
    body: Vec<u8>,
) -> Result<PeerHttpResponse> {
    let plan = plan_peer_transport(state, node)?;
    let availability_sync = path_and_query == "/cluster/availability/subjects/local";
    let started = availability_sync.then(Instant::now);

    match plan.path_kind {
        TransportPathKind::DirectHttps | TransportPathKind::DirectQuic => {
            let base_url = plan
                .candidate
                .as_ref()
                .map(|candidate| candidate.endpoint.trim_end_matches('/').to_string())
                .context("peer transport plan did not include a selected candidate")?;
            let internal_http = build_direct_peer_http_client(state, node)?;
            let response = execute_direct_peer_request(
                &internal_http,
                &base_url,
                method,
                path_and_query,
                headers,
                body,
            )
            .await?;
            if let Some(started) = started {
                info!(
                    peer_node_id = %node.node_id,
                    transport = ?plan.path_kind,
                    elapsed_ms = started.elapsed().as_millis(),
                    "availability peer request transport finished"
                );
            }
            Ok(response)
        }
        TransportPathKind::RelayTunnel => {
            let response =
                execute_relay_peer_request(state, node, method, path_and_query, headers, body)
                    .await?;
            if let Some(started) = started {
                info!(
                    peer_node_id = %node.node_id,
                    transport = ?plan.path_kind,
                    elapsed_ms = started.elapsed().as_millis(),
                    "availability peer request transport finished"
                );
            }
            Ok(response)
        }
    }
}

async fn execute_direct_peer_request(
    http: &reqwest::Client,
    base_url: &str,
    method: reqwest::Method,
    path_and_query: &str,
    headers: Vec<RelayHttpHeader>,
    body: Vec<u8>,
) -> Result<PeerHttpResponse> {
    let url = join_peer_url(base_url, path_and_query)?;
    let request_url = url.to_string();
    let request_method = method.as_str().to_string();
    let request_timeout_secs = if path_and_query.starts_with("/cluster/replication/repair") {
        DIRECT_PEER_REPAIR_REQUEST_TIMEOUT_SECS
    } else {
        DIRECT_PEER_REQUEST_TIMEOUT_SECS
    };
    let request_timeout = Duration::from_secs(request_timeout_secs);
    let mut request = http.request(method, url);
    for header in headers {
        request = request.header(header.name, header.value);
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let response = tokio::time::timeout(request_timeout, request.send())
        .await
        .with_context(|| {
            format!(
                "timed out after {request_timeout_secs}s sending direct peer request {request_method} {request_url}"
            )
        })?
        .with_context(|| {
            format!(
                "failed sending direct peer request {request_method} {request_url}"
            )
        })?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| RelayHttpHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect::<Vec<_>>();
    let body = tokio::time::timeout(request_timeout, response.bytes())
        .await
        .with_context(|| {
            format!(
                "timed out after {request_timeout_secs}s reading direct peer response body {request_method} {request_url}"
            )
        })?
        .with_context(|| {
            format!(
                "failed reading direct peer response body {request_method} {request_url}"
            )
        })?;

    Ok(PeerHttpResponse {
        status,
        headers,
        body,
    })
}

async fn open_relay_peer_session(
    state: &ServerState,
    rendezvous: &RendezvousControlClient,
    node: &NodeDescriptor,
) -> Result<EstablishedPeerRelaySession> {
    let ticket = rendezvous
        .issue_relay_ticket(&RelayTicketRequest {
            cluster_id: state.cluster_id,
            source: PeerIdentity::Node(state.node_id),
            target: PeerIdentity::Node(node.node_id),
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
            requested_expires_in_secs: Some(300),
        })
        .await
        .with_context(|| format!("failed issuing relay ticket for node {}", node.node_id))?;
    let (relay_session, session) = rendezvous
        .connect_relay_multiplex_source(&ticket, MultiplexConfig::default())
        .await
        .with_context(|| {
            format!(
                "failed opening multiplex relay session for node {}",
                node.node_id
            )
        })?;
    perform_transport_client_handshake(
        &session,
        TransportSessionControlMessage::Hello {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            cluster_id: state.cluster_id,
            role: TransportSessionRole::Node,
            peer: PeerIdentity::Node(state.node_id),
            target: Some(PeerIdentity::Node(node.node_id)),
        },
    )
    .await
    .with_context(|| {
        format!(
            "failed completing multiplex relay handshake for session {} to node {}",
            relay_session.session_id, node.node_id
        )
    })?;

    Ok(EstablishedPeerRelaySession {
        session,
        relay_session,
    })
}

async fn ensure_relay_peer_session(
    state: &ServerState,
    node: &NodeDescriptor,
) -> Result<CachedPeerRelaySession> {
    if let Some(existing) = cached_peer_relay_session(state, node.node_id).await {
        return Ok(existing);
    }

    let rendezvous = current_rendezvous_control(state)
        .await
        .context("relay peer transport requires rendezvous control client")?;
    let established = open_relay_peer_session(state, &rendezvous, node).await?;
    let cached = CachedPeerRelaySession {
        session: Arc::new(established.session),
        relay_session: established.relay_session,
    };

    let mut sessions = state.peer_relay_sessions.sessions.lock().await;
    if let Some(existing) = sessions.get(&node.node_id).cloned() {
        drop(sessions);
        if let Ok(unused_session) = Arc::try_unwrap(cached.session)
            && let Err(err) = unused_session.close().await
        {
            tracing::debug!(
                error = %err,
                peer_node_id = %node.node_id,
                session_id = %cached.relay_session.session_id,
                "failed closing redundant relay peer session"
            );
        }
        return Ok(existing);
    }

    sessions.insert(node.node_id, cached.clone());
    Ok(cached)
}

async fn execute_relay_peer_request(
    state: &ServerState,
    node: &NodeDescriptor,
    method: reqwest::Method,
    path_and_query: &str,
    headers: Vec<RelayHttpHeader>,
    body: Vec<u8>,
) -> Result<PeerHttpResponse> {
    let normalized_path = normalize_peer_path_and_query(path_and_query)?;
    let request_headers = transport_headers_from_relay_headers(&headers);

    for attempt in 0..2 {
        let cached = ensure_relay_peer_session(state, node).await?;
        let request = BufferedTransportRequest::new(
            TransportStreamKind::Rpc,
            method.as_str(),
            normalized_path.clone(),
            request_headers.clone(),
            body.clone(),
        );

        let result = async {
            let mut stream = cached.session.open_stream().await.with_context(|| {
                format!(
                    "failed opening multiplex relay peer stream for node {}",
                    node.node_id
                )
            })?;
            write_buffered_transport_request(&mut stream, &request)
                .await
                .with_context(|| {
                    format!(
                        "failed writing multiplex relay peer request for node {}",
                        node.node_id
                    )
                })?;
            let response = read_buffered_transport_response(&mut stream)
                .await
                .with_context(|| {
                    format!(
                        "failed reading multiplex relay peer response for node {}",
                        node.node_id
                    )
                })?;
            Ok::<PeerHttpResponse, anyhow::Error>(peer_http_response_from_multiplex(response))
        }
        .await;

        match result {
            Ok(response) => return Ok(response),
            Err(err) if attempt == 0 => {
                invalidate_peer_relay_session(state, node.node_id).await;
                tracing::debug!(
                    error = %err,
                    peer_node_id = %node.node_id,
                    session_id = %cached.relay_session.session_id,
                    "retrying relay peer request after resetting cached session"
                );
            }
            Err(err) => {
                invalidate_peer_relay_session(state, node.node_id).await;
                return Err(err);
            }
        }
    }

    bail!(
        "relay peer request retried without producing a response for node {}",
        node.node_id
    )
}

fn join_peer_url(base_url: &str, path_and_query: &str) -> Result<reqwest::Url> {
    reqwest::Url::parse(base_url.trim())
        .with_context(|| format!("invalid peer base URL {base_url}"))?
        .join(path_and_query.trim_start_matches('/'))
        .with_context(|| format!("failed to join peer URL {base_url} and {path_and_query}"))
}

fn normalize_peer_path_and_query(path_and_query: &str) -> Result<String> {
    let trimmed = path_and_query.trim();
    if trimmed.is_empty() {
        bail!("peer path_and_query must not be empty");
    }
    if trimmed.starts_with('/') {
        Ok(trimmed.to_string())
    } else {
        Ok(format!("/{trimmed}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectTransportWsMessage {
    Binary(Vec<u8>),
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

impl transport_sdk::WebSocketMessageCodec for DirectTransportWsMessage {
    fn decode(self) -> std::io::Result<transport_sdk::DecodedWebSocketMessage> {
        Ok(match self {
            Self::Binary(bytes) => transport_sdk::DecodedWebSocketMessage::Binary(bytes),
            Self::Text(_) => transport_sdk::DecodedWebSocketMessage::Ignore,
            Self::Ping(payload) => transport_sdk::DecodedWebSocketMessage::Ping(payload),
            Self::Pong(_) => transport_sdk::DecodedWebSocketMessage::Pong,
            Self::Close => transport_sdk::DecodedWebSocketMessage::Close,
        })
    }

    fn binary(bytes: Vec<u8>) -> Self {
        Self::Binary(bytes)
    }

    fn pong(bytes: Vec<u8>) -> Self {
        Self::Pong(bytes)
    }
}

struct DirectTransportSocketAdapter {
    socket: AxumWebSocket,
}

impl Stream for DirectTransportSocketAdapter {
    type Item = Result<DirectTransportWsMessage, axum::Error>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.socket).poll_next(cx) {
            Poll::Ready(Some(Ok(AxumWsMessage::Binary(bytes)))) => {
                Poll::Ready(Some(Ok(DirectTransportWsMessage::Binary(bytes.to_vec()))))
            }
            Poll::Ready(Some(Ok(AxumWsMessage::Text(text)))) => {
                Poll::Ready(Some(Ok(DirectTransportWsMessage::Text(text.to_string()))))
            }
            Poll::Ready(Some(Ok(AxumWsMessage::Ping(payload)))) => {
                Poll::Ready(Some(Ok(DirectTransportWsMessage::Ping(payload.to_vec()))))
            }
            Poll::Ready(Some(Ok(AxumWsMessage::Pong(payload)))) => {
                Poll::Ready(Some(Ok(DirectTransportWsMessage::Pong(payload.to_vec()))))
            }
            Poll::Ready(Some(Ok(AxumWsMessage::Close(_)))) => {
                Poll::Ready(Some(Ok(DirectTransportWsMessage::Close)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<DirectTransportWsMessage> for DirectTransportSocketAdapter {
    type Error = axum::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: DirectTransportWsMessage) -> Result<(), Self::Error> {
        let message = match item {
            DirectTransportWsMessage::Binary(bytes) => AxumWsMessage::Binary(bytes.into()),
            DirectTransportWsMessage::Text(text) => AxumWsMessage::Text(text.into()),
            DirectTransportWsMessage::Ping(payload) => AxumWsMessage::Ping(payload.into()),
            DirectTransportWsMessage::Pong(payload) => AxumWsMessage::Pong(payload.into()),
            DirectTransportWsMessage::Close => AxumWsMessage::Close(None),
        };
        Pin::new(&mut self.get_mut().socket).start_send(message)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_close(cx)
    }
}

async fn serve_direct_transport_session(
    state: ServerState,
    peer: PeerIdentity,
    mut session: MultiplexedSession,
) -> Result<()> {
    let hello = perform_transport_server_handshake(
        &mut session,
        TransportSessionControlMessage::Ready {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            session_id: format!("direct-{}", Uuid::now_v7()),
            max_concurrent_streams: MultiplexConfig::default().max_num_streams,
        },
    )
    .await
    .context("failed completing direct transport handshake")?;
    let TransportSessionControlMessage::Hello {
        cluster_id,
        peer: hello_peer,
        ..
    } = hello
    else {
        bail!("direct transport handshake did not return a hello control message");
    };
    if cluster_id != state.cluster_id {
        bail!(
            "direct transport handshake cluster_id {} did not match local cluster {}",
            cluster_id,
            state.cluster_id
        );
    }
    if hello_peer != peer {
        bail!(
            "direct transport handshake peer {} did not match authenticated peer {}",
            hello_peer,
            peer
        );
    }

    loop {
        let next = session
            .accept_stream()
            .await
            .context("failed accepting direct transport stream")?;
        let Some(stream) = next else {
            return Ok(());
        };

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_multiplexed_relay_stream(
                state,
                transport_service::TransportExecutionScope::Public,
                stream,
            )
            .await
            {
                warn!(error = %err, "direct transport request stream failed");
            }
        });
    }
}

async fn client_transport_ws(
    State(state): State<ServerState>,
    websocket: WebSocketUpgrade,
    headers: HeaderMap,
) -> Response {
    let Some(device_id) =
        request_device_id(&headers).and_then(|value| DeviceId::parse_str(&value).ok())
    else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let peer = PeerIdentity::Device(device_id);

    websocket
        .on_upgrade(move |socket| async move {
            let transport =
                transport_sdk::WebSocketByteStream::new(DirectTransportSocketAdapter { socket });
            let session = match MultiplexedSession::spawn(
                transport,
                MultiplexMode::Server,
                MultiplexConfig::default(),
            ) {
                Ok(session) => session,
                Err(err) => {
                    warn!(error = %err, "failed spawning direct transport session");
                    return;
                }
            };

            if let Err(err) = serve_direct_transport_session(state, peer, session).await {
                warn!(error = %err, "direct transport session failed");
            }
        })
        .into_response()
}

fn transport_headers_from_response(headers: &HeaderMap) -> Vec<TransportHeader> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| TransportHeader {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect()
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

fn relay_headers_from_transport_headers(headers: &[TransportHeader]) -> Vec<RelayHttpHeader> {
    headers
        .iter()
        .map(|header| RelayHttpHeader {
            name: header.name.clone(),
            value: header.value.clone(),
        })
        .collect()
}

fn peer_http_response_from_multiplex(response: BufferedTransportResponse) -> PeerHttpResponse {
    PeerHttpResponse {
        status: response.status,
        headers: relay_headers_from_transport_headers(&response.headers),
        body: Bytes::from(response.body),
    }
}

fn buffered_transport_error_response(
    request_id: impl Into<String>,
    status: u16,
    body: String,
) -> BufferedTransportResponse {
    let content_length = body.len();
    BufferedTransportResponse {
        request_id: request_id.into(),
        status,
        headers: vec![
            TransportHeader {
                name: "content-type".to_string(),
                value: "text/plain; charset=utf-8".to_string(),
            },
            TransportHeader {
                name: "content-length".to_string(),
                value: content_length.to_string(),
            },
        ],
        body: body.into_bytes(),
    }
}

async fn handle_multiplexed_relay_stream<S>(
    state: ServerState,
    scope: transport_service::TransportExecutionScope,
    mut stream: S,
) -> Result<()>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    let request_head = read_transport_request_head(&mut stream)
        .await
        .context("failed decoding multiplexed relay request head")?;
    if request_head.kind == TransportStreamKind::ObjectRead {
        return handle_streamed_object_read_request(&state, request_head, &mut stream).await;
    }
    if request_head.kind == TransportStreamKind::ObjectWrite {
        return handle_streamed_object_write_request(&state, request_head, &mut stream).await;
    }
    let request = read_buffered_transport_request_from_head(&mut stream, request_head)
        .await
        .context("failed decoding multiplexed relay request body")?;
    let response =
        match transport_service::execute_buffered_transport_request(&state, &scope, &request).await
        {
            Ok(response) => {
                if response.body.len() >= LARGE_RELAY_HTTP_RESPONSE_LOG_THRESHOLD_BYTES {
                    info!(
                        request_id = %response.request_id,
                        path = %request.path,
                        relay_response_body_bytes = response.body.len(),
                        "large multiplexed relay response"
                    );
                }
                response
            }
            Err(err) => buffered_transport_error_response(
                request.request_id.clone(),
                502,
                format!("transport execution failed: {err:#}"),
            ),
        };

    write_buffered_transport_response(&mut stream, &response)
        .await
        .context("failed writing multiplexed relay response")
}

async fn read_buffered_transport_request_from_head<S>(
    stream: &mut S,
    request_head: TransportRequestHead,
) -> Result<BufferedTransportRequest>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .context("failed reading multiplexed relay request body")?;
    let request = BufferedTransportRequest {
        request_id: request_head.request_id,
        kind: request_head.kind,
        method: request_head.method,
        path: request_head.path,
        headers: request_head.headers,
        body,
    };
    request.validate()?;
    Ok(request)
}

async fn handle_streamed_object_read_request<S>(
    state: &ServerState,
    request_head: TransportRequestHead,
    stream: &mut S,
) -> Result<()>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    if request_head.method != "GET" {
        let response = buffered_transport_error_response(
            request_head.request_id,
            405,
            format!(
                "object read streams only support GET, received {}",
                request_head.method
            ),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object read method error");
    }

    if !request_head.end_of_stream {
        let mut ignored = Vec::new();
        stream
            .read_to_end(&mut ignored)
            .await
            .context("failed draining unexpected object read request body")?;
        let response = buffered_transport_error_response(
            request_head.request_id,
            400,
            "object read streams must not include request bodies".to_string(),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object read body error");
    }

    let raw_path = request_head.path.trim();
    let normalized_raw_path = transport_service::normalize_public_api_v1_path_and_query(raw_path);
    let path_only = raw_path
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(raw_path);
    let path_only = transport_service::strip_public_api_v1_prefix(path_only);
    if !path_only.starts_with("/store/") {
        let response = buffered_transport_error_response(
            request_head.request_id,
            400,
            format!("object read streams only support /store/* paths, received {path_only}"),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object read path error");
    }

    let headers = match transport_service::header_map_from_transport_headers(&request_head.headers)
    {
        Ok(headers) => headers,
        Err(err) => {
            let response = buffered_transport_error_response(
                request_head.request_id,
                400,
                format!("invalid object read headers: {err:#}"),
            );
            return write_buffered_transport_response(stream, &response)
                .await
                .context("failed writing object read header error");
        }
    };
    let query = match transport_service::parse_query::<ObjectGetQuery>(&normalized_raw_path) {
        Ok(query) => query,
        Err(err) => {
            let response = buffered_transport_error_response(
                request_head.request_id,
                400,
                format!("invalid object read query: {err:#}"),
            );
            return write_buffered_transport_response(stream, &response)
                .await
                .context("failed writing object read query error");
        }
    };
    let key = match transport_service::decode_route_tail(path_only, "/store/") {
        Ok(key) => key,
        Err(err) => {
            let response = buffered_transport_error_response(
                request_head.request_id,
                400,
                format!("invalid object read path: {err:#}"),
            );
            return write_buffered_transport_response(stream, &response)
                .await
                .context("failed writing object read key error");
        }
    };

    let response = get_object_response(state, &key, query, &headers, false).await;
    write_transport_response_from_axum(stream, request_head.request_id, response).await
}

async fn handle_streamed_object_write_request<S>(
    state: &ServerState,
    request_head: TransportRequestHead,
    stream: &mut S,
) -> Result<()>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    if request_head.method != "PUT" {
        let response = buffered_transport_error_response(
            request_head.request_id,
            405,
            format!(
                "object write streams only support PUT, received {}",
                request_head.method
            ),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object write method error");
    }

    let raw_path = request_head.path.trim();
    let path_only = raw_path
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(raw_path);
    let path_only = transport_service::strip_public_api_v1_prefix(path_only);
    let Some(path_tail) = path_only.strip_prefix("/store/uploads/") else {
        let response = buffered_transport_error_response(
            request_head.request_id,
            400,
            format!("object write streams only support /store/uploads/*, received {path_only}"),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object write path error");
    };
    let Some((upload_id, index_raw)) = path_tail.split_once("/chunk/") else {
        let response = buffered_transport_error_response(
            request_head.request_id,
            400,
            format!("object write streams only support upload chunk paths, received {path_only}"),
        );
        return write_buffered_transport_response(stream, &response)
            .await
            .context("failed writing object write chunk-path error");
    };
    let index = match index_raw.parse::<usize>() {
        Ok(index) => index,
        Err(err) => {
            let response = buffered_transport_error_response(
                request_head.request_id,
                400,
                format!("invalid upload chunk index {index_raw}: {err}"),
            );
            return write_buffered_transport_response(stream, &response)
                .await
                .context("failed writing object write chunk-index error");
        }
    };
    let headers = match transport_service::header_map_from_transport_headers(&request_head.headers)
    {
        Ok(headers) => headers,
        Err(err) => {
            let response = buffered_transport_error_response(
                request_head.request_id,
                400,
                format!("invalid object write headers: {err:#}"),
            );
            return write_buffered_transport_response(stream, &response)
                .await
                .context("failed writing object write header error");
        }
    };
    let mut body = Vec::new();
    stream
        .read_to_end(&mut body)
        .await
        .context("failed reading object write request body")?;

    let response =
        upload_session_chunk_response(state, &headers, upload_id, index, Bytes::from(body)).await;
    write_transport_response_from_axum(stream, request_head.request_id, response).await
}

async fn write_transport_response_from_axum<S>(
    stream: &mut S,
    request_id: String,
    response: Response,
) -> Result<()>
where
    S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin,
{
    let (parts, mut body) = response.into_parts();
    write_transport_response_head(
        stream,
        &TransportResponseHead {
            request_id,
            status: parts.status.as_u16(),
            headers: transport_headers_from_response(&parts.headers),
        },
    )
    .await
    .context("failed writing streamed transport response head")?;

    while let Some(frame) = body.frame().await {
        let frame = frame.context("failed reading streamed transport response body frame")?;
        if let Ok(data) = frame.into_data() {
            stream
                .write_all(data.as_ref())
                .await
                .context("failed writing streamed transport response body")?;
        }
    }

    stream
        .close()
        .await
        .context("failed closing streamed transport response")
}

async fn complete_relay_multiplex_handshake(
    state: &ServerState,
    endpoint_url: &str,
    relay_session: &RelayTunnelSession,
    session: &mut MultiplexedSession,
) -> Result<transport_service::TransportExecutionScope> {
    let hello = perform_transport_server_handshake(
        session,
        TransportSessionControlMessage::Ready {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            session_id: relay_session.session_id.clone(),
            max_concurrent_streams: MultiplexConfig::default().max_num_streams,
        },
    )
    .await
    .with_context(|| {
        format!(
            "failed completing multiplex relay handshake for session {} from {}",
            relay_session.session_id, endpoint_url
        )
    })?;
    let TransportSessionControlMessage::Hello {
        cluster_id,
        peer,
        target,
        ..
    } = hello
    else {
        bail!("multiplex relay handshake did not return a hello control message");
    };

    if cluster_id != state.cluster_id {
        bail!(
            "multiplex relay handshake cluster_id {} did not match local cluster {}",
            cluster_id,
            state.cluster_id
        );
    }
    if peer != relay_session.source {
        bail!(
            "multiplex relay handshake peer {} did not match relay source {}",
            peer,
            relay_session.source
        );
    }
    if target.as_ref() != Some(&PeerIdentity::Node(state.node_id)) {
        bail!(
            "multiplex relay handshake target {:?} did not match local node {}",
            target,
            state.node_id
        );
    }

    Ok(match &peer {
        PeerIdentity::Device(_) => transport_service::TransportExecutionScope::Public,
        PeerIdentity::Node(node_id) => {
            transport_service::TransportExecutionScope::Internal(InternalCaller {
                node_id: *node_id,
                cluster_id: state.cluster_id,
            })
        }
    })
}

async fn serve_relay_multiplex_streams(
    state: ServerState,
    endpoint_url: String,
    relay_session: RelayTunnelSession,
    mut session: MultiplexedSession,
    execution_scope: transport_service::TransportExecutionScope,
) -> Result<()> {
    loop {
        let next = session.accept_stream().await.with_context(|| {
            format!(
                "failed accepting multiplex relay stream for session {}",
                relay_session.session_id
            )
        })?;
        let Some(stream) = next else {
            return Ok(());
        };

        let state = state.clone();
        let session_id = relay_session.session_id.clone();
        let endpoint_url = endpoint_url.clone();
        let execution_scope = execution_scope.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_multiplexed_relay_stream(state, execution_scope, stream).await
            {
                warn!(
                    error = %err,
                    rendezvous_url = %endpoint_url,
                    session_id = %session_id,
                    "multiplexed relay request stream failed"
                );
            }
        });
    }
}

fn spawn_rendezvous_relay_multiplex_agent(state: ServerState) {
    tokio::spawn(async move {
        loop {
            let clients = current_rendezvous_endpoint_clients(&state).await;
            if clients.is_empty() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }

            let cluster_id = state.cluster_id;
            let node_id = state.node_id;
            let mut accepts = tokio::task::JoinSet::new();
            for endpoint in clients {
                accepts.spawn(async move {
                    let result = endpoint
                        .control
                        .accept_relay_multiplex_target(
                            &RelayTunnelAcceptRequest {
                                cluster_id,
                                target: PeerIdentity::Node(node_id),
                                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                                wait_timeout_ms: Some(15_000),
                            },
                            MultiplexConfig::default(),
                        )
                        .await;
                    (endpoint, result)
                });
            }

            let mut handled_session = false;
            while let Some(result) = accepts.join_next().await {
                let Ok((endpoint, result)) = result else {
                    continue;
                };
                match result {
                    Ok((relay_session, multiplexed)) => {
                        handled_session = true;
                        accepts.abort_all();

                        let state = state.clone();
                        let endpoint_url = endpoint.url.clone();
                        tokio::spawn(async move {
                            let mut multiplexed = multiplexed;
                            match complete_relay_multiplex_handshake(
                                &state,
                                &endpoint_url,
                                &relay_session,
                                &mut multiplexed,
                            )
                            .await
                            {
                                Ok(execution_scope) => {
                                    let _ = record_rendezvous_registration_success(
                                        &state,
                                        &endpoint_url,
                                    )
                                    .await;
                                    if let Err(err) = serve_relay_multiplex_streams(
                                        state,
                                        endpoint_url.clone(),
                                        relay_session.clone(),
                                        multiplexed,
                                        execution_scope,
                                    )
                                    .await
                                    {
                                        warn!(
                                            error = %err,
                                            rendezvous_url = %endpoint_url,
                                            session_id = %relay_session.session_id,
                                            "multiplex relay session failed"
                                        );
                                    }
                                }
                                Err(err) => {
                                    let error_text = err.to_string();
                                    let failures = record_rendezvous_registration_failure(
                                        &state,
                                        &endpoint_url,
                                        &error_text,
                                    )
                                    .await;
                                    warn!(
                                        error = %err,
                                        rendezvous_url = %endpoint_url,
                                        session_id = %relay_session.session_id,
                                        consecutive_failures = failures,
                                        "multiplex relay session failed before handshake"
                                    );
                                }
                            }
                        });
                        break;
                    }
                    Err(err) => {
                        if transport_sdk::is_expected_idle_relay_tunnel_accept_timeout(
                            &err.to_string(),
                        ) {
                            tracing::debug!(
                                error = %err,
                                rendezvous_url = %endpoint.url,
                                "multiplex relay accept timed out without a source connection"
                            );
                        } else {
                            let error_text = err.to_string();
                            let failures = record_rendezvous_registration_failure(
                                &state,
                                &endpoint.url,
                                &error_text,
                            )
                            .await;
                            warn!(
                                error = %err,
                                rendezvous_url = %endpoint.url,
                                consecutive_failures = failures,
                                "multiplex relay accept failed"
                            );
                        }
                    }
                }
            }

            if !handled_session {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    });
}

fn spawn_replication_auditor(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));

        loop {
            ticker.tick().await;

            let keys = planning_replication_subjects(&state).await;

            let (node_transitioned_offline, plan) = {
                let mut cluster = state.cluster.lock().await;
                let node_transitioned_offline =
                    cluster.update_health_and_detect_offline_transition();
                let plan = cluster.replication_plan(&keys);
                (node_transitioned_offline, plan)
            };

            if node_transitioned_offline || !plan.items.is_empty() {
                info!(
                    under_replicated = plan.under_replicated,
                    over_replicated = plan.over_replicated,
                    items = plan.items.len(),
                    "replication audit result"
                );
            }

            if state.repair_config.enabled && !plan.items.is_empty() {
                let report = execute_tracked_local_replication_repair(
                    &state,
                    None,
                    RepairRunTrigger::BackgroundAudit,
                    Some(RepairPlanSummary::from_plan(&plan)),
                )
                .await;
                info!(
                    attempted = report.attempted_transfers,
                    success = report.successful_transfers,
                    failed = report.failed_transfers,
                    skipped = report.skipped_items,
                    skipped_backoff = report.skipped_backoff,
                    skipped_max_retries = report.skipped_max_retries,
                    "replication repair executor run"
                );
            }
        }
    });
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalAvailableSubjectsResponse {
    node_id: NodeId,
    subject_count: usize,
    generated_at_unix: u64,
    subjects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalMetadataSubjectsResponse {
    node_id: NodeId,
    subject_count: usize,
    generated_at_unix: u64,
    subjects: Vec<String>,
}

pub(crate) async fn sync_availability_views_once(state: &ServerState) {
    let started = Instant::now();
    let local_started = Instant::now();
    let local_refresh_timed_out = match tokio::time::timeout(
        Duration::from_secs(REPAIR_LOCAL_AVAILABILITY_SYNC_TIMEOUT_SECS),
        refresh_local_availability_view_once(state),
    )
    .await
    {
        Ok(subject_count) => {
            info!(
                subject_count,
                elapsed_ms = local_started.elapsed().as_millis(),
                "availability local refresh finished"
            );
            false
        }
        Err(_) => {
            request_local_availability_refresh(state);
            warn!(
                timeout_secs = REPAIR_LOCAL_AVAILABILITY_SYNC_TIMEOUT_SECS,
                elapsed_ms = local_started.elapsed().as_millis(),
                "availability local refresh timed out; continuing with cached local availability"
            );
            true
        }
    };
    let local_elapsed_ms = local_started.elapsed().as_millis();
    let remote_started = Instant::now();
    sync_remote_availability_views_once(state).await;
    info!(
        local_elapsed_ms,
        local_refresh_timed_out,
        remote_elapsed_ms = remote_started.elapsed().as_millis(),
        total_elapsed_ms = started.elapsed().as_millis(),
        "availability sync finished"
    );
}

async fn sync_remote_availability_views_once(state: &ServerState) {
    let peers = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster
            .list_nodes()
            .into_iter()
            .filter(|node| {
                node.node_id != state.node_id && node.status == cluster::NodeStatus::Online
            })
            .collect::<Vec<_>>()
    };

    info!(peer_count = peers.len(), "availability remote sync start");

    for peer in peers {
        let peer_started = Instant::now();
        info!(peer_node_id = %peer.node_id, "availability peer sync start");
        match execute_peer_request(
            state,
            &peer,
            reqwest::Method::GET,
            "/cluster/availability/subjects/local",
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<LocalAvailableSubjectsResponse>() {
                    Ok(payload) => {
                        let replicas_changed = {
                            let mut cluster = state.cluster.lock().await;
                            cluster.reconcile_node_subjects(payload.node_id, &payload.subjects)
                        };
                        if replicas_changed
                            && let Err(err) = persist_cluster_replicas_state(state).await
                        {
                            warn!(
                                error = %err,
                                peer_node_id = %payload.node_id,
                                subject_count = payload.subjects.len(),
                                "failed to persist cluster replicas after remote availability sync"
                            );
                        }
                        info!(
                            peer_node_id = %peer.node_id,
                            subject_count = payload.subjects.len(),
                            elapsed_ms = peer_started.elapsed().as_millis(),
                            "availability peer sync finished"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            error = %err,
                            "failed decoding availability subject sync payload"
                        );
                    }
                }
            }
            Ok(response) => {
                info!(
                    peer_node_id = %peer.node_id,
                    status = response.status,
                    elapsed_ms = peer_started.elapsed().as_millis(),
                    "availability peer sync rejected"
                );
                tracing::debug!(
                    node_id = %peer.node_id,
                    status = response.status,
                    "availability subject sync request rejected"
                );
            }
            Err(err) => {
                warn!(
                    peer_node_id = %peer.node_id,
                    elapsed_ms = peer_started.elapsed().as_millis(),
                    error = %err,
                    "availability peer sync failed"
                );
                tracing::debug!(
                    node_id = %peer.node_id,
                    error = %err,
                    "failed availability subject sync request"
                );
            }
        }
    }
}

pub(crate) async fn sync_cluster_metadata_once(state: &ServerState) {
    let mut local_metadata_subjects = {
        let store = read_store(state, "cluster_metadata.list_local_subjects").await;
        store
            .list_metadata_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
            .into_iter()
            .collect::<HashSet<_>>()
    };

    let peers = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster
            .list_nodes()
            .into_iter()
            .filter(|node| {
                node.node_id != state.node_id && node.status == cluster::NodeStatus::Online
            })
            .collect::<Vec<_>>()
    };

    let mut imported_any = false;

    for peer in peers {
        let peer_subjects = match execute_peer_request(
            state,
            &peer,
            reqwest::Method::GET,
            "/cluster/metadata/subjects/local",
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<LocalMetadataSubjectsResponse>() {
                    Ok(payload) => payload.subjects,
                    Err(err) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            error = %err,
                            "failed decoding metadata subject sync payload"
                        );
                        continue;
                    }
                }
            }
            Ok(response) => {
                tracing::debug!(
                    node_id = %peer.node_id,
                    status = response.status,
                    "metadata subject sync request rejected"
                );
                continue;
            }
            Err(err) => {
                tracing::debug!(
                    node_id = %peer.node_id,
                    error = %err,
                    "failed metadata subject sync request"
                );
                continue;
            }
        };

        for subject in peer_subjects {
            if local_metadata_subjects.contains(&subject) {
                continue;
            }

            let Some((key, version_id)) = parse_replication_subject(&subject) else {
                continue;
            };

            let export_path = build_metadata_export_path(&key, version_id.as_deref());
            let response = match execute_peer_request(
                state,
                &peer,
                reqwest::Method::GET,
                &export_path,
                Vec::new(),
                Vec::new(),
            )
            .await
            {
                Ok(response) if response.is_success() => response,
                Ok(response) => {
                    tracing::debug!(
                        node_id = %peer.node_id,
                        key = %key,
                        version_id = ?version_id,
                        status = response.status,
                        "metadata export request rejected"
                    );
                    continue;
                }
                Err(err) => {
                    tracing::debug!(
                        node_id = %peer.node_id,
                        key = %key,
                        version_id = ?version_id,
                        error = %err,
                        "failed metadata export request"
                    );
                    continue;
                }
            };

            let bundle = match response.json::<MetadataExportBundle>() {
                Ok(bundle) => bundle,
                Err(err) => {
                    tracing::debug!(
                        node_id = %peer.node_id,
                        key = %key,
                        version_id = ?version_id,
                        error = %err,
                        "failed decoding metadata export bundle"
                    );
                    continue;
                }
            };

            let import_changed = {
                let mut store = lock_store(state, "cluster_metadata.import_bundle").await;
                match store.import_metadata_bundle(&bundle).await {
                    Ok(changed) => changed,
                    Err(err) => {
                        tracing::warn!(
                            node_id = %peer.node_id,
                            key = %bundle.key,
                            version_id = ?version_id,
                            error = %err,
                            "failed importing metadata bundle"
                        );
                        false
                    }
                }
            };

            if import_changed {
                imported_any = true;
            }

            local_metadata_subjects.insert(subject);
            if bundle.current_manifest_hash.is_some() {
                local_metadata_subjects.insert(bundle.key.clone());
            }
            for version in &bundle.versions {
                local_metadata_subjects.insert(format!("{}@{}", bundle.key, version.version_id));
            }
        }
    }

    if imported_any {
        publish_namespace_change(state);
    }
}

fn spawn_replica_view_synchronizer(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));

        loop {
            ticker.tick().await;
            sync_remote_availability_views_once(&state).await;
            sync_cluster_metadata_once(&state).await;
        }
    });
}

fn spawn_node_enrollment_auto_renew(
    state: ServerState,
    config: ServerNodeConfig,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(
            node_enrollment_auto_renew_interval_secs(interval_secs),
        ));

        loop {
            ticker.tick().await;
            {
                let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
                renewal_state.last_attempt_unix = Some(unix_ts());
            }

            match renew_node_enrollment_package_if_due(&state, &config).await {
                Ok(true) => match reload_live_tls_from_disk(&state).await {
                    Ok(()) => {
                        {
                            let mut renewal_state =
                                state.node_enrollment_auto_renew_state.lock().await;
                            renewal_state.last_success_unix = Some(unix_ts());
                            renewal_state.last_error = None;
                        }
                        info!(
                            enrollment_path = ?state.node_enrollment_path.as_ref().map(|path| path.display().to_string()),
                            "node enrollment auto-renew reloaded live TLS material"
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, "node enrollment auto-renew reloaded package but failed to apply live TLS reload");
                        let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
                        renewal_state.last_error = Some(err.to_string());
                    }
                },
                Ok(false) => {
                    let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
                    renewal_state.last_error = None;
                }
                Err(err) => {
                    warn!(error = %err, "node enrollment auto-renew failed");
                    let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
                    renewal_state.last_error = Some(err.to_string());
                }
            }
        }
    });
}

fn node_enrollment_auto_renew_interval_secs(interval_secs: u64) -> u64 {
    #[cfg(test)]
    {
        interval_secs.max(1)
    }

    #[cfg(not(test))]
    {
        interval_secs.max(30)
    }
}

async fn track_inflight_requests(
    State(state): State<ServerState>,
    request: Request,
    next: Next,
) -> Response {
    state.inflight_requests.fetch_add(1, Ordering::Relaxed);
    let response = next.run(request).await;
    state.inflight_requests.fetch_sub(1, Ordering::Relaxed);
    response
}

async fn planning_replication_subjects(state: &ServerState) -> Vec<String> {
    let local_subjects = cached_local_cluster_available_subjects(state).await;
    let cluster_subjects = {
        let cluster = state.cluster.lock().await;
        cluster.known_replication_subjects()
    };

    let mut subjects = BTreeSet::new();
    subjects.extend(local_subjects);
    subjects.extend(cluster_subjects);
    subjects.into_iter().collect()
}

async fn recompute_local_cluster_available_subjects(state: &ServerState) -> Vec<String> {
    let inspector = {
        let store = read_store(state, "availability.recompute_local_subjects.snapshot").await;
        store.replication_subject_inspector()
    };
    let mut subjects = inspector
        .list_replication_subjects()
        .await
        .unwrap_or_else(|_| inspector.current_keys());
    subjects.sort();
    subjects
}

async fn cached_local_cluster_available_subjects(state: &ServerState) -> Vec<String> {
    let cluster = state.cluster.lock().await;
    cluster.available_subjects_for_node(state.node_id)
}

async fn refresh_local_availability_view_once(state: &ServerState) -> usize {
    let _refresh_guard = state.local_availability_refresh_lock.lock().await;
    let local_subjects = recompute_local_cluster_available_subjects(state).await;
    let subject_count = local_subjects.len();
    let replicas_changed = {
        let mut cluster = state.cluster.lock().await;
        cluster.reconcile_node_subjects(state.node_id, &local_subjects)
    };

    if replicas_changed && let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            subject_count,
            "failed to persist cluster replicas after local availability refresh"
        );
    }
    subject_count
}

async fn await_repair_busy_threshold(state: &ServerState) {
    if !state.repair_config.busy_throttle_enabled {
        return;
    }

    let threshold = state.repair_config.busy_inflight_threshold.max(1);
    let wait_duration = Duration::from_millis(state.repair_config.busy_wait_millis.max(10));

    loop {
        let inflight = state.inflight_requests.load(Ordering::Relaxed);
        if inflight <= threshold {
            break;
        }
        tokio::time::sleep(wait_duration).await;
    }
}

#[derive(Debug, Clone)]
struct RepairRunTracker {
    run_id: String,
    scope: replication::ReplicationRepairScope,
    trigger: RepairRunTrigger,
    started_at_unix: u64,
    started_at_instant: Instant,
}

async fn current_replication_plan(state: &ServerState) -> ReplicationPlan {
    let keys = planning_replication_subjects(state).await;
    current_replication_plan_for_subjects(state, &keys).await
}

async fn current_replication_plan_for_subjects(
    state: &ServerState,
    subjects: &[String],
) -> ReplicationPlan {
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    cluster.replication_plan(subjects)
}

async fn begin_repair_run_tracking(
    state: &ServerState,
    scope: replication::ReplicationRepairScope,
    trigger: RepairRunTrigger,
) -> RepairRunTracker {
    let run_id = Uuid::now_v7().to_string();
    let started_at_unix = unix_ts();

    {
        let mut activity = state.repair_activity.lock().await;
        activity.active_runs.push(RepairActiveRun {
            run_id: run_id.clone(),
            scope,
            trigger,
            started_at_unix,
        });
    }

    RepairRunTracker {
        run_id,
        scope,
        trigger,
        started_at_unix,
        started_at_instant: Instant::now(),
    }
}

fn serialize_repair_run_report<T>(report: &T) -> Option<serde_json::Value>
where
    T: Serialize,
{
    match serde_json::to_value(report) {
        Ok(value) => Some(value),
        Err(err) => {
            warn!(error = %err, "failed serializing repair run report");
            None
        }
    }
}

async fn persist_repair_run_record_with_retention(state: &ServerState, record: &RepairRunRecord) {
    let store = lock_store(state, "repair_run.persist").await;
    if let Err(err) = store.persist_repair_run_record(record).await {
        warn!(error = %err, run_id = %record.run_id, "failed to persist repair run history record");
        return;
    }

    let retention_cutoff = record
        .finished_at_unix
        .saturating_sub(state.repair_run_history_retention_secs);
    if let Err(err) = store
        .prune_repair_run_history_before(retention_cutoff)
        .await
    {
        warn!(
            error = %err,
            retention_cutoff,
            run_id = %record.run_id,
            "failed to prune repair run history"
        );
    }
}

async fn finish_repair_run_tracking(
    state: &ServerState,
    tracker: RepairRunTracker,
    plan_summary: RepairPlanSummary,
    status: RepairRunStatus,
    summary: Option<RepairRunSummary>,
    report: Option<serde_json::Value>,
) -> RepairRunRecord {
    {
        let mut activity = state.repair_activity.lock().await;
        activity
            .active_runs
            .retain(|active_run| active_run.run_id != tracker.run_id);
    }

    let duration_ms =
        u64::try_from(tracker.started_at_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
    let record = RepairRunRecord {
        run_id: tracker.run_id,
        reporting_node_id: state.node_id,
        scope: tracker.scope,
        trigger: tracker.trigger,
        status,
        started_at_unix: tracker.started_at_unix,
        finished_at_unix: unix_ts(),
        duration_ms,
        plan_summary,
        summary,
        report,
    };

    persist_repair_run_record_with_retention(state, &record).await;
    record
}

fn current_repair_activity_state(
    active_runs: &[RepairActiveRun],
    startup_status: StartupRepairStatus,
) -> RepairActivityState {
    if !active_runs.is_empty() || startup_status == StartupRepairStatus::Running {
        RepairActivityState::Running
    } else if startup_status == StartupRepairStatus::Scheduled {
        RepairActivityState::Scheduled
    } else {
        RepairActivityState::Idle
    }
}

async fn latest_repair_run_record(state: &ServerState) -> Result<Option<RepairRunRecord>> {
    let store = read_store(state, "repair_run.latest").await;
    Ok(store
        .list_repair_run_history(Some(1), None)
        .await?
        .into_iter()
        .next())
}

#[derive(Debug, Clone)]
struct DataScrubRunTracker {
    run_id: String,
    trigger: DataScrubRunTrigger,
    started_at_unix: u64,
    started_at_instant: Instant,
}

fn current_data_scrub_activity_state(active_runs: &[DataScrubActiveRun]) -> DataScrubActivityState {
    if active_runs.is_empty() {
        DataScrubActivityState::Idle
    } else {
        DataScrubActivityState::Running
    }
}

async fn latest_data_scrub_run_record(state: &ServerState) -> Result<Option<DataScrubRunRecord>> {
    let store = read_store(state, "data_scrub.latest").await;
    Ok(store
        .list_data_scrub_run_history(Some(1), None)
        .await?
        .into_iter()
        .next())
}

async fn persist_data_scrub_run_record_with_retention(
    state: &ServerState,
    record: &DataScrubRunRecord,
) {
    let store = lock_store(state, "data_scrub.persist").await;
    if let Err(err) = store.persist_data_scrub_run_record(record).await {
        warn!(
            error = %err,
            run_id = %record.run_id,
            "failed to persist data scrub history record"
        );
        return;
    }

    let retention_cutoff = record
        .finished_at_unix
        .saturating_sub(state.data_scrub_history_retention_secs);
    if let Err(err) = store
        .prune_data_scrub_run_history_before(retention_cutoff)
        .await
    {
        warn!(
            error = %err,
            retention_cutoff,
            run_id = %record.run_id,
            "failed to prune data scrub history"
        );
    }
}

async fn finish_data_scrub_run_tracking(
    state: &ServerState,
    tracker: DataScrubRunTracker,
    status: DataScrubRunStatus,
    summary: DataScrubReport,
    last_error: Option<String>,
) -> DataScrubRunRecord {
    {
        let mut activity = state.data_scrub_activity.lock().await;
        activity
            .active_runs
            .retain(|active_run| active_run.run_id != tracker.run_id);
    }

    let duration_ms =
        u64::try_from(tracker.started_at_instant.elapsed().as_millis()).unwrap_or(u64::MAX);
    let record = DataScrubRunRecord {
        run_id: tracker.run_id,
        reporting_node_id: state.node_id,
        trigger: tracker.trigger,
        status,
        started_at_unix: tracker.started_at_unix,
        finished_at_unix: unix_ts(),
        duration_ms,
        summary,
        last_error,
    };

    persist_data_scrub_run_record_with_retention(state, &record).await;
    record
}

async fn mark_local_replication_subjects_degraded(
    state: &ServerState,
    subjects: &BTreeSet<String>,
) {
    if subjects.is_empty() {
        return;
    }

    let changed = {
        let mut cluster = state.cluster.lock().await;
        let local_replicas = cluster
            .subjects_for_node(state.node_id)
            .into_iter()
            .collect::<HashSet<_>>();
        let local_available = cluster
            .available_subjects_for_node(state.node_id)
            .into_iter()
            .collect::<HashSet<_>>();
        let mut changed = false;
        for subject in subjects {
            if local_replicas.contains(subject) || local_available.contains(subject) {
                changed = true;
            }
            cluster.remove_replica(subject, state.node_id);
            cluster.remove_available(subject, state.node_id);
        }
        changed
    };

    if changed && let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            subject_count = subjects.len(),
            "failed to persist degraded local scrub subjects"
        );
    }
}

async fn execute_data_scrub_follow_on_repair(
    state: ServerState,
    scrub_run_id: String,
    degraded_subjects: BTreeSet<String>,
    repair_subjects: BTreeSet<String>,
) {
    if repair_subjects.is_empty() {
        return;
    }

    mark_local_replication_subjects_degraded(&state, &degraded_subjects).await;

    if !state.repair_config.enabled {
        info!(
            scrub_run_id = %scrub_run_id,
            subject_count = repair_subjects.len(),
            "skipping scrub follow-on repair because repair execution is disabled"
        );
        return;
    }

    let subjects = repair_subjects.into_iter().collect::<Vec<_>>();
    info!(
        scrub_run_id = %scrub_run_id,
        subject_count = subjects.len(),
        "starting scrub follow-on repair"
    );

    let report = execute_tracked_targeted_local_replication_repair(
        &state,
        subjects.clone(),
        RepairRunTrigger::DataScrubAutoRepair,
    )
    .await;

    info!(
        scrub_run_id = %scrub_run_id,
        subject_count = subjects.len(),
        attempted = report.attempted_transfers,
        successful = report.successful_transfers,
        failed = report.failed_transfers,
        skipped = report.skipped_items,
        skipped_backoff = report.skipped_backoff,
        skipped_max_retries = report.skipped_max_retries,
        "finished scrub follow-on repair"
    );
}

async fn execute_data_scrub_run(state: ServerState, tracker: DataScrubRunTracker) {
    info!(run_id = %tracker.run_id, trigger = ?tracker.trigger, "data scrub run started");
    let scrubber = {
        let store = read_store(&state, "data_scrub.clone_worker").await;
        store.data_scrubber()
    };
    let result = scrubber.run_with_repair_subjects().await;

    match result {
        Ok(output) => {
            let summary = output.report;
            let status = if summary.issue_count > 0 {
                DataScrubRunStatus::IssuesDetected
            } else {
                DataScrubRunStatus::Clean
            };
            info!(
                run_id = %tracker.run_id,
                status = ?status,
                issue_count = summary.issue_count,
                manifests_scanned = summary.manifests_scanned,
                chunks_scanned = summary.chunks_scanned,
                bytes_scanned = summary.bytes_scanned,
                "data scrub run finished"
            );
            let record =
                finish_data_scrub_run_tracking(&state, tracker, status, summary, None).await;
            if !output.repair_subjects.is_empty() {
                let state_clone = state.clone();
                tokio::spawn(async move {
                    execute_data_scrub_follow_on_repair(
                        state_clone,
                        record.run_id,
                        output.degraded_subjects,
                        output.repair_subjects,
                    )
                    .await;
                });
            }
        }
        Err(err) => {
            warn!(
                run_id = %tracker.run_id,
                error = %err,
                "data scrub run failed"
            );
            let _ = finish_data_scrub_run_tracking(
                &state,
                tracker,
                DataScrubRunStatus::Failed,
                DataScrubReport::default(),
                Some(err.to_string()),
            )
            .await;
        }
    }
}

async fn start_local_data_scrub(
    state: &ServerState,
    trigger: DataScrubRunTrigger,
) -> DataScrubTriggerNodeResult {
    let active_or_new = {
        let mut activity = state.data_scrub_activity.lock().await;
        if let Some(active_run) = activity.active_runs.first().cloned() {
            return DataScrubTriggerNodeResult {
                node_id: state.node_id,
                started: false,
                active_run: Some(active_run),
                error: None,
            };
        }

        let run_id = Uuid::now_v7().to_string();
        let started_at_unix = unix_ts();
        let active_run = DataScrubActiveRun {
            run_id: run_id.clone(),
            trigger,
            started_at_unix,
        };
        activity.active_runs.push(active_run.clone());
        (
            active_run,
            DataScrubRunTracker {
                run_id,
                trigger,
                started_at_unix,
                started_at_instant: Instant::now(),
            },
        )
    };

    let (active_run, tracker) = active_or_new;
    let state_clone = state.clone();
    tokio::spawn(async move {
        execute_data_scrub_run(state_clone, tracker).await;
    });

    DataScrubTriggerNodeResult {
        node_id: state.node_id,
        started: true,
        active_run: Some(active_run),
        error: None,
    }
}

async fn execute_tracked_local_replication_repair(
    state: &ServerState,
    batch_size_override: Option<usize>,
    trigger: RepairRunTrigger,
    plan_summary_override: Option<RepairPlanSummary>,
) -> replication::ReplicationRepairReport {
    let plan_summary = match plan_summary_override {
        Some(plan_summary) => plan_summary,
        None => RepairPlanSummary::from_plan(&current_replication_plan(state).await),
    };
    let tracker =
        begin_repair_run_tracking(state, replication::ReplicationRepairScope::Local, trigger).await;
    let report = replication::execute_replication_repair_inner(state, batch_size_override).await;
    finish_repair_run_tracking(
        state,
        tracker,
        plan_summary,
        RepairRunStatus::Completed,
        Some(RepairRunSummary::from_local_report(&report)),
        serialize_repair_run_report(&report),
    )
    .await;
    report
}

async fn execute_tracked_targeted_local_replication_repair(
    state: &ServerState,
    subjects: Vec<String>,
    trigger: RepairRunTrigger,
) -> replication::ReplicationRepairReport {
    let plan_summary = RepairPlanSummary {
        generated_at_unix: unix_ts(),
        under_replicated: subjects.len(),
        over_replicated: 0,
        cleanup_deferred_items: 0,
        cleanup_deferred_extra_nodes: 0,
        item_count: subjects.len(),
    };
    let tracker =
        begin_repair_run_tracking(state, replication::ReplicationRepairScope::Local, trigger).await;
    let report = replication::execute_targeted_replication_repair_inner(
        state,
        subjects.clone(),
        Some(subjects.len().max(1)),
    )
    .await;
    finish_repair_run_tracking(
        state,
        tracker,
        plan_summary,
        RepairRunStatus::Completed,
        Some(RepairRunSummary::from_local_report(&report)),
        serialize_repair_run_report(&report),
    )
    .await;
    report
}

async fn execute_tracked_cluster_replication_repair(
    state: &ServerState,
    batch_size_override: Option<usize>,
    trigger: RepairRunTrigger,
    plan_summary_override: Option<RepairPlanSummary>,
) -> replication::ClusterReplicationRepairReport {
    let plan_summary = match plan_summary_override {
        Some(plan_summary) => plan_summary,
        None => RepairPlanSummary::from_plan(&current_replication_plan(state).await),
    };
    let tracker =
        begin_repair_run_tracking(state, replication::ReplicationRepairScope::Cluster, trigger)
            .await;
    let report =
        replication::execute_cluster_replication_repair_inner(state, batch_size_override).await;
    finish_repair_run_tracking(
        state,
        tracker,
        plan_summary,
        RepairRunStatus::Completed,
        Some(RepairRunSummary::from_cluster_report(&report)),
        serialize_repair_run_report(&report),
    )
    .await;
    report
}

fn spawn_startup_replication_repair(state: ServerState, delay_secs: u64) {
    tokio::spawn(async move {
        {
            let mut status = state.startup_repair_status.lock().await;
            *status = StartupRepairStatus::Running;
        }

        if delay_secs > 0 {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
        }

        let tracker = begin_repair_run_tracking(
            &state,
            replication::ReplicationRepairScope::Local,
            RepairRunTrigger::StartupRepair,
        )
        .await;
        let plan = current_replication_plan(&state).await;
        let plan_summary = RepairPlanSummary::from_plan(&plan);

        if plan.items.is_empty() {
            {
                let mut status = state.startup_repair_status.lock().await;
                *status = StartupRepairStatus::SkippedNoGaps;
            }
            finish_repair_run_tracking(
                &state,
                tracker,
                plan_summary,
                RepairRunStatus::SkippedNoGaps,
                None,
                None,
            )
            .await;
            info!(
                delay_secs,
                "startup replication repair skipped: no replication gaps detected"
            );
            return;
        }

        let report = replication::execute_replication_repair_inner(&state, None).await;
        {
            let mut status = state.startup_repair_status.lock().await;
            *status = StartupRepairStatus::Completed;
        }
        finish_repair_run_tracking(
            &state,
            tracker,
            plan_summary,
            RepairRunStatus::Completed,
            Some(RepairRunSummary::from_local_report(&report)),
            serialize_repair_run_report(&report),
        )
        .await;
        info!(
            delay_secs,
            under_replicated = plan.under_replicated,
            over_replicated = plan.over_replicated,
            items = plan.items.len(),
            attempted = report.attempted_transfers,
            success = report.successful_transfers,
            failed = report.failed_transfers,
            skipped = report.skipped_items,
            skipped_backoff = report.skipped_backoff,
            skipped_max_retries = report.skipped_max_retries,
            "startup replication repair run"
        );
    });
}

#[cfg_attr(not(test), allow(dead_code))]
async fn run_startup_replication_repair_once(
    state: &ServerState,
    delay_secs: u64,
) -> Option<(ReplicationPlan, replication::ReplicationRepairReport)> {
    if delay_secs > 0 {
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
    }

    let plan = current_replication_plan(state).await;

    if plan.items.is_empty() {
        return None;
    }

    let report = replication::execute_replication_repair_inner(state, None).await;
    Some((plan, report))
}

fn spawn_peer_heartbeat_emitter(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));

        loop {
            ticker.tick().await;
            refresh_local_node_storage(&state).await;

            let (local_descriptor, peers) = {
                let mut cluster = state.cluster.lock().await;
                cluster.update_health_and_detect_offline_transition();

                let nodes = cluster.list_nodes();
                let local_descriptor = nodes
                    .iter()
                    .find(|node| node.node_id == state.node_id)
                    .cloned();
                let peers = nodes
                    .into_iter()
                    .filter(|node| node.node_id != state.node_id)
                    .collect::<Vec<_>>();

                (local_descriptor, peers)
            };

            let Some(local_descriptor) = local_descriptor else {
                continue;
            };

            let payload = OutboundNodeHeartbeatRequest {
                free_bytes: Some(local_descriptor.free_bytes),
                capacity_bytes: Some(local_descriptor.capacity_bytes),
                storage_stats: local_descriptor.storage_stats,
                labels: Some(local_descriptor.labels),
            };

            for peer in peers {
                let body = match serde_json::to_vec(&payload)
                    .context("failed to serialize peer heartbeat payload")
                {
                    Ok(body) => body,
                    Err(err) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            error = %err,
                            "failed to serialize peer heartbeat"
                        );
                        continue;
                    }
                };

                match execute_peer_request(
                    &state,
                    &peer,
                    reqwest::Method::POST,
                    &format!("/cluster/nodes/{}/heartbeat", state.node_id),
                    vec![RelayHttpHeader {
                        name: "content-type".to_string(),
                        value: "application/json".to_string(),
                    }],
                    body,
                )
                .await
                {
                    Ok(response) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            status = response.status,
                            "peer heartbeat request rejected"
                        );
                    }
                    Err(err) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            error = %err,
                            "failed sending peer heartbeat"
                        );
                    }
                }
            }
        }
    });
}

async fn health(State(state): State<ServerState>) -> Json<HealthStatus> {
    Json(HealthStatus {
        node_id: state.node_id,
        role: "server-node".to_string(),
        online: true,
        version: BUILD_VERSION.to_string(),
        revision: BUILD_REVISION.to_string(),
    })
}

async fn latency_diagnostic(
    State(state): State<ServerState>,
    Query(query): Query<LatencyDiagnosticQuery>,
) -> Response {
    let response_bytes = query.response_bytes.unwrap_or(0);
    if response_bytes > MAX_LATENCY_DIAGNOSTIC_RESPONSE_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "response_bytes must be <= {MAX_LATENCY_DIAGNOSTIC_RESPONSE_BYTES}"
                )
            })),
        )
            .into_response();
    }

    let server_delay_ms = query.server_delay_ms.unwrap_or(0);
    if server_delay_ms > MAX_LATENCY_DIAGNOSTIC_SERVER_DELAY_MS {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "server_delay_ms must be <= {MAX_LATENCY_DIAGNOSTIC_SERVER_DELAY_MS}"
                )
            })),
        )
            .into_response();
    }

    let started_unix_ms = unix_ts_ms();
    let started_at = Instant::now();
    if server_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(server_delay_ms)).await;
    }
    let server_duration_ms = started_at.elapsed().as_millis() as u64;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&response_bytes.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        "x-ironmesh-latency-node-id",
        HeaderValue::from_str(&state.node_id.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    headers.insert(
        "x-ironmesh-latency-response-bytes",
        HeaderValue::from_str(&response_bytes.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        "x-ironmesh-latency-server-duration-ms",
        HeaderValue::from_str(&server_duration_ms.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );
    headers.insert(
        "x-ironmesh-latency-started-unix-ms",
        HeaderValue::from_str(&started_unix_ms.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    (StatusCode::OK, headers, vec![0_u8; response_bytes]).into_response()
}

async fn node_certificate_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/node-certificates/status";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "node_id": state.node_id }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let auto_renew_state = state.node_enrollment_auto_renew_state.lock().await.clone();
    let auto_renew = NodeCertificateAutoRenewStatusView {
        enabled: state.node_enrollment_auto_renew_enabled,
        enrollment_path: state
            .node_enrollment_path
            .as_ref()
            .map(|path| path.display().to_string()),
        issuer_url: state.enrollment_issuer_url.clone(),
        check_interval_secs: state
            .node_enrollment_auto_renew_enabled
            .then_some(state.node_enrollment_auto_renew_check_secs),
        last_attempt_unix: auto_renew_state.last_attempt_unix,
        last_success_unix: auto_renew_state.last_success_unix,
        last_error: auto_renew_state.last_error.clone(),
        restart_required: false,
    };
    let mut status = collect_node_certificate_status(
        state
            .public_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        state
            .public_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        state
            .internal_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        state
            .internal_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        auto_renew,
    );
    status.auto_renew.restart_required = node_certificate_restart_required(
        &status.public_tls,
        &status.internal_tls,
        auto_renew_state.loaded_public_tls_fingerprint.as_deref(),
        auto_renew_state.loaded_internal_tls_fingerprint.as_deref(),
    );

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "public_tls_state": status.public_tls.state,
            "internal_tls_state": status.internal_tls.state,
            "auto_renew_enabled": status.auto_renew.enabled,
            "auto_renew_restart_required": status.auto_renew.restart_required,
        }),
    )
    .await;

    (StatusCode::OK, Json(status)).into_response()
}

async fn list_snapshots(State(state): State<ServerState>) -> impl IntoResponse {
    list_snapshots_response(&state).await
}

async fn list_snapshots_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/store/snapshots/get";
    if let Err(status) =
        authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        return status.into_response();
    }

    list_snapshots_response(&state).await
}

async fn list_snapshots_response(state: &ServerState) -> Response {
    let store = read_store(state, "snapshots.list").await;
    match store.list_snapshots().await {
        Ok(snapshots) => (StatusCode::OK, Json(snapshots)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to list snapshots");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ObjectGetQuery {
    snapshot: Option<String>,
    version: Option<String>,
    read_mode: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct ObjectByteRange {
    start: usize,
    end_inclusive: usize,
}

fn format_object_byte_range(range: Option<ObjectByteRange>) -> String {
    range
        .map(|range| format!("{}-{}", range.start, range.end_inclusive))
        .unwrap_or_else(|| "<full>".to_string())
}

#[derive(Clone, Debug, Deserialize)]
struct StoreIndexQuery {
    prefix: Option<String>,
    depth: Option<usize>,
    snapshot: Option<String>,
    view: Option<StoreIndexView>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StoreIndexView {
    Raw,
    Tree,
}

#[derive(Debug, Deserialize)]
struct StoreIndexChangeWaitQuery {
    since: Option<u64>,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreIndexChangeWaitResponse {
    sequence: u64,
    changed: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct MediaThumbnailQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    read_mode: Option<String>,
}

#[derive(Debug, Serialize)]
struct MediaGpsResponse {
    latitude: f64,
    longitude: f64,
}

#[derive(Debug, Serialize)]
struct MediaThumbnailResponse {
    url: String,
    profile: String,
    width: u32,
    height: u32,
    format: String,
    size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct MediaIndexResponse {
    status: String,
    content_fingerprint: String,
    media_type: Option<String>,
    mime_type: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
    orientation: Option<u16>,
    taken_at_unix: Option<u64>,
    gps: Option<MediaGpsResponse>,
    thumbnail: Option<MediaThumbnailResponse>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct StoreIndexEntry {
    path: String,
    entry_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    modified_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    media: Option<MediaIndexResponse>,
}

#[derive(Debug, Serialize)]
struct StoreIndexResponse {
    prefix: String,
    depth: usize,
    entry_count: usize,
    entries: Vec<StoreIndexEntry>,
}

type StoreIndexSnapshotScan = (
    Vec<String>,
    HashMap<String, String>,
    HashMap<String, u64>,
    HashMap<String, String>,
    HashMap<String, u64>,
);

#[derive(Debug, Deserialize)]
struct PutObjectQuery {
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    version_id: Option<String>,
    #[serde(default)]
    internal_replication: bool,
    #[serde(default)]
    recursive: bool,
}

#[derive(Debug, Deserialize)]
struct DeleteObjectByQuery {
    key: String,
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    version_id: Option<String>,
    #[serde(default)]
    internal_replication: bool,
    #[serde(default)]
    recursive: bool,
}

#[derive(Debug, Deserialize)]
struct PathMutationRequest {
    from_path: String,
    to_path: String,
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize)]
struct SnapshotRestoreRequest {
    snapshot: String,
    from_path: String,
    to_path: String,
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    overwrite: bool,
}

fn should_trigger_autonomous_post_write_replication(
    autonomous_replication_on_put_enabled: bool,
    internal_replication: bool,
) -> bool {
    autonomous_replication_on_put_enabled && !internal_replication
}

fn spawn_media_metadata_warmup(state: ServerState, key: String, manifest_hash: String) {
    tokio::spawn(async move {
        let media_cache_worker = {
            let store = read_store(&state, "media_cache_warmup.clone_worker").await;
            store.media_cache_worker()
        };
        if let Err(err) = media_cache_worker
            .ensure_media_metadata(&manifest_hash)
            .await
        {
            warn!(
                key = %key,
                manifest_hash = %manifest_hash,
                error = %err,
                "failed to warm media metadata after write"
            );
        }
    });
}

fn spawn_media_metadata_backfill(state: ServerState, reason: &'static str) {
    tokio::spawn(async move {
        let (media_cache_worker, targets) = {
            let store = read_store(&state, "media_metadata_backfill.snapshot").await;
            let inspector = store.store_index_inspector();
            let mut targets = BTreeMap::new();
            for (key, manifest_hash) in inspector.current_object_hashes() {
                if looks_like_media_path(&key) && manifest_hash != TOMBSTONE_MANIFEST_HASH {
                    targets.entry(manifest_hash).or_insert(key);
                }
            }
            (store.media_cache_worker(), targets)
        };

        let target_count = targets.len();
        if target_count == 0 {
            return;
        }

        info!(
            reason,
            media_entries = target_count,
            "starting media metadata backfill"
        );
        for (manifest_hash, key) in targets {
            if let Err(err) = media_cache_worker
                .ensure_media_metadata(&manifest_hash)
                .await
            {
                warn!(
                    reason,
                    key = %key,
                    manifest_hash = %manifest_hash,
                    error = %err,
                    "failed to backfill media metadata"
                );
            }
        }
        info!(
            reason,
            media_entries = target_count,
            "finished media metadata backfill"
        );
    });
}

async fn delete_object_by_query(
    State(state): State<ServerState>,
    Query(query): Query<DeleteObjectByQuery>,
) -> Response {
    delete_object_by_query_response(&state, query).await
}

async fn delete_object_by_query_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<DeleteObjectByQuery>,
) -> Response {
    let action = "auth/store/delete";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "key": query.key.clone(),
            "state": query.state.clone(),
            "parent": query.parent.clone(),
            "version_id": query.version_id.clone(),
            "recursive": query.recursive,
        }),
    )
    .await
    {
        return status.into_response();
    }

    delete_object_by_query_response(&state, query).await
}

async fn delete_object_by_query_response(
    state: &ServerState,
    query: DeleteObjectByQuery,
) -> Response {
    if query.key.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    delete_object(
        State(state.clone()),
        Path(query.key),
        Query(PutObjectQuery {
            state: query.state,
            parent: query.parent,
            version_id: query.version_id,
            internal_replication: query.internal_replication,
            recursive: query.recursive,
        }),
    )
    .await
    .into_response()
}

async fn rename_object_path(
    State(state): State<ServerState>,
    Json(request): Json<PathMutationRequest>,
) -> Response {
    rename_object_path_response(&state, request).await
}

async fn rename_object_path_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<PathMutationRequest>,
) -> Response {
    let action = "auth/store/rename";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "from_path": request.from_path.clone(),
            "to_path": request.to_path.clone(),
            "overwrite": request.overwrite,
        }),
    )
    .await
    {
        return status.into_response();
    }

    rename_object_path_response(&state, request).await
}

async fn rename_object_path_response(
    state: &ServerState,
    request: PathMutationRequest,
) -> Response {
    if request.from_path.trim().is_empty() || request.to_path.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let started = Instant::now();
    info!(
        from_path = %request.from_path,
        to_path = %request.to_path,
        overwrite = request.overwrite,
        "store path rename request start"
    );
    let mut store = lock_store(state, "store_path.rename").await;
    let store_lock_wait_ms = store.waited_ms();
    let store_started = Instant::now();
    match store
        .rename_object_path(&request.from_path, &request.to_path, request.overwrite)
        .await
    {
        Ok(PathMutationResult::Applied) => {
            info!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "store path rename applied; publishing namespace change"
            );
            drop(store);
            publish_namespace_change(state);
            request_local_availability_refresh(state);
            info!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                total_elapsed_ms = started.elapsed().as_millis(),
                "store path rename response ready after queueing background availability refresh"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(PathMutationResult::SourceMissing) => {
            info!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "store path rename source missing"
            );
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(PathMutationResult::TargetExists) => {
            info!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "store path rename target exists"
            );
            StatusCode::CONFLICT.into_response()
        }
        Err(err) => {
            tracing::error!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                error = %err,
                "failed to rename object path"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn copy_object_path(
    State(state): State<ServerState>,
    Json(request): Json<PathMutationRequest>,
) -> Response {
    if request.from_path.trim().is_empty() || request.to_path.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut store = lock_store(&state, "store_path.copy").await;
    match store
        .copy_object_path(&request.from_path, &request.to_path, request.overwrite)
        .await
    {
        Ok(PathMutationResult::Applied) => {
            drop(store);
            publish_namespace_change(&state);
            request_local_availability_refresh(&state);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(PathMutationResult::SourceMissing) => StatusCode::NOT_FOUND.into_response(),
        Ok(PathMutationResult::TargetExists) => StatusCode::CONFLICT.into_response(),
        Err(err) => {
            tracing::error!(
                from_path = %request.from_path,
                to_path = %request.to_path,
                error = %err,
                "failed to copy object path"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn restore_snapshot_path(
    State(state): State<ServerState>,
    Json(request): Json<SnapshotRestoreRequest>,
) -> Response {
    if request.snapshot.trim().is_empty()
        || request.from_path.trim().is_empty()
        || request.to_path.trim().is_empty()
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let started = Instant::now();
    info!(
        snapshot = %request.snapshot,
        from_path = %request.from_path,
        to_path = %request.to_path,
        recursive = request.recursive,
        overwrite = request.overwrite,
        "snapshot restore request start"
    );
    let mut store = lock_store(&state, "store_path.restore").await;
    let store_lock_wait_ms = store.waited_ms();
    let store_started = Instant::now();
    match store
        .restore_snapshot_path(
            &request.snapshot,
            &request.from_path,
            &request.to_path,
            request.recursive,
            request.overwrite,
        )
        .await
    {
        Ok(SnapshotRestoreMutationResult::Applied(report)) => {
            info!(
                snapshot = %request.snapshot,
                from_path = %request.from_path,
                to_path = %request.to_path,
                recursive = request.recursive,
                restored_count = report.restored_count,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "snapshot restore applied; publishing namespace change"
            );
            drop(store);
            publish_namespace_change(&state);
            request_local_availability_refresh(&state);
            (StatusCode::OK, Json(report)).into_response()
        }
        Ok(SnapshotRestoreMutationResult::SourceMissing) => {
            info!(
                snapshot = %request.snapshot,
                from_path = %request.from_path,
                to_path = %request.to_path,
                recursive = request.recursive,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "snapshot restore source missing"
            );
            StatusCode::NOT_FOUND.into_response()
        }
        Ok(SnapshotRestoreMutationResult::TargetExists { path }) => {
            info!(
                snapshot = %request.snapshot,
                from_path = %request.from_path,
                to_path = %request.to_path,
                recursive = request.recursive,
                conflict_path = %path,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                "snapshot restore target exists"
            );
            StatusCode::CONFLICT.into_response()
        }
        Err(err) => {
            tracing::error!(
                snapshot = %request.snapshot,
                from_path = %request.from_path,
                to_path = %request.to_path,
                recursive = request.recursive,
                store_lock_wait_ms,
                store_elapsed_ms = store_started.elapsed().as_millis(),
                total_elapsed_ms = started.elapsed().as_millis(),
                error = %err,
                "failed to restore snapshot path"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn put_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    Query(query): Query<PutObjectQuery>,
    payload: Bytes,
) -> impl IntoResponse {
    if query.version_id.is_some() && !query.internal_replication {
        return StatusCode::BAD_REQUEST;
    }

    let version_state = match query.state.as_deref() {
        None | Some("confirmed") => VersionConsistencyState::Confirmed,
        Some("provisional") => VersionConsistencyState::Provisional,
        Some(_) => return StatusCode::BAD_REQUEST,
    };

    let mut store = lock_store(&state, "store_object.put").await;
    match store
        .put_object_versioned(
            &key,
            payload,
            PutOptions {
                parent_version_ids: query.parent,
                state: version_state,
                inherit_preferred_parent: true,
                create_snapshot: !query.internal_replication,
                explicit_version_id: query.version_id,
            },
        )
        .await
    {
        Ok(outcome) => {
            drop(store);
            publish_namespace_change(&state);
            spawn_media_metadata_warmup(state.clone(), key.clone(), outcome.manifest_hash.clone());

            let mut cluster = state.cluster.lock().await;
            cluster.note_replica(&key, state.node_id);
            cluster.note_replica(
                format!("{}@{}", key, outcome.version_id.as_str()),
                state.node_id,
            );
            drop(cluster);

            if let Err(err) = persist_cluster_replicas_state(&state).await {
                warn!(error = %err, "failed to persist cluster replicas after put");
            }

            if should_trigger_autonomous_post_write_replication(
                state.autonomous_replication_on_put_enabled,
                query.internal_replication,
            ) {
                let state_for_repair = state.clone();
                tokio::spawn(async move {
                    let report = execute_tracked_local_replication_repair(
                        &state_for_repair,
                        None,
                        RepairRunTrigger::AutonomousPostWrite,
                        None,
                    )
                    .await;
                    if report.attempted_transfers > 0 || report.failed_transfers > 0 {
                        info!(
                            attempted = report.attempted_transfers,
                            success = report.successful_transfers,
                            failed = report.failed_transfers,
                            skipped = report.skipped_items,
                            skipped_backoff = report.skipped_backoff,
                            skipped_max_retries = report.skipped_max_retries,
                            "autonomous post-write replication run"
                        );
                    }
                });
            }

            info!(
                key = %key,
                snapshot_id = %outcome.snapshot_id,
                version_id = %outcome.version_id,
                version_state = ?outcome.state,
                created_new_version = outcome.created_new_version,
                new_chunks = outcome.new_chunks,
                dedup_reused_chunks = outcome.dedup_reused_chunks,
                "stored object"
            );
            StatusCode::CREATED
        }
        Err(err) => {
            tracing::error!(error = %err, key = %key, "failed to store object");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn start_upload_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<UploadSessionStartRequest>,
) -> impl IntoResponse {
    let key = request.key.trim();
    if key.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let version_state = match request.state.as_deref() {
        None | Some("confirmed") => VersionConsistencyState::Confirmed,
        Some("provisional") => VersionConsistencyState::Provisional,
        Some(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let chunk_size_bytes = 1024 * 1024;
    let chunk_count = if request.total_size_bytes == 0 {
        1
    } else {
        ((request.total_size_bytes - 1) / chunk_size_bytes as u64 + 1) as usize
    };
    let now = unix_ts();

    let mut sessions = write_upload_sessions(&state, "upload_sessions.start").await;
    prune_expired_upload_sessions(&mut sessions, now);

    let session = UploadSessionRecord {
        upload_id: Uuid::now_v7().to_string(),
        owner_device_id: request_device_id(&headers),
        key: key.to_string(),
        total_size_bytes: request.total_size_bytes,
        chunk_size_bytes,
        chunk_count,
        state: version_state,
        parent_version_ids: request.parent,
        explicit_version_id: request.version_id,
        received_chunks: vec![None; chunk_count],
        created_at_unix: now,
        updated_at_unix: now,
        expires_at_unix: now.saturating_add(UPLOAD_SESSION_TTL_SECS),
        finalizing: false,
        completed: false,
        completed_result: None,
    };
    let response = upload_session_view(&session);
    info!(
        upload_id = %session.upload_id,
        key = %key,
        total_size_bytes = request.total_size_bytes,
        chunk_count,
        chunk_size_bytes,
        state = ?session.state,
        "started upload session"
    );
    sessions.sessions.insert(session.upload_id.clone(), session);
    drop(sessions);
    persist_upload_session_store_after_mutation(&state, "start_upload_session").await;

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn get_upload_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    let requester_device_id = request_device_id(&headers);
    let now = unix_ts();
    let mut sessions = write_upload_sessions(&state, "upload_sessions.get").await;
    prune_expired_upload_sessions(&mut sessions, now);
    let Some(session) = sessions.sessions.get(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(owner_device_id) = session.owner_device_id.as_deref()
        && requester_device_id.as_deref() != Some(owner_device_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(upload_session_view(session)).into_response()
}

async fn delete_upload_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    let requester_device_id = request_device_id(&headers);
    let now = unix_ts();
    let mut sessions = write_upload_sessions(&state, "upload_sessions.delete").await;
    prune_expired_upload_sessions(&mut sessions, now);

    let Some(session) = sessions.sessions.get(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(owner_device_id) = session.owner_device_id.as_deref()
        && requester_device_id.as_deref() != Some(owner_device_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if session.finalizing {
        return StatusCode::CONFLICT.into_response();
    }

    sessions.sessions.remove(&upload_id);
    drop(sessions);
    persist_upload_session_store_after_mutation(&state, "delete_upload_session").await;

    StatusCode::NO_CONTENT.into_response()
}

async fn upload_session_chunk(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((upload_id, index)): Path<(String, usize)>,
    payload: Bytes,
) -> impl IntoResponse {
    upload_session_chunk_response(&state, &headers, &upload_id, index, payload).await
}

async fn upload_session_chunk_response(
    state: &ServerState,
    headers: &HeaderMap,
    upload_id: &str,
    index: usize,
    payload: Bytes,
) -> Response {
    let request_started_at = Instant::now();
    let requester_device_id = request_device_id(headers);
    let (total_size_bytes, chunk_size_bytes, chunk_count) = {
        let now = unix_ts();
        let mut sessions = write_upload_sessions(state, "upload_sessions.chunk.preflight").await;
        prune_expired_upload_sessions(&mut sessions, now);

        let Some(session) = sessions.sessions.get(upload_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if let Some(owner_device_id) = session.owner_device_id.as_deref()
            && requester_device_id.as_deref() != Some(owner_device_id)
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        if session.completed || session.finalizing {
            return StatusCode::CONFLICT.into_response();
        }

        (
            session.total_size_bytes,
            session.chunk_size_bytes,
            session.chunk_count,
        )
    };

    let Some(expected_size) =
        expected_upload_chunk_size(total_size_bytes, chunk_size_bytes, chunk_count, index)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if payload.len() != expected_size {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let store_ingest_started_at = Instant::now();
    let (hash, stored) = match state
        .upload_chunk_ingestor
        .ingest_chunk_auto(&payload)
        .await
    {
        Ok(result) => result,
        Err(err) => {
            let store_ingest_ms = store_ingest_started_at.elapsed().as_millis();
            let total_ms = request_started_at.elapsed().as_millis();
            tracing::warn!(
                error = %err,
                upload_id = %upload_id,
                index,
                size_bytes = payload.len(),
                store_lock_wait_ms = 0,
                store_ingest_ms,
                total_ms,
                "failed to ingest upload session chunk"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
    };
    let store_ingest_ms = store_ingest_started_at.elapsed().as_millis();
    let store_lock_wait_ms = 0;
    let next_ref = UploadChunkRef {
        hash,
        size_bytes: payload.len(),
    };

    let now = unix_ts();
    let mut sessions = write_upload_sessions(state, "upload_sessions.chunk.commit").await;
    prune_expired_upload_sessions(&mut sessions, now);

    let Some(session) = sessions.sessions.get_mut(upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(owner_device_id) = session.owner_device_id.as_deref()
        && requester_device_id.as_deref() != Some(owner_device_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if session.completed || session.finalizing {
        return StatusCode::CONFLICT.into_response();
    }

    if let Some(existing) = session
        .received_chunks
        .get(index)
        .and_then(|entry| entry.as_ref())
        && (existing.hash != next_ref.hash || existing.size_bytes != next_ref.size_bytes)
    {
        return StatusCode::CONFLICT.into_response();
    }

    session.received_chunks[index] = Some(next_ref);
    session.updated_at_unix = now;
    session.expires_at_unix = now.saturating_add(UPLOAD_SESSION_TTL_SECS);
    let response = UploadSessionChunkResponse {
        stored,
        received_index: index,
    };

    drop(sessions);
    persist_upload_session_store_after_mutation(state, "upload_session_chunk").await;
    let total_ms = request_started_at.elapsed().as_millis();
    if total_ms >= SLOW_UPLOAD_CHUNK_LOG_THRESHOLD_MS
        || store_lock_wait_ms >= SLOW_UPLOAD_CHUNK_LOG_THRESHOLD_MS
        || store_ingest_ms >= SLOW_UPLOAD_CHUNK_LOG_THRESHOLD_MS
    {
        info!(
            upload_id = %upload_id,
            index,
            size_bytes = payload.len(),
            stored,
            store_lock_wait_ms,
            store_ingest_ms,
            total_ms,
            "stored upload session chunk"
        );
    }

    (StatusCode::OK, Json(response)).into_response()
}

async fn complete_upload_session_route(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    let finalize_started_at = Instant::now();
    let requester_device_id = request_device_id(&headers);
    let (key, total_size_bytes, parent_version_ids, version_state, explicit_version_id, chunk_refs) = {
        let now = unix_ts();
        let mut sessions = write_upload_sessions(&state, "upload_sessions.complete.prepare").await;
        prune_expired_upload_sessions(&mut sessions, now);

        let Some(session) = sessions.sessions.get_mut(&upload_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if let Some(owner_device_id) = session.owner_device_id.as_deref()
            && requester_device_id.as_deref() != Some(owner_device_id)
        {
            return StatusCode::FORBIDDEN.into_response();
        }
        if session.completed
            && let Some(result) = session.completed_result.clone()
        {
            return (StatusCode::OK, Json(result)).into_response();
        }
        if session.finalizing || session.received_chunks.iter().any(|entry| entry.is_none()) {
            return StatusCode::CONFLICT.into_response();
        }

        session.finalizing = true;
        session.updated_at_unix = now;
        session.expires_at_unix = now.saturating_add(UPLOAD_SESSION_TTL_SECS);

        (
            session.key.clone(),
            session.total_size_bytes,
            session.parent_version_ids.clone(),
            session.state.clone(),
            session.explicit_version_id.clone(),
            session
                .received_chunks
                .iter()
                .filter_map(|entry| entry.clone())
                .collect::<Vec<_>>(),
        )
    };
    info!(
        upload_id = %upload_id,
        key = %key,
        total_size_bytes,
        chunk_count = chunk_refs.len(),
        "finalizing upload session"
    );

    let mut store = lock_store(&state, "upload_session.complete.put_object_from_chunks").await;
    let store_lock_wait_ms = store.waited_ms();
    let store_finalize_started_at = Instant::now();
    let outcome = match store
        .put_object_from_chunks(
            &key,
            total_size_bytes as usize,
            &chunk_refs,
            PutOptions {
                parent_version_ids: parent_version_ids.clone(),
                state: version_state.clone(),
                inherit_preferred_parent: true,
                create_snapshot: true,
                explicit_version_id: explicit_version_id.clone(),
            },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            let store_finalize_ms = store_finalize_started_at.elapsed().as_millis();
            drop(store);
            let mut sessions =
                write_upload_sessions(&state, "upload_sessions.complete.rollback").await;
            if let Some(session) = sessions.sessions.get_mut(&upload_id)
                && !session.completed
            {
                session.finalizing = false;
                session.updated_at_unix = unix_ts();
                session.expires_at_unix = session
                    .updated_at_unix
                    .saturating_add(UPLOAD_SESSION_TTL_SECS);
            }
            drop(sessions);
            persist_upload_session_store_after_mutation(&state, "complete_upload_session_error")
                .await;
            tracing::error!(
                error = %err,
                key = %key,
                upload_id = %upload_id,
                chunk_count = chunk_refs.len(),
                store_lock_wait_ms,
                store_finalize_ms,
                total_ms = finalize_started_at.elapsed().as_millis(),
                "failed to finalize upload session"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let store_finalize_ms = store_finalize_started_at.elapsed().as_millis();
    drop(store);

    publish_namespace_change(&state);
    spawn_media_metadata_warmup(state.clone(), key.clone(), outcome.manifest_hash.clone());

    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(&key, state.node_id);
    cluster.note_replica(
        format!("{}@{}", key, outcome.version_id.as_str()),
        state.node_id,
    );
    drop(cluster);

    if let Err(err) = persist_cluster_replicas_state(&state).await {
        warn!(
            error = %err,
            "failed to persist cluster replicas after upload session complete"
        );
    }

    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        let state_for_repair = state.clone();
        tokio::spawn(async move {
            let report = execute_tracked_local_replication_repair(
                &state_for_repair,
                None,
                RepairRunTrigger::AutonomousPostWrite,
                None,
            )
            .await;
            if report.attempted_transfers > 0 || report.failed_transfers > 0 {
                info!(
                    attempted = report.attempted_transfers,
                    success = report.successful_transfers,
                    failed = report.failed_transfers,
                    skipped = report.skipped_items,
                    skipped_backoff = report.skipped_backoff,
                    skipped_max_retries = report.skipped_max_retries,
                    "autonomous post-write replication run"
                );
            }
        });
    }

    let response = UploadSessionCompleteResponse {
        snapshot_id: outcome.snapshot_id.clone(),
        version_id: outcome.version_id.clone(),
        manifest_hash: outcome.manifest_hash.clone(),
        state: outcome.state.clone(),
        new_chunks: outcome.new_chunks,
        dedup_reused_chunks: outcome.dedup_reused_chunks,
        created_new_version: outcome.created_new_version,
        total_size_bytes,
    };
    let now = unix_ts();
    let mut sessions = write_upload_sessions(&state, "upload_sessions.complete.finish").await;
    if let Some(session) = sessions.sessions.get_mut(&upload_id) {
        session.completed = true;
        session.finalizing = false;
        session.completed_result = Some(response.clone());
        session.updated_at_unix = now;
        session.expires_at_unix = now.saturating_add(UPLOAD_SESSION_TTL_SECS);
    } else {
        warn!(
            upload_id = %upload_id,
            key = %key,
            "upload session disappeared before completion state could be persisted"
        );
        return (StatusCode::OK, Json(response)).into_response();
    }
    drop(sessions);
    persist_upload_session_store_after_mutation(&state, "complete_upload_session").await;
    let total_ms = finalize_started_at.elapsed().as_millis();
    info!(
        upload_id = %upload_id,
        key = %key,
        total_size_bytes,
        chunk_count = chunk_refs.len(),
        manifest_hash = %outcome.manifest_hash,
        version_id = %outcome.version_id,
        new_chunks = outcome.new_chunks,
        dedup_reused_chunks = outcome.dedup_reused_chunks,
        created_new_version = outcome.created_new_version,
        store_lock_wait_ms,
        store_finalize_ms,
        total_ms,
        slow = total_ms >= SLOW_UPLOAD_FINALIZE_LOG_THRESHOLD_MS,
        "completed upload session"
    );

    (StatusCode::OK, Json(response)).into_response()
}

async fn delete_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    Query(query): Query<PutObjectQuery>,
) -> impl IntoResponse {
    if key.trim().is_empty() {
        return StatusCode::BAD_REQUEST;
    }
    if query.version_id.is_some() && !query.internal_replication {
        return StatusCode::BAD_REQUEST;
    }

    let version_state = match query.state.as_deref() {
        None | Some("confirmed") => VersionConsistencyState::Confirmed,
        Some("provisional") => VersionConsistencyState::Provisional,
        Some(_) => return StatusCode::BAD_REQUEST,
    };
    let recursive = query.recursive
        || (key.ends_with('/') && !query.internal_replication && query.version_id.is_none());
    if recursive && (!query.parent.is_empty() || query.version_id.is_some()) {
        return StatusCode::BAD_REQUEST;
    }

    let mut store = lock_store(&state, "store_object.tombstone").await;
    let delete_result = if recursive {
        store
            .tombstone_subtree(
                &key,
                PutOptions {
                    parent_version_ids: query.parent,
                    state: version_state,
                    inherit_preferred_parent: true,
                    create_snapshot: !query.internal_replication,
                    explicit_version_id: query.version_id,
                },
            )
            .await
            .map(|results| {
                results
                    .into_iter()
                    .map(|entry| (entry.path, entry.version_id))
                    .collect::<Vec<_>>()
            })
    } else {
        store
            .tombstone_object(
                &key,
                PutOptions {
                    parent_version_ids: query.parent,
                    state: version_state,
                    inherit_preferred_parent: true,
                    create_snapshot: !query.internal_replication,
                    explicit_version_id: query.version_id,
                },
            )
            .await
            .map(|version_id| vec![(key.clone(), version_id)])
    };

    match delete_result {
        Ok(deleted_paths) => {
            drop(store);
            publish_namespace_change(&state);

            let mut cluster = state.cluster.lock().await;
            for (deleted_path, version_id) in &deleted_paths {
                cluster.note_replica(deleted_path, state.node_id);
                cluster.note_replica(format!("{}@{}", deleted_path, version_id), state.node_id);
            }
            drop(cluster);

            if let Err(err) = persist_cluster_replicas_state(&state).await {
                warn!(error = %err, "failed to persist cluster replicas after tombstone");
            }

            if should_trigger_autonomous_post_write_replication(
                state.autonomous_replication_on_put_enabled,
                query.internal_replication,
            ) {
                let state_for_repair = state.clone();
                tokio::spawn(async move {
                    let report = execute_tracked_local_replication_repair(
                        &state_for_repair,
                        None,
                        RepairRunTrigger::AutonomousPostWrite,
                        None,
                    )
                    .await;
                    if report.attempted_transfers > 0 || report.failed_transfers > 0 {
                        info!(
                            attempted = report.attempted_transfers,
                            success = report.successful_transfers,
                            failed = report.failed_transfers,
                            skipped = report.skipped_items,
                            skipped_backoff = report.skipped_backoff,
                            skipped_max_retries = report.skipped_max_retries,
                            "autonomous post-write replication run"
                        );
                    }
                });
            }

            info!(
                key = %key,
                recursive,
                deleted_paths = deleted_paths.len(),
                "tombstoned object path(s)"
            );
            StatusCode::CREATED
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                key = %key,
                recursive,
                "failed to tombstone object path(s)"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn list_store_index(
    State(state): State<ServerState>,
    Query(query): Query<StoreIndexQuery>,
) -> impl IntoResponse {
    list_store_index_response(&state, query, PUBLIC_API_V1_MEDIA_THUMBNAIL_ROUTE).await
}

async fn list_store_index_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<StoreIndexQuery>,
) -> impl IntoResponse {
    let action = "auth/store/index/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "prefix": query.prefix.clone(),
            "depth": query.depth,
            "snapshot": query.snapshot.clone(),
            "view": query.view,
        }),
    )
    .await
    {
        return status.into_response();
    }

    list_store_index_response(&state, query, PUBLIC_API_V1_ADMIN_MEDIA_THUMBNAIL_ROUTE).await
}

async fn list_store_index_response(
    state: &ServerState,
    query: StoreIndexQuery,
    thumbnail_route: &str,
) -> Response {
    let request_id = Uuid::new_v4();
    let prefix = query.prefix.unwrap_or_default();
    let depth = query.depth.unwrap_or(1).max(1);
    let snapshot_label = query.snapshot.as_deref().unwrap_or("<current>");

    let snapshot_scan_started_at = Instant::now();
    let (store_index_inspector, snapshot_scan_waited_ms) = {
        let store = read_store(state, "store_index.clone_worker").await;
        (store.store_index_inspector(), store.waited_ms())
    };
    let (
        keys,
        key_hashes,
        key_sizes,
        key_content_fingerprints,
        key_modified_times,
    ): StoreIndexSnapshotScan = if let Some(snapshot_id) =
        query.snapshot.as_deref()
    {
        match store_index_inspector
            .snapshot_object_state(snapshot_id)
            .await
        {
            Ok(Some(snapshot_state)) => {
                let (object_hashes, object_ids) = filter_store_index_object_maps_for_prefix(
                    snapshot_state.objects,
                    snapshot_state.object_ids,
                    &prefix,
                );
                let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
                keys.sort();
                let (sizes, content_fingerprints) = match store_index_inspector
                    .object_sizes_and_content_fingerprints_by_key(&object_hashes)
                    .await
                {
                    Ok(values) => values,
                    Err(err) => {
                        tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to compute snapshot key metadata");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                let modified_times = match store_index_inspector
                    .object_modified_at_by_key(
                        &object_hashes,
                        &object_ids,
                        Some(snapshot_state.created_at_unix),
                    )
                    .await
                {
                    Ok(modified_times) => modified_times,
                    Err(err) => {
                        tracing::error!(
                            snapshot_id = %snapshot_id,
                            error = %err,
                            "failed to compute snapshot key modified times"
                        );
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };
                (keys, object_hashes, sizes, content_fingerprints, modified_times)
            }
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(err) => {
                tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to list snapshot key index");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        let (object_hashes, object_ids) = filter_store_index_object_maps_for_prefix(
            store_index_inspector.current_object_hashes(),
            store_index_inspector.current_object_ids(),
            &prefix,
        );
        let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
        keys.sort();
        let (sizes, content_fingerprints) = match store_index_inspector
            .object_sizes_and_content_fingerprints_by_key(&object_hashes)
            .await
        {
            Ok(values) => values,
            Err(err) => {
                tracing::error!(error = %err, "failed to compute current key metadata");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let modified_times = match store_index_inspector
            .object_modified_at_by_key(&object_hashes, &object_ids, None)
            .await
        {
            Ok(modified_times) => modified_times,
            Err(err) => {
                tracing::error!(error = %err, "failed to compute current key modified times");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        (keys, object_hashes, sizes, content_fingerprints, modified_times)
    };
    let snapshot_scan_ms = snapshot_scan_started_at.elapsed().as_millis();
    if snapshot_scan_waited_ms >= SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS
        || snapshot_scan_ms >= SLOW_STORE_INDEX_PHASE_LOG_THRESHOLD_MS
    {
        warn!(
            request_id = %request_id,
            prefix = %prefix,
            snapshot = snapshot_label,
            depth,
            key_count = keys.len(),
            lock_waited_ms = snapshot_scan_waited_ms,
            phase_ms = snapshot_scan_ms,
            "slow store index snapshot scan"
        );
    }

    let mut entries = build_store_index_entries_with_hashes(
        &keys,
        &prefix,
        depth,
        Some(&key_hashes),
        Some(&key_sizes),
        Some(&key_content_fingerprints),
        Some(&key_modified_times),
    );
    let media_entry_count = entries
        .iter()
        .filter(|entry| entry.entry_type == "key" && looks_like_media_path(&entry.path))
        .count();
    let media_lookup_started_at = Instant::now();
    let mut media_ready_count = 0;
    let mut media_pending_count = 0;
    let mut media_unsupported_count = 0;
    let mut media_failed_count = 0;
    let mut media_missing_count = 0;
    let mut media_error_count = 0;
    let media_lookup_waited_ms = 0;
    for entry in &mut entries {
        if entry.entry_type != "key" || !looks_like_media_path(&entry.path) {
            continue;
        }

        let Some(manifest_hash) = entry.content_hash.as_deref() else {
            continue;
        };

        match store_index_inspector
            .lookup_media_cache(manifest_hash)
            .await
        {
            Ok(Some(lookup)) => {
                match lookup.metadata.as_ref().map(|metadata| &metadata.status) {
                    Some(MediaCacheStatus::Ready) => media_ready_count += 1,
                    Some(MediaCacheStatus::Unsupported) => media_unsupported_count += 1,
                    Some(MediaCacheStatus::Failed) => media_failed_count += 1,
                    None => media_pending_count += 1,
                }
                entry.content_fingerprint = Some(lookup.content_fingerprint.clone());
                entry.media = Some(build_media_index_response(
                    &entry.path,
                    query.snapshot.as_deref(),
                    &lookup,
                    thumbnail_route,
                ));
            }
            Ok(None) => {
                media_missing_count += 1;
            }
            Err(err) => {
                media_error_count += 1;
                warn!(
                    key = %entry.path,
                    manifest_hash = %manifest_hash,
                    error = %err,
                    "failed to read cached media metadata for store index"
                );
            }
        }
    }
    let media_lookup_ms = media_lookup_started_at.elapsed().as_millis();
    if media_entry_count > 0
        && (media_lookup_waited_ms >= SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS
            || media_lookup_ms >= SLOW_STORE_INDEX_PHASE_LOG_THRESHOLD_MS)
    {
        warn!(
            request_id = %request_id,
            prefix = %prefix,
            snapshot = snapshot_label,
            depth,
            entry_count = entries.len(),
            media_entry_count,
            lock_waited_ms = media_lookup_waited_ms,
            phase_ms = media_lookup_ms,
            ready_count = media_ready_count,
            pending_count = media_pending_count,
            unsupported_count = media_unsupported_count,
            failed_count = media_failed_count,
            missing_count = media_missing_count,
            error_count = media_error_count,
            "slow store index media lookup"
        );
    }

    if matches!(query.view, Some(StoreIndexView::Tree)) {
        entries = collapse_store_index_entries_for_tree_view(entries);
    }

    let mut response = (
        StatusCode::OK,
        Json(StoreIndexResponse {
            prefix,
            depth,
            entry_count: entries.len(),
            entries,
        }),
    )
        .into_response();
    let change_sequence = state.namespace_change_sequence.load(Ordering::SeqCst);
    if let Ok(header_value) = HeaderValue::from_str(&change_sequence.to_string()) {
        response
            .headers_mut()
            .insert("x-ironmesh-change-sequence", header_value);
    }
    response
}

fn collapse_store_index_entries_for_tree_view(
    entries: Vec<StoreIndexEntry>,
) -> Vec<StoreIndexEntry> {
    let mut collapsed = BTreeMap::new();

    for entry in entries {
        let is_directory_like = entry.entry_type == "prefix" || entry.path.ends_with('/');
        if !is_directory_like {
            collapsed.insert(entry.path.clone(), entry);
            continue;
        }

        collapsed
            .entry(entry.path.clone())
            .or_insert_with(|| StoreIndexEntry {
                path: entry.path,
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            });
    }

    collapsed.into_values().collect()
}

async fn wait_for_store_index_change(
    State(state): State<ServerState>,
    Query(query): Query<StoreIndexChangeWaitQuery>,
) -> impl IntoResponse {
    let since = query.since.unwrap_or(0);
    let timeout_ms = query.timeout_ms.unwrap_or(25_000).clamp(250, 60_000);

    let current = state.namespace_change_sequence.load(Ordering::SeqCst);
    if current > since {
        return (
            StatusCode::OK,
            Json(StoreIndexChangeWaitResponse {
                sequence: current,
                changed: true,
            }),
        )
            .into_response();
    }

    let mut receiver = state.namespace_change_tx.subscribe();
    if *receiver.borrow() > since {
        return (
            StatusCode::OK,
            Json(StoreIndexChangeWaitResponse {
                sequence: *receiver.borrow(),
                changed: true,
            }),
        )
            .into_response();
    }

    let waited = tokio::time::timeout(Duration::from_millis(timeout_ms), async {
        loop {
            if receiver.changed().await.is_err() {
                return state.namespace_change_sequence.load(Ordering::SeqCst);
            }
            let sequence = *receiver.borrow_and_update();
            if sequence > since {
                return sequence;
            }
        }
    })
    .await;

    let sequence = match waited {
        Ok(sequence) => sequence,
        Err(_) => state.namespace_change_sequence.load(Ordering::SeqCst),
    };

    (
        StatusCode::OK,
        Json(StoreIndexChangeWaitResponse {
            sequence,
            changed: sequence > since,
        }),
    )
        .into_response()
}

fn build_media_index_response(
    key: &str,
    snapshot: Option<&str>,
    lookup: &MediaCacheLookup,
    thumbnail_route: &str,
) -> MediaIndexResponse {
    let thumbnail_url = build_thumbnail_url(key, snapshot, thumbnail_route);
    let pending_media_type = media_type_for_path(key).unwrap_or("image");
    match lookup.metadata.as_ref() {
        Some(metadata) => MediaIndexResponse {
            status: media_cache_status_label(&metadata.status).to_string(),
            content_fingerprint: lookup.content_fingerprint.clone(),
            media_type: metadata.media_type.clone(),
            mime_type: metadata.mime_type.clone(),
            width: metadata.width,
            height: metadata.height,
            orientation: metadata.orientation,
            taken_at_unix: metadata.taken_at_unix,
            gps: metadata.gps.as_ref().map(media_gps_response),
            thumbnail: metadata
                .thumbnail
                .as_ref()
                .map(|thumb| MediaThumbnailResponse {
                    url: thumbnail_url.clone(),
                    profile: thumb.profile.clone(),
                    width: thumb.width,
                    height: thumb.height,
                    format: thumb.format.clone(),
                    size_bytes: thumb.size_bytes,
                }),
            error: metadata.error.clone(),
        },
        None => MediaIndexResponse {
            status: "pending".to_string(),
            content_fingerprint: lookup.content_fingerprint.clone(),
            media_type: Some(pending_media_type.to_string()),
            mime_type: None,
            width: None,
            height: None,
            orientation: None,
            taken_at_unix: None,
            gps: None,
            thumbnail: Some(MediaThumbnailResponse {
                url: thumbnail_url,
                profile: "grid".to_string(),
                width: 256,
                height: 256,
                format: "jpeg".to_string(),
                size_bytes: 0,
            }),
            error: None,
        },
    }
}

fn build_thumbnail_url(key: &str, snapshot: Option<&str>, thumbnail_route: &str) -> String {
    let encoded_key = utf8_percent_encode(key, QUERY_COMPONENT_ENCODE_SET).to_string();
    match snapshot {
        Some(snapshot_id) => {
            let encoded_snapshot =
                utf8_percent_encode(snapshot_id, QUERY_COMPONENT_ENCODE_SET).to_string();
            format!("{thumbnail_route}?key={encoded_key}&snapshot={encoded_snapshot}")
        }
        None => format!("{thumbnail_route}?key={encoded_key}"),
    }
}

fn media_cache_status_label(status: &MediaCacheStatus) -> &'static str {
    match status {
        MediaCacheStatus::Ready => "ready",
        MediaCacheStatus::Unsupported => "unsupported",
        MediaCacheStatus::Failed => "failed",
    }
}

fn media_gps_response(value: &MediaGpsCoordinates) -> MediaGpsResponse {
    MediaGpsResponse {
        latitude: value.latitude,
        longitude: value.longitude,
    }
}

fn looks_like_media_path(path: &str) -> bool {
    media_type_for_path(path).is_some()
}

fn media_type_for_path(path: &str) -> Option<&'static str> {
    let extension = path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(
        extension.as_str(),
        "bmp" | "gif" | "jpeg" | "jpg" | "png" | "webp"
    ) {
        return Some("image");
    }
    if matches!(
        extension.as_str(),
        "avi" | "m4v" | "mkv" | "mov" | "mp4" | "mpeg" | "mpg" | "ogv" | "ts" | "webm"
    ) {
        return Some("video");
    }
    None
}

#[cfg(test)]
fn build_store_index_entries(keys: &[String], prefix: &str, depth: usize) -> Vec<StoreIndexEntry> {
    build_store_index_entries_with_hashes(keys, prefix, depth, None, None, None, None)
}

fn filter_store_index_object_maps_for_prefix(
    object_hashes: HashMap<String, String>,
    object_ids: HashMap<String, String>,
    prefix: &str,
) -> (HashMap<String, String>, HashMap<String, String>) {
    let normalized_prefix = prefix.trim().trim_matches('/');
    if normalized_prefix.is_empty() {
        return (object_hashes, object_ids);
    }

    let object_hashes = object_hashes
        .into_iter()
        .filter(|(key, _)| store_index_remainder_for_prefix(key, normalized_prefix).is_some())
        .collect();
    let object_ids = object_ids
        .into_iter()
        .filter(|(key, _)| store_index_remainder_for_prefix(key, normalized_prefix).is_some())
        .collect();
    (object_hashes, object_ids)
}

fn build_store_index_entries_with_hashes(
    keys: &[String],
    prefix: &str,
    depth: usize,
    hashes_by_key: Option<&HashMap<String, String>>,
    sizes_by_key: Option<&HashMap<String, u64>>,
    content_fingerprints_by_key: Option<&HashMap<String, String>>,
    modified_times_by_key: Option<&HashMap<String, u64>>,
) -> Vec<StoreIndexEntry> {
    let normalized_prefix = prefix.trim().trim_matches('/');
    let mut file_entries = BTreeSet::new();
    let mut prefix_entries = BTreeSet::new();

    for key in keys {
        let Some(remainder) = store_index_remainder_for_prefix(key, normalized_prefix) else {
            continue;
        };

        let segments: Vec<&str> = remainder
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();

        if segments.is_empty() || segments.len() <= depth {
            file_entries.insert(key.clone());
            continue;
        }

        let partial = segments[..depth].join("/");
        let combined = if normalized_prefix.is_empty() {
            partial
        } else {
            format!("{normalized_prefix}/{partial}")
        };
        prefix_entries.insert(format!("{}/", combined.trim_end_matches('/')));
    }

    let mut entries = Vec::with_capacity(file_entries.len() + prefix_entries.len());
    for path in prefix_entries {
        entries.push(StoreIndexEntry {
            path,
            entry_type: "prefix".to_string(),
            version: None,
            content_hash: None,
            size_bytes: None,
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        });
    }
    for path in file_entries {
        let content_hash = hashes_by_key.and_then(|values| values.get(&path)).cloned();
        let size_bytes = sizes_by_key.and_then(|values| values.get(&path)).copied();
        let content_fingerprint = content_fingerprints_by_key
            .and_then(|values| values.get(&path))
            .cloned();
        let modified_at_unix = modified_times_by_key
            .and_then(|values| values.get(&path))
            .copied();
        entries.push(StoreIndexEntry {
            path,
            entry_type: "key".to_string(),
            version: None,
            content_hash,
            size_bytes,
            modified_at_unix,
            content_fingerprint,
            media: None,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn store_index_remainder_for_prefix<'a>(key: &'a str, normalized_prefix: &str) -> Option<&'a str> {
    if normalized_prefix.is_empty() {
        return Some(key.trim_start_matches('/'));
    }

    if key == normalized_prefix {
        return Some("");
    }

    let remainder = key.strip_prefix(normalized_prefix)?;
    if remainder.is_empty() {
        return Some("");
    }
    if remainder.starts_with('/') {
        return Some(remainder.trim_start_matches('/'));
    }

    None
}

async fn get_object(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Query(query): Query<ObjectGetQuery>,
) -> impl IntoResponse {
    get_object_response(&state, &key, query, &headers, false).await
}

async fn head_object(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Query(query): Query<ObjectGetQuery>,
) -> impl IntoResponse {
    get_object_response(&state, &key, query, &headers, true).await
}

async fn get_object_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
    Query(query): Query<ObjectGetQuery>,
) -> impl IntoResponse {
    let action = "auth/store/object/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "key": key.clone(),
            "snapshot": query.snapshot.clone(),
            "version": query.version.clone(),
        }),
    )
    .await
    {
        return status.into_response();
    }

    get_object_response(&state, &key, query, &headers, false).await
}

fn object_etag(manifest_hash: &str) -> String {
    format!("\"{manifest_hash}\"")
}

fn parse_object_byte_range(value: &str, total_size_bytes: usize) -> Option<ObjectByteRange> {
    let trimmed = value.trim();
    let range_spec = trimmed.strip_prefix("bytes=")?.trim();
    if range_spec.contains(',') {
        return None;
    }
    let (start_raw, end_raw) = range_spec.split_once('-')?;
    if start_raw.is_empty() {
        let suffix_len = end_raw.parse::<usize>().ok()?;
        if suffix_len == 0 || total_size_bytes == 0 {
            return None;
        }
        let clamped_len = suffix_len.min(total_size_bytes);
        return Some(ObjectByteRange {
            start: total_size_bytes.saturating_sub(clamped_len),
            end_inclusive: total_size_bytes.saturating_sub(1),
        });
    }

    let start = start_raw.parse::<usize>().ok()?;
    if start >= total_size_bytes {
        return None;
    }
    let end_inclusive = if end_raw.is_empty() {
        total_size_bytes.saturating_sub(1)
    } else {
        end_raw
            .parse::<usize>()
            .ok()?
            .min(total_size_bytes.saturating_sub(1))
    };
    if end_inclusive < start {
        return None;
    }

    Some(ObjectByteRange {
        start,
        end_inclusive,
    })
}

fn range_matches_if_range(headers: &HeaderMap, current_etag: &str) -> bool {
    let Some(value) = headers.get(header::IF_RANGE) else {
        return true;
    };
    let Ok(value) = value.to_str() else {
        return false;
    };
    let trimmed = value.trim();
    trimmed == current_etag || trimmed.trim_matches('"') == current_etag.trim_matches('"')
}

fn add_object_common_headers(
    response: &mut Response,
    etag: &str,
    total_size_bytes: usize,
    content_length: usize,
) {
    if let Ok(value) = HeaderValue::from_str("bytes") {
        response.headers_mut().insert(header::ACCEPT_RANGES, value);
    }
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
    if let Ok(value) = HeaderValue::from_str(&total_size_bytes.to_string()) {
        response
            .headers_mut()
            .insert("x-ironmesh-object-size", value);
    }
    if let Ok(value) = HeaderValue::from_str(&content_length.to_string()) {
        response.headers_mut().insert(header::CONTENT_LENGTH, value);
    }
}

fn build_range_not_satisfiable_response(etag: &str, total_size_bytes: usize) -> Response {
    let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
    add_object_common_headers(&mut response, etag, total_size_bytes, 0);
    if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total_size_bytes}")) {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
}

fn build_object_head_response(
    status: StatusCode,
    etag: &str,
    total_size_bytes: usize,
    selected_range: Option<ObjectByteRange>,
) -> Response {
    let content_length = selected_range
        .map(|range| range.end_inclusive - range.start + 1)
        .unwrap_or(total_size_bytes);
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    add_object_common_headers(&mut response, etag, total_size_bytes, content_length);
    if let Some(range) = selected_range
        && let Ok(value) = HeaderValue::from_str(&format!(
            "bytes {}-{}/{}",
            range.start, range.end_inclusive, total_size_bytes
        ))
    {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
}

fn build_object_stream(
    plan: ObjectStreamPlan,
) -> impl futures_core::stream::Stream<Item = std::result::Result<Bytes, io::Error>> + Send + 'static
{
    async_stream::try_stream! {
        for chunk in plan.chunks {
            let mut file = TokioFile::open(&chunk.path).await.map_err(|err| {
                io::Error::other(format!(
                    "failed to open chunk hash={} path={}: {err}",
                    chunk.hash,
                    chunk.path.display()
                ))
            })?;

            if chunk.start > 0 {
                file.seek(SeekFrom::Start(chunk.start as u64)).await.map_err(|err| {
                    io::Error::other(format!(
                        "failed to seek chunk hash={} path={} offset={}: {err}",
                        chunk.hash,
                        chunk.path.display(),
                        chunk.start
                    ))
                })?;
            }

            let mut remaining = chunk.len;
            let buffer_len = remaining.clamp(1, OBJECT_RESPONSE_STREAM_CHUNK_SIZE_BYTES);
            let mut buffer = vec![0_u8; buffer_len];

            while remaining > 0 {
                let read_len = std::cmp::min(remaining, buffer.len());
                let bytes_read = file.read(&mut buffer[..read_len]).await.map_err(|err| {
                    io::Error::other(format!(
                        "failed to read chunk hash={} path={}: {err}",
                        chunk.hash,
                        chunk.path.display()
                    ))
                })?;
                if bytes_read == 0 {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "unexpected EOF while streaming chunk hash={} path={}",
                            chunk.hash,
                            chunk.path.display()
                        ),
                    ))?;
                }

                remaining -= bytes_read;
                yield Bytes::copy_from_slice(&buffer[..bytes_read]);
            }
        }
    }
}

fn build_object_stream_body(plan: ObjectStreamPlan) -> Body {
    Body::from_stream(build_object_stream(plan))
}

fn build_object_stream_response(
    status: StatusCode,
    etag: &str,
    total_size_bytes: usize,
    selected_range: Option<ObjectByteRange>,
    stream_plan: ObjectStreamPlan,
) -> Response {
    let content_length = stream_plan.content_length();
    let mut response = Response::new(build_object_stream_body(stream_plan));
    *response.status_mut() = status;
    add_object_common_headers(&mut response, etag, total_size_bytes, content_length);
    if let Some(range) = selected_range
        && let Ok(value) = HeaderValue::from_str(&format!(
            "bytes {}-{}/{}",
            range.start, range.end_inclusive, total_size_bytes
        ))
    {
        response.headers_mut().insert(header::CONTENT_RANGE, value);
    }
    response
}

fn read_through_replication_subject(
    key: &str,
    snapshot_id: Option<&str>,
    version_id: Option<&str>,
) -> Option<String> {
    if let Some(version_id) = version_id {
        return Some(format!("{key}@{version_id}"));
    }
    if snapshot_id.is_some() {
        return None;
    }
    Some(key.to_string())
}

async fn read_through_source_nodes(state: &ServerState, subject: &str) -> Vec<NodeDescriptor> {
    let cluster = state.cluster.lock().await;
    cluster
        .available_nodes_for_subject(subject)
        .into_iter()
        .filter(|node| node.node_id != state.node_id)
        .collect()
}

async fn hydrate_missing_chunks_for_range(
    state: &ServerState,
    subject: &str,
    missing_chunks: &[ReplicationChunkInfo],
) -> Result<()> {
    let sources = read_through_source_nodes(state, subject).await;
    if sources.is_empty() {
        bail!("no readable replica source available for subject={subject}");
    }

    for chunk in missing_chunks {
        let mut fetched = false;
        let chunk_path = format!("/cluster/replication/chunk/{}", chunk.hash);

        for source in &sources {
            let response = match execute_peer_request(
                state,
                source,
                reqwest::Method::GET,
                &chunk_path,
                Vec::new(),
                Vec::new(),
            )
            .await
            {
                Ok(response) if response.is_success() => response,
                Ok(_) => continue,
                Err(err) => {
                    tracing::debug!(
                        node_id = %source.node_id,
                        chunk_hash = %chunk.hash,
                        error = %err,
                        "failed read-through chunk fetch"
                    );
                    continue;
                }
            };

            {
                let store = lock_store(state, "object_read.hydrate_missing_chunk").await;
                store
                    .ingest_chunk(&chunk.hash, response.body.as_ref())
                    .await?;
                store
                    .note_cached_chunk_fetch(
                        &chunk.hash,
                        chunk.size_bytes,
                        Some(&source.node_id.to_string()),
                    )
                    .await?;
            }
            fetched = true;
            break;
        }

        if !fetched {
            bail!(
                "failed read-through chunk fetch for subject={subject} chunk_hash={}",
                chunk.hash
            );
        }
    }

    Ok(())
}

async fn get_object_response(
    state: &ServerState,
    key: &str,
    query: ObjectGetQuery,
    headers: &HeaderMap,
    head_only: bool,
) -> Response {
    let read_mode = match parse_read_mode(query.read_mode.as_deref()) {
        Some(value) => value,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let descriptor = {
        let store = read_store(state, "object_read.describe").await;
        store
            .describe_object(
                key,
                query.snapshot.as_deref(),
                query.version.as_deref(),
                read_mode,
            )
            .await
    };

    let descriptor = match descriptor {
        Ok(descriptor) => descriptor,
        Err(StoreReadError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(StoreReadError::Corrupt(msg)) => {
            tracing::error!(key = %key, error = %msg, "detected corrupt data while reading object");
            return StatusCode::CONFLICT.into_response();
        }
        Err(StoreReadError::Internal(err)) => {
            tracing::error!(key = %key, error = %err, "internal error while reading object");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let ObjectReadDescriptor {
        manifest_hash,
        total_size_bytes,
    } = descriptor;
    let etag = object_etag(&manifest_hash);

    let selected_range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .filter(|_| range_matches_if_range(headers, &etag))
        .map(|value| parse_object_byte_range(value, total_size_bytes));

    let selected_range = match selected_range {
        Some(Some(range)) => Some(range),
        Some(None) => return build_range_not_satisfiable_response(&etag, total_size_bytes),
        None => None,
    };

    if head_only {
        return build_object_head_response(
            if selected_range.is_some() {
                StatusCode::PARTIAL_CONTENT
            } else {
                StatusCode::OK
            },
            &etag,
            total_size_bytes,
            selected_range,
        );
    }

    let (range_start, range_end_exclusive) = selected_range
        .map(|range| (range.start, range.end_inclusive.saturating_add(1)))
        .unwrap_or((0, total_size_bytes));

    let missing_chunks = {
        let store = read_store(state, "object_read.plan_missing_chunks").await;
        match store
            .missing_chunks_for_manifest_range(&manifest_hash, range_start, range_end_exclusive)
            .await
        {
            Ok(chunks) => chunks,
            Err(StoreReadError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(StoreReadError::Corrupt(msg)) => {
                tracing::error!(key = %key, error = %msg, "detected corrupt data while planning object read");
                return StatusCode::CONFLICT.into_response();
            }
            Err(StoreReadError::Internal(err)) => {
                tracing::error!(key = %key, error = %err, "internal error while planning object read");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let mut refreshed_local_availability = false;
    if !missing_chunks.is_empty()
        && let Some(subject) = read_through_replication_subject(
            key,
            query.snapshot.as_deref(),
            query.version.as_deref(),
        )
    {
        match hydrate_missing_chunks_for_range(state, &subject, &missing_chunks).await {
            Ok(()) => {
                request_local_availability_refresh(state);
                refreshed_local_availability = true;
            }
            Err(err) => {
                tracing::warn!(
                    key = %key,
                    subject = %subject,
                    missing_chunks = missing_chunks.len(),
                    error = %err,
                    "read-through chunk hydration failed"
                );
            }
        }
    }

    if refreshed_local_availability {
        tracing::debug!(
            key = %key,
            manifest_hash = %manifest_hash,
            "queued local availability refresh after read-through hydration"
        );
    }

    let touched_chunk_hashes = {
        let store = read_store(state, "object_read.list_range_chunk_hashes").await;
        match store
            .chunk_hashes_for_manifest_range(&manifest_hash, range_start, range_end_exclusive)
            .await
        {
            Ok(hashes) => hashes,
            Err(StoreReadError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(StoreReadError::Corrupt(msg)) => {
                tracing::error!(key = %key, error = %msg, "detected corrupt data while collecting object range chunk hashes");
                return StatusCode::CONFLICT.into_response();
            }
            Err(StoreReadError::Internal(err)) => {
                tracing::error!(key = %key, error = %err, "internal error while collecting object range chunk hashes");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    {
        let store = lock_store(state, "object_read.touch_cached_chunks").await;
        if let Err(err) = store
            .touch_cached_chunk_accesses(&touched_chunk_hashes)
            .await
        {
            tracing::debug!(
                key = %key,
                error = %err,
                "failed to update cached chunk access timestamps"
            );
        }
    }

    let read_result = {
        let store = read_store(state, "object_read.plan_stream").await;
        match selected_range {
            Some(range) => store
                .plan_object_range_by_manifest_hash(
                    &manifest_hash,
                    range.start,
                    range.end_inclusive.saturating_add(1),
                )
                .await
                .map(|stream_plan| (StatusCode::PARTIAL_CONTENT, Some(range), stream_plan)),
            None => store
                .plan_object_range_by_manifest_hash(&manifest_hash, 0, total_size_bytes)
                .await
                .map(|stream_plan| (StatusCode::OK, None, stream_plan)),
        }
    };

    match read_result {
        Ok((status, range, stream_plan)) => {
            let planned_content_length = stream_plan.content_length();
            let planned_chunk_count = stream_plan.chunks.len();
            let first_chunk = stream_plan
                .chunks
                .first()
                .map(|chunk| {
                    format!(
                        "hash={} start={} len={}",
                        chunk.hash, chunk.start, chunk.len
                    )
                })
                .unwrap_or_else(|| "<none>".to_string());

            if range.is_some() {
                info!(
                    key = %key,
                    snapshot = query.snapshot.as_deref().unwrap_or("<none>"),
                    version = query.version.as_deref().unwrap_or("<none>"),
                    manifest_hash = %manifest_hash,
                    requested_range = %headers
                        .get(header::RANGE)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("<none>"),
                    if_range = %headers
                        .get(header::IF_RANGE)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("<none>"),
                    selected_range = %format_object_byte_range(range),
                    total_size_bytes,
                    planned_content_length,
                    planned_chunk_count,
                    missing_chunks = missing_chunks.len(),
                    refreshed_local_availability,
                    first_chunk = %first_chunk,
                    status = %status,
                    "server object range response planned"
                );
            }

            build_object_stream_response(status, &etag, total_size_bytes, range, stream_plan)
        }
        Err(StoreReadError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(StoreReadError::Corrupt(msg)) => {
            tracing::error!(key = %key, error = %msg, "detected corrupt data while reading object");
            StatusCode::CONFLICT.into_response()
        }
        Err(StoreReadError::Internal(err)) => {
            tracing::error!(key = %key, error = %err, "internal error while reading object");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_media_thumbnail(
    State(state): State<ServerState>,
    Query(query): Query<MediaThumbnailQuery>,
) -> impl IntoResponse {
    get_media_thumbnail_response(&state, query).await
}

async fn get_media_thumbnail_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<MediaThumbnailQuery>,
) -> impl IntoResponse {
    let action = "auth/media/thumbnail/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "key": query.key.clone(),
            "snapshot": query.snapshot.clone(),
            "version": query.version.clone(),
        }),
    )
    .await
    {
        return status.into_response();
    }

    get_media_thumbnail_response(&state, query).await
}

async fn clear_media_cache_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<ApprovalQuery>,
) -> impl IntoResponse {
    let approve = query.approve.unwrap_or(false);
    let action = "auth/media/cache/clear";
    let request_details = json!({ "approve": approve });
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        false,
        approve,
        request_details.clone(),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = lock_store(&state, "maintenance.media_cache_clear").await;
        store.clear_media_cache().await
    };

    match result {
        Ok(report) => {
            refresh_storage_stats_once(&state).await;
            spawn_media_metadata_backfill(state.clone(), "clear_media_cache");
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                false,
                approve,
                "success",
                json!({
                    "deleted_metadata_records": report.deleted_metadata_records,
                    "deleted_thumbnail_files": report.deleted_thumbnail_files,
                    "deleted_thumbnail_bytes": report.deleted_thumbnail_bytes,
                }),
            )
            .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                false,
                approve,
                "error",
                json!({
                    "approve": approve,
                    "error": err.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %err, "media cache clear failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn get_media_thumbnail_response(state: &ServerState, query: MediaThumbnailQuery) -> Response {
    let request_id = Uuid::new_v4();
    let read_mode = match parse_read_mode(query.read_mode.as_deref()) {
        Some(value) => value,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let snapshot_label = query.snapshot.as_deref().unwrap_or("<current>");
    let version_label = query.version.as_deref().unwrap_or("<latest>");

    let request_started_at = Instant::now();
    let resolve_started_at = Instant::now();
    let (manifest_hash, media_cache_worker, resolve_waited_ms) = {
        let store = read_store(state, "media_thumbnail.resolve_and_ensure").await;
        let waited_ms = store.waited_ms();
        let manifest_hash = match store
            .resolve_manifest_hash_for_key(
                &query.key,
                query.snapshot.as_deref(),
                query.version.as_deref(),
                read_mode,
            )
            .await
        {
            Ok(value) => value,
            Err(StoreReadError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(StoreReadError::Corrupt(msg)) => {
                tracing::error!(key = %query.key, error = %msg, "corrupt object while resolving media thumbnail");
                return StatusCode::CONFLICT.into_response();
            }
            Err(StoreReadError::Internal(err)) => {
                tracing::error!(key = %query.key, error = %err, "internal error while resolving media thumbnail");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        (manifest_hash, store.media_cache_worker(), waited_ms)
    };
    let resolve_ms = resolve_started_at.elapsed().as_millis();
    if resolve_waited_ms >= SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS
        || resolve_ms >= SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS
    {
        warn!(
            request_id = %request_id,
            key = %query.key,
            snapshot = snapshot_label,
            version = version_label,
            read_mode = ?read_mode,
            manifest_hash = %manifest_hash,
            lock_waited_ms = resolve_waited_ms,
            phase_ms = resolve_ms,
            "slow media thumbnail resolve"
        );
    }

    let ensure_started_at = Instant::now();
    let metadata = match media_cache_worker.ensure_media_cache(&manifest_hash).await {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(key = %query.key, error = %err, "failed to build media thumbnail cache");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let ensure_ms = ensure_started_at.elapsed().as_millis();
    if ensure_ms >= SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS {
        warn!(
            request_id = %request_id,
            key = %query.key,
            snapshot = snapshot_label,
            version = version_label,
            manifest_hash = %manifest_hash,
            phase_ms = ensure_ms,
            status = ?metadata.status,
            has_thumbnail = metadata.thumbnail.is_some(),
            "slow media thumbnail cache ensure"
        );
    }

    if metadata.status != MediaCacheStatus::Ready {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(thumbnail) = metadata.thumbnail.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let path_lookup_started_at = Instant::now();
    let (thumbnail_path, path_lookup_waited_ms) = {
        let store = read_store(state, "media_thumbnail.path_lookup").await;
        (
            store.media_thumbnail_path(&metadata.content_fingerprint, &thumbnail.profile),
            store.waited_ms(),
        )
    };
    let path_lookup_ms = path_lookup_started_at.elapsed().as_millis();
    if path_lookup_waited_ms >= SLOW_STORE_LOCK_WAIT_LOG_THRESHOLD_MS
        || path_lookup_ms >= SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS
    {
        warn!(
            request_id = %request_id,
            key = %query.key,
            snapshot = snapshot_label,
            version = version_label,
            content_fingerprint = %metadata.content_fingerprint,
            thumbnail_profile = %thumbnail.profile,
            lock_waited_ms = path_lookup_waited_ms,
            phase_ms = path_lookup_ms,
            "slow media thumbnail path lookup"
        );
    }

    let file_read_started_at = Instant::now();
    let payload = match tokio::fs::read(&thumbnail_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Err(err) => {
            tracing::error!(
                key = %query.key,
                path = %thumbnail_path.display(),
                error = %err,
                "failed to read generated thumbnail"
            );
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let file_read_ms = file_read_started_at.elapsed().as_millis();
    let total_ms = request_started_at.elapsed().as_millis();
    if file_read_ms >= SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS
        || total_ms >= SLOW_MEDIA_THUMBNAIL_PHASE_LOG_THRESHOLD_MS
    {
        warn!(
            request_id = %request_id,
            key = %query.key,
            snapshot = snapshot_label,
            version = version_label,
            manifest_hash = %manifest_hash,
            content_fingerprint = %metadata.content_fingerprint,
            thumbnail_profile = %thumbnail.profile,
            file_read_ms,
            total_ms,
            payload_bytes = payload.len(),
            "slow media thumbnail response"
        );
    }

    (
        [
            (header::CONTENT_TYPE, "image/jpeg"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        payload,
    )
        .into_response()
}

fn parse_read_mode(value: Option<&str>) -> Option<ObjectReadMode> {
    match value {
        None | Some("preferred") => Some(ObjectReadMode::Preferred),
        Some("confirmed_only") => Some(ObjectReadMode::ConfirmedOnly),
        Some("provisional_allowed") => Some(ObjectReadMode::ProvisionalAllowed),
        Some(_) => None,
    }
}

async fn list_versions(
    State(state): State<ServerState>,
    Path(key): Path<String>,
) -> impl IntoResponse {
    list_versions_response(&state, &key).await
}

async fn list_versions_admin(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(key): Path<String>,
) -> impl IntoResponse {
    let action = "auth/versions/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "key": key.clone(),
        }),
    )
    .await
    {
        return status.into_response();
    }

    list_versions_response(&state, &key).await
}

async fn list_versions_response(state: &ServerState, key: &str) -> Response {
    let store = read_store(state, "versions.list").await;
    match store.list_versions(key).await {
        Ok(Some(summary)) => (StatusCode::OK, Json(summary)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(key = %key, error = %err, "failed to list versions");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn confirm_version(
    State(state): State<ServerState>,
    Path((key, version_id)): Path<(String, String)>,
) -> impl IntoResponse {
    commit_version_inner(state, key, version_id).await
}

async fn commit_version(
    State(state): State<ServerState>,
    Path((key, version_id)): Path<(String, String)>,
) -> impl IntoResponse {
    commit_version_inner(state, key, version_id).await
}

async fn commit_version_inner(state: ServerState, key: String, version_id: String) -> StatusCode {
    if matches!(state.metadata_commit_mode, MetadataCommitMode::Quorum) {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();

        if !cluster.has_metadata_commit_quorum() {
            let summary = cluster.summary();
            let quorum_required = cluster.metadata_commit_quorum_size();
            tracing::warn!(
                key = %key,
                version_id = %version_id,
                online_nodes = summary.online_nodes,
                total_nodes = summary.total_nodes,
                quorum_required,
                "metadata commit rejected: quorum unavailable"
            );
            return StatusCode::CONFLICT;
        }
    }

    let mut store = lock_store(&state, "versions.commit").await;
    match store.commit_version(&key, &version_id).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(err) => {
            tracing::error!(key = %key, version_id = %version_id, error = %err, "failed to commit version");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[derive(Debug, Deserialize)]
struct RegisterNodeRequest {
    reachability: NodeReachability,
    #[serde(default)]
    capabilities: Option<NodeCapabilities>,
    labels: HashMap<String, String>,
    capacity_bytes: Option<u64>,
    free_bytes: Option<u64>,
    #[serde(default)]
    storage_stats: Option<NodeStorageStatsSummary>,
}

#[derive(Debug, Deserialize)]
struct NodeHeartbeatRequest {
    free_bytes: Option<u64>,
    capacity_bytes: Option<u64>,
    #[serde(default)]
    storage_stats: Option<NodeStorageStatsSummary>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct OutboundNodeHeartbeatRequest {
    free_bytes: Option<u64>,
    capacity_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    storage_stats: Option<NodeStorageStatsSummary>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CleanupQuery {
    retention_secs: Option<u64>,
    dry_run: Option<bool>,
    approve: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ApprovalQuery {
    approve: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct StorageStatsHistoryQuery {
    limit: Option<usize>,
    since_unix: Option<u64>,
    max_points: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RepairHistoryQuery {
    limit: Option<usize>,
    since_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DataScrubHistoryQuery {
    limit: Option<usize>,
    since_unix: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DataScrubTriggerQuery {
    scope: Option<DataScrubScope>,
}

#[derive(Debug, Serialize)]
struct StorageStatsCurrentResponse {
    sample: Option<StorageStatsSample>,
    collecting: bool,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TombstoneRestoreQuery {
    object_id: String,
    archive_file: Option<String>,
    overwrite: Option<bool>,
    dry_run: Option<bool>,
    approve: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct PairingTokenIssueRequest {
    label: Option<String>,
    expires_in_secs: Option<u64>,
    preferred_rendezvous_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NodeBootstrapIssueRequest {
    node_id: Option<NodeId>,
    mode: Option<NodeBootstrapMode>,
    data_dir: Option<String>,
    bind_addr: Option<String>,
    public_url: Option<String>,
    labels: Option<HashMap<String, String>>,
    public_tls: Option<BootstrapServerTlsFiles>,
    public_ca_cert_path: Option<String>,
    public_peer_api_enabled: Option<bool>,
    internal_bind_addr: Option<String>,
    internal_url: Option<String>,
    internal_tls: Option<BootstrapTlsFiles>,
    enrollment_issuer_url: Option<String>,
    tls_validity_secs: Option<u64>,
    tls_renewal_window_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeEnrollmentRenewRequest {
    current_public_tls_cert_pem: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct NodeEnrollmentRenewResponse {
    cluster_id: ClusterId,
    node_id: NodeId,
    trust_roots: BootstrapTrustRoots,
    enrollment_issuer_url: Option<String>,
    #[serde(default)]
    public_tls_material: Option<BootstrapMutualTlsMaterial>,
    internal_tls_material: BootstrapMutualTlsMaterial,
}

#[derive(Debug, Deserialize)]
struct NodeJoinEnrollmentIssueRequest {
    join_request: NodeJoinRequest,
    tls_validity_secs: Option<u64>,
    tls_renewal_window_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ManagedSignerBackupExportRequest {
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct ManagedSignerBackupImportRequest {
    passphrase: String,
    backup: ManagedSignerBackup,
}

#[derive(Debug, Deserialize)]
struct ManagedRendezvousFailoverExportRequest {
    passphrase: String,
    target_node_id: NodeId,
    public_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManagedRendezvousFailoverImportRequest {
    passphrase: String,
    package: ManagedRendezvousFailoverPackage,
    bind_addr: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManagedControlPlanePromotionPackage {
    signer_backup: ManagedSignerBackup,
    rendezvous_failover: ManagedRendezvousFailoverPackage,
}

#[derive(Debug, Deserialize)]
struct ManagedControlPlanePromotionExportRequest {
    passphrase: String,
    target_node_id: NodeId,
    public_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManagedControlPlanePromotionImportRequest {
    passphrase: String,
    package: ManagedControlPlanePromotionPackage,
    bind_addr: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManagedSignerBackupImportResponse {
    status: String,
    cluster_id: ClusterId,
    source_node_id: NodeId,
    restart_required: bool,
    signer_ca_cert_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManagedRendezvousFailoverImportResponse {
    status: String,
    cluster_id: ClusterId,
    source_node_id: NodeId,
    target_node_id: NodeId,
    public_url: String,
    restart_required: bool,
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManagedControlPlanePromotionImportResponse {
    status: String,
    cluster_id: ClusterId,
    source_node_id: NodeId,
    target_node_id: NodeId,
    public_url: String,
    restart_required: bool,
    signer_ca_cert_path: String,
    rendezvous_cert_path: String,
    rendezvous_key_path: String,
}

#[derive(Debug, Serialize)]
struct RendezvousConfigView {
    effective_urls: Vec<String>,
    editable_urls: Vec<String>,
    managed_embedded_url: Option<String>,
    registration_enabled: bool,
    registration_interval_secs: u64,
    disconnected_retry_interval_secs: u64,
    endpoint_registrations: Vec<RendezvousEndpointRegistrationView>,
    mtls_required: bool,
    persistence_source: RendezvousConfigPersistenceSource,
    persisted: bool,
}

#[derive(Debug, Deserialize)]
struct UpdateRendezvousConfigRequest {
    editable_urls: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AdminLoginRequest {
    password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminSessionStatusResponse {
    login_required: bool,
    authenticated: bool,
    session_expires_at_unix: Option<u64>,
    token_override_enabled: bool,
}

#[derive(Debug, Serialize)]
struct PairingTokenIssueResponse {
    token_id: String,
    pairing_token: String,
    label: Option<String>,
    created_at_unix: u64,
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize)]
struct ClientDeviceEnrollRequest {
    cluster_id: ClusterId,
    pairing_token: String,
    device_id: Option<String>,
    #[serde(rename = "device_label", alias = "label")]
    label: Option<String>,
    public_key_pem: String,
}

#[derive(Debug, Serialize)]
struct ClientDeviceEnrollResponse {
    cluster_id: ClusterId,
    device_id: String,
    #[serde(rename = "device_label", alias = "label")]
    label: Option<String>,
    public_key_pem: String,
    credential_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous_client_identity_pem: Option<String>,
    created_at_unix: u64,
    expires_at_unix: Option<u64>,
}

impl ClientDeviceEnrollRequest {
    fn into_transport_request(self) -> std::result::Result<ClientEnrollmentRequest, StatusCode> {
        let device_id = self
            .device_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse().map_err(|_| {
                    warn!(
                        device_id = value,
                        "received invalid client enrollment device_id"
                    );
                    StatusCode::BAD_REQUEST
                })
            })
            .transpose()?;
        Ok(ClientEnrollmentRequest {
            cluster_id: self.cluster_id,
            pairing_token: self.pairing_token,
            device_id,
            label: self.label,
            public_key_pem: self.public_key_pem,
        })
    }
}

#[derive(Debug, Serialize)]
struct ClientCredentialView {
    device_id: String,
    label: Option<String>,
    public_key_fingerprint: Option<String>,
    credential_fingerprint: Option<String>,
    created_at_unix: u64,
    revocation_reason: Option<String>,
    revoked_by_actor: Option<String>,
    revoked_by_source_node: Option<String>,
    revoked_at_unix: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct RevokeClientCredentialQuery {
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct NodeTlsIssuePolicy {
    issued_at_unix: u64,
    not_before_unix: u64,
    not_after_unix: u64,
    renew_after_unix: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum NodeCertificateLifecycleState {
    NotConfigured,
    Missing,
    Valid,
    RenewalDue,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NodeCertificateStatusView {
    name: String,
    configured: bool,
    cert_path: Option<String>,
    metadata_path: Option<String>,
    issued_at_unix: Option<u64>,
    renew_after_unix: Option<u64>,
    expires_at_unix: Option<u64>,
    seconds_until_expiry: Option<i64>,
    certificate_fingerprint: Option<String>,
    metadata_matches_certificate: Option<bool>,
    state: NodeCertificateLifecycleState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NodeCertificateStatusResponse {
    public_tls: NodeCertificateStatusView,
    internal_tls: NodeCertificateStatusView,
    auto_renew: NodeCertificateAutoRenewStatusView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NodeCertificateAutoRenewStatusView {
    enabled: bool,
    enrollment_path: Option<String>,
    issuer_url: Option<String>,
    check_interval_secs: Option<u64>,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
    restart_required: bool,
}

async fn persist_client_credential_state(state: &ServerState) -> Result<()> {
    let snapshot = {
        let auth = state.client_credentials.lock().await;
        auth.clone()
    };
    let store = lock_store(state, "client_credentials.persist").await;
    store.persist_client_credential_state(&snapshot).await
}

async fn issue_pairing_token(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<PairingTokenIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/pairing-tokens/issue";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "label": request.label,
            "expires_in_secs": request.expires_in_secs,
            "preferred_rendezvous_url": request.preferred_rendezvous_url,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let response = match issue_pairing_token_impl(&state, request).await {
        Ok(response) => response,
        Err((status, error)) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": error }),
            )
            .await;
            return (status, Json(json!({ "error": error }))).into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "token_id": response.token_id,
            "label": response.label,
            "expires_at_unix": response.expires_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(response)).into_response()
}

fn bootstrap_trust_roots(
    state: &ServerState,
) -> std::result::Result<BootstrapTrustRoots, StatusCode> {
    let trust_material =
        load_live_trust_material(state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cluster_ca_pem = trust_material.cluster_ca_pem.clone();
    let public_api_ca_pem = trust_material.public_ca_pem.clone();
    Ok(BootstrapTrustRoots {
        cluster_ca_pem: cluster_ca_pem.clone(),
        public_api_ca_pem: public_api_ca_pem.clone(),
        rendezvous_ca_pem: trust_material
            .rendezvous_ca_pem
            .or(public_api_ca_pem)
            .or(cluster_ca_pem),
    })
}

fn bootstrap_rendezvous_urls(state: &ServerState) -> std::result::Result<Vec<String>, StatusCode> {
    Ok(if state.rendezvous_registration_enabled {
        normalize_rendezvous_url_list(&current_rendezvous_urls(state))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        Vec::new()
    })
}

async fn issue_client_bootstrap_impl(
    state: &ServerState,
    request: PairingTokenIssueRequest,
) -> std::result::Result<(TransportClientBootstrap, u64), (StatusCode, String)> {
    let rendezvous_urls = bootstrap_rendezvous_urls(state).map_err(|status| {
        (
            status,
            "failed to resolve bootstrap rendezvous URLs on this node".to_string(),
        )
    })?;
    let pairing_response = issue_pairing_token_impl(state, request).await?;

    let endpoints = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        let mut endpoints = cluster
            .list_nodes()
            .into_iter()
            .filter_map(|node| {
                node.public_api_url().map(|url| BootstrapEndpoint {
                    url: url.to_string(),
                    usage: Some(BootstrapEndpointUse::PublicApi),
                    node_id: Some(node.node_id),
                })
            })
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| {
            left.url
                .cmp(&right.url)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });
        endpoints.dedup_by(|left, right| left.url == right.url && left.node_id == right.node_id);
        endpoints
    };

    let bootstrap = TransportClientBootstrap {
        version: 1,
        cluster_id: state.cluster_id,
        rendezvous_urls,
        rendezvous_mtls_required: state.rendezvous_mtls_required,
        direct_endpoints: endpoints,
        relay_mode: state.relay_mode,
        trust_roots: bootstrap_trust_roots(state).map_err(|status| {
            (
                status,
                "failed to resolve bootstrap trust roots on this node".to_string(),
            )
        })?,
        pairing_token: Some(pairing_response.pairing_token),
        device_label: pairing_response.label,
        device_id: None,
    };

    Ok((bootstrap, pairing_response.expires_at_unix))
}

fn rendezvous_claim_trust_from_bootstrap(
    bootstrap: &TransportClientBootstrap,
) -> std::result::Result<ClientBootstrapClaimTrust, StatusCode> {
    let rendezvous_ca_pem = bootstrap
        .trust_roots
        .rendezvous_ca_pem
        .as_deref()
        .or(bootstrap.trust_roots.public_api_ca_pem.as_deref())
        .or(bootstrap.trust_roots.cluster_ca_pem.as_deref())
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut reader = std::io::BufReader::new(rendezvous_ca_pem.as_bytes());
    let cert = CertificateDer::pem_reader_iter(&mut reader)
        .next()
        .transpose()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(ClientBootstrapClaimTrust {
        ca_der_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cert.as_ref()),
    })
}

fn generate_bootstrap_claim_token() -> String {
    format!(
        "im-claim-{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

async fn resolve_bootstrap_claim_rendezvous_candidates(
    state: &ServerState,
    bootstrap: &TransportClientBootstrap,
    preferred_rendezvous_url: Option<&str>,
) -> std::result::Result<Vec<String>, (StatusCode, String)> {
    if let Some(preferred_rendezvous_url) = preferred_rendezvous_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let preferred_rendezvous_url = canonicalize_rendezvous_url(preferred_rendezvous_url)
            .map_err(|err| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid preferred rendezvous URL: {err}"),
                )
            })?;
        let configured_urls = bootstrap_rendezvous_urls(state).map_err(|status| {
            (
                status,
                "bootstrap claim issuance requires rendezvous to be configured on this node"
                    .to_string(),
            )
        })?;
        if !configured_urls.contains(&preferred_rendezvous_url) {
            return Err((
                StatusCode::PRECONDITION_FAILED,
                format!(
                    "selected rendezvous service is not configured on this node: {preferred_rendezvous_url}"
                ),
            ));
        }
        return Ok(vec![preferred_rendezvous_url]);
    }

    let rendezvous_urls =
        normalize_rendezvous_url_list(&bootstrap.rendezvous_urls).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to normalize bootstrap rendezvous URLs: {err}"),
            )
        })?;
    if rendezvous_urls.is_empty() {
        return Err((
            StatusCode::PRECONDITION_FAILED,
            "bootstrap claim issuance requires rendezvous to be configured on this node"
                .to_string(),
        ));
    }
    Ok(rendezvous_urls)
}

fn build_bootstrap_claim_rendezvous_client(
    state: &ServerState,
    rendezvous_url: &str,
) -> std::result::Result<RendezvousControlClient, (StatusCode, String)> {
    let trust_material = load_live_trust_material(state).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load rendezvous trust material: {err}"),
        )
    })?;
    let rendezvous_client_identity_pem = state
        .internal_tls_runtime
        .as_ref()
        .map(|tls| build_identity_pem_from_paths(&tls.cert_path, &tls.key_path))
        .transpose()
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to load rendezvous client identity: {err}"),
            )
        })?;
    let rendezvous_url = canonicalize_rendezvous_url(rendezvous_url).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid rendezvous URL: {err}"),
        )
    })?;

    RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url],
            heartbeat_interval_secs: state.peer_heartbeat_config.interval_secs.max(5),
        },
        trust_material
            .rendezvous_ca_pem
            .as_deref()
            .or(trust_material.public_ca_pem.as_deref())
            .or(trust_material.cluster_ca_pem.as_deref()),
        rendezvous_client_identity_pem.as_deref(),
    )
    .map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build rendezvous client for bootstrap claim issuance: {err}"),
        )
    })
}

fn map_bootstrap_claim_rendezvous_error(error: String) -> (StatusCode, String) {
    (
        StatusCode::BAD_GATEWAY,
        format!(
            "failed selecting a reachable rendezvous service for bootstrap claim redemption: {error}"
        ),
    )
}

async fn select_bootstrap_claim_rendezvous_urls(
    state: &ServerState,
    bootstrap: &TransportClientBootstrap,
    preferred_rendezvous_url: Option<&str>,
) -> std::result::Result<Vec<String>, (StatusCode, String)> {
    let candidate_urls =
        resolve_bootstrap_claim_rendezvous_candidates(state, bootstrap, preferred_rendezvous_url)
            .await?;
    let registered_urls = connected_rendezvous_registration_urls(state, &candidate_urls).await;
    let preferred_rendezvous_selected = preferred_rendezvous_url
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let mut healthy_urls = Vec::new();
    let mut last_error = None;

    for rendezvous_url in candidate_urls {
        let rendezvous = build_bootstrap_claim_rendezvous_client(state, &rendezvous_url)?;
        let normalized_rendezvous_url = rendezvous_url.trim_end_matches('/');
        match rendezvous.probe_health_endpoints().await {
            Ok(runtime) => {
                if runtime.endpoint_statuses.iter().any(|status| {
                    status.url == normalized_rendezvous_url
                        && status.status
                            == transport_sdk::RendezvousEndpointConnectionState::Connected
                }) {
                    healthy_urls.push(rendezvous_url);
                    continue;
                }
                let message =
                    format!("rendezvous endpoint is not currently reachable: {rendezvous_url}");
                if preferred_rendezvous_selected {
                    return Err((StatusCode::BAD_GATEWAY, message));
                }
                last_error = Some(message);
            }
            Err(err) => {
                let error = err.to_string();
                if preferred_rendezvous_selected {
                    return Err(map_bootstrap_claim_rendezvous_error(error));
                }
                last_error = Some(error);
            }
        }
    }

    if healthy_urls.is_empty() {
        return Err(map_bootstrap_claim_rendezvous_error(
            last_error.unwrap_or_else(|| {
                "bootstrap claim issuance requires a reachable rendezvous service".to_string()
            }),
        ));
    }

    let primary_rendezvous_url = healthy_urls[0].clone();
    let mut ordered_rendezvous_urls = vec![primary_rendezvous_url.clone()];
    for rendezvous_url in registered_urls {
        if rendezvous_url != primary_rendezvous_url && healthy_urls.contains(&rendezvous_url) {
            ordered_rendezvous_urls.push(rendezvous_url);
        }
    }
    if ordered_rendezvous_urls.len() == 1 {
        for rendezvous_url in healthy_urls {
            if rendezvous_url != primary_rendezvous_url {
                ordered_rendezvous_urls.push(rendezvous_url);
            }
        }
    }

    Ok(ordered_rendezvous_urls)
}

async fn store_client_bootstrap_claim(
    state: &ServerState,
    bootstrap: &TransportClientBootstrap,
    expires_at_unix: u64,
    preferred_rendezvous_url: Option<&str>,
) -> std::result::Result<ClientBootstrapClaim, (StatusCode, String)> {
    let claim_rendezvous_urls =
        select_bootstrap_claim_rendezvous_urls(state, bootstrap, preferred_rendezvous_url).await?;
    let claim_token = generate_bootstrap_claim_token();
    let claim_trust = rendezvous_claim_trust_from_bootstrap(bootstrap).map_err(|status| {
        (
            status,
            "failed to build compact rendezvous trust material for the bootstrap claim".to_string(),
        )
    })?;
    let publish_request = ClientBootstrapClaimPublishRequest {
        cluster_id: state.cluster_id,
        issuer: PeerIdentity::Node(state.node_id),
        target_node_id: state.node_id,
        claim_secret_hash: hash_token(&claim_token),
        expires_at_unix,
        bootstrap: bootstrap.clone(),
    };
    state
        .bootstrap_claims
        .publish(publish_request)
        .await
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed storing bootstrap claim on issuing node: {err}"),
            )
        })?;
    let claim = ClientBootstrapClaim {
        version: CLIENT_BOOTSTRAP_CLAIM_VERSION,
        cluster_id: bootstrap.cluster_id,
        target_node_id: state.node_id,
        rendezvous_urls: claim_rendezvous_urls,
        trust: claim_trust,
        claim_token,
    };
    claim.validate().map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to validate generated bootstrap claim: {err}"),
        )
    })?;
    Ok(claim)
}

fn build_bootstrap_direct_endpoints(
    public_url: Option<&str>,
    internal_url: Option<&str>,
    _public_peer_api_enabled: bool,
    node_id: NodeId,
) -> Vec<BootstrapEndpoint> {
    let mut endpoints = Vec::new();

    if let Some(public_url) = public_url {
        endpoints.push(BootstrapEndpoint {
            url: public_url.to_string(),
            usage: Some(BootstrapEndpointUse::PublicApi),
            node_id: Some(node_id),
        });
    }

    if let Some(peer_url) = internal_url {
        endpoints.push(BootstrapEndpoint {
            url: peer_url.to_string(),
            usage: Some(BootstrapEndpointUse::PeerApi),
            node_id: Some(node_id),
        });
    }

    endpoints
}

fn default_public_url(bind_addr: &str, tls_enabled: bool) -> String {
    let scheme = if tls_enabled { "https" } else { "http" };
    format!("{scheme}://{bind_addr}")
}

fn default_internal_url(bind_addr: &str) -> String {
    format!("https://{bind_addr}")
}

fn node_bootstrap_issue_request_from_join_request(
    join_request: NodeJoinRequest,
) -> NodeBootstrapIssueRequest {
    NodeBootstrapIssueRequest {
        node_id: Some(join_request.node_id),
        mode: Some(join_request.mode),
        data_dir: Some(join_request.data_dir),
        bind_addr: Some(join_request.bind_addr),
        public_url: join_request.public_url,
        labels: Some(join_request.labels),
        public_tls: join_request.public_tls,
        public_ca_cert_path: join_request.public_ca_cert_path,
        public_peer_api_enabled: Some(join_request.public_peer_api_enabled),
        internal_bind_addr: join_request.internal_bind_addr,
        internal_url: join_request.internal_url,
        internal_tls: join_request.internal_tls,
        enrollment_issuer_url: None,
        tls_validity_secs: None,
        tls_renewal_window_secs: None,
    }
}

fn build_issued_node_bootstrap(
    state: &ServerState,
    request: NodeBootstrapIssueRequest,
    enrollment_issuer_url: Option<String>,
) -> std::result::Result<TransportNodeBootstrap, StatusCode> {
    let rendezvous_urls = bootstrap_rendezvous_urls(state)?;
    let mode = request.mode.unwrap_or(NodeBootstrapMode::Cluster);
    let node_id = request.node_id.unwrap_or_else(NodeId::new_v4);
    let bind_addr = request
        .bind_addr
        .unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let public_url = request
        .public_url
        .or_else(|| Some(default_public_url(&bind_addr, request.public_tls.is_some())));
    let internal_bind_addr = request
        .internal_bind_addr
        .or_else(|| Some("127.0.0.1:18080".to_string()));
    let internal_url = request
        .internal_url
        .or_else(|| internal_bind_addr.as_deref().map(default_internal_url));
    let _compat_public_peer_api_enabled = request.public_peer_api_enabled.unwrap_or(false);

    let bootstrap = TransportNodeBootstrap {
        version: 1,
        cluster_id: state.cluster_id,
        node_id,
        mode,
        data_dir: request
            .data_dir
            .unwrap_or_else(|| "./data/server-node".to_string()),
        bind_addr,
        public_url: public_url.clone(),
        labels: request.labels.unwrap_or_default(),
        public_tls: request.public_tls,
        public_ca_cert_path: request.public_ca_cert_path,
        public_peer_api_enabled: false,
        internal_bind_addr: internal_bind_addr.clone(),
        internal_url: internal_url.clone(),
        internal_tls: request.internal_tls,
        rendezvous_urls,
        rendezvous_mtls_required: state.rendezvous_mtls_required,
        direct_endpoints: build_bootstrap_direct_endpoints(
            public_url.as_deref(),
            internal_url.as_deref(),
            false,
            node_id,
        ),
        relay_mode: state.relay_mode,
        trust_roots: bootstrap_trust_roots(state)?,
        enrollment_issuer_url,
    };

    bootstrap.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(bootstrap)
}

fn build_internal_node_subject_alt_names(
    bootstrap: &TransportNodeBootstrap,
) -> Result<Vec<SanType>> {
    Ok(vec![
        SanType::URI(
            format!("urn:ironmesh:node:{}", bootstrap.node_id)
                .try_into()
                .context("invalid node identity URI SAN")?,
        ),
        SanType::URI(
            format!("urn:ironmesh:cluster:{}", bootstrap.cluster_id)
                .try_into()
                .context("invalid cluster identity URI SAN")?,
        ),
    ])
}

fn build_public_node_subject_alt_names(bootstrap: &TransportNodeBootstrap) -> Result<Vec<SanType>> {
    let mut subject_alt_names = Vec::new();
    let mut seen_dns = HashSet::new();
    let mut seen_ips = HashSet::new();

    if let Some(public_url) = bootstrap.public_url.as_deref() {
        let parsed =
            reqwest::Url::parse(public_url).with_context(|| format!("invalid {public_url}"))?;
        if let Some(host) = parsed.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if seen_ips.insert(ip) {
                    subject_alt_names.push(SanType::IpAddress(ip));
                }
            } else if seen_dns.insert(host.to_string()) {
                subject_alt_names.push(SanType::DnsName(
                    host.try_into().context("invalid public DNS SAN")?,
                ));
            }
        }
    }

    let socket_addr = bootstrap
        .bind_addr
        .parse::<SocketAddr>()
        .context("invalid node bootstrap bind_addr")?;
    let ip = socket_addr.ip();
    if !ip.is_unspecified() && seen_ips.insert(ip) {
        subject_alt_names.push(SanType::IpAddress(ip));
    }

    Ok(subject_alt_names)
}

fn extract_public_node_subject_alt_names_from_cert_pem(cert_pem: &str) -> Result<Vec<SanType>> {
    let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
        .context("failed parsing current public TLS certificate PEM")?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der.as_ref())
        .context("failed parsing current public TLS certificate")?;

    let mut subject_alt_names = Vec::new();
    let mut seen_dns = HashSet::new();
    let mut seen_ips = HashSet::new();

    for extension in parsed.extensions() {
        let parsed_extension = extension.parsed_extension();
        if let ParsedExtension::SubjectAlternativeName(san) = parsed_extension {
            for name in &san.general_names {
                match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => {
                        let dns_name = (*name).to_string();
                        if seen_dns.insert(dns_name.clone()) {
                            subject_alt_names.push(SanType::DnsName(
                                dns_name
                                    .try_into()
                                    .context("invalid current public TLS DNS SAN")?,
                            ));
                        }
                    }
                    x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                        let ip_addr = match bytes.len() {
                            4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                            16 => {
                                let mut octets = [0_u8; 16];
                                octets.copy_from_slice(bytes);
                                IpAddr::V6(Ipv6Addr::from(octets))
                            }
                            len => bail!("unsupported current public TLS IP SAN length {len}"),
                        };
                        if seen_ips.insert(ip_addr) {
                            subject_alt_names.push(SanType::IpAddress(ip_addr));
                        }
                    }
                    other => {
                        bail!("unsupported SAN type in current public TLS certificate: {other:?}");
                    }
                }
            }
        }
    }

    Ok(subject_alt_names)
}

fn issue_internal_node_tls_material_for_identity(
    state: &ServerState,
    cluster_id: ClusterId,
    node_id: NodeId,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<BootstrapMutualTlsMaterial, StatusCode> {
    let trust_material =
        load_live_trust_material(state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ca_cert_pem = trust_material
        .cluster_ca_pem
        .as_deref()
        .or(state.cluster_ca_pem.as_deref())
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let ca_key_pem = trust_material
        .internal_ca_key_pem
        .as_deref()
        .or(state.internal_ca_key_pem.as_deref())
        .ok_or(StatusCode::PRECONDITION_FAILED)?;

    let issuer_key =
        KeyPair::from_pem(ca_key_pem).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut params =
        CertificateParams::new(Vec::new()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("ironmesh-node-{node_id}"));
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.subject_alt_names = vec![
        SanType::URI(
            format!("urn:ironmesh:node:{node_id}")
                .try_into()
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        ),
        SanType::URI(
            format!("urn:ironmesh:cluster:{cluster_id}")
                .try_into()
                .map_err(|_| StatusCode::BAD_REQUEST)?,
        ),
    ];

    let key_pair = KeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert_pem = cert.pem();
    let metadata = build_tls_material_metadata(&cert_pem, policy)?;

    Ok(BootstrapMutualTlsMaterial {
        ca_cert_pem: ca_cert_pem.to_string(),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        metadata,
    })
}

fn issue_public_node_tls_material_with_subject_alt_names(
    state: &ServerState,
    node_id: NodeId,
    subject_alt_names: Vec<SanType>,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<BootstrapMutualTlsMaterial, StatusCode> {
    let trust_material =
        load_live_trust_material(state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let ca_cert_pem = trust_material
        .public_ca_pem
        .as_deref()
        .or(trust_material.cluster_ca_pem.as_deref())
        .or(state.public_ca_pem.as_deref())
        .or(state.cluster_ca_pem.as_deref())
        .ok_or(StatusCode::PRECONDITION_FAILED)?;
    let ca_key_pem = trust_material
        .public_ca_key_pem
        .as_deref()
        .or(trust_material.internal_ca_key_pem.as_deref())
        .or(state.public_ca_key_pem.as_deref())
        .or(state.internal_ca_key_pem.as_deref())
        .ok_or(StatusCode::PRECONDITION_FAILED)?;

    let issuer_key =
        KeyPair::from_pem(ca_key_pem).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let mut params =
        CertificateParams::new(Vec::new()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("ironmesh-public-{node_id}"));
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = subject_alt_names;

    let key_pair = KeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert_pem = cert.pem();
    let metadata = build_tls_material_metadata(&cert_pem, policy)?;

    Ok(BootstrapMutualTlsMaterial {
        ca_cert_pem: ca_cert_pem.to_string(),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        metadata,
    })
}

fn issue_internal_node_tls_material(
    state: &ServerState,
    bootstrap: &TransportNodeBootstrap,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<BootstrapMutualTlsMaterial, StatusCode> {
    if bootstrap.internal_tls.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
    issue_internal_node_tls_material_for_identity(
        state,
        bootstrap.cluster_id,
        bootstrap.node_id,
        policy,
    )
}

fn issue_public_node_tls_material(
    state: &ServerState,
    bootstrap: &TransportNodeBootstrap,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<Option<BootstrapMutualTlsMaterial>, StatusCode> {
    if bootstrap.public_tls.is_none() {
        return Ok(None);
    }
    let subject_alt_names =
        build_public_node_subject_alt_names(bootstrap).map_err(|_| StatusCode::BAD_REQUEST)?;
    issue_public_node_tls_material_with_subject_alt_names(
        state,
        bootstrap.node_id,
        subject_alt_names,
        policy,
    )
    .map(Some)
}

async fn issue_bootstrap_bundle(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<PairingTokenIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/bootstrap-bundles/issue";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "label": request.label,
            "expires_in_secs": request.expires_in_secs,
            "preferred_rendezvous_url": request.preferred_rendezvous_url,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let request_label = request.label.clone();
    let (bootstrap, expires_at_unix) = match issue_client_bootstrap_impl(&state, request).await {
        Ok(response) => response,
        Err((status, error)) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": error }),
            )
            .await;
            return (status, Json(json!({ "error": error }))).into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "label": request_label,
            "endpoint_count": bootstrap.direct_endpoints.len(),
            "expires_at_unix": expires_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(bootstrap)).into_response()
}

async fn issue_bootstrap_claim(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<PairingTokenIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/bootstrap-claims/issue";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "label": request.label,
            "expires_in_secs": request.expires_in_secs,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let request_label = request.label.clone();
    let preferred_rendezvous_url = request.preferred_rendezvous_url.clone();
    let (bootstrap_bundle, expires_at_unix) =
        match issue_client_bootstrap_impl(&state, request).await {
            Ok(response) => response,
            Err((status, error)) => {
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": error }),
                )
                .await;
                return (status, Json(json!({ "error": error }))).into_response();
            }
        };
    let bootstrap_claim = match store_client_bootstrap_claim(
        &state,
        &bootstrap_bundle,
        expires_at_unix,
        preferred_rendezvous_url.as_deref(),
    )
    .await
    {
        Ok(claim) => claim,
        Err((status, error)) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": error }),
            )
            .await;
            return (status, Json(json!({ "error": error }))).into_response();
        }
    };
    let response = ClientBootstrapClaimIssueResponse {
        bootstrap_bundle,
        bootstrap_claim,
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "label": request_label,
            "endpoint_count": response.bootstrap_bundle.direct_endpoints.len(),
            "expires_at_unix": expires_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn issue_node_bootstrap(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<NodeBootstrapIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/node-bootstraps/issue";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "node_id": request.node_id,
            "mode": request.mode,
            "data_dir": request.data_dir,
            "bind_addr": request.bind_addr,
            "public_url": request.public_url,
            "enrollment_issuer_url": request.enrollment_issuer_url,
            "tls_validity_secs": request.tls_validity_secs,
            "tls_renewal_window_secs": request.tls_renewal_window_secs,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let enrollment_issuer_url = request
        .enrollment_issuer_url
        .clone()
        .or(local_public_enrollment_issuer_url(&state).await);
    let bootstrap = match build_issued_node_bootstrap(&state, request, enrollment_issuer_url) {
        Ok(bootstrap) => bootstrap,
        Err(status) => {
            let err = "invalid node bootstrap request";
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err }),
            )
            .await;
            return (status, Json(json!({ "error": err }))).into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "node_id": bootstrap.node_id,
            "mode": bootstrap.mode,
            "direct_endpoint_count": bootstrap.direct_endpoints.len(),
            "rendezvous_url_count": bootstrap.rendezvous_urls.len(),
        }),
    )
    .await;

    (StatusCode::CREATED, Json(bootstrap)).into_response()
}

async fn issue_node_enrollment(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<NodeBootstrapIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/node-enrollments/issue";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "node_id": request.node_id,
            "mode": request.mode,
            "data_dir": request.data_dir,
            "bind_addr": request.bind_addr,
            "public_url": request.public_url,
            "enrollment_issuer_url": request.enrollment_issuer_url,
            "tls_validity_secs": request.tls_validity_secs,
            "tls_renewal_window_secs": request.tls_renewal_window_secs,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let tls_validity_secs = request.tls_validity_secs;
    let tls_renewal_window_secs = request.tls_renewal_window_secs;
    let enrollment_issuer_url = request
        .enrollment_issuer_url
        .clone()
        .or(local_public_enrollment_issuer_url(&state).await);
    let bootstrap = match build_issued_node_bootstrap(&state, request, enrollment_issuer_url) {
        Ok(bootstrap) => bootstrap,
        Err(status) => {
            let err = "invalid node enrollment request";
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err }),
            )
            .await;
            return (status, Json(json!({ "error": err }))).into_response();
        }
    };

    let issue_policy = match build_tls_issue_policy(tls_validity_secs, tls_renewal_window_secs) {
        Ok(policy) => policy,
        Err(status) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": "invalid TLS validity policy" }),
            )
            .await;
            return (
                status,
                Json(json!({ "error": "invalid TLS validity policy" })),
            )
                .into_response();
        }
    };

    let internal_tls_material = if bootstrap.internal_tls.is_some() {
        match issue_internal_node_tls_material(&state, &bootstrap, issue_policy) {
            Ok(material) => Some(material),
            Err(status) => {
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": "failed to issue internal node TLS material" }),
                )
                .await;
                return (
                    status,
                    Json(json!({ "error": "failed to issue internal node TLS material" })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let public_tls_material = match issue_public_node_tls_material(&state, &bootstrap, issue_policy)
    {
        Ok(material) => material,
        Err(status) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": "failed to issue public node TLS material" }),
            )
            .await;
            return (
                status,
                Json(json!({ "error": "failed to issue public node TLS material" })),
            )
                .into_response();
        }
    };

    let package = NodeEnrollmentPackage {
        bootstrap,
        public_tls_material,
        internal_tls_material,
    };

    if let Err(err) = package.validate() {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "node_id": package.bootstrap.node_id,
            "mode": package.bootstrap.mode,
            "includes_public_tls_material": package.public_tls_material.is_some(),
            "public_tls_expires_at_unix": package
                .public_tls_material
                .as_ref()
                .map(|material| material.metadata.not_after_unix),
            "internal_tls_expires_at_unix": package
                .internal_tls_material
                .as_ref()
                .map(|material| material.metadata.not_after_unix),
        }),
    )
    .await;

    (StatusCode::CREATED, Json(package)).into_response()
}

async fn issue_node_enrollment_from_join_request(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<NodeJoinEnrollmentIssueRequest>,
) -> impl IntoResponse {
    let action = "auth/node-join-requests/issue-enrollment";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "node_id": request.join_request.node_id,
            "mode": request.join_request.mode,
            "data_dir": request.join_request.data_dir,
            "bind_addr": request.join_request.bind_addr,
            "public_url": request.join_request.public_url,
            "tls_validity_secs": request.tls_validity_secs,
            "tls_renewal_window_secs": request.tls_renewal_window_secs,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    if let Err(err) = request.join_request.validate() {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    let mut bootstrap_request =
        node_bootstrap_issue_request_from_join_request(request.join_request);
    bootstrap_request.tls_validity_secs = request.tls_validity_secs;
    bootstrap_request.tls_renewal_window_secs = request.tls_renewal_window_secs;

    let tls_validity_secs = bootstrap_request.tls_validity_secs;
    let tls_renewal_window_secs = bootstrap_request.tls_renewal_window_secs;
    let enrollment_issuer_url = local_public_enrollment_issuer_url(&state).await;
    let bootstrap =
        match build_issued_node_bootstrap(&state, bootstrap_request, enrollment_issuer_url) {
            Ok(bootstrap) => bootstrap,
            Err(status) => {
                let err = "invalid node join request";
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": err }),
                )
                .await;
                return (status, Json(json!({ "error": err }))).into_response();
            }
        };

    let issue_policy = match build_tls_issue_policy(tls_validity_secs, tls_renewal_window_secs) {
        Ok(policy) => policy,
        Err(status) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": "invalid TLS validity policy" }),
            )
            .await;
            return (
                status,
                Json(json!({ "error": "invalid TLS validity policy" })),
            )
                .into_response();
        }
    };

    let internal_tls_material = if bootstrap.internal_tls.is_some() {
        match issue_internal_node_tls_material(&state, &bootstrap, issue_policy) {
            Ok(material) => Some(material),
            Err(status) => {
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": "failed to issue internal node TLS material" }),
                )
                .await;
                return (
                    status,
                    Json(json!({ "error": "failed to issue internal node TLS material" })),
                )
                    .into_response();
            }
        }
    } else {
        None
    };
    let public_tls_material = match issue_public_node_tls_material(&state, &bootstrap, issue_policy)
    {
        Ok(material) => material,
        Err(status) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": "failed to issue public node TLS material" }),
            )
            .await;
            return (
                status,
                Json(json!({ "error": "failed to issue public node TLS material" })),
            )
                .into_response();
        }
    };

    let package = NodeEnrollmentPackage {
        bootstrap,
        public_tls_material,
        internal_tls_material,
    };

    if let Err(err) = package.validate() {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "node_id": package.bootstrap.node_id,
            "mode": package.bootstrap.mode,
            "includes_public_tls_material": package.public_tls_material.is_some(),
            "public_tls_expires_at_unix": package
                .public_tls_material
                .as_ref()
                .map(|material| material.metadata.not_after_unix),
            "internal_tls_expires_at_unix": package
                .internal_tls_material
                .as_ref()
                .map(|material| material.metadata.not_after_unix),
        }),
    )
    .await;

    (StatusCode::CREATED, Json(package)).into_response()
}

async fn export_managed_signer_backup_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedSignerBackupExportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-signer/backup/export";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let trust_material =
        match load_live_trust_material(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(material) => material,
            Err(status) => return status.into_response(),
        };
    let Some(ca_cert_pem) = trust_material
        .cluster_ca_pem
        .as_deref()
        .or(state.cluster_ca_pem.as_deref())
        .or(trust_material.public_ca_pem.as_deref())
        .or(state.public_ca_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA certificate is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA certificate is not available on this node" })),
        )
            .into_response();
    };
    let Some(ca_key_pem) = trust_material
        .internal_ca_key_pem
        .as_deref()
        .or(state.internal_ca_key_pem.as_deref())
        .or(trust_material.public_ca_key_pem.as_deref())
        .or(state.public_ca_key_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA private key is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA private key is not available on this node" })),
        )
            .into_response();
    };

    let backup = match export_managed_signer_backup(
        state.cluster_id,
        state.node_id,
        ca_cert_pem,
        ca_key_pem,
        &request.passphrase,
    ) {
        Ok(backup) => backup,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "cluster_id": backup.cluster_id,
            "source_node_id": backup.source_node_id,
            "exported_at_unix": backup.exported_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(backup)).into_response()
}

async fn import_managed_signer_backup_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedSignerBackupImportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-signer/backup/import";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "cluster_id": request.backup.cluster_id,
            "source_node_id": request.backup.source_node_id,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    if request.backup.cluster_id != state.cluster_id {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer backup belongs to a different cluster" }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "managed signer backup belongs to a different cluster" })),
        )
            .into_response();
    }

    if let Err(err) = import_managed_signer_backup(
        &state.data_dir,
        &request.backup,
        &request.passphrase,
        Some(state.cluster_id),
    ) {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "cluster_id": request.backup.cluster_id,
            "source_node_id": request.backup.source_node_id,
            "restart_required": true,
        }),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(ManagedSignerBackupImportResponse {
            status: "imported".to_string(),
            cluster_id: state.cluster_id,
            source_node_id: request.backup.source_node_id,
            restart_required: true,
            signer_ca_cert_path: managed_signer_ca_cert_path(&state.data_dir)
                .display()
                .to_string(),
        }),
    )
        .into_response()
}

async fn export_managed_rendezvous_failover_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedRendezvousFailoverExportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-rendezvous/failover/export";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "target_node_id": request.target_node_id,
            "public_url": request.public_url,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let public_url = request
        .public_url
        .clone()
        .or_else(|| current_rendezvous_urls(&state).first().cloned());
    let Some(public_url) = public_url else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "no managed rendezvous URL is configured on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "no managed rendezvous URL is configured on this node" })),
        )
            .into_response();
    };

    let trust_material =
        match load_live_trust_material(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(material) => material,
            Err(status) => return status.into_response(),
        };
    let Some(ca_cert_pem) = trust_material
        .cluster_ca_pem
        .as_deref()
        .or(state.cluster_ca_pem.as_deref())
        .or(trust_material.public_ca_pem.as_deref())
        .or(state.public_ca_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA certificate is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA certificate is not available on this node" })),
        )
            .into_response();
    };
    let Some(ca_key_pem) = trust_material
        .internal_ca_key_pem
        .as_deref()
        .or(state.internal_ca_key_pem.as_deref())
        .or(trust_material.public_ca_key_pem.as_deref())
        .or(state.public_ca_key_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA private key is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA private key is not available on this node" })),
        )
            .into_response();
    };

    let (cert_pem, key_pem) = match issue_managed_rendezvous_tls_identity_from_ca(
        state.cluster_id,
        &public_url,
        ca_cert_pem,
        ca_key_pem,
    ) {
        Ok(material) => material,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let package = match export_managed_rendezvous_failover_package(
        state.cluster_id,
        state.node_id,
        request.target_node_id,
        &public_url,
        ca_cert_pem,
        &cert_pem,
        &key_pem,
        &request.passphrase,
    ) {
        Ok(package) => package,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "target_node_id": package.target_node_id,
            "public_url": package.public_url,
            "exported_at_unix": package.exported_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(package)).into_response()
}

async fn import_managed_rendezvous_failover_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedRendezvousFailoverImportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-rendezvous/failover/import";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "cluster_id": request.package.cluster_id,
            "source_node_id": request.package.source_node_id,
            "target_node_id": request.package.target_node_id,
            "public_url": request.package.public_url,
            "bind_addr": request.bind_addr,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    if request.package.cluster_id != state.cluster_id {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed rendezvous failover package belongs to a different cluster" }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "managed rendezvous failover package belongs to a different cluster" })),
        )
            .into_response();
    }
    if request.package.target_node_id != state.node_id {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed rendezvous failover package targets a different node" }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({ "error": "managed rendezvous failover package targets a different node" }),
            ),
        )
            .into_response();
    }

    let bind_addr = match request.bind_addr.as_deref() {
        Some(raw) => match raw.parse::<SocketAddr>() {
            Ok(parsed) => parsed,
            Err(_) => {
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": "invalid managed rendezvous bind_addr" }),
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid managed rendezvous bind_addr" })),
                )
                    .into_response();
            }
        },
        None => {
            let port = match reqwest::Url::parse(&request.package.public_url)
                .ok()
                .and_then(|url| url.port_or_known_default())
            {
                Some(port) => port,
                None => {
                    append_admin_audit(
                        &state,
                        action,
                        &authz,
                        true,
                        true,
                        true,
                        "error",
                        json!({ "error": "managed rendezvous public URL must include a valid port" }),
                    )
                    .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "managed rendezvous public URL must include a valid port" })),
                    )
                        .into_response();
                }
            };
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port)
        }
    };

    if let Err(err) = import_managed_rendezvous_failover_package(
        &state.data_dir,
        &request.package,
        &request.passphrase,
        bind_addr,
        Some(state.cluster_id),
        Some(state.node_id),
    ) {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "source_node_id": request.package.source_node_id,
            "target_node_id": request.package.target_node_id,
            "public_url": request.package.public_url,
            "restart_required": true,
        }),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(ManagedRendezvousFailoverImportResponse {
            status: "imported".to_string(),
            cluster_id: state.cluster_id,
            source_node_id: request.package.source_node_id,
            target_node_id: request.package.target_node_id,
            public_url: request.package.public_url,
            restart_required: true,
            cert_path: managed_rendezvous_cert_path(&state.data_dir)
                .display()
                .to_string(),
            key_path: managed_rendezvous_key_path(&state.data_dir)
                .display()
                .to_string(),
        }),
    )
        .into_response()
}

async fn export_managed_control_plane_promotion_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedControlPlanePromotionExportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-control-plane/promotion/export";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "target_node_id": request.target_node_id,
            "public_url": request.public_url,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let public_url = request
        .public_url
        .clone()
        .or_else(|| current_rendezvous_urls(&state).first().cloned());
    let Some(public_url) = public_url else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "no managed rendezvous URL is configured on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "no managed rendezvous URL is configured on this node" })),
        )
            .into_response();
    };

    let trust_material =
        match load_live_trust_material(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR) {
            Ok(material) => material,
            Err(status) => return status.into_response(),
        };
    let Some(ca_cert_pem) = trust_material
        .cluster_ca_pem
        .as_deref()
        .or(state.cluster_ca_pem.as_deref())
        .or(trust_material.public_ca_pem.as_deref())
        .or(state.public_ca_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA certificate is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA certificate is not available on this node" })),
        )
            .into_response();
    };
    let Some(ca_key_pem) = trust_material
        .internal_ca_key_pem
        .as_deref()
        .or(state.internal_ca_key_pem.as_deref())
        .or(trust_material.public_ca_key_pem.as_deref())
        .or(state.public_ca_key_pem.as_deref())
    else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed signer CA private key is not available on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "managed signer CA private key is not available on this node" })),
        )
            .into_response();
    };

    let signer_backup = match export_managed_signer_backup(
        state.cluster_id,
        state.node_id,
        ca_cert_pem,
        ca_key_pem,
        &request.passphrase,
    ) {
        Ok(backup) => backup,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let (cert_pem, key_pem) = match issue_managed_rendezvous_tls_identity_from_ca(
        state.cluster_id,
        &public_url,
        ca_cert_pem,
        ca_key_pem,
    ) {
        Ok(material) => material,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let rendezvous_failover = match export_managed_rendezvous_failover_package(
        state.cluster_id,
        state.node_id,
        request.target_node_id,
        &public_url,
        ca_cert_pem,
        &cert_pem,
        &key_pem,
        &request.passphrase,
    ) {
        Ok(package) => package,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let package = ManagedControlPlanePromotionPackage {
        signer_backup,
        rendezvous_failover,
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "target_node_id": package.rendezvous_failover.target_node_id,
            "public_url": package.rendezvous_failover.public_url,
            "exported_at_unix": package.rendezvous_failover.exported_at_unix,
        }),
    )
    .await;

    (StatusCode::CREATED, Json(package)).into_response()
}

async fn import_managed_control_plane_promotion_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<ManagedControlPlanePromotionImportRequest>,
) -> impl IntoResponse {
    let action = "auth/managed-control-plane/promotion/import";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "cluster_id": request.package.rendezvous_failover.cluster_id,
            "source_node_id": request.package.rendezvous_failover.source_node_id,
            "target_node_id": request.package.rendezvous_failover.target_node_id,
            "public_url": request.package.rendezvous_failover.public_url,
            "bind_addr": request.bind_addr,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    if request.package.signer_backup.cluster_id != state.cluster_id
        || request.package.rendezvous_failover.cluster_id != state.cluster_id
    {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed control-plane promotion package belongs to a different cluster" }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "managed control-plane promotion package belongs to a different cluster" })),
        )
            .into_response();
    }
    if request.package.rendezvous_failover.target_node_id != state.node_id {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": "managed control-plane promotion package targets a different node" }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "managed control-plane promotion package targets a different node" })),
        )
            .into_response();
    }

    let bind_addr = match request.bind_addr.as_deref() {
        Some(raw) => match raw.parse::<SocketAddr>() {
            Ok(parsed) => parsed,
            Err(_) => {
                append_admin_audit(
                    &state,
                    action,
                    &authz,
                    true,
                    true,
                    true,
                    "error",
                    json!({ "error": "invalid managed rendezvous bind_addr" }),
                )
                .await;
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid managed rendezvous bind_addr" })),
                )
                    .into_response();
            }
        },
        None => {
            let port = match reqwest::Url::parse(&request.package.rendezvous_failover.public_url)
                .ok()
                .and_then(|url| url.port_or_known_default())
            {
                Some(port) => port,
                None => {
                    append_admin_audit(
                        &state,
                        action,
                        &authz,
                        true,
                        true,
                        true,
                        "error",
                        json!({ "error": "managed rendezvous public URL must include a valid port" }),
                    )
                    .await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": "managed rendezvous public URL must include a valid port" })),
                    )
                        .into_response();
                }
            };
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port)
        }
    };

    if let Err(err) = import_managed_signer_backup(
        &state.data_dir,
        &request.package.signer_backup,
        &request.passphrase,
        Some(state.cluster_id),
    ) {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    if let Err(err) = import_managed_rendezvous_failover_package(
        &state.data_dir,
        &request.package.rendezvous_failover,
        &request.passphrase,
        bind_addr,
        Some(state.cluster_id),
        Some(state.node_id),
    ) {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "error",
            json!({ "error": err.to_string() }),
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "source_node_id": request.package.rendezvous_failover.source_node_id,
            "target_node_id": request.package.rendezvous_failover.target_node_id,
            "public_url": request.package.rendezvous_failover.public_url,
            "restart_required": true,
        }),
    )
    .await;

    (
        StatusCode::CREATED,
        Json(ManagedControlPlanePromotionImportResponse {
            status: "imported".to_string(),
            cluster_id: state.cluster_id,
            source_node_id: request.package.rendezvous_failover.source_node_id,
            target_node_id: request.package.rendezvous_failover.target_node_id,
            public_url: request.package.rendezvous_failover.public_url.clone(),
            restart_required: true,
            signer_ca_cert_path: managed_signer_ca_cert_path(&state.data_dir)
                .display()
                .to_string(),
            rendezvous_cert_path: managed_rendezvous_cert_path(&state.data_dir)
                .display()
                .to_string(),
            rendezvous_key_path: managed_rendezvous_key_path(&state.data_dir)
                .display()
                .to_string(),
        }),
    )
        .into_response()
}

async fn renew_node_enrollment_authenticated(
    State(state): State<ServerState>,
    caller: InternalCaller,
    Json(request): Json<NodeEnrollmentRenewRequest>,
) -> impl IntoResponse {
    let error_response = |status: StatusCode, message: String| {
        (status, Json(json!({ "error": message }))).into_response()
    };

    if caller.cluster_id != state.cluster_id {
        return error_response(
            StatusCode::FORBIDDEN,
            "authenticated renewal caller does not belong to this cluster".to_string(),
        );
    }

    let renewal_authorized = {
        let cluster = state.cluster.lock().await;
        cluster
            .list_nodes()
            .into_iter()
            .any(|node| node.node_id == caller.node_id)
    };
    if !renewal_authorized {
        return error_response(
            StatusCode::FORBIDDEN,
            "authenticated node is not currently authorized to renew in cluster membership"
                .to_string(),
        );
    }

    let issue_policy = match build_tls_issue_policy(None, None) {
        Ok(policy) => policy,
        Err(status) => {
            return error_response(status, "invalid issuer TLS validity policy".to_string());
        }
    };

    let previous_public_fingerprint = request
        .current_public_tls_cert_pem
        .as_deref()
        .and_then(|cert_pem| parse_certificate_details_from_pem(cert_pem).ok())
        .map(|details| details.certificate_fingerprint);

    let internal_tls_material = match issue_internal_node_tls_material_for_identity(
        &state,
        state.cluster_id,
        caller.node_id,
        issue_policy,
    ) {
        Ok(material) => material,
        Err(status) => {
            return error_response(
                status,
                "failed to renew internal node TLS material".to_string(),
            );
        }
    };

    let public_tls_material = match request.current_public_tls_cert_pem.as_deref() {
        Some(cert_pem) => {
            let subject_alt_names =
                match extract_public_node_subject_alt_names_from_cert_pem(cert_pem) {
                    Ok(subject_alt_names) => subject_alt_names,
                    Err(err) => {
                        return error_response(StatusCode::BAD_REQUEST, err.to_string());
                    }
                };
            match issue_public_node_tls_material_with_subject_alt_names(
                &state,
                caller.node_id,
                subject_alt_names,
                issue_policy,
            ) {
                Ok(material) => Some(material),
                Err(status) => {
                    return error_response(
                        status,
                        "failed to renew public node TLS material".to_string(),
                    );
                }
            }
        }
        None => None,
    };

    let trust_roots = match bootstrap_trust_roots(&state) {
        Ok(trust_roots) => trust_roots,
        Err(status) => {
            return error_response(status, "failed to resolve renewal trust roots".to_string());
        }
    };
    let response = NodeEnrollmentRenewResponse {
        cluster_id: state.cluster_id,
        node_id: caller.node_id,
        trust_roots,
        enrollment_issuer_url: local_public_enrollment_issuer_url(&state).await,
        public_tls_material,
        internal_tls_material,
    };

    info!(
        node_id = %caller.node_id,
        previous_public_certificate_fingerprint = ?previous_public_fingerprint,
        new_public_certificate_fingerprint = ?response
            .public_tls_material
            .as_ref()
            .map(|material| material.metadata.certificate_fingerprint.clone()),
        new_internal_certificate_fingerprint = %response
            .internal_tls_material
            .metadata
            .certificate_fingerprint,
        "renewed node enrollment via internal mTLS authentication"
    );

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn issue_pairing_token_impl(
    state: &ServerState,
    request: PairingTokenIssueRequest,
) -> std::result::Result<PairingTokenIssueResponse, (StatusCode, String)> {
    ensure_client_enrollment_issuance_available(state)?;

    let now = unix_ts();
    let expires_in_secs = request
        .expires_in_secs
        .unwrap_or(15 * 60)
        .clamp(60, 24 * 60 * 60);
    let pairing_token = generate_pairing_token();
    let record = PairingAuthorizationRecord {
        token_id: Uuid::now_v7().to_string(),
        pairing_secret_hash: hash_token(&pairing_token),
        label: request.label.clone(),
        created_at_unix: now,
        expires_at_unix: now + expires_in_secs,
        used_at_unix: None,
        consumed_by_device_id: None,
    };

    {
        let mut auth_state = state.client_credentials.lock().await;
        auth_state
            .pairing_authorizations
            .retain(|token| token.used_at_unix.is_none() && token.expires_at_unix > now);
        auth_state.pairing_authorizations.push(record.clone());
    }

    if let Err(err) = persist_client_credential_state(state).await {
        warn!(
            error = %err,
            "failed to persist client credential state after pairing token issue"
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to persist client credential state after pairing token issue".to_string(),
        ));
    }

    Ok(PairingTokenIssueResponse {
        token_id: record.token_id,
        pairing_token,
        label: record.label,
        created_at_unix: record.created_at_unix,
        expires_at_unix: record.expires_at_unix,
    })
}

async fn enroll_client_device_impl(
    state: &ServerState,
    request: ClientEnrollmentRequest,
) -> std::result::Result<ClientDeviceEnrollResponse, StatusCode> {
    request.validate().map_err(|_| StatusCode::BAD_REQUEST)?;
    if request.cluster_id != state.cluster_id {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pairing_token = request.pairing_token.trim();
    let public_key_pem = request.public_key_pem.trim();
    if pairing_token.is_empty() || public_key_pem.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = unix_ts();
    let credential_expires_at_unix = Some(now + (30 * 24 * 60 * 60));
    let device_id = request
        .device_id
        .map(|value| value.to_string())
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    let provided_hash = hash_token(pairing_token);
    let label = request
        .label
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToString::to_string);
    let credential_pem = generate_client_credential_pem(
        state.cluster_id,
        device_id.as_str(),
        public_key_pem,
        now,
        credential_expires_at_unix,
    );
    let rendezvous_client_identity_pem = match issue_client_rendezvous_identity_pem(
        state,
        device_id.as_str(),
        credential_expires_at_unix,
    ) {
        Ok(identity) => identity,
        Err(err) => {
            warn!(
                error = %err,
                device_id = %device_id,
                "failed to issue rendezvous client identity during device enrollment"
            );
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let response: std::result::Result<ClientDeviceEnrollResponse, StatusCode> = {
        let mut auth_state = state.client_credentials.lock().await;
        auth_state
            .pairing_authorizations
            .retain(|token| token.used_at_unix.is_none() && token.expires_at_unix > now);

        if auth_state
            .credentials
            .iter()
            .any(|device| device.device_id == device_id && device.revoked_at_unix.is_none())
        {
            return Err(StatusCode::CONFLICT);
        }

        let Some(pairing_auth) = auth_state.pairing_authorizations.iter_mut().find(|token| {
            token.used_at_unix.is_none()
                && token.expires_at_unix > now
                && token_matches(
                    token.pairing_secret_hash.as_str(),
                    Some(provided_hash.as_str()),
                )
        }) else {
            return Err(StatusCode::UNAUTHORIZED);
        };

        pairing_auth.used_at_unix = Some(now);
        pairing_auth.consumed_by_device_id = Some(device_id.clone());

        let final_label = label.or_else(|| pairing_auth.label.clone());
        let public_key_fingerprint = text_fingerprint(public_key_pem);
        let credential_fingerprint = match credential_fingerprint(&credential_pem) {
            Ok(fingerprint) => fingerprint,
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };
        let device = ClientCredentialRecord {
            device_id: device_id.clone(),
            label: final_label.clone(),
            public_key_pem: Some(public_key_pem.to_string()),
            public_key_fingerprint: Some(public_key_fingerprint),
            issued_credential_pem: Some(credential_pem.clone()),
            credential_fingerprint: Some(credential_fingerprint),
            created_at_unix: now,
            revocation_reason: None,
            revoked_by_actor: None,
            revoked_by_source_node: None,
            revoked_at_unix: None,
        };
        auth_state.credentials.push(device);

        Ok(ClientDeviceEnrollResponse {
            cluster_id: state.cluster_id,
            device_id,
            label: final_label,
            public_key_pem: public_key_pem.to_string(),
            credential_pem,
            rendezvous_client_identity_pem,
            created_at_unix: now,
            expires_at_unix: credential_expires_at_unix,
        })
    };

    let response = response?;

    if let Err(err) = persist_client_credential_state(state).await {
        warn!(
            error = %err,
            "failed to persist client credential state after enrollment"
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(response)
}

async fn enroll_client_device(
    State(state): State<ServerState>,
    Json(request): Json<ClientDeviceEnrollRequest>,
) -> impl IntoResponse {
    let request = match request.into_transport_request() {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    match enroll_client_device_impl(&state, request).await {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
        Err(status) => status.into_response(),
    }
}

async fn redeem_client_bootstrap_claim(
    State(state): State<ServerState>,
    Json(request): Json<ClientBootstrapClaimRedeemRequest>,
) -> impl IntoResponse {
    if let Err(err) = request.validate() {
        return (StatusCode::BAD_REQUEST, err.to_string()).into_response();
    }
    if request.target_node_id != state.node_id {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "bootstrap claim target_node_id {} does not match node {}",
                request.target_node_id, state.node_id
            ),
        )
            .into_response();
    }

    let device_id = match request
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid device_id {value}"),
                )
            })
        })
        .transpose()
    {
        Ok(device_id) => device_id,
        Err((status, error)) => return (status, error).into_response(),
    };
    let label = request
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let claim_token = request.claim_token.clone();
    let claim = match state.bootstrap_claims.take_for_redeem(&claim_token).await {
        Ok(claim) => claim,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                "bootstrap claim is unavailable".to_string(),
            )
                .into_response();
        }
    };

    if claim.target_node_id != state.node_id {
        let claim_target_node_id = claim.target_node_id;
        state.bootstrap_claims.restore(&claim_token, claim).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "bootstrap claim target node {} does not match node {}",
                claim_target_node_id, state.node_id
            ),
        )
            .into_response();
    }

    let pairing_token = match claim
        .bootstrap
        .pairing_token
        .clone()
        .filter(|value| !value.trim().is_empty())
    {
        Some(pairing_token) => pairing_token,
        None => {
            state.bootstrap_claims.restore(&claim_token, claim).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bootstrap claim is missing a pairing token".to_string(),
            )
                .into_response();
        }
    };
    let enroll_request = ClientEnrollmentRequest {
        cluster_id: claim.bootstrap.cluster_id,
        pairing_token,
        device_id,
        label,
        public_key_pem: request.public_key_pem.clone(),
    };

    match enroll_client_device_impl(&state, enroll_request).await {
        Ok(enrolled) => {
            let mut bootstrap = claim.bootstrap.clone();
            bootstrap.pairing_token = None;
            bootstrap.device_id = enrolled.device_id.parse().ok();
            bootstrap.device_label = enrolled.label.clone();

            let response = ClientBootstrapClaimRedeemResponse {
                bootstrap,
                cluster_id: enrolled.cluster_id,
                device_id: enrolled.device_id,
                label: enrolled.label,
                public_key_pem: enrolled.public_key_pem,
                credential_pem: enrolled.credential_pem,
                rendezvous_client_identity_pem: enrolled.rendezvous_client_identity_pem,
                created_at_unix: Some(enrolled.created_at_unix),
                expires_at_unix: enrolled.expires_at_unix,
            };
            if let Err(err) = response.validate() {
                state.bootstrap_claims.restore(&claim_token, claim).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response();
            }

            ([(header::CACHE_CONTROL, "no-store")], Json(response)).into_response()
        }
        Err(status) => {
            if status.is_server_error() {
                state.bootstrap_claims.restore(&claim_token, claim).await;
            }
            status.into_response()
        }
    }
}

async fn list_client_credentials(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/client-credentials/list";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let credentials = {
        let auth_state = state.client_credentials.lock().await;
        auth_state
            .credentials
            .iter()
            .map(|credential| ClientCredentialView {
                device_id: credential.device_id.clone(),
                label: credential.label.clone(),
                public_key_fingerprint: credential
                    .public_key_fingerprint
                    .clone()
                    .or_else(|| credential.public_key_pem.as_deref().map(text_fingerprint)),
                credential_fingerprint: credential.credential_fingerprint.clone().or_else(|| {
                    credential
                        .issued_credential_pem
                        .as_deref()
                        .and_then(|pem| credential_fingerprint(pem).ok())
                }),
                created_at_unix: credential.created_at_unix,
                revocation_reason: credential.revocation_reason.clone(),
                revoked_by_actor: credential.revoked_by_actor.clone(),
                revoked_by_source_node: credential.revoked_by_source_node.clone(),
                revoked_at_unix: credential.revoked_at_unix,
            })
            .collect::<Vec<_>>()
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({ "credentials": credentials.len() }),
    )
    .await;

    (StatusCode::OK, Json(credentials)).into_response()
}

fn rendezvous_config_persistence_source(state: &ServerState) -> RendezvousConfigPersistenceSource {
    if state.node_enrollment_path.is_some() {
        RendezvousConfigPersistenceSource::NodeEnrollment
    } else {
        RendezvousConfigPersistenceSource::RuntimeOnly
    }
}

async fn build_rendezvous_config_view(
    state: &ServerState,
    persisted: bool,
) -> RendezvousConfigView {
    let effective_urls = normalize_rendezvous_url_list(&current_rendezvous_urls(state))
        .unwrap_or_else(|_| current_rendezvous_urls(state));
    RendezvousConfigView {
        effective_urls,
        editable_urls: current_editable_rendezvous_urls(state),
        managed_embedded_url: state.managed_rendezvous_public_url.clone(),
        registration_enabled: state.rendezvous_registration_enabled,
        registration_interval_secs: state.peer_heartbeat_config.interval_secs.max(5),
        disconnected_retry_interval_secs: RENDEZVOUS_REGISTRATION_RETRY_INTERVAL_SECS,
        endpoint_registrations: rendezvous_registration_views(state).await,
        mtls_required: state.rendezvous_mtls_required,
        persistence_source: rendezvous_config_persistence_source(state),
        persisted,
    }
}

fn canonicalize_rendezvous_url(value: &str) -> Result<String> {
    let trimmed = value.trim();
    let parsed = reqwest::Url::parse(trimmed)
        .with_context(|| format!("invalid rendezvous URL {trimmed:?}"))?;
    Ok(parsed.to_string())
}

fn normalize_rendezvous_url_list(values: &[String]) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let canonical = canonicalize_rendezvous_url(trimmed)?;
        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }

    Ok(normalized)
}

fn build_effective_rendezvous_urls(
    state: &ServerState,
    editable_urls: &[String],
) -> Result<Vec<String>> {
    let mut effective_urls = Vec::new();
    let mut seen = HashSet::new();

    if let Some(managed_url) = state.managed_rendezvous_public_url.as_deref() {
        let canonical = canonicalize_rendezvous_url(managed_url)?;
        seen.insert(canonical.clone());
        effective_urls.push(canonical);
    }

    for url in normalize_rendezvous_url_list(editable_urls)? {
        if seen.insert(url.clone()) {
            effective_urls.push(url);
        }
    }

    Ok(effective_urls)
}

fn persist_rendezvous_urls_if_possible(
    state: &ServerState,
    effective_urls: &[String],
) -> Result<bool> {
    let Some(path) = state.node_enrollment_path.as_ref() else {
        return Ok(false);
    };

    let mut package = NodeEnrollmentPackage::from_path(path)?;
    package.bootstrap.rendezvous_urls = effective_urls.to_vec();
    package.write_to_path(path)?;
    Ok(true)
}

async fn get_rendezvous_config(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/rendezvous-config/get";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let view = build_rendezvous_config_view(&state, state.node_enrollment_path.is_some()).await;
    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "effective_urls": view.effective_urls.len(),
            "editable_urls": view.editable_urls.len(),
            "persistence_source": view.persistence_source,
        }),
    )
    .await;

    (StatusCode::OK, Json(view)).into_response()
}

async fn update_rendezvous_config(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<UpdateRendezvousConfigRequest>,
) -> impl IntoResponse {
    let action = "auth/rendezvous-config/update";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "editable_urls": request.editable_urls }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let effective_urls = match build_effective_rendezvous_urls(&state, &request.editable_urls) {
        Ok(urls) => urls,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let outbound_clients = match build_outbound_clients_with_urls(&state, &effective_urls) {
        Ok(clients) => clients,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let persisted = match persist_rendezvous_urls_if_possible(&state, &effective_urls) {
        Ok(persisted) => persisted,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    replace_rendezvous_urls(&state, effective_urls);
    replace_outbound_clients(&state, outbound_clients).await;
    sync_rendezvous_registration_state(&state).await;
    let view = build_rendezvous_config_view(&state, persisted).await;

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "effective_urls": view.effective_urls,
            "editable_urls": view.editable_urls,
            "persistence_source": view.persistence_source,
            "persisted": view.persisted,
        }),
    )
    .await;

    (StatusCode::OK, Json(view)).into_response()
}

async fn revoke_client_credential(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Query(query): Query<RevokeClientCredentialQuery>,
) -> impl IntoResponse {
    let reason = match query
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(reason) if reason.len() > 256 => return StatusCode::BAD_REQUEST.into_response(),
        Some(reason) => Some(reason.to_string()),
        None => None,
    };
    let action = "auth/client-credentials/revoke";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "device_id": device_id, "reason": reason }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let now = unix_ts();
    let revoked = {
        let mut auth_state = state.client_credentials.lock().await;
        let Some(device) = auth_state
            .credentials
            .iter_mut()
            .find(|device| device.device_id == device_id && device.revoked_at_unix.is_none())
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        device.revoked_at_unix = Some(now);
        device.revocation_reason = reason.clone();
        device.revoked_by_actor = authz.actor.clone();
        device.revoked_by_source_node = authz.source_node.clone();
        true
    };

    if revoked && let Err(err) = persist_client_credential_state(&state).await {
        warn!(
            error = %err,
            "failed to persist client credential state after client credential revocation"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({ "device_id": device_id, "reason": reason }),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

async fn cluster_status(State(state): State<ServerState>) -> Json<cluster::ClusterSummary> {
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.summary())
}

async fn list_nodes(State(state): State<ServerState>) -> Json<Vec<NodeDescriptor>> {
    refresh_local_node_storage(&state).await;
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.list_nodes())
}

async fn storage_stats_current(State(state): State<ServerState>) -> impl IntoResponse {
    let sample = {
        let store = read_store(&state, "storage_stats.load_current").await;
        match store.load_current_storage_stats().await {
            Ok(sample) => sample,
            Err(err) => {
                tracing::error!(error = %err, "failed loading current storage stats");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let runtime = state.storage_stats_runtime.lock().await.clone();
    (
        StatusCode::OK,
        Json(StorageStatsCurrentResponse {
            sample,
            collecting: runtime.collecting,
            last_attempt_unix: runtime.last_attempt_unix,
            last_success_unix: runtime.last_success_unix,
            last_error: runtime.last_error,
        }),
    )
        .into_response()
}

async fn storage_stats_history(
    State(state): State<ServerState>,
    Query(query): Query<StorageStatsHistoryQuery>,
) -> impl IntoResponse {
    let limit = query
        .limit
        .map(|limit| limit.clamp(1, MAX_STORAGE_STATS_HISTORY_LIMIT))
        .or_else(|| {
            if query.since_unix.is_none() && query.max_points.is_none() {
                Some(120)
            } else {
                None
            }
        });
    let max_points = query
        .max_points
        .map(|max_points| max_points.clamp(2, MAX_STORAGE_STATS_HISTORY_POINTS));
    let samples = {
        let store = read_store(&state, "storage_stats.load_history").await;
        match store
            .list_storage_stats_history(limit, query.since_unix)
            .await
        {
            Ok(samples) => samples,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    ?limit,
                    since_unix = query.since_unix,
                    ?max_points,
                    "failed loading storage stats history"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let samples = downsample_storage_stats_samples(samples, max_points);

    (StatusCode::OK, Json(samples)).into_response()
}

fn resolved_data_scrub_history_limit(
    limit: Option<usize>,
    since_unix: Option<u64>,
) -> Option<usize> {
    limit
        .map(|limit| limit.clamp(1, MAX_DATA_SCRUB_HISTORY_LIMIT))
        .or_else(|| {
            if since_unix.is_none() {
                Some(120)
            } else {
                None
            }
        })
}

async fn load_data_scrub_history_runs(
    state: &ServerState,
    limit: Option<usize>,
    since_unix: Option<u64>,
) -> Result<Vec<DataScrubRunRecord>> {
    let store = read_store(state, "data_scrub.load_history").await;
    store.list_data_scrub_run_history(limit, since_unix).await
}

async fn local_data_scrub_activity_payload(
    state: &ServerState,
) -> Result<DataScrubActivityStatusResponse> {
    let latest_run = latest_data_scrub_run_record(state).await?;
    let active_runs = state.data_scrub_activity.lock().await.active_runs.clone();
    Ok(DataScrubActivityStatusResponse {
        state: current_data_scrub_activity_state(&active_runs),
        enabled: state.data_scrub_enabled,
        interval_secs: state.data_scrub_interval_secs,
        retention_secs: state.data_scrub_history_retention_secs,
        active_runs,
        latest_run,
    })
}

async fn local_data_scrub_history_payload(
    state: &ServerState,
    limit: Option<usize>,
    since_unix: Option<u64>,
) -> Result<DataScrubHistoryResponse> {
    let runs = load_data_scrub_history_runs(state, limit, since_unix).await?;
    Ok(DataScrubHistoryResponse {
        retention_secs: state.data_scrub_history_retention_secs,
        runs,
    })
}

fn build_data_scrub_history_path(limit: Option<usize>, since_unix: Option<u64>) -> String {
    let mut query = Vec::new();
    if let Some(limit) = limit {
        query.push(format!("limit={limit}"));
    }
    if let Some(since_unix) = since_unix {
        query.push(format!("since_unix={since_unix}"));
    }
    if query.is_empty() {
        "/cluster/scrub/history".to_string()
    } else {
        format!("/cluster/scrub/history?{}", query.join("&"))
    }
}

async fn data_scrub_activity_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/scrub/activity/get";
    if let Err(status) =
        authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        return status.into_response();
    }

    match local_data_scrub_activity_payload(&state).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed loading data scrub activity state");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn data_scrub_activity_status_internal(
    State(state): State<ServerState>,
) -> impl IntoResponse {
    match local_data_scrub_activity_payload(&state).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed loading internal data scrub activity state");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn data_scrub_history(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<DataScrubHistoryQuery>,
) -> impl IntoResponse {
    let action = "auth/scrub/history/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "limit": query.limit,
            "since_unix": query.since_unix,
        }),
    )
    .await
    {
        return status.into_response();
    }

    let limit = resolved_data_scrub_history_limit(query.limit, query.since_unix);
    match local_data_scrub_history_payload(&state, limit, query.since_unix).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::error!(
                error = %err,
                ?limit,
                since_unix = query.since_unix,
                "failed loading data scrub history"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn data_scrub_history_internal(
    State(state): State<ServerState>,
    Query(query): Query<DataScrubHistoryQuery>,
) -> impl IntoResponse {
    let limit = resolved_data_scrub_history_limit(query.limit, query.since_unix);
    match local_data_scrub_history_payload(&state, limit, query.since_unix).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => {
            tracing::error!(
                error = %err,
                ?limit,
                since_unix = query.since_unix,
                "failed loading internal data scrub history"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn data_scrub_cluster_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<DataScrubHistoryQuery>,
) -> impl IntoResponse {
    let action = "auth/scrub/cluster/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "limit": query.limit,
            "since_unix": query.since_unix,
        }),
    )
    .await
    {
        return status.into_response();
    }

    let limit = resolved_data_scrub_history_limit(query.limit, query.since_unix);
    let local_activity = match local_data_scrub_activity_payload(&state).await {
        Ok(activity) => activity,
        Err(err) => {
            tracing::error!(error = %err, "failed loading local data scrub cluster activity");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let local_history =
        match local_data_scrub_history_payload(&state, limit, query.since_unix).await {
            Ok(history) => history,
            Err(err) => {
                tracing::error!(error = %err, "failed loading local data scrub cluster history");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let mut nodes = vec![DataScrubClusterNodeStatus {
        node_id: state.node_id,
        state: local_activity.state,
        enabled: local_activity.enabled,
        interval_secs: local_activity.interval_secs,
        retention_secs: local_activity.retention_secs,
        active_runs: local_activity.active_runs,
        latest_run: local_activity.latest_run,
    }];
    let mut runs = local_history.runs;
    let mut skipped_nodes = Vec::new();

    let peers = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster
            .list_nodes()
            .into_iter()
            .filter(|node| {
                node.node_id != state.node_id && node.status == cluster::NodeStatus::Online
            })
            .collect::<Vec<_>>()
    };

    for peer in peers {
        let activity = match execute_peer_request(
            &state,
            &peer,
            reqwest::Method::GET,
            "/cluster/scrub/activity",
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<DataScrubActivityStatusResponse>() {
                    Ok(activity) => activity,
                    Err(err) => {
                        skipped_nodes.push(DataScrubClusterSkippedNode {
                            node_id: peer.node_id,
                            error: format!("failed decoding activity response: {err}"),
                        });
                        continue;
                    }
                }
            }
            Ok(response) => {
                skipped_nodes.push(DataScrubClusterSkippedNode {
                    node_id: peer.node_id,
                    error: format!("activity request returned HTTP {}", response.status),
                });
                continue;
            }
            Err(err) => {
                skipped_nodes.push(DataScrubClusterSkippedNode {
                    node_id: peer.node_id,
                    error: format!("activity request failed: {err:#}"),
                });
                continue;
            }
        };

        let history = match execute_peer_request(
            &state,
            &peer,
            reqwest::Method::GET,
            &build_data_scrub_history_path(limit, query.since_unix),
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<DataScrubHistoryResponse>() {
                    Ok(history) => history,
                    Err(err) => {
                        skipped_nodes.push(DataScrubClusterSkippedNode {
                            node_id: peer.node_id,
                            error: format!("failed decoding history response: {err}"),
                        });
                        DataScrubHistoryResponse {
                            retention_secs: activity.retention_secs,
                            runs: Vec::new(),
                        }
                    }
                }
            }
            Ok(response) => {
                skipped_nodes.push(DataScrubClusterSkippedNode {
                    node_id: peer.node_id,
                    error: format!("history request returned HTTP {}", response.status),
                });
                DataScrubHistoryResponse {
                    retention_secs: activity.retention_secs,
                    runs: Vec::new(),
                }
            }
            Err(err) => {
                skipped_nodes.push(DataScrubClusterSkippedNode {
                    node_id: peer.node_id,
                    error: format!("history request failed: {err:#}"),
                });
                DataScrubHistoryResponse {
                    retention_secs: activity.retention_secs,
                    runs: Vec::new(),
                }
            }
        };

        runs.extend(history.runs);
        nodes.push(DataScrubClusterNodeStatus {
            node_id: peer.node_id,
            state: activity.state,
            enabled: activity.enabled,
            interval_secs: activity.interval_secs,
            retention_secs: activity.retention_secs,
            active_runs: activity.active_runs,
            latest_run: activity.latest_run,
        });
    }

    nodes.sort_by_key(|node| node.node_id);
    runs.sort_by(|a, b| {
        b.finished_at_unix
            .cmp(&a.finished_at_unix)
            .then_with(|| b.run_id.cmp(&a.run_id))
    });
    skipped_nodes.sort_by_key(|node| node.node_id);

    (
        StatusCode::OK,
        Json(DataScrubClusterStatusResponse {
            nodes,
            skipped_nodes,
            runs,
        }),
    )
        .into_response()
}

async fn trigger_data_scrub_public(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<DataScrubTriggerQuery>,
) -> impl IntoResponse {
    let action = "auth/scrub/run";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "scope": query.scope }),
    )
    .await
    {
        return status.into_response();
    }

    let scope = query.scope.unwrap_or(DataScrubScope::Cluster);
    let mut node_results =
        vec![start_local_data_scrub(&state, DataScrubRunTrigger::ManualRequest).await];
    let mut failed_nodes = 0usize;

    if scope == DataScrubScope::Cluster {
        let peers = {
            let mut cluster = state.cluster.lock().await;
            cluster.update_health_and_detect_offline_transition();
            cluster
                .list_nodes()
                .into_iter()
                .filter(|node| {
                    node.node_id != state.node_id && node.status == cluster::NodeStatus::Online
                })
                .collect::<Vec<_>>()
        };

        for peer in peers {
            match execute_peer_request(
                &state,
                &peer,
                reqwest::Method::POST,
                "/cluster/scrub/run",
                Vec::new(),
                Vec::new(),
            )
            .await
            {
                Ok(response) if response.is_success() => match response
                    .json::<DataScrubTriggerNodeResult>()
                {
                    Ok(result) => node_results.push(result),
                    Err(err) => {
                        failed_nodes = failed_nodes.saturating_add(1);
                        node_results.push(DataScrubTriggerNodeResult {
                            node_id: peer.node_id,
                            started: false,
                            active_run: None,
                            error: Some(format!("failed decoding peer trigger response: {err}")),
                        });
                    }
                },
                Ok(response) => {
                    failed_nodes = failed_nodes.saturating_add(1);
                    node_results.push(DataScrubTriggerNodeResult {
                        node_id: peer.node_id,
                        started: false,
                        active_run: None,
                        error: Some(format!("peer trigger returned HTTP {}", response.status)),
                    });
                }
                Err(err) => {
                    failed_nodes = failed_nodes.saturating_add(1);
                    node_results.push(DataScrubTriggerNodeResult {
                        node_id: peer.node_id,
                        started: false,
                        active_run: None,
                        error: Some(format!("peer trigger failed: {err:#}")),
                    });
                }
            }
        }
    }

    (
        StatusCode::ACCEPTED,
        Json(DataScrubTriggerResponse {
            scope,
            nodes_contacted: node_results.len(),
            failed_nodes,
            node_results,
        }),
    )
        .into_response()
}

async fn trigger_data_scrub_peer(State(state): State<ServerState>) -> impl IntoResponse {
    let result = start_local_data_scrub(&state, DataScrubRunTrigger::PeerClusterRequest).await;
    (StatusCode::ACCEPTED, Json(result)).into_response()
}

async fn repair_activity_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/repair/activity/get";
    if let Err(status) =
        authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        return status.into_response();
    }

    let latest_run = match latest_repair_run_record(&state).await {
        Ok(latest_run) => latest_run,
        Err(err) => {
            tracing::error!(error = %err, "failed loading latest repair run record");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let startup_status = *state.startup_repair_status.lock().await;
    let active_runs = state.repair_activity.lock().await.active_runs.clone();
    let response = RepairActivityStatusResponse {
        state: current_repair_activity_state(&active_runs, startup_status),
        startup_status,
        active_runs,
        latest_run,
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn repair_history(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<RepairHistoryQuery>,
) -> impl IntoResponse {
    let action = "auth/repair/history/get";
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "limit": query.limit,
            "since_unix": query.since_unix,
        }),
    )
    .await
    {
        return status.into_response();
    }

    let limit = query
        .limit
        .map(|limit| limit.clamp(1, MAX_REPAIR_RUN_HISTORY_LIMIT))
        .or_else(|| {
            if query.since_unix.is_none() {
                Some(120)
            } else {
                None
            }
        });
    let runs = {
        let store = read_store(&state, "repair_run.load_history").await;
        match store.list_repair_run_history(limit, query.since_unix).await {
            Ok(runs) => runs,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    ?limit,
                    since_unix = query.since_unix,
                    "failed loading repair run history"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    (
        StatusCode::OK,
        Json(RepairHistoryResponse {
            retention_secs: state.repair_run_history_retention_secs,
            runs,
        }),
    )
        .into_response()
}

fn downsample_storage_stats_samples(
    samples: Vec<StorageStatsSample>,
    max_points: Option<usize>,
) -> Vec<StorageStatsSample> {
    let Some(max_points) = max_points else {
        return samples;
    };
    if samples.len() <= max_points || max_points < 2 {
        return samples;
    }

    let chronological = samples.into_iter().rev().collect::<Vec<_>>();
    let last_index = chronological.len() - 1;
    let mut selected = Vec::with_capacity(max_points);
    let mut previous_index = None;

    for step in 0..max_points {
        let position = step as f64 / (max_points - 1) as f64;
        let index = (position * last_index as f64).round() as usize;
        if Some(index) == previous_index {
            continue;
        }
        selected.push(chronological[index].clone());
        previous_index = Some(index);
    }

    if selected.first().map(|sample| sample.collected_at_unix)
        != chronological.first().map(|sample| sample.collected_at_unix)
        && let Some(first) = chronological.first()
    {
        selected.insert(0, first.clone());
    }
    if selected.last().map(|sample| sample.collected_at_unix)
        != chronological.last().map(|sample| sample.collected_at_unix)
        && let Some(last) = chronological.last()
    {
        selected.push(last.clone());
    }

    selected.reverse();
    selected
}

async fn local_public_enrollment_issuer_url(state: &ServerState) -> Option<String> {
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    cluster
        .list_nodes()
        .into_iter()
        .find(|node| node.node_id == state.node_id)
        .and_then(|node| {
            node.public_api_url()
                .map(|url| url.trim_end_matches('/').to_string())
        })
}

async fn apply_node_heartbeat(
    state: &ServerState,
    node_id: NodeId,
    request: NodeHeartbeatRequest,
) -> StatusCode {
    let mut cluster = state.cluster.lock().await;
    if cluster.touch_heartbeat(
        node_id,
        request.free_bytes,
        request.capacity_bytes,
        request.storage_stats,
        request.labels,
    ) {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn register_node(
    State(state): State<ServerState>,
    Path(node_id): Path<String>,
    Json(request): Json<RegisterNodeRequest>,
) -> impl IntoResponse {
    let node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    let reachability = NodeReachability {
        public_api_url: request
            .reachability
            .public_api_url
            .as_deref()
            .and_then(|value| normalize_optional_url(Some(value))),
        peer_api_url: request
            .reachability
            .peer_api_url
            .as_deref()
            .and_then(|value| normalize_optional_url(Some(value))),
        relay_required: request.reachability.relay_required,
    };
    let requested_capabilities = request.capabilities.unwrap_or_default();
    let capabilities = NodeCapabilities {
        public_api: requested_capabilities.public_api || reachability.public_api_url.is_some(),
        peer_api: requested_capabilities.peer_api || reachability.peer_api_url.is_some(),
        relay_tunnel: requested_capabilities.relay_tunnel || reachability.relay_required,
    };

    let mut cluster = state.cluster.lock().await;
    cluster.register_node(NodeDescriptor {
        node_id,
        reachability,
        capabilities,
        labels: request.labels,
        capacity_bytes: request.capacity_bytes.unwrap_or(0),
        free_bytes: request.free_bytes.unwrap_or(0),
        storage_stats: request.storage_stats,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    StatusCode::NO_CONTENT
}

async fn remove_node(
    State(state): State<ServerState>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    let node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    if node_id == state.node_id {
        return StatusCode::CONFLICT;
    }

    let removed = {
        let mut cluster = state.cluster.lock().await;
        cluster.remove_node(node_id)
    };

    if !removed {
        return StatusCode::NOT_FOUND;
    }

    if let Err(err) = persist_cluster_replicas_state(&state).await {
        warn!(
            error = %err,
            node_id = %node_id,
            "failed to persist cluster replicas after node removal"
        );
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::NO_CONTENT
}

async fn node_heartbeat(
    State(state): State<ServerState>,
    caller: InternalCaller,
    Path(node_id): Path<String>,
    Json(request): Json<NodeHeartbeatRequest>,
) -> impl IntoResponse {
    let node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    if caller.node_id != node_id {
        return StatusCode::FORBIDDEN;
    }

    apply_node_heartbeat(&state, node_id, request).await
}

async fn placement_for_key(
    State(state): State<ServerState>,
    Path(key): Path<String>,
) -> Json<cluster::PlacementDecision> {
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.placement_for_key(&key))
}

async fn replication_plan(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = planning_replication_subjects(&state).await;

    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.replication_plan(&keys))
}

async fn trigger_replication_audit(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = planning_replication_subjects(&state).await;

    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    let plan = cluster.replication_plan(&keys);

    info!(
        under_replicated = plan.under_replicated,
        over_replicated = plan.over_replicated,
        items = plan.items.len(),
        "manual replication audit result"
    );

    Json(plan)
}

async fn local_available_subjects(State(state): State<ServerState>) -> impl IntoResponse {
    let subjects = cached_local_cluster_available_subjects(&state).await;

    (
        StatusCode::OK,
        Json(LocalAvailableSubjectsResponse {
            node_id: state.node_id,
            subject_count: subjects.len(),
            generated_at_unix: unix_ts(),
            subjects,
        }),
    )
        .into_response()
}

async fn local_metadata_subjects(State(state): State<ServerState>) -> impl IntoResponse {
    let mut subjects = {
        let store = read_store(&state, "metadata_subjects.list").await;
        store
            .list_metadata_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };
    subjects.sort();

    (
        StatusCode::OK,
        Json(LocalMetadataSubjectsResponse {
            node_id: state.node_id,
            subject_count: subjects.len(),
            generated_at_unix: unix_ts(),
            subjects,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct ReplicationCleanupQuery {
    dry_run: Option<bool>,
    max_deletions: Option<usize>,
    retained_overhead_bytes: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationDropQuery {
    key: String,
    version_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReplicationDropReport {
    dropped: bool,
}

#[derive(Debug, Serialize)]
struct ReplicationCleanupReport {
    dry_run: bool,
    planned_candidates: usize,
    considered_candidates: usize,
    target_reclaimed_bytes: u64,
    estimated_overhead_bytes: u64,
    reclaimed_bytes: u64,
    attempted_deletions: usize,
    successful_deletions: usize,
    failed_deletions: usize,
    skipped_items: usize,
}

async fn drop_replication_subject(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationDropQuery>,
) -> impl IntoResponse {
    let dropped = {
        let mut store = lock_store(&state, "replication.drop_subject").await;
        match store
            .drop_replica_subject(&query.key, query.version_id.as_deref())
            .await
        {
            Ok(dropped) => dropped,
            Err(err) => {
                tracing::warn!(
                    key = %query.key,
                    version_id = ?query.version_id,
                    error = %err,
                    "failed dropping replication subject"
                );
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    };

    if dropped {
        publish_namespace_change(&state);
        let mut cluster = state.cluster.lock().await;
        cluster.remove_replica(&query.key, state.node_id);
        cluster.remove_available(&query.key, state.node_id);
        if let Some(version_id) = &query.version_id {
            cluster.remove_replica(&format!("{}@{}", query.key, version_id), state.node_id);
            cluster.remove_available(&format!("{}@{}", query.key, version_id), state.node_id);
        }
        drop(cluster);

        if let Err(err) = persist_cluster_replicas_state(&state).await {
            warn!(error = %err, "failed to persist cluster replicas after drop");
        }
    }

    (StatusCode::OK, Json(ReplicationDropReport { dropped })).into_response()
}

#[derive(Debug, Clone)]
struct CleanupCandidate {
    subject: String,
    key: String,
    version_id: String,
    node_id: NodeId,
    node: NodeDescriptor,
    size_bytes: u64,
    node_free_bytes: u64,
}

fn build_replication_drop_path(key: &str, version_id: &str) -> String {
    let encoded_key = utf8_percent_encode(key, QUERY_COMPONENT_ENCODE_SET).to_string();
    let encoded_version_id =
        utf8_percent_encode(version_id, QUERY_COMPONENT_ENCODE_SET).to_string();
    format!("/cluster/replication/drop?key={encoded_key}&version_id={encoded_version_id}")
}

async fn execute_replication_cleanup(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationCleanupQuery>,
) -> impl IntoResponse {
    let dry_run = query.dry_run.unwrap_or(true);
    let max_deletions = query.max_deletions.unwrap_or(64).max(1);
    let retained_overhead_bytes = query.retained_overhead_bytes.unwrap_or(0);

    let keys = planning_replication_subjects(&state).await;

    let (plan, nodes) = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        (cluster.replication_plan(&keys), cluster.list_nodes())
    };

    let node_by_id: HashMap<NodeId, NodeDescriptor> =
        nodes.into_iter().map(|node| (node.node_id, node)).collect();

    let mut candidates = Vec::<CleanupCandidate>::new();
    let mut skipped_items = 0usize;

    for item in plan
        .items
        .iter()
        .filter(|item| !item.extra_nodes.is_empty())
    {
        let Some((key, version_id)) = parse_replication_subject(&item.key) else {
            skipped_items += 1;
            continue;
        };

        let Some(version_id) = version_id else {
            skipped_items += 1;
            continue;
        };

        let bundle = {
            let store = read_store(&state, "replication_cleanup.export_bundle").await;
            match store
                .export_replication_bundle(&key, Some(&version_id), ObjectReadMode::Preferred)
                .await
            {
                Ok(Some(bundle)) => bundle,
                _ => {
                    skipped_items += 1;
                    continue;
                }
            }
        };

        let size_bytes = bundle.manifest.total_size_bytes as u64;

        for extra_node in &item.extra_nodes {
            let Some(node) = node_by_id.get(extra_node) else {
                skipped_items += 1;
                continue;
            };

            candidates.push(CleanupCandidate {
                subject: item.key.clone(),
                key: key.clone(),
                version_id: version_id.clone(),
                node_id: *extra_node,
                node: node.clone(),
                size_bytes,
                node_free_bytes: node.free_bytes,
            });
        }
    }

    candidates.sort_by(|a, b| {
        a.node_free_bytes
            .cmp(&b.node_free_bytes)
            .then_with(|| b.size_bytes.cmp(&a.size_bytes))
    });

    let estimated_overhead_bytes = candidates.iter().fold(0u64, |acc, candidate| {
        acc.saturating_add(candidate.size_bytes)
    });
    let target_reclaimed_bytes = estimated_overhead_bytes.saturating_sub(retained_overhead_bytes);

    let mut selected = Vec::<CleanupCandidate>::new();
    let mut selected_bytes = 0u64;
    for candidate in candidates {
        if selected.len() >= max_deletions {
            break;
        }
        if selected_bytes >= target_reclaimed_bytes {
            break;
        }
        selected_bytes = selected_bytes.saturating_add(candidate.size_bytes);
        selected.push(candidate);
    }

    let mut attempted_deletions = 0usize;
    let mut successful_deletions = 0usize;
    let mut failed_deletions = 0usize;
    let mut reclaimed_bytes = 0u64;

    if dry_run {
        attempted_deletions = selected.len();
        successful_deletions = selected.len();
        reclaimed_bytes = selected_bytes;
    } else {
        for candidate in selected {
            attempted_deletions += 1;

            let path_and_query = build_replication_drop_path(&candidate.key, &candidate.version_id);
            let response = execute_peer_request(
                &state,
                &candidate.node,
                reqwest::Method::POST,
                &path_and_query,
                Vec::new(),
                Vec::new(),
            )
            .await;

            match response {
                Ok(resp) if (200..300).contains(&resp.status) => {
                    successful_deletions += 1;
                    reclaimed_bytes = reclaimed_bytes.saturating_add(candidate.size_bytes);

                    let mut cluster = state.cluster.lock().await;
                    cluster.remove_replica(&candidate.subject, candidate.node_id);
                    cluster.remove_available(&candidate.subject, candidate.node_id);
                    cluster.remove_replica(
                        &format!("{}@{}", candidate.key, candidate.version_id),
                        candidate.node_id,
                    );
                    cluster.remove_available(
                        &format!("{}@{}", candidate.key, candidate.version_id),
                        candidate.node_id,
                    );
                    drop(cluster);

                    if let Err(err) = persist_cluster_replicas_state(&state).await {
                        warn!(
                            error = %err,
                            "failed to persist cluster replicas after cleanup deletion"
                        );
                    }
                }
                _ => {
                    failed_deletions += 1;
                }
            }
        }
    }

    (
        StatusCode::OK,
        Json(ReplicationCleanupReport {
            dry_run,
            planned_candidates: plan.over_replicated,
            considered_candidates: attempted_deletions,
            target_reclaimed_bytes,
            estimated_overhead_bytes,
            reclaimed_bytes,
            attempted_deletions,
            successful_deletions,
            failed_deletions,
            skipped_items,
        }),
    )
        .into_response()
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationManifestPushQuery {
    key: String,
    version_id: Option<String>,
    #[serde(default)]
    parent_version_ids_json: Option<String>,
    state: VersionConsistencyState,
    manifest_hash: String,
}

#[derive(Debug, Serialize)]
struct ReplicationChunkPushReport {
    stored: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationExportQuery {
    key: String,
    version_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MetadataExportQuery {
    key: String,
    version_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationManifestPushReport {
    version_id: String,
}

async fn export_replication_bundle(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationExportQuery>,
) -> impl IntoResponse {
    let store = read_store(&state, "replication.export_bundle").await;
    match store
        .export_replication_bundle(
            &query.key,
            query.version_id.as_deref(),
            ObjectReadMode::Preferred,
        )
        .await
    {
        Ok(Some(bundle)) => (StatusCode::OK, Json(bundle)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(
                key = %query.key,
                version_id = ?query.version_id,
                error = %err,
                "failed exporting replication bundle"
            );
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

fn build_metadata_export_path(key: &str, version_id: Option<&str>) -> String {
    let encoded_key = utf8_percent_encode(key, QUERY_COMPONENT_ENCODE_SET).to_string();
    let mut path = format!("/cluster/metadata/export?key={encoded_key}");
    if let Some(version_id) = version_id {
        let encoded_version =
            utf8_percent_encode(version_id, QUERY_COMPONENT_ENCODE_SET).to_string();
        path.push_str("&version_id=");
        path.push_str(&encoded_version);
    }
    path
}

async fn export_metadata_bundle(
    State(state): State<ServerState>,
    Query(query): Query<MetadataExportQuery>,
) -> impl IntoResponse {
    let store = read_store(&state, "metadata.export_bundle").await;
    match store
        .export_metadata_bundle(
            &query.key,
            query.version_id.as_deref(),
            ObjectReadMode::Preferred,
        )
        .await
    {
        Ok(Some(bundle)) => (StatusCode::OK, Json(bundle)).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(
                key = %query.key,
                version_id = ?query.version_id,
                error = %err,
                "failed exporting metadata bundle"
            );
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn get_replication_chunk(
    State(state): State<ServerState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let store = read_store(&state, "replication.read_chunk").await;
    match store.read_chunk_payload(&hash).await {
        Ok(Some(payload)) => (StatusCode::OK, payload).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::warn!(hash = %hash, error = %err, "failed reading replication chunk");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn push_replication_chunk(
    State(state): State<ServerState>,
    Path(hash): Path<String>,
    payload: Bytes,
) -> impl IntoResponse {
    let store = lock_store(&state, "replication.ingest_chunk").await;
    match store.ingest_chunk(&hash, &payload).await {
        Ok(stored) => (StatusCode::OK, Json(ReplicationChunkPushReport { stored })).into_response(),
        Err(err) => {
            tracing::warn!(hash = %hash, error = %err, "failed to ingest replication chunk");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn push_replication_manifest(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationManifestPushQuery>,
    payload: Bytes,
) -> impl IntoResponse {
    let parent_version_ids = match query.parent_version_ids_json.as_deref() {
        Some(raw) => match serde_json::from_str::<Vec<String>>(raw) {
            Ok(parent_version_ids) => parent_version_ids,
            Err(err) => {
                tracing::warn!(
                    key = %query.key,
                    version_id = ?query.version_id,
                    error = %err,
                    "failed decoding replication manifest parent_version_ids"
                );
                return StatusCode::BAD_REQUEST.into_response();
            }
        },
        None => Vec::new(),
    };

    let import_result = {
        let mut store = lock_store(&state, "replication.import_manifest").await;
        store
            .import_replica_manifest(
                &query.key,
                query.version_id.as_deref(),
                &parent_version_ids,
                query.state,
                &query.manifest_hash,
                &payload,
            )
            .await
    };

    match import_result {
        Ok(version_id) => {
            publish_namespace_change(&state);
            let mut cluster = state.cluster.lock().await;
            cluster.note_replica(&query.key, state.node_id);
            cluster.note_replica(format!("{}@{}", query.key, version_id), state.node_id);
            drop(cluster);

            if let Err(err) = persist_cluster_replicas_state(&state).await {
                warn!(
                    error = %err,
                    "failed to persist cluster replicas after manifest import"
                );
            }

            (
                StatusCode::OK,
                Json(ReplicationManifestPushReport { version_id }),
            )
                .into_response()
        }
        Err(err) => {
            tracing::warn!(
                key = %query.key,
                version_id = ?query.version_id,
                error = %err,
                "failed to import replication manifest"
            );
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn persist_repair_state(state: &ServerState) -> Result<()> {
    let attempts = {
        let repair_state = state.repair_state.lock().await;
        repair_state
            .attempts
            .iter()
            .map(|(key, entry)| {
                (
                    key.clone(),
                    RepairAttemptRecord {
                        attempts: entry.attempts,
                        last_failure_unix: entry.last_failure_unix,
                    },
                )
            })
            .collect::<HashMap<_, _>>()
    };

    let store = lock_store(state, "repair_state.persist").await;
    store.persist_repair_attempts(&attempts).await
}

async fn persist_cluster_replicas_state(state: &ServerState) -> Result<()> {
    let replicas = {
        let cluster = state.cluster.lock().await;
        cluster.export_replicas_by_key()
    };

    let persister = {
        let store = read_store(state, "cluster_replicas.clone_persister").await;
        store.cluster_replicas_persister()
    };
    persister.persist_cluster_replicas(&replicas).await
}

#[cfg(test)]
fn build_http_client_from_optional_pem(server_ca_pem: Option<&str>) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder();
    let builder = if let Some(server_ca_pem) = server_ca_pem {
        builder.add_root_certificate(
            reqwest::Certificate::from_pem(server_ca_pem.as_bytes())
                .context("failed parsing relay server CA PEM")?,
        )
    } else {
        builder
    };

    builder.build().context("failed building relay HTTP client")
}

fn build_identity_pem_from_paths(cert_path: &PathBuf, key_path: &PathBuf) -> Result<Vec<u8>> {
    let mut identity_pem = Vec::new();
    identity_pem.extend_from_slice(
        &std::fs::read(cert_path)
            .with_context(|| format!("failed reading {}", cert_path.display()))?,
    );
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(
        &std::fs::read(key_path)
            .with_context(|| format!("failed reading {}", key_path.display()))?,
    );
    Ok(identity_pem)
}

fn parse_client_identity_pem(
    identity_pem: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = std::io::Cursor::new(identity_pem);
    let cert_chain = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing internal node certificate chain")?;
    if cert_chain.is_empty() {
        bail!("internal node identity PEM is missing a certificate chain");
    }

    let mut key_reader = std::io::Cursor::new(identity_pem);
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing internal node private key")?;
    Ok((cert_chain, key))
}

fn load_root_cert_store_from_pem_path(ca_path: &PathBuf) -> Result<RootCertStore> {
    let ca_pem =
        std::fs::read(ca_path).with_context(|| format!("failed reading {}", ca_path.display()))?;
    let mut reader = std::io::Cursor::new(ca_pem);
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut reader) {
        let cert = cert.context("failed parsing internal CA PEM")?;
        roots
            .add(cert)
            .context("failed adding internal CA certificate to trust store")?;
    }

    Ok(roots)
}

#[cfg(test)]
fn build_internal_mtls_http_client(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<reqwest::Client> {
    build_internal_mtls_http_client_with_expected_peer(ca_path, cert_path, key_path, None)
}

fn build_internal_mtls_http_client_for_expected_peer(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
    expected_node_id: NodeId,
    expected_cluster_id: ClusterId,
) -> Result<reqwest::Client> {
    build_internal_mtls_http_client_with_expected_peer(
        ca_path,
        cert_path,
        key_path,
        Some((expected_node_id, expected_cluster_id)),
    )
}

fn build_internal_mtls_http_client_with_expected_peer(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
    expected_peer: Option<(NodeId, ClusterId)>,
) -> Result<reqwest::Client> {
    let roots = load_root_cert_store_from_pem_path(ca_path)?;
    let identity_pem = build_identity_pem_from_paths(cert_path, key_path)?;
    let (cert_chain, key) = parse_client_identity_pem(&identity_pem)?;

    let tls_config = match expected_peer {
        Some((expected_node_id, expected_cluster_id)) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ExpectedPeerServerCertVerifier::new(
                Arc::new(roots.clone()),
                expected_node_id,
                expected_cluster_id,
            )?))
            .with_client_auth_cert(cert_chain, key)
            .context("failed building internal peer TLS client identity")?,
        None => rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(cert_chain, key)
            .context("failed building internal peer TLS client identity")?,
    };

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .context("failed building internal mTLS http client")
}

fn build_internal_mtls_server_config(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<rustls::ServerConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let mut ca_reader = BufReader::new(
        File::open(ca_path).with_context(|| format!("failed reading {}", ca_path.display()))?,
    );
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
        let cert = cert.context("failed parsing internal CA certificate")?;
        roots
            .add(cert)
            .context("failed adding internal CA certificate to trust store")?;
    }

    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("failed reading {}", cert_path.display()))?,
    );
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed parsing internal node certificate chain")?;

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("failed reading {}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing internal node private key")?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed creating internal client certificate verifier")?;

    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .context("failed creating internal rustls server config")?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(config)
}

fn build_internal_mtls_rustls_config(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<RustlsConfig> {
    Ok(RustlsConfig::from_config(Arc::new(
        build_internal_mtls_server_config(ca_path, cert_path, key_path)?,
    )))
}

fn jittered_backoff_secs(base_backoff_secs: u64, transfer_key: &str, attempts: u32) -> u64 {
    if base_backoff_secs == 0 {
        return 0;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    transfer_key.hash(&mut hasher);
    attempts.hash(&mut hasher);
    let jitter_max = (base_backoff_secs / 2).max(1);
    let jitter = hasher.finish() % (jitter_max + 1);

    base_backoff_secs.saturating_add(jitter)
}

const ADMIN_TOKEN_HEADER: &str = "x-ironmesh-admin-token";
const ADMIN_ACTOR_HEADER: &str = "x-ironmesh-admin-actor";
const ADMIN_SOURCE_NODE_HEADER: &str = "x-ironmesh-node-id";
const ADMIN_SESSION_COOKIE_PREFIX: &str = "ironmesh_admin_session";

#[derive(Debug, Clone)]
struct AdminRequestMetadata {
    actor: Option<String>,
    source_node: Option<String>,
}

fn admin_request_metadata(headers: &HeaderMap) -> AdminRequestMetadata {
    let actor = headers
        .get(ADMIN_ACTOR_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let source_node = headers
        .get(ADMIN_SOURCE_NODE_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    AdminRequestMetadata { actor, source_node }
}

fn parse_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|entry| {
                let (cookie_name, cookie_value) = entry.trim().split_once('=')?;
                if cookie_name.trim() == name {
                    Some(cookie_value.trim().to_string())
                } else {
                    None
                }
            })
        })
}

async fn current_admin_session_expiry(state: &ServerState, headers: &HeaderMap) -> Option<u64> {
    let session_id = parse_cookie_value(headers, &admin_session_cookie_name(state))?;
    let mut sessions = state.admin_sessions.lock().await;
    sessions.is_valid(&session_id, unix_ts())
}

fn password_hash_matches(expected_hash: &str, password: &str) -> bool {
    let provided_hash = hash_token(password);
    constant_time_eq(expected_hash.as_bytes(), provided_hash.as_bytes())
}

fn admin_session_cookie_name(state: &ServerState) -> String {
    format!("{ADMIN_SESSION_COOKIE_PREFIX}_{}", state.node_id.simple())
}

fn build_admin_session_cookie(
    cookie_name: &str,
    session_id: &str,
    secure: bool,
    max_age_secs: u64,
) -> Result<HeaderValue> {
    let mut cookie = format!(
        "{cookie_name}={session_id}; Path=/; Max-Age={max_age_secs}; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).context("failed building admin session cookie header")
}

fn clear_admin_session_cookie(cookie_name: &str, secure: bool) -> Result<HeaderValue> {
    let mut cookie = format!("{cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).context("failed building admin session clear-cookie header")
}

#[allow(clippy::too_many_arguments)]
async fn append_admin_audit(
    state: &ServerState,
    action: &str,
    request: &AdminRequestMetadata,
    authorized: bool,
    dry_run: bool,
    approved: bool,
    outcome: &str,
    details: serde_json::Value,
) {
    let event = AdminAuditEvent {
        event_id: Uuid::now_v7().to_string(),
        action: action.to_string(),
        actor: request.actor.clone(),
        source_node: request.source_node.clone(),
        authorized,
        dry_run,
        approved,
        outcome: outcome.to_string(),
        details_json: serde_json::to_string(&details).unwrap_or_else(|_| "{}".to_string()),
        created_at_unix: unix_ts(),
    };
    let store = lock_store(state, "admin_audit.append").await;
    if let Err(err) = store.append_admin_audit_event(&event).await {
        warn!(error = %err, action = %action, "failed to append admin audit event");
    }
}

async fn get_admin_session_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token_valid = state
        .admin_control
        .admin_token
        .as_deref()
        .map(|expected| {
            token_matches(
                expected,
                headers
                    .get(ADMIN_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok()),
            )
        })
        .unwrap_or(false);
    let session_expires_at_unix = current_admin_session_expiry(&state, &headers).await;
    let authenticated = token_valid || session_expires_at_unix.is_some();

    (
        StatusCode::OK,
        Json(AdminSessionStatusResponse {
            login_required: true,
            authenticated,
            session_expires_at_unix,
            token_override_enabled: state.admin_control.admin_token.is_some(),
        }),
    )
}

async fn login_admin_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<AdminLoginRequest>,
) -> impl IntoResponse {
    let action = "auth/admin/login";
    let request_meta = admin_request_metadata(&headers);
    let Some(expected_hash) = state.admin_control.admin_password_hash.as_deref() else {
        append_admin_audit(
            &state,
            action,
            &request_meta,
            false,
            true,
            true,
            "denied_unconfigured",
            json!({ "error": "password-backed admin login is not enabled on this node" }),
        )
        .await;
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({ "error": "password-backed admin login is not enabled on this node" })),
        )
            .into_response();
    };

    if !password_hash_matches(expected_hash, &request.password) {
        append_admin_audit(
            &state,
            action,
            &request_meta,
            false,
            true,
            true,
            "denied_auth",
            json!({ "error": "invalid admin password" }),
        )
        .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid admin password" })),
        )
            .into_response();
    }

    let (session_id, session_expires_at_unix) = {
        let mut sessions = state.admin_sessions.lock().await;
        sessions.create_session(unix_ts())
    };
    let cookie_name = admin_session_cookie_name(&state);
    let cookie = match build_admin_session_cookie(
        &cookie_name,
        &session_id,
        state.public_tls_runtime.is_some(),
        ADMIN_SESSION_TTL_SECS,
    ) {
        Ok(cookie) => cookie,
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request_meta,
                false,
                true,
                true,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    append_admin_audit(
        &state,
        action,
        &AdminRequestMetadata {
            actor: Some("local-admin".to_string()),
            source_node: request_meta.source_node.clone(),
        },
        true,
        true,
        true,
        "success",
        json!({
            "session_expires_at_unix": session_expires_at_unix,
        }),
    )
    .await;

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(AdminSessionStatusResponse {
            login_required: true,
            authenticated: true,
            session_expires_at_unix: Some(session_expires_at_unix),
            token_override_enabled: state.admin_control.admin_token.is_some(),
        }),
    )
        .into_response()
}

async fn logout_admin_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let cookie_name = admin_session_cookie_name(&state);
    let session_id = parse_cookie_value(&headers, &cookie_name);
    if let Some(session_id) = session_id.as_deref() {
        let mut sessions = state.admin_sessions.lock().await;
        sessions.revoke(session_id);
    }

    let cookie = match clear_admin_session_cookie(&cookie_name, state.public_tls_runtime.is_some())
    {
        Ok(cookie) => cookie,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        [(header::SET_COOKIE, cookie)],
        Json(AdminSessionStatusResponse {
            login_required: true,
            authenticated: false,
            session_expires_at_unix: None,
            token_override_enabled: state.admin_control.admin_token.is_some(),
        }),
    )
        .into_response()
}

async fn authorize_admin_request(
    state: &ServerState,
    headers: &HeaderMap,
    action: &str,
    dry_run: bool,
    approve: bool,
    details: serde_json::Value,
) -> std::result::Result<AdminRequestMetadata, StatusCode> {
    let mut request = admin_request_metadata(headers);
    if !admin_auth_configured(state) {
        append_admin_audit(
            state,
            action,
            &request,
            false,
            dry_run,
            approve,
            "denied_unconfigured",
            details.clone(),
        )
        .await;
        return Err(StatusCode::PRECONDITION_FAILED);
    }
    let token_valid = state
        .admin_control
        .admin_token
        .as_deref()
        .map(|expected| {
            token_matches(
                expected,
                headers
                    .get(ADMIN_TOKEN_HEADER)
                    .and_then(|value| value.to_str().ok()),
            )
        })
        .unwrap_or(false);
    let session_expires_at_unix = current_admin_session_expiry(state, headers).await;

    if !token_valid && session_expires_at_unix.is_none() {
        append_admin_audit(
            state,
            action,
            &request,
            false,
            dry_run,
            approve,
            "denied_auth",
            details,
        )
        .await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    if request.actor.is_none() && session_expires_at_unix.is_some() {
        request.actor = Some("local-admin".to_string());
    }

    if !dry_run && !approve {
        append_admin_audit(
            state,
            action,
            &request,
            true,
            dry_run,
            approve,
            "denied_missing_approval",
            details,
        )
        .await;
        return Err(StatusCode::PRECONDITION_FAILED);
    }

    Ok(request)
}

fn token_matches(expected: &str, provided: Option<&str>) -> bool {
    provided
        .map(|token| constant_time_eq(expected.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());

    for index in 0..max_len {
        let left_byte = *left.get(index).unwrap_or(&0);
        let right_byte = *right.get(index).unwrap_or(&0);
        diff |= usize::from(left_byte ^ right_byte);
    }

    diff == 0
}

fn parse_replication_subject(subject: &str) -> Option<(String, Option<String>)> {
    if subject.is_empty() {
        return None;
    }

    if let Some((key, version_id)) = subject.rsplit_once('@')
        && !key.is_empty()
        && !version_id.is_empty()
    {
        return Some((key.to_string(), Some(version_id.to_string())));
    }

    Some((subject.to_string(), None))
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn write_json_atomic(path: &FsPath, payload: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path {} has no parent directory", path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed creating {}", parent.display()))?;

    let temp_path = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("state"),
        Uuid::new_v4().simple()
    ));
    tokio::fs::write(&temp_path, payload)
        .await
        .with_context(|| format!("failed writing {}", temp_path.display()))?;
    tokio::fs::rename(&temp_path, path).await.with_context(|| {
        format!(
            "failed renaming {} -> {}",
            temp_path.display(),
            path.display()
        )
    })
}

async fn run_cleanup(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<CleanupQuery>,
) -> impl IntoResponse {
    let retention_secs = query.retention_secs.unwrap_or(60 * 60 * 24);
    let dry_run = query.dry_run.unwrap_or(true);
    let approve = query.approve.unwrap_or(false);
    let action = "maintenance/cleanup";
    let request_details = json!({
        "retention_secs": retention_secs,
        "dry_run": dry_run,
        "approve": approve,
    });
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        dry_run,
        approve,
        request_details.clone(),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = lock_store(&state, "maintenance.cleanup").await;
        store.cleanup_unreferenced(retention_secs, dry_run).await
    };
    match result {
        Ok(report) => {
            if !dry_run {
                request_local_availability_refresh(&state);
            }
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "success",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "deleted_manifests": report.deleted_manifests,
                    "deleted_chunks": report.deleted_chunks,
                }),
            )
            .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "error",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "error": err.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %err, "maintenance cleanup failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn run_tombstone_compaction(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<CleanupQuery>,
) -> impl IntoResponse {
    let retention_secs = query.retention_secs.unwrap_or(60 * 60 * 24 * 30);
    let dry_run = query.dry_run.unwrap_or(true);
    let approve = query.approve.unwrap_or(false);
    let action = "maintenance/tombstones/compact";
    let request_details = json!({
        "retention_secs": retention_secs,
        "dry_run": dry_run,
        "approve": approve,
    });
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        dry_run,
        approve,
        request_details.clone(),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = lock_store(&state, "maintenance.tombstones.compact").await;
        store
            .compact_tombstone_indexes(retention_secs, dry_run)
            .await
    };
    match result {
        Ok(report) => {
            if !dry_run {
                request_local_availability_refresh(&state);
            }
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "success",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "eligible_indexes": report.eligible_indexes,
                    "removed_indexes": report.removed_indexes,
                }),
            )
            .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "error",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "error": err.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %err, "maintenance tombstone compaction failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn list_tombstone_archives(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let dry_run = true;
    let approve = true;
    let action = "maintenance/tombstones/archive/list";
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        dry_run,
        approve,
        json!({}),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = read_store(&state, "maintenance.tombstones.archive_list").await;
        store.list_tombstone_archives().await
    };
    match result {
        Ok(entries) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "success",
                json!({ "entries": entries.len() }),
            )
            .await;
            (StatusCode::OK, Json(entries)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "error",
                json!({ "error": err.to_string() }),
            )
            .await;
            tracing::error!(error = %err, "failed to list tombstone archives");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn run_tombstone_archive_restore(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<TombstoneRestoreQuery>,
) -> impl IntoResponse {
    let object_id = query.object_id.trim();
    if object_id.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let dry_run = query.dry_run.unwrap_or(true);
    let approve = query.approve.unwrap_or(false);
    let overwrite = query.overwrite.unwrap_or(false);
    let action = "maintenance/tombstones/archive/restore";
    let request_details = json!({
        "object_id": object_id,
        "archive_file": query.archive_file.clone(),
        "overwrite": overwrite,
        "dry_run": dry_run,
        "approve": approve,
    });
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        dry_run,
        approve,
        request_details.clone(),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = lock_store(&state, "maintenance.tombstones.restore").await;
        store
            .restore_tombstone_index_from_archive(
                object_id,
                query.archive_file.as_deref(),
                overwrite,
                dry_run,
            )
            .await
    };
    match result {
        Ok(report) => {
            if !dry_run && report.restored {
                request_local_availability_refresh(&state);
            }
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "success",
                json!({
                    "object_id": object_id,
                    "dry_run": dry_run,
                    "overwrite": overwrite,
                    "found": report.found,
                    "restored": report.restored,
                    "skipped_existing": report.skipped_existing,
                }),
            )
            .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "error",
                json!({
                    "object_id": object_id,
                    "dry_run": dry_run,
                    "overwrite": overwrite,
                    "error": err.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %err, object_id = %object_id, "failed to restore tombstone archive");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn run_tombstone_archive_purge(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Query(query): Query<CleanupQuery>,
) -> impl IntoResponse {
    let retention_secs = query.retention_secs.unwrap_or(60 * 60 * 24 * 180);
    let dry_run = query.dry_run.unwrap_or(true);
    let approve = query.approve.unwrap_or(false);
    let action = "maintenance/tombstones/archive/purge";
    let request_details = json!({
        "retention_secs": retention_secs,
        "dry_run": dry_run,
        "approve": approve,
    });
    let request = match authorize_admin_request(
        &state,
        &headers,
        action,
        dry_run,
        approve,
        request_details.clone(),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let result = {
        let store = lock_store(&state, "maintenance.tombstones.archive_purge").await;
        store
            .purge_tombstone_archives(retention_secs, dry_run)
            .await
    };
    match result {
        Ok(report) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "success",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "eligible_files": report.eligible_files,
                    "deleted_files": report.deleted_files,
                }),
            )
            .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        Err(err) => {
            append_admin_audit(
                &state,
                action,
                &request,
                true,
                dry_run,
                approve,
                "error",
                json!({
                    "retention_secs": retention_secs,
                    "dry_run": dry_run,
                    "error": err.to_string(),
                }),
            )
            .await;
            tracing::error!(error = %err, "failed to purge tombstone archives");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Serialize)]
struct ReconcileReport {
    source_node_id: NodeId,
    imported: usize,
    skipped_existing: usize,
    skipped_replayed: usize,
    failed: usize,
}

async fn export_provisional_versions(State(state): State<ServerState>) -> impl IntoResponse {
    let store = read_store(&state, "reconcile.export_provisional_versions").await;
    match store.list_provisional_versions().await {
        Ok(entries) => (StatusCode::OK, Json(entries)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to export provisional versions");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

async fn reconcile_from_node(
    State(state): State<ServerState>,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    let source_node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let remote_node = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();

        let Some(node) = cluster
            .list_nodes()
            .into_iter()
            .find(|entry| entry.node_id == source_node_id)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };

        node
    };
    let remote_entries: Vec<ReconcileVersionEntry> = match execute_peer_request(
        &state,
        &remote_node,
        reqwest::Method::GET,
        "/cluster/reconcile/export/provisional",
        Vec::new(),
        Vec::new(),
    )
    .await
    {
        Ok(response) if response.is_success() => {
            match response.json::<Vec<ReconcileVersionEntry>>() {
                Ok(entries) => entries,
                Err(err) => {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        error = %err,
                        "failed to parse reconciliation export payload"
                    );
                    return StatusCode::BAD_GATEWAY.into_response();
                }
            }
        }
        Ok(response) => {
            tracing::error!(
                source_node_id = %source_node_id,
                status = response.status,
                "reconciliation export endpoint returned error"
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
        Err(err) => {
            tracing::error!(
                source_node_id = %source_node_id,
                error = %err,
                "failed to call reconciliation export endpoint"
            );
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let mut imported = 0usize;
    let mut skipped_existing = 0usize;
    let mut skipped_replayed = 0usize;
    let mut failed = 0usize;
    let source_node_id_string = source_node_id.to_string();

    for entry in remote_entries {
        let replayed = {
            let store = read_store(&state, "reconcile.check_marker").await;
            match store
                .has_reconcile_marker(&source_node_id_string, &entry.key, &entry.version_id)
                .await
            {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        key = %entry.key,
                        version_id = %entry.version_id,
                        error = %err,
                        "failed checking reconciliation replay marker"
                    );
                    failed += 1;
                    continue;
                }
            }
        };

        if replayed {
            skipped_replayed += 1;
            continue;
        }

        let already_present = {
            let store = read_store(&state, "reconcile.check_manifest").await;
            match store
                .has_manifest_for_key(&entry.key, &entry.manifest_hash)
                .await
            {
                Ok(value) => value,
                Err(err) => {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        key = %entry.key,
                        error = %err,
                        "failed checking local manifest during reconciliation"
                    );
                    failed += 1;
                    continue;
                }
            }
        };

        if already_present {
            skipped_existing += 1;
            let mark_result = {
                let store = lock_store(&state, "reconcile.mark_existing").await;
                store
                    .mark_reconciled(&source_node_id_string, &entry.key, &entry.version_id, None)
                    .await
            };

            if let Err(err) = mark_result {
                tracing::error!(
                    source_node_id = %source_node_id,
                    key = %entry.key,
                    version_id = %entry.version_id,
                    error = %err,
                    "failed writing reconciliation marker for existing manifest"
                );
            }
            continue;
        }

        let object_path = format!("/store/{}?version={}", entry.key, entry.version_id);
        let payload = match execute_peer_request(
            &state,
            &remote_node,
            reqwest::Method::GET,
            &object_path,
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => response.body,
            Ok(response) => {
                tracing::error!(
                    source_node_id = %source_node_id,
                    key = %entry.key,
                    version_id = %entry.version_id,
                    status = response.status,
                    "reconciliation object fetch returned error"
                );
                failed += 1;
                continue;
            }
            Err(err) => {
                tracing::error!(
                    source_node_id = %source_node_id,
                    key = %entry.key,
                    version_id = %entry.version_id,
                    error = %err,
                    "failed to call reconciliation object fetch"
                );
                failed += 1;
                continue;
            }
        };

        let put_result = {
            let mut store = lock_store(&state, "reconcile.import_object").await;
            store
                .put_object_versioned(
                    &entry.key,
                    payload,
                    PutOptions {
                        parent_version_ids: Vec::new(),
                        state: VersionConsistencyState::Provisional,
                        inherit_preferred_parent: false,
                        create_snapshot: true,
                        explicit_version_id: Some(entry.version_id.clone()),
                    },
                )
                .await
        };

        match put_result {
            Ok(outcome) => {
                imported += 1;

                let mark_result = {
                    let store = lock_store(&state, "reconcile.mark_imported").await;
                    store
                        .mark_reconciled(
                            &source_node_id_string,
                            &entry.key,
                            &entry.version_id,
                            Some(outcome.version_id.as_str()),
                        )
                        .await
                };

                if let Err(err) = mark_result {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        key = %entry.key,
                        version_id = %entry.version_id,
                        error = %err,
                        "failed writing reconciliation marker"
                    );
                    failed += 1;
                    continue;
                }

                let mut cluster = state.cluster.lock().await;
                cluster.note_replica(&entry.key, state.node_id);
                cluster.note_replica(
                    format!("{}@{}", entry.key, outcome.version_id.as_str()),
                    state.node_id,
                );
                drop(cluster);

                if let Err(err) = persist_cluster_replicas_state(&state).await {
                    warn!(
                        error = %err,
                        "failed to persist cluster replicas after reconciliation import"
                    );
                }
            }
            Err(err) => {
                tracing::error!(
                    source_node_id = %source_node_id,
                    key = %entry.key,
                    version_id = %entry.version_id,
                    error = %err,
                    "failed importing provisional version during reconciliation"
                );
                failed += 1;
            }
        }
    }

    (
        StatusCode::OK,
        Json(ReconcileReport {
            source_node_id,
            imported,
            skipped_existing,
            skipped_replayed,
            failed,
        }),
    )
        .into_response()
}
