use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::extract::{Path, Query, Request, State};
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use bytes::Bytes;
use common::{ClusterId, HealthStatus, NodeId};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    SanType,
};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use time::OffsetDateTime;
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use tokio::sync::{Mutex, RwLock, watch};
use tower::Service;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapMutualTlsMaterial, BootstrapServerTlsFiles,
    BootstrapTlsFiles, BootstrapTlsMaterialMetadata, BootstrapTrustRoots,
    CLIENT_BOOTSTRAP_CLAIM_KIND, CLIENT_BOOTSTRAP_CLAIM_VERSION, CandidateKind,
    ClientBootstrap as TransportClientBootstrap, ClientBootstrapClaim,
    ClientBootstrapClaimIssueResponse, ClientBootstrapClaimPublishRequest,
    ClientBootstrapClaimTrust, ClientBootstrapClaimTrustMode, ConnectionCandidate,
    NodeBootstrap as TransportNodeBootstrap, NodeBootstrapMode, NodeEnrollmentPackage,
    NodeJoinRequest, PeerIdentity, PeerTransportClient, PeerTransportClientConfig,
    PresenceRegistration, RelayHttpHeader, RelayHttpPollRequest, RelayHttpRequest,
    RelayHttpResponse, RelayMode, RelayTicketRequest, RendezvousClientConfig,
    RendezvousControlClient, SignedRequestHeaders, TransportCapability, TransportPathKind,
    credential_fingerprint, encode_optional_body_base64, verify_signed_request_headers,
};
use uuid::Uuid;

const BUILD_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_REVISION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

mod cluster;
mod embedded_rendezvous;
mod replication;
mod setup;
mod storage;
mod ui;

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
const OBJECT_RESPONSE_STREAM_CHUNK_SIZE_BYTES: usize = 64 * 1024;

use cluster::{
    ClusterService, NodeCapabilities, NodeDescriptor, NodeReachability, ReplicationPlan,
    ReplicationPolicy,
};
use setup::{
    ManagedRendezvousFailoverPackage, ManagedSignerBackup,
    export_managed_rendezvous_failover_package, export_managed_signer_backup,
    import_managed_rendezvous_failover_package, import_managed_signer_backup,
    issue_managed_rendezvous_tls_identity_from_ca, managed_rendezvous_cert_path,
    managed_rendezvous_key_path, managed_signer_ca_cert_path,
};
use storage::{
    AdminAuditEvent, ClientCredentialRecord, ClientCredentialState, MediaCacheLookup,
    MediaCacheStatus, MediaGpsCoordinates, MetadataBackendKind, ObjectReadDescriptor,
    ObjectReadMode, ObjectStreamPlan, PairingAuthorizationRecord, PathMutationResult,
    PersistentStore, PutOptions, ReconcileVersionEntry, RepairAttemptRecord, StoreReadError,
    UploadChunkRef, VersionConsistencyState,
};

#[derive(Clone)]
struct ServerState {
    data_dir: PathBuf,
    cluster_id: ClusterId,
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
    cluster: Arc<Mutex<ClusterService>>,
    client_credentials: Arc<Mutex<ClientCredentialState>>,
    upload_sessions: Arc<Mutex<UploadSessionStore>>,
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
    metadata_commit_mode: MetadataCommitMode,
    autonomous_replication_on_put_enabled: bool,
    inflight_requests: Arc<AtomicUsize>,
    peer_heartbeat_config: PeerHeartbeatConfig,
    repair_config: RepairConfig,
    log_buffer: Arc<LogBuffer>,
    startup_repair_status: Arc<Mutex<StartupRepairStatus>>,
    repair_state: Arc<Mutex<RepairExecutorState>>,
    namespace_change_sequence: Arc<AtomicU64>,
    namespace_change_tx: watch::Sender<u64>,
    admin_control: AdminControl,
    admin_sessions: Arc<Mutex<AdminSessionStore>>,
    client_auth_control: ClientAuthControl,
    client_auth_replay_cache: Arc<Mutex<ClientAuthReplayCache>>,
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
    internal_http: reqwest::Client,
    rendezvous_control: Option<RendezvousControlClient>,
    rendezvous_controls: Vec<RendezvousEndpointClient>,
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

    let signed_headers = SignedRequestHeaders::from_header_lookup(|name| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string)
    })
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    if signed_headers.cluster_id != state.cluster_id {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let request_path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| request.uri().path())
        .to_string();
    let request_method = request.method().as_str().to_string();
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
        &request_method,
        &request_path_and_query,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut replay_cache = state.client_auth_replay_cache.lock().await;
    if !replay_cache.remember(&signed_headers.device_id, &signed_headers.nonce, now) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    drop(replay_cache);

    Ok(next.run(request).await)
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

fn issue_client_rendezvous_identity_pem(
    state: &ServerState,
    device_id: &str,
    expires_at_unix: Option<u64>,
) -> Result<Option<String>> {
    if !state.rendezvous_mtls_required {
        return Ok(None);
    }

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

    let node_id = extract_node_id_from_peer_certs(certs)?;
    Ok(InternalCaller { node_id })
}

fn extract_node_id_from_peer_certs(certs: &[CertificateDer<'_>]) -> Result<NodeId> {
    let cert = certs
        .first()
        .context("missing end-entity peer certificate")?;

    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("failed parsing peer certificate")?;

    for extension in parsed.extensions() {
        let parsed_extension = extension.parsed_extension();
        if let ParsedExtension::SubjectAlternativeName(san) = parsed_extension {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name
                    && let Some(node_id) = parse_node_id_from_san_uri(uri)
                {
                    return Ok(node_id);
                }
            }
        }
    }

    anyhow::bail!("missing urn:ironmesh:node:<uuid> SAN URI in peer certificate");
}

fn parse_node_id_from_san_uri(uri: &str) -> Option<NodeId> {
    let prefix = "urn:ironmesh:node:";
    uri.strip_prefix(prefix)
        .and_then(|rest| rest.trim().parse::<NodeId>().ok())
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
    LocalEdge,
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
    pub node_enrollment_renewal_admin_token: Option<String>,
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

#[derive(Debug, Clone, Copy)]
enum StartupRepairStatus {
    Disabled,
    Scheduled,
    Running,
    SkippedNoGaps,
    Completed,
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

fn node_enrollment_preserved_tls_policy(
    package: &NodeEnrollmentPackage,
) -> (Option<u64>, Option<u64>) {
    let material = package
        .internal_tls_material
        .as_ref()
        .or(package.public_tls_material.as_ref());
    let Some(material) = material else {
        return (None, None);
    };
    let validity_secs = material
        .metadata
        .not_after_unix
        .saturating_sub(material.metadata.issued_at_unix);
    let renewal_window_secs = material
        .metadata
        .not_after_unix
        .saturating_sub(material.metadata.renew_after_unix);
    if validity_secs < 60 * 60 || renewal_window_secs < 300 || renewal_window_secs >= validity_secs
    {
        return (None, None);
    }
    (
        (validity_secs > 0).then_some(validity_secs),
        (renewal_window_secs > 0).then_some(renewal_window_secs),
    )
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

async fn renew_node_enrollment_package_if_due(config: &ServerNodeConfig) -> Result<bool> {
    if !config.node_enrollment_auto_renew_enabled {
        return Ok(false);
    }
    let Some(enrollment_path) = config.node_enrollment_path.as_ref() else {
        return Ok(false);
    };
    let Some(admin_token) = config.node_enrollment_renewal_admin_token.as_deref() else {
        return Ok(false);
    };

    let package = NodeEnrollmentPackage::from_path(enrollment_path)?;
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
    let (tls_validity_secs, tls_renewal_window_secs) =
        node_enrollment_preserved_tls_policy(&package);
    let client = build_http_client_from_optional_pem(
        package.bootstrap.trust_roots.public_api_ca_pem.as_deref(),
    )?;
    let response = client
        .post(format!("{issuer_url}/auth/node-enrollments/renew"))
        .header(ADMIN_TOKEN_HEADER, admin_token)
        .json(&OutboundNodeEnrollmentRenewRequest {
            package: package.clone(),
            tls_validity_secs,
            tls_renewal_window_secs,
        })
        .send()
        .await
        .context("failed requesting automatic node enrollment renewal")?
        .error_for_status()
        .context("automatic node enrollment renewal returned error")?;
    let renewed = response
        .json::<NodeEnrollmentPackage>()
        .await
        .context("failed decoding automatic node enrollment renewal response")?;
    renewed.validate()?;
    renewed.write_to_path(enrollment_path)?;
    let _ = materialize_node_enrollment_package(renewed)?;
    Ok(true)
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
    *state.outbound_clients.write().await = outbound_clients;
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

fn node_enrollment_auto_renew_check_secs() -> u64 {
    std::env::var("IRONMESH_NODE_ENROLLMENT_RENEWAL_CHECK_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(300)
}

fn node_enrollment_renewal_admin_token_from_env() -> Option<String> {
    std::env::var("IRONMESH_NODE_ENROLLMENT_RENEWAL_ADMIN_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

impl ServerNodeConfig {
    pub fn from_enrollment_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let package = NodeEnrollmentPackage::from_path(path.as_ref())?;
        let mut config = Self::from_enrollment(package)?;
        config.node_enrollment_path = Some(path.as_ref().to_path_buf());
        config.node_enrollment_renewal_admin_token = node_enrollment_renewal_admin_token_from_env();
        config.node_enrollment_auto_renew_enabled = parse_enrollment_auto_renew_enabled(
            config.node_enrollment_renewal_admin_token.is_some(),
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

        let mode = match bootstrap.mode {
            NodeBootstrapMode::Cluster => ServerNodeMode::Cluster,
            NodeBootstrapMode::LocalEdge => ServerNodeMode::LocalEdge,
        };
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
        let local_edge_clustered = mode == ServerNodeMode::LocalEdge && rendezvous_configured;

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
            node_enrollment_renewal_admin_token: node_enrollment_renewal_admin_token_from_env(),
            heartbeat_timeout_secs: std::env::var("IRONMESH_HEARTBEAT_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(90),
            audit_interval_secs: std::env::var("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS")
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(if local_edge_clustered { 5 } else { 3600 }),
            replica_view_sync_interval_secs: std::env::var(
                "IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS",
            )
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(5),
            replication_factor: std::env::var("IRONMESH_REPLICATION_FACTOR")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(if local_edge_clustered {
                    2
                } else if mode == ServerNodeMode::LocalEdge {
                    1
                } else {
                    3
                }),
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
            autonomous_replication_on_put_enabled: match mode {
                ServerNodeMode::Cluster => {
                    std::env::var("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED")
                        .ok()
                        .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                        .unwrap_or(true)
                }
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
            replication_repair_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
                    .ok()
                    .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false),
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
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
            .unwrap_or(if local_edge_clustered { 2 } else { 30 }),
            repair_busy_throttle_enabled: std::env::var("IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(false),
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
            startup_repair_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_STARTUP_REPAIR_ENABLED")
                    .ok()
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                    .unwrap_or(true),
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
            startup_repair_delay_secs: std::env::var("IRONMESH_STARTUP_REPAIR_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
            peer_heartbeat_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED")
                    .ok()
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                    .unwrap_or(true),
                ServerNodeMode::LocalEdge => false,
            },
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
            require_client_auth: std::env::var("IRONMESH_REQUIRE_CLIENT_AUTH")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(false),
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

        let mode = match std::env::var("IRONMESH_NODE_MODE")
            .unwrap_or_else(|_| "cluster".to_string())
            .as_str()
        {
            "cluster" => ServerNodeMode::Cluster,
            "local-edge" => ServerNodeMode::LocalEdge,
            raw => bail!("invalid IRONMESH_NODE_MODE '{raw}', expected 'cluster' or 'local-edge'"),
        };

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

        let internal_tls = match mode {
            ServerNodeMode::Cluster => {
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
                Some(InternalTlsConfig {
                    bind_addr: internal_bind_addr,
                    internal_url: std::env::var("IRONMESH_INTERNAL_URL")
                        .ok()
                        .or_else(|| Some(format!("https://{internal_bind_addr}"))),
                    metadata_path: existing_tls_metadata_sidecar_path(&cert_path),
                    ca_cert_path,
                    cert_path,
                    key_path,
                })
            }
            ServerNodeMode::LocalEdge => None,
        };

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

        let local_edge_clustered =
            mode == ServerNodeMode::LocalEdge && rendezvous_registration_enabled;
        let default_replication_factor = if local_edge_clustered {
            2
        } else if mode == ServerNodeMode::LocalEdge {
            1
        } else {
            3
        };
        let public_peer_api_enabled = std::env::var("IRONMESH_PUBLIC_PEER_API_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(local_edge_clustered);
        let default_audit_interval_secs = if local_edge_clustered { 5 } else { 3600 };
        let default_replication_repair_backoff_secs = if local_edge_clustered { 2 } else { 30 };

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
            node_enrollment_renewal_admin_token: node_enrollment_renewal_admin_token_from_env(),
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
            .unwrap_or(5),
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
            autonomous_replication_on_put_enabled: match mode {
                ServerNodeMode::Cluster => {
                    std::env::var("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED")
                        .ok()
                        .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                        .unwrap_or(true)
                }
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
            replication_repair_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
                    .ok()
                    .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false),
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
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
                .unwrap_or(false),
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
            startup_repair_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_STARTUP_REPAIR_ENABLED")
                    .ok()
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                    .unwrap_or(true),
                ServerNodeMode::LocalEdge => local_edge_clustered,
            },
            startup_repair_delay_secs: std::env::var("IRONMESH_STARTUP_REPAIR_DELAY_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(5),
            peer_heartbeat_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED")
                    .ok()
                    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                    .unwrap_or(true),
                ServerNodeMode::LocalEdge => false,
            },
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
            require_client_auth: std::env::var("IRONMESH_REQUIRE_CLIENT_AUTH")
                .ok()
                .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
                .unwrap_or(false),
        })
    }

    pub fn local_edge(data_dir: impl Into<PathBuf>, bind_addr: SocketAddr) -> Self {
        let mut labels = HashMap::new();
        labels.insert("region".to_string(), "local".to_string());
        labels.insert("dc".to_string(), "local-edge".to_string());
        labels.insert("rack".to_string(), "local-edge".to_string());

        Self {
            mode: ServerNodeMode::LocalEdge,
            cluster_id: Uuid::now_v7(),
            node_id: NodeId::new_v4(),
            data_dir: data_dir.into(),
            metadata_backend: MetadataBackendKind::Sqlite,
            bind_addr,
            public_url: Some(format!("http://{bind_addr}")),
            labels,
            public_tls: None,
            public_ca_cert_path: None,
            public_ca_key_path: None,
            bootstrap_trust_roots: None,
            public_peer_api_enabled: false,
            internal_tls: None,
            internal_ca_key_path: None,
            rendezvous_ca_cert_path: None,
            rendezvous_urls: vec![format!("http://{bind_addr}")],
            rendezvous_registration_enabled: false,
            rendezvous_mtls_required: false,
            managed_rendezvous: None,
            relay_mode: RelayMode::Fallback,
            enrollment_issuer_url: None,
            node_enrollment_path: None,
            node_enrollment_auto_renew_enabled: false,
            node_enrollment_auto_renew_check_secs: node_enrollment_auto_renew_check_secs(),
            node_enrollment_renewal_admin_token: None,
            heartbeat_timeout_secs: 90,
            audit_interval_secs: 3600,
            replica_view_sync_interval_secs: 5,
            replication_factor: 1,
            accepted_over_replication_items: 0,
            metadata_commit_mode: MetadataCommitMode::Local,
            autonomous_replication_on_put_enabled: false,
            replication_repair_enabled: false,
            replication_repair_batch_size: 256,
            replication_repair_max_retries: 3,
            replication_repair_backoff_secs: 30,
            repair_busy_throttle_enabled: false,
            repair_busy_inflight_threshold: 32,
            repair_busy_wait_millis: 100,
            startup_repair_enabled: false,
            startup_repair_delay_secs: 5,
            peer_heartbeat_enabled: false,
            peer_heartbeat_interval_secs: 15,
            admin_token: None,
            admin_password_hash: None,
            require_client_auth: false,
        }
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
    pub fn start_local_edge(data_dir: impl Into<PathBuf>) -> Result<Self> {
        let bind_addr = local_loopback_bind_addr()?;
        let config = ServerNodeConfig::local_edge(data_dir, bind_addr);
        Self::start(config)
    }

    pub fn start(config: ServerNodeConfig) -> Result<Self> {
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

fn local_loopback_bind_addr() -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("failed to allocate local loopback port")?;
    let bind_addr = listener
        .local_addr()
        .context("failed to read allocated local loopback port")?;
    drop(listener);
    Ok(bind_addr)
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
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .compact(),
        )
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

async fn run_inner(config: ServerNodeConfig, log_buffer: Option<Arc<LogBuffer>>) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = if config.node_enrollment_auto_renew_enabled {
        if let Some(enrollment_path) = config.node_enrollment_path.clone() {
            match renew_node_enrollment_package_if_due(&config).await {
                Ok(true) => {
                    info!(
                        enrollment_path = %enrollment_path.display(),
                        "renewed node enrollment package before startup"
                    );
                    ServerNodeConfig::from_enrollment_path(&enrollment_path)?
                }
                Ok(false) => config,
                Err(err) => {
                    warn!(error = %err, "failed automatic node enrollment renewal before startup");
                    config
                }
            }
        } else {
            config
        }
    } else {
        config
    };
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
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    let store = Arc::new(Mutex::new(
        PersistentStore::init_with_metadata_backend(
            config.data_dir.clone(),
            config.metadata_backend(),
        )
        .await?,
    ));
    info!(
        data_dir = %config.data_dir.display(),
        metadata_backend = ?config.metadata_backend(),
        "server node metadata backend initialized"
    );

    let internal_http = if let Some(internal_tls) = config.internal_tls.as_ref() {
        build_internal_mtls_http_client(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )?
    } else {
        reqwest::Client::new()
    };

    let persisted_cluster_replicas = {
        let store_guard = store.lock().await;
        match store_guard.load_cluster_replicas().await {
            Ok(replicas) => replicas,
            Err(err) => {
                warn!(error = %err, "failed to load cluster replica state; starting empty");
                HashMap::new()
            }
        }
    };
    cluster.import_replicas_by_key(persisted_cluster_replicas);

    let persisted_client_credentials = {
        let store_guard = store.lock().await;
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

    let state = ServerState {
        data_dir: config.data_dir.clone(),
        cluster_id: config.cluster_id,
        node_id: config.node_id,
        store,
        cluster: Arc::new(Mutex::new(cluster)),
        client_credentials: Arc::new(Mutex::new(persisted_client_credentials)),
        upload_sessions: Arc::new(Mutex::new(upload_session_store)),
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
            internal_http,
            rendezvous_control,
            rendezvous_controls,
        })),
        metadata_commit_mode: config.metadata_commit_mode,
        autonomous_replication_on_put_enabled: config.autonomous_replication_on_put_enabled,
        inflight_requests: Arc::new(AtomicUsize::new(0)),
        peer_heartbeat_config,
        repair_config,
        log_buffer: log_buffer.unwrap_or_else(|| Arc::new(LogBuffer::new(500))),
        startup_repair_status: Arc::new(Mutex::new(startup_repair_status)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
        namespace_change_sequence: Arc::new(AtomicU64::new(0)),
        namespace_change_tx: watch::channel(0).0,
        admin_control,
        admin_sessions: Arc::new(Mutex::new(AdminSessionStore::default())),
        client_auth_control,
        client_auth_replay_cache: Arc::new(Mutex::new(ClientAuthReplayCache::default())),
    };

    refresh_local_node_storage(&state).await;

    let persisted_attempts = {
        let store = state.store.lock().await;
        match store.load_repair_attempts().await {
            Ok(attempts) => attempts,
            Err(err) => {
                warn!(error = %err, "failed to load repair attempts state; starting empty");
                HashMap::new()
            }
        }
    };

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

        let relay_self_base_url = config
            .internal_tls
            .as_ref()
            .and_then(|tls| tls.internal_url.clone())
            .or_else(|| {
                if config.public_peer_api_enabled {
                    Some(public_url.clone())
                } else {
                    None
                }
            });
        if state.relay_mode != RelayMode::Disabled
            && let Some(self_base_url) = relay_self_base_url
        {
            spawn_rendezvous_relay_http_agent(state.clone(), self_base_url);
        }
    }

    let peer_sync_enabled =
        config.mode == ServerNodeMode::Cluster || config.rendezvous_registration_enabled;

    if peer_sync_enabled {
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
    }

    if config.node_enrollment_auto_renew_enabled {
        spawn_node_enrollment_auto_renew(
            state.clone(),
            config.clone(),
            config.node_enrollment_auto_renew_check_secs,
        );
    }

    let public_client_api = Router::new()
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

    let public_admin_api = Router::new()
        .route("/auth/admin/session", get(get_admin_session_status))
        .route("/auth/admin/login", post(login_admin_session))
        .route("/auth/admin/logout", post(logout_admin_session))
        .route("/auth/store/snapshots", get(list_snapshots_admin))
        .route("/auth/store/index", get(list_store_index_admin))
        .route("/auth/media/thumbnail", get(get_media_thumbnail_admin))
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
        .route("/auth/node-enrollments/renew", post(renew_node_enrollment))
        .route(
            "/auth/node-certificates/status",
            get(node_certificate_status),
        )
        .route("/auth/pairing-tokens/issue", post(issue_pairing_token));

    let public_peer_api = Router::new()
        .route(
            "/cluster/nodes/{node_id}/heartbeat",
            post(node_heartbeat_public),
        )
        .route(
            "/cluster/replication/subjects/local",
            get(local_replication_subjects),
        )
        .route(
            "/cluster/replication/export",
            get(export_replication_bundle),
        )
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
            "/cluster/reconcile/export/provisional",
            get(export_provisional_versions),
        );

    let mut public_app = Router::new()
        .route("/", get(ui::index))
        .route("/ui/app.css", get(ui::app_css))
        .route("/ui/app.js", get(ui::app_js))
        .route("/logs", get(ui::list_logs))
        .route("/health", get(health))
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route(
            "/cluster/nodes/{node_id}",
            put(register_node).delete(remove_node),
        )
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route("/cluster/replication/plan", get(replication_plan))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair),
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
        .merge(public_client_api);

    if config.public_peer_api_enabled {
        public_app = public_app.merge(public_peer_api);
    }

    let public_app = public_app
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_inflight_requests,
        ));

    let internal_app = Router::new()
        .route("/health", get(health))
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
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
        .route("/cluster/nodes/{node_id}/heartbeat", post(node_heartbeat))
        .route(
            "/cluster/replication/subjects/local",
            get(local_replication_subjects),
        )
        .route(
            "/cluster/replication/export",
            get(export_replication_bundle),
        )
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
            "/cluster/reconcile/export/provisional",
            get(export_provisional_versions),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_internal_caller,
        ));

    if let Some(internal_tls) = config.internal_tls.as_ref() {
        let internal_bind_addr = internal_tls.bind_addr;
        let internal_tls = state
            .internal_tls_runtime
            .as_ref()
            .map(|runtime| runtime.config.clone())
            .context("internal TLS runtime missing for configured internal listener")?;
        let internal_state = state.clone();
        tokio::spawn(async move {
            info!(
                bind_addr = %internal_bind_addr,
                node_id = %internal_state.node_id,
                "server node internal (mTLS) listener"
            );

            let acceptor = MtlsCallerAcceptor::new(internal_tls);
            if let Err(err) = axum_server::Server::bind(internal_bind_addr)
                .acceptor(acceptor)
                .serve(internal_app.into_make_service())
                .await
            {
                warn!(error = %err, "internal server listener stopped");
            }
        });
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

    if config.public_tls.is_some() {
        let tls_config = state
            .public_tls_runtime
            .as_ref()
            .map(|runtime| runtime.config.clone())
            .context("public TLS runtime missing for configured public listener")?;
        axum_server::bind_rustls(config.bind_addr, tls_config)
            .serve(public_app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
        axum::serve(listener, public_app).await?;
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
    let _ = cluster.update_node_storage(state.node_id, free_bytes, capacity_bytes);
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
    public_peer_api_enabled: bool,
    local_descriptor: Option<&NodeDescriptor>,
) -> PresenceRegistration {
    let mut direct_candidates = Vec::new();
    let mut seen_endpoints = BTreeSet::new();
    let public_api_url = public_peer_api_enabled
        .then(|| normalize_optional_url(public_url))
        .flatten();
    let peer_api_url = normalize_optional_url(internal_peer_url).or_else(|| public_api_url.clone());

    if public_peer_api_enabled {
        push_rendezvous_direct_candidate(&mut direct_candidates, &mut seen_endpoints, public_url);
    }
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
        push_ranked_peer_candidate(
            &mut candidates,
            &mut seen_endpoints,
            normalize_optional_url(node.public_api_url()),
            Some(100),
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

    match plan.path_kind {
        TransportPathKind::DirectHttps | TransportPathKind::DirectQuic => {
            let base_url = plan
                .candidate
                .as_ref()
                .map(|candidate| candidate.endpoint.trim_end_matches('/').to_string())
                .context("peer transport plan did not include a selected candidate")?;
            let internal_http = current_internal_http(state).await;
            execute_direct_peer_request(
                &internal_http,
                &base_url,
                method,
                path_and_query,
                headers,
                body,
            )
            .await
        }
        TransportPathKind::RelayTunnel => {
            execute_relay_peer_request(state, node, method, path_and_query, headers, body).await
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
    let mut request = http.request(method, url);
    for header in headers {
        request = request.header(header.name, header.value);
    }
    if !body.is_empty() {
        request = request.body(body);
    }

    let response = request
        .send()
        .await
        .context("failed sending direct peer request")?;
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
    let body = response
        .bytes()
        .await
        .context("failed reading direct peer response body")?;

    Ok(PeerHttpResponse {
        status,
        headers,
        body,
    })
}

async fn execute_relay_peer_request(
    state: &ServerState,
    node: &NodeDescriptor,
    method: reqwest::Method,
    path_and_query: &str,
    headers: Vec<RelayHttpHeader>,
    body: Vec<u8>,
) -> Result<PeerHttpResponse> {
    let rendezvous = current_rendezvous_control(state)
        .await
        .context("relay peer transport requires rendezvous control client")?;
    let ticket = rendezvous
        .issue_relay_ticket(&RelayTicketRequest {
            cluster_id: state.cluster_id,
            source: PeerIdentity::Node(state.node_id),
            target: PeerIdentity::Node(node.node_id),
            requested_expires_in_secs: Some(30),
        })
        .await
        .with_context(|| format!("failed issuing relay ticket for node {}", node.node_id))?;

    let response = rendezvous
        .submit_relay_http_request(&RelayHttpRequest {
            ticket,
            request_id: Uuid::now_v7().to_string(),
            method: method.as_str().to_string(),
            path_and_query: normalize_peer_path_and_query(path_and_query)?,
            headers,
            body_base64: encode_optional_body_base64(&body),
        })
        .await
        .with_context(|| {
            format!(
                "failed executing relayed peer request for node {}",
                node.node_id
            )
        })?;

    let status = response.status;
    let body = Bytes::from(response.body_bytes()?);
    let headers = response.headers;

    Ok(PeerHttpResponse {
        status,
        headers,
        body,
    })
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

fn spawn_rendezvous_relay_http_agent(state: ServerState, local_base_url: String) {
    tokio::spawn(async move {
        loop {
            let clients = current_rendezvous_endpoint_clients(&state).await;
            if clients.is_empty() {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            let cluster_id = state.cluster_id;
            let node_id = state.node_id;

            let mut polls = tokio::task::JoinSet::new();
            for endpoint in clients {
                polls.spawn(async move {
                    let result = endpoint
                        .control
                        .poll_relay_http_request(&RelayHttpPollRequest {
                            cluster_id,
                            target: PeerIdentity::Node(node_id),
                            wait_timeout_ms: Some(15_000),
                        })
                        .await;
                    (endpoint, result)
                });
            }

            let mut handled_request = false;
            while let Some(result) = polls.join_next().await {
                let Ok((endpoint, result)) = result else {
                    continue;
                };
                match result {
                    Ok(response) => {
                        let Some(request) = response.request else {
                            continue;
                        };
                        handled_request = true;
                        polls.abort_all();
                        let local_http = current_internal_http(&state).await;

                        let relay_response = match execute_local_relay_http_request(
                            &local_http,
                            &local_base_url,
                            &request,
                        )
                        .await
                        {
                            Ok(response) => response,
                            Err(err) => RelayHttpResponse {
                                cluster_id: request.cluster_id,
                                session_id: request.session_id.clone(),
                                request_id: request.request_id.clone(),
                                responder: request.target.clone(),
                                status: 502,
                                headers: vec![RelayHttpHeader {
                                    name: "content-type".to_string(),
                                    value: "text/plain; charset=utf-8".to_string(),
                                }],
                                body_base64: encode_optional_body_base64(
                                    format!("relay execution failed: {err:#}").as_bytes(),
                                ),
                            },
                        };

                        if let Err(err) = endpoint
                            .control
                            .respond_relay_http_request(&relay_response)
                            .await
                        {
                            warn!(
                                error = %err,
                                rendezvous_url = %endpoint.url,
                                request_id = %request.request_id,
                                "failed to submit relayed HTTP response"
                            );
                        }
                        break;
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            rendezvous_url = %endpoint.url,
                            "relay HTTP poll failed"
                        );
                    }
                }
            }

            if !handled_request {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    });
}

async fn execute_local_relay_http_request(
    local_http: &reqwest::Client,
    local_base_url: &str,
    request: &transport_sdk::PendingRelayHttpRequest,
) -> Result<RelayHttpResponse> {
    let url = join_peer_url(local_base_url, &request.path_and_query)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .with_context(|| format!("invalid relayed HTTP method {}", request.method))?;
    let mut outbound = local_http.request(method, url);
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("host")
            || header.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        outbound = outbound.header(&header.name, &header.value);
    }
    let body = request.body_bytes()?;
    if !body.is_empty() {
        outbound = outbound.body(body);
    }

    let response = outbound
        .send()
        .await
        .context("failed executing local relayed HTTP request")?;
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
    let body = response
        .bytes()
        .await
        .context("failed reading local relayed HTTP response body")?;

    Ok(RelayHttpResponse {
        cluster_id: request.cluster_id,
        session_id: request.session_id.clone(),
        request_id: request.request_id.clone(),
        responder: request.target.clone(),
        status,
        headers,
        body_base64: encode_optional_body_base64(&body),
    })
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
                let report = replication::execute_replication_repair_inner(&state, None).await;
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
struct LocalReplicationSubjectsResponse {
    node_id: NodeId,
    subject_count: usize,
    generated_at_unix: u64,
    subjects: Vec<String>,
}

pub(crate) async fn sync_replica_views_once(state: &ServerState) {
    let local_subjects = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

    let mut changed = {
        let mut cluster = state.cluster.lock().await;
        cluster.replace_node_replica_view(state.node_id, &local_subjects)
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

    for peer in peers {
        match execute_peer_request(
            state,
            &peer,
            reqwest::Method::GET,
            "/cluster/replication/subjects/local",
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<LocalReplicationSubjectsResponse>() {
                    Ok(payload) => {
                        let mut cluster = state.cluster.lock().await;
                        if cluster.replace_node_replica_view(payload.node_id, &payload.subjects) {
                            changed = true;
                        }
                    }
                    Err(err) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            error = %err,
                            "failed decoding replica subject sync payload"
                        );
                    }
                }
            }
            Ok(response) => {
                tracing::debug!(
                    node_id = %peer.node_id,
                    status = response.status,
                    "replica subject sync request rejected"
                );
            }
            Err(err) => {
                tracing::debug!(
                    node_id = %peer.node_id,
                    error = %err,
                    "failed replica subject sync request"
                );
            }
        }
    }

    if changed && let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            "failed persisting cluster replicas after replica subject sync"
        );
    }
}

fn spawn_replica_view_synchronizer(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));

        loop {
            ticker.tick().await;
            sync_replica_views_once(&state).await;
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

            match renew_node_enrollment_package_if_due(&config).await {
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
    let local_subjects = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };
    let cluster_subjects = {
        let cluster = state.cluster.lock().await;
        cluster.known_replication_subjects()
    };

    let mut subjects = BTreeSet::new();
    subjects.extend(local_subjects);
    subjects.extend(cluster_subjects);
    subjects.into_iter().collect()
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

fn spawn_startup_replication_repair(state: ServerState, delay_secs: u64) {
    tokio::spawn(async move {
        {
            let mut status = state.startup_repair_status.lock().await;
            *status = StartupRepairStatus::Running;
        }

        match run_startup_replication_repair_once(&state, delay_secs).await {
            Some((plan, report)) => {
                {
                    let mut status = state.startup_repair_status.lock().await;
                    *status = StartupRepairStatus::Completed;
                }
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
            }
            None => {
                {
                    let mut status = state.startup_repair_status.lock().await;
                    *status = StartupRepairStatus::SkippedNoGaps;
                }
                info!(
                    delay_secs,
                    "startup replication repair skipped: no replication gaps detected"
                );
            }
        }
    });
}

async fn run_startup_replication_repair_once(
    state: &ServerState,
    delay_secs: u64,
) -> Option<(ReplicationPlan, replication::ReplicationRepairReport)> {
    if delay_secs > 0 {
        tokio::time::sleep(Duration::from_secs(delay_secs)).await;
    }

    let keys = planning_replication_subjects(state).await;

    let plan = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster.replication_plan(&keys)
    };

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
                    Ok(response) if response.is_success() => {}
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
    let store = state.store.lock().await;
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

fn should_trigger_autonomous_post_write_replication(
    autonomous_replication_on_put_enabled: bool,
    internal_replication: bool,
) -> bool {
    autonomous_replication_on_put_enabled && !internal_replication
}

fn spawn_media_cache_warmup(state: ServerState, key: String, manifest_hash: String) {
    tokio::spawn(async move {
        let store = state.store.lock().await;
        if let Err(err) = store.ensure_media_cache(&manifest_hash).await {
            warn!(
                key = %key,
                manifest_hash = %manifest_hash,
                error = %err,
                "failed to warm media cache after write"
            );
        }
    });
}

async fn delete_object_by_query(
    State(state): State<ServerState>,
    Query(query): Query<DeleteObjectByQuery>,
) -> Response {
    if query.key.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    delete_object(
        State(state),
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
    if request.from_path.trim().is_empty() || request.to_path.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let mut store = state.store.lock().await;
    match store
        .rename_object_path(&request.from_path, &request.to_path, request.overwrite)
        .await
    {
        Ok(PathMutationResult::Applied) => {
            drop(store);
            publish_namespace_change(&state);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(PathMutationResult::SourceMissing) => StatusCode::NOT_FOUND.into_response(),
        Ok(PathMutationResult::TargetExists) => StatusCode::CONFLICT.into_response(),
        Err(err) => {
            tracing::error!(
                from_path = %request.from_path,
                to_path = %request.to_path,
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

    let mut store = state.store.lock().await;
    match store
        .copy_object_path(&request.from_path, &request.to_path, request.overwrite)
        .await
    {
        Ok(PathMutationResult::Applied) => {
            drop(store);
            publish_namespace_change(&state);
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

    let mut store = state.store.lock().await;
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
            spawn_media_cache_warmup(state.clone(), key.clone(), outcome.manifest_hash.clone());

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
                    let report =
                        replication::execute_replication_repair_inner(&state_for_repair, None)
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

    let mut sessions = state.upload_sessions.lock().await;
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
        completed: false,
        completed_result: None,
    };
    let response = upload_session_view(&session);
    sessions.sessions.insert(session.upload_id.clone(), session);
    if let Err(err) = persist_upload_session_store(&sessions).await {
        warn!(error = %err, "failed to persist upload session state");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn get_upload_session(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    let requester_device_id = request_device_id(&headers);
    let now = unix_ts();
    let mut sessions = state.upload_sessions.lock().await;
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
    let mut sessions = state.upload_sessions.lock().await;
    prune_expired_upload_sessions(&mut sessions, now);

    let Some(session) = sessions.sessions.get(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(owner_device_id) = session.owner_device_id.as_deref()
        && requester_device_id.as_deref() != Some(owner_device_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }

    sessions.sessions.remove(&upload_id);
    if let Err(err) = persist_upload_session_store(&sessions).await {
        warn!(error = %err, "failed to persist upload session deletion");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

async fn upload_session_chunk(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path((upload_id, index)): Path<(String, usize)>,
    payload: Bytes,
) -> impl IntoResponse {
    let requester_device_id = request_device_id(&headers);
    let now = unix_ts();

    let mut sessions = state.upload_sessions.lock().await;
    prune_expired_upload_sessions(&mut sessions, now);

    let Some(session) = sessions.sessions.get_mut(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Some(owner_device_id) = session.owner_device_id.as_deref()
        && requester_device_id.as_deref() != Some(owner_device_id)
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    if session.completed {
        return StatusCode::CONFLICT.into_response();
    }

    let Some(expected_size) = expected_upload_chunk_size(
        session.total_size_bytes,
        session.chunk_size_bytes,
        session.chunk_count,
        index,
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if payload.len() != expected_size {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let (hash, stored) = {
        let store = state.store.lock().await;
        match store.ingest_chunk_auto(&payload).await {
            Ok(result) => result,
            Err(err) => {
                tracing::warn!(error = %err, upload_id = %upload_id, index, "failed to ingest upload session chunk");
                return StatusCode::BAD_REQUEST.into_response();
            }
        }
    };
    let next_ref = UploadChunkRef {
        hash,
        size_bytes: payload.len(),
    };

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

    if let Err(err) = persist_upload_session_store(&sessions).await {
        warn!(error = %err, "failed to persist upload session chunk state");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::OK, Json(response)).into_response()
}

async fn complete_upload_session_route(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    let requester_device_id = request_device_id(&headers);
    let now = unix_ts();
    let mut sessions = state.upload_sessions.lock().await;
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
    if session.received_chunks.iter().any(|entry| entry.is_none()) {
        return StatusCode::CONFLICT.into_response();
    }

    let chunk_refs = session
        .received_chunks
        .iter()
        .filter_map(|entry| entry.clone())
        .collect::<Vec<_>>();

    let outcome = {
        let mut store = state.store.lock().await;
        match store
            .put_object_from_chunks(
                &session.key,
                session.total_size_bytes as usize,
                &chunk_refs,
                PutOptions {
                    parent_version_ids: session.parent_version_ids.clone(),
                    state: session.state.clone(),
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: session.explicit_version_id.clone(),
                },
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    key = %session.key,
                    upload_id = %upload_id,
                    "failed to finalize upload session"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    publish_namespace_change(&state);
    spawn_media_cache_warmup(
        state.clone(),
        session.key.clone(),
        outcome.manifest_hash.clone(),
    );

    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(&session.key, state.node_id);
    cluster.note_replica(
        format!("{}@{}", session.key, outcome.version_id.as_str()),
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
            let report =
                replication::execute_replication_repair_inner(&state_for_repair, None).await;
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
        total_size_bytes: session.total_size_bytes,
    };
    session.completed = true;
    session.completed_result = Some(response.clone());
    session.updated_at_unix = now;
    session.expires_at_unix = now.saturating_add(UPLOAD_SESSION_TTL_SECS);
    if let Err(err) = persist_upload_session_store(&sessions).await {
        warn!(error = %err, "failed to persist completed upload session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

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

    let mut store = state.store.lock().await;
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
                    let report =
                        replication::execute_replication_repair_inner(&state_for_repair, None)
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
    list_store_index_response(&state, query, "/media/thumbnail").await
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

    list_store_index_response(&state, query, "/auth/media/thumbnail").await
}

async fn list_store_index_response(
    state: &ServerState,
    query: StoreIndexQuery,
    thumbnail_route: &str,
) -> Response {
    let prefix = query.prefix.unwrap_or_default();
    let depth = query.depth.unwrap_or(1).max(1);

    let (keys, key_hashes, key_sizes, key_modified_times) = {
        let store = state.store.lock().await;
        if let Some(snapshot_id) = query.snapshot.as_deref() {
            match store.snapshot_object_state(snapshot_id).await {
                Ok(Some(snapshot_state)) => {
                    let object_hashes = snapshot_state.objects;
                    let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
                    keys.sort();
                    let sizes = match store.object_sizes_by_key(&object_hashes).await {
                        Ok(sizes) => sizes,
                        Err(err) => {
                            tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to compute snapshot key sizes");
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };
                    let modified_times = match store
                        .object_modified_at_by_key(
                            &object_hashes,
                            &snapshot_state.object_ids,
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
                    (keys, object_hashes, sizes, modified_times)
                }
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(err) => {
                    tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to list snapshot key index");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        } else {
            let object_hashes = store.current_object_hashes();
            let object_ids = store.current_object_ids();
            let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
            keys.sort();
            let sizes = match store.object_sizes_by_key(&object_hashes).await {
                Ok(sizes) => sizes,
                Err(err) => {
                    tracing::error!(error = %err, "failed to compute current key sizes");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let modified_times = match store
                .object_modified_at_by_key(&object_hashes, &object_ids, None)
                .await
            {
                Ok(modified_times) => modified_times,
                Err(err) => {
                    tracing::error!(error = %err, "failed to compute current key modified times");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            (keys, object_hashes, sizes, modified_times)
        }
    };

    let mut entries = build_store_index_entries_with_hashes(
        &keys,
        &prefix,
        depth,
        Some(&key_hashes),
        Some(&key_sizes),
        Some(&key_modified_times),
    );
    {
        let store = state.store.lock().await;
        for entry in &mut entries {
            if entry.entry_type != "key" || !looks_like_image_path(&entry.path) {
                continue;
            }

            let Some(manifest_hash) = entry.content_hash.as_deref() else {
                continue;
            };

            match store.lookup_media_cache(manifest_hash).await {
                Ok(Some(lookup)) => {
                    entry.content_fingerprint = Some(lookup.content_fingerprint.clone());
                    entry.media = Some(build_media_index_response(
                        &entry.path,
                        query.snapshot.as_deref(),
                        &lookup,
                        thumbnail_route,
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    warn!(
                        key = %entry.path,
                        manifest_hash = %manifest_hash,
                        error = %err,
                        "failed to read cached media metadata for store index"
                    );
                }
            }
        }
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
            media_type: Some("image".to_string()),
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

fn looks_like_image_path(path: &str) -> bool {
    let extension = path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "bmp" | "gif" | "jpeg" | "jpg" | "png" | "webp"
    )
}

#[cfg(test)]
fn build_store_index_entries(keys: &[String], prefix: &str, depth: usize) -> Vec<StoreIndexEntry> {
    build_store_index_entries_with_hashes(keys, prefix, depth, None, None, None)
}

fn build_store_index_entries_with_hashes(
    keys: &[String],
    prefix: &str,
    depth: usize,
    hashes_by_key: Option<&HashMap<String, String>>,
    sizes_by_key: Option<&HashMap<String, u64>>,
    modified_times_by_key: Option<&HashMap<String, u64>>,
) -> Vec<StoreIndexEntry> {
    let normalized_prefix = prefix.trim_end_matches('/');
    let mut file_entries = BTreeSet::new();
    let mut prefix_entries = BTreeSet::new();

    for key in keys {
        if !normalized_prefix.is_empty() && !key.starts_with(normalized_prefix) {
            continue;
        }

        let mut remainder = if normalized_prefix.is_empty() {
            key.as_str()
        } else {
            match key.strip_prefix(normalized_prefix) {
                Some(value) => value,
                None => continue,
            }
        };

        if remainder.starts_with('/') {
            remainder = remainder.trim_start_matches('/');
        }

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
            content_fingerprint: None,
            media: None,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
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

    let store = state.store.lock().await;
    let descriptor = match store
        .describe_object(
            key,
            query.snapshot.as_deref(),
            query.version.as_deref(),
            read_mode,
        )
        .await
    {
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

    let read_result = match selected_range {
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
    };

    match read_result {
        Ok((status, range, stream_plan)) => {
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

async fn get_media_thumbnail_response(state: &ServerState, query: MediaThumbnailQuery) -> Response {
    let read_mode = match parse_read_mode(query.read_mode.as_deref()) {
        Some(value) => value,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let metadata = {
        let store = state.store.lock().await;
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

        match store.ensure_media_cache(&manifest_hash).await {
            Ok(Some(metadata)) => metadata,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Err(err) => {
                tracing::error!(key = %query.key, error = %err, "failed to build media thumbnail cache");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    if metadata.status != MediaCacheStatus::Ready {
        return StatusCode::NOT_FOUND.into_response();
    }

    let Some(thumbnail) = metadata.thumbnail.as_ref() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let payload = {
        let store = state.store.lock().await;
        let thumbnail_path =
            store.media_thumbnail_path(&metadata.content_fingerprint, &thumbnail.profile);
        match tokio::fs::read(&thumbnail_path).await {
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
        }
    };

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
    let store = state.store.lock().await;
    match store.list_versions(&key).await {
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

    let mut store = state.store.lock().await;
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
}

#[derive(Debug, Deserialize)]
struct NodeHeartbeatRequest {
    free_bytes: Option<u64>,
    capacity_bytes: Option<u64>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
struct OutboundNodeHeartbeatRequest {
    free_bytes: Option<u64>,
    capacity_bytes: Option<u64>,
    labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct CleanupQuery {
    retention_secs: Option<u64>,
    dry_run: Option<bool>,
    approve: Option<bool>,
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

#[derive(Debug, Deserialize)]
struct NodeEnrollmentRenewRequest {
    package: NodeEnrollmentPackage,
    tls_validity_secs: Option<u64>,
    tls_renewal_window_secs: Option<u64>,
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
struct OutboundNodeEnrollmentRenewRequest {
    package: NodeEnrollmentPackage,
    tls_validity_secs: Option<u64>,
    tls_renewal_window_secs: Option<u64>,
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
    label: Option<String>,
    public_key_pem: String,
}

#[derive(Debug, Serialize)]
struct ClientDeviceEnrollResponse {
    cluster_id: ClusterId,
    device_id: String,
    label: Option<String>,
    public_key_pem: String,
    credential_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rendezvous_client_identity_pem: Option<String>,
    created_at_unix: u64,
    expires_at_unix: Option<u64>,
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
    let store = state.store.lock().await;
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
        Err(status) => return status.into_response(),
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
) -> std::result::Result<(TransportClientBootstrap, u64), StatusCode> {
    let rendezvous_urls = bootstrap_rendezvous_urls(state)?;
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
        trust_roots: bootstrap_trust_roots(state)?,
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
        mode: ClientBootstrapClaimTrustMode::RendezvousCaDerB64u,
        ca_der_b64u: Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cert.as_ref())),
        ca_pem: None,
    })
}

fn generate_bootstrap_claim_token() -> String {
    format!(
        "im-claim-{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

async fn resolve_bootstrap_claim_publish_target(
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

fn build_bootstrap_claim_publish_client(
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
            format!("failed to build rendezvous client for bootstrap claim publication: {err}"),
        )
    })
}

fn map_bootstrap_claim_publish_error(error: String) -> (StatusCode, String) {
    if error.contains("404") {
        (
            StatusCode::BAD_GATEWAY,
            "configured rendezvous service does not support bootstrap claims yet; restart it with the updated build".to_string(),
        )
    } else {
        (
            StatusCode::BAD_GATEWAY,
            format!("failed publishing bootstrap claim to rendezvous: {error}"),
        )
    }
}

async fn publish_client_bootstrap_claim(
    state: &ServerState,
    bootstrap: &TransportClientBootstrap,
    expires_at_unix: u64,
    preferred_rendezvous_url: Option<&str>,
) -> std::result::Result<ClientBootstrapClaim, (StatusCode, String)> {
    let rendezvous_urls =
        resolve_bootstrap_claim_publish_target(state, bootstrap, preferred_rendezvous_url).await?;
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
    let preferred_rendezvous_selected = preferred_rendezvous_url
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let mut last_error = None;

    for rendezvous_url in rendezvous_urls {
        let rendezvous = build_bootstrap_claim_publish_client(state, &rendezvous_url)?;
        match rendezvous.publish_bootstrap_claim(&publish_request).await {
            Ok(_) => {
                let claim = ClientBootstrapClaim {
                    version: CLIENT_BOOTSTRAP_CLAIM_VERSION,
                    kind: CLIENT_BOOTSTRAP_CLAIM_KIND.to_string(),
                    cluster_id: bootstrap.cluster_id,
                    rendezvous_url,
                    trust: claim_trust.clone(),
                    claim_token: claim_token.clone(),
                    expires_at_unix,
                };
                claim.validate().map_err(|err| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("failed to validate generated bootstrap claim: {err}"),
                    )
                })?;
                return Ok(claim);
            }
            Err(err) => {
                let error = err.to_string();
                if preferred_rendezvous_selected {
                    return Err(map_bootstrap_claim_publish_error(error));
                }
                last_error = Some(error);
            }
        }
    }

    Err(map_bootstrap_claim_publish_error(
        last_error.unwrap_or_else(|| {
            "bootstrap claim issuance requires a reachable rendezvous service".to_string()
        }),
    ))
}

fn build_bootstrap_direct_endpoints(
    public_url: Option<&str>,
    internal_url: Option<&str>,
    public_peer_api_enabled: bool,
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

    let peer_url = if public_peer_api_enabled {
        internal_url.or(public_url)
    } else {
        internal_url
    };
    if let Some(peer_url) = peer_url {
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
    let internal_bind_addr = request.internal_bind_addr.or_else(|| match mode {
        NodeBootstrapMode::Cluster => Some("127.0.0.1:18080".to_string()),
        NodeBootstrapMode::LocalEdge => None,
    });
    let internal_url = request
        .internal_url
        .or_else(|| internal_bind_addr.as_deref().map(default_internal_url));
    let public_peer_api_enabled = request
        .public_peer_api_enabled
        .unwrap_or(mode == NodeBootstrapMode::LocalEdge && !rendezvous_urls.is_empty());
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
        public_peer_api_enabled,
        internal_bind_addr: internal_bind_addr.clone(),
        internal_url: internal_url.clone(),
        internal_tls: request.internal_tls,
        rendezvous_urls,
        rendezvous_mtls_required: state.rendezvous_mtls_required,
        direct_endpoints: build_bootstrap_direct_endpoints(
            public_url.as_deref(),
            internal_url.as_deref(),
            public_peer_api_enabled,
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
    let mut subject_alt_names = Vec::new();
    let mut seen_dns = HashSet::new();
    let mut seen_ips = HashSet::new();

    subject_alt_names.push(SanType::URI(
        format!("urn:ironmesh:node:{}", bootstrap.node_id)
            .try_into()
            .context("invalid node identity URI SAN")?,
    ));

    if let Some(internal_url) = bootstrap.internal_url.as_deref() {
        let parsed =
            reqwest::Url::parse(internal_url).with_context(|| format!("invalid {internal_url}"))?;
        if let Some(host) = parsed.host_str() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                if seen_ips.insert(ip) {
                    subject_alt_names.push(SanType::IpAddress(ip));
                }
            } else if seen_dns.insert(host.to_string()) {
                subject_alt_names.push(SanType::DnsName(
                    host.try_into().context("invalid internal DNS SAN")?,
                ));
            }
        }
    }

    if let Some(bind_addr) = bootstrap.internal_bind_addr.as_deref()
        && let Ok(socket_addr) = bind_addr.parse::<SocketAddr>()
    {
        let ip = socket_addr.ip();
        if !ip.is_unspecified() && seen_ips.insert(ip) {
            subject_alt_names.push(SanType::IpAddress(ip));
        }
    }

    Ok(subject_alt_names)
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

fn issue_internal_node_tls_material(
    state: &ServerState,
    bootstrap: &TransportNodeBootstrap,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<BootstrapMutualTlsMaterial, StatusCode> {
    if bootstrap.internal_tls.is_none() {
        return Err(StatusCode::BAD_REQUEST);
    }
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
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ironmesh-node-{}", bootstrap.node_id),
    );
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.subject_alt_names =
        build_internal_node_subject_alt_names(bootstrap).map_err(|_| StatusCode::BAD_REQUEST)?;

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

fn issue_public_node_tls_material(
    state: &ServerState,
    bootstrap: &TransportNodeBootstrap,
    policy: NodeTlsIssuePolicy,
) -> std::result::Result<Option<BootstrapMutualTlsMaterial>, StatusCode> {
    if bootstrap.public_tls.is_none() {
        return Ok(None);
    }
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
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ironmesh-public-{}", bootstrap.node_id),
    );
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names =
        build_public_node_subject_alt_names(bootstrap).map_err(|_| StatusCode::BAD_REQUEST)?;

    let key_pair = KeyPair::generate().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert_pem = cert.pem();
    let metadata = build_tls_material_metadata(&cert_pem, policy)?;

    Ok(Some(BootstrapMutualTlsMaterial {
        ca_cert_pem: ca_cert_pem.to_string(),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        metadata,
    }))
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
        Err(status) => return status.into_response(),
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
            Err(status) => {
                let error = "failed to issue bootstrap bundle backing the bootstrap claim";
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
    let bootstrap_claim = match publish_client_bootstrap_claim(
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
            "expires_at_unix": response.bootstrap_claim.expires_at_unix,
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

async fn renew_node_enrollment(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<NodeEnrollmentRenewRequest>,
) -> impl IntoResponse {
    let action = "auth/node-enrollments/renew";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "node_id": request.package.bootstrap.node_id,
            "mode": request.package.bootstrap.mode,
            "tls_validity_secs": request.tls_validity_secs,
            "tls_renewal_window_secs": request.tls_renewal_window_secs,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    if let Err(err) = request.package.validate() {
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

    let issue_policy =
        match build_tls_issue_policy(request.tls_validity_secs, request.tls_renewal_window_secs) {
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

    let previous_public_fingerprint = request
        .package
        .public_tls_material
        .as_ref()
        .map(|material| material.metadata.certificate_fingerprint.clone());
    let previous_internal_fingerprint = request
        .package
        .internal_tls_material
        .as_ref()
        .map(|material| material.metadata.certificate_fingerprint.clone());

    let bootstrap = request.package.bootstrap;
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
                    json!({ "error": "failed to renew internal node TLS material" }),
                )
                .await;
                return (
                    status,
                    Json(json!({ "error": "failed to renew internal node TLS material" })),
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
                json!({ "error": "failed to renew public node TLS material" }),
            )
            .await;
            return (
                status,
                Json(json!({ "error": "failed to renew public node TLS material" })),
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
            "previous_public_certificate_fingerprint": previous_public_fingerprint,
            "new_public_certificate_fingerprint": package
                .public_tls_material
                .as_ref()
                .map(|material| material.metadata.certificate_fingerprint.clone()),
            "previous_internal_certificate_fingerprint": previous_internal_fingerprint,
            "new_internal_certificate_fingerprint": package
                .internal_tls_material
                .as_ref()
                .map(|material| material.metadata.certificate_fingerprint.clone()),
        }),
    )
    .await;

    (StatusCode::CREATED, Json(package)).into_response()
}

async fn issue_pairing_token_impl(
    state: &ServerState,
    request: PairingTokenIssueRequest,
) -> std::result::Result<PairingTokenIssueResponse, StatusCode> {
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
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(PairingTokenIssueResponse {
        token_id: record.token_id,
        pairing_token,
        label: record.label,
        created_at_unix: record.created_at_unix,
        expires_at_unix: record.expires_at_unix,
    })
}

async fn enroll_client_device(
    State(state): State<ServerState>,
    Json(request): Json<ClientDeviceEnrollRequest>,
) -> impl IntoResponse {
    if request.cluster_id != state.cluster_id {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let pairing_token = request.pairing_token.trim();
    let public_key_pem = request.public_key_pem.trim();
    if pairing_token.is_empty() || public_key_pem.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let now = unix_ts();
    let credential_expires_at_unix = Some(now + (30 * 24 * 60 * 60));
    let device_id = request
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
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
        &state,
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
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let response = {
        let mut auth_state = state.client_credentials.lock().await;
        auth_state
            .pairing_authorizations
            .retain(|token| token.used_at_unix.is_none() && token.expires_at_unix > now);

        if auth_state
            .credentials
            .iter()
            .any(|device| device.device_id == device_id && device.revoked_at_unix.is_none())
        {
            return StatusCode::CONFLICT.into_response();
        }

        let Some(pairing_auth) = auth_state.pairing_authorizations.iter_mut().find(|token| {
            token.used_at_unix.is_none()
                && token.expires_at_unix > now
                && token_matches(
                    token.pairing_secret_hash.as_str(),
                    Some(provided_hash.as_str()),
                )
        }) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        pairing_auth.used_at_unix = Some(now);
        pairing_auth.consumed_by_device_id = Some(device_id.clone());

        let final_label = label.or_else(|| pairing_auth.label.clone());
        let public_key_fingerprint = text_fingerprint(public_key_pem);
        let credential_fingerprint = match credential_fingerprint(&credential_pem) {
            Ok(fingerprint) => fingerprint,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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

        ClientDeviceEnrollResponse {
            cluster_id: state.cluster_id,
            device_id,
            label: final_label,
            public_key_pem: public_key_pem.to_string(),
            credential_pem,
            rendezvous_client_identity_pem,
            created_at_unix: now,
            expires_at_unix: credential_expires_at_unix,
        }
    };

    if let Err(err) = persist_client_credential_state(&state).await {
        warn!(
            error = %err,
            "failed to persist client credential state after enrollment"
        );
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::CREATED, Json(response)).into_response()
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
    *state.outbound_clients.write().await = outbound_clients;
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

async fn node_heartbeat_public(
    State(state): State<ServerState>,
    Path(node_id): Path<String>,
    Json(request): Json<NodeHeartbeatRequest>,
) -> impl IntoResponse {
    let node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

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

async fn local_replication_subjects(State(state): State<ServerState>) -> impl IntoResponse {
    let subjects = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

    (
        StatusCode::OK,
        Json(LocalReplicationSubjectsResponse {
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
        let mut store = state.store.lock().await;
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
        if let Some(version_id) = &query.version_id {
            cluster.remove_replica(&format!("{}@{}", query.key, version_id), state.node_id);
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
            let store = state.store.lock().await;
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
                    cluster.remove_replica(
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
struct ReplicationManifestPushReport {
    version_id: String,
}

async fn export_replication_bundle(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationExportQuery>,
) -> impl IntoResponse {
    let store = state.store.lock().await;
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

async fn get_replication_chunk(
    State(state): State<ServerState>,
    Path(hash): Path<String>,
) -> impl IntoResponse {
    let store = state.store.lock().await;
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
    let store = state.store.lock().await;
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
        let mut store = state.store.lock().await;
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

    let store = state.store.lock().await;
    store.persist_repair_attempts(&attempts).await
}

async fn persist_cluster_replicas_state(state: &ServerState) -> Result<()> {
    let replicas = {
        let cluster = state.cluster.lock().await;
        cluster.export_replicas_by_key()
    };

    let store = state.store.lock().await;
    store.persist_cluster_replicas(&replicas).await
}

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

fn build_internal_mtls_http_client(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<reqwest::Client> {
    let ca_pem =
        std::fs::read(ca_path).with_context(|| format!("failed reading {}", ca_path.display()))?;
    let ca_cert =
        reqwest::Certificate::from_pem(&ca_pem).context("failed parsing internal CA PEM")?;

    let identity_pem = build_identity_pem_from_paths(cert_path, key_path)?;

    let identity = reqwest::Identity::from_pem(&identity_pem)
        .context("failed parsing internal node identity PEM")?;

    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
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
const ADMIN_SESSION_COOKIE: &str = "ironmesh_admin_session";

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
    let session_id = parse_cookie_value(headers, ADMIN_SESSION_COOKIE)?;
    let mut sessions = state.admin_sessions.lock().await;
    sessions.is_valid(&session_id, unix_ts())
}

fn password_hash_matches(expected_hash: &str, password: &str) -> bool {
    let provided_hash = hash_token(password);
    constant_time_eq(expected_hash.as_bytes(), provided_hash.as_bytes())
}

fn build_admin_session_cookie(
    session_id: &str,
    secure: bool,
    max_age_secs: u64,
) -> Result<HeaderValue> {
    let mut cookie = format!(
        "{ADMIN_SESSION_COOKIE}={session_id}; Path=/; Max-Age={max_age_secs}; HttpOnly; SameSite=Lax"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    HeaderValue::from_str(&cookie).context("failed building admin session cookie header")
}

fn clear_admin_session_cookie(secure: bool) -> Result<HeaderValue> {
    let mut cookie = format!("{ADMIN_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
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
    let store = state.store.lock().await;
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
    let auth_configured = state.admin_control.admin_password_hash.is_some()
        || state.admin_control.admin_token.is_some();
    let authenticated = if auth_configured {
        token_valid || session_expires_at_unix.is_some()
    } else {
        true
    };

    (
        StatusCode::OK,
        Json(AdminSessionStatusResponse {
            login_required: auth_configured,
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
    let cookie = match build_admin_session_cookie(
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
    let session_id = parse_cookie_value(&headers, ADMIN_SESSION_COOKIE);
    if let Some(session_id) = session_id.as_deref() {
        let mut sessions = state.admin_sessions.lock().await;
        sessions.revoke(session_id);
    }

    let cookie = match clear_admin_session_cookie(state.public_tls_runtime.is_some()) {
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
            login_required: state.admin_control.admin_password_hash.is_some()
                || state.admin_control.admin_token.is_some(),
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

    let requires_admin_auth = state.admin_control.admin_token.is_some()
        || state.admin_control.admin_password_hash.is_some();
    if requires_admin_auth && !token_valid && session_expires_at_unix.is_none() {
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
        let store = state.store.lock().await;
        store.cleanup_unreferenced(retention_secs, dry_run).await
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
        let store = state.store.lock().await;
        store
            .compact_tombstone_indexes(retention_secs, dry_run)
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
        let store = state.store.lock().await;
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
        let store = state.store.lock().await;
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
        let store = state.store.lock().await;
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
    let store = state.store.lock().await;
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
            let store = state.store.lock().await;
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
            let store = state.store.lock().await;
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
                let store = state.store.lock().await;
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
            let mut store = state.store.lock().await;
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
                    let store = state.store.lock().await;
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
