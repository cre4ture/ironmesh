use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
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
use bytes::Bytes;
use common::{ClusterId, HealthStatus, NodeId};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use tokio::sync::{Mutex, watch};
use tower::Service;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, CandidateKind,
    ClientBootstrap as TransportClientBootstrap, ConnectionCandidate, PeerIdentity,
    PeerTransportClient, PeerTransportClientConfig, PresenceRegistration, RelayHttpHeader,
    RelayHttpPollRequest, RelayHttpRequest, RelayHttpResponse, RelayMode, RelayTicketRequest,
    RendezvousClientConfig, RendezvousControlClient, SignedRequestHeaders, TransportCapability,
    TransportPathKind, credential_fingerprint, encode_optional_body_base64,
    verify_signed_request_headers,
};
use uuid::Uuid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

mod cluster;
mod replication;
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

use cluster::{ClusterService, NodeDescriptor, ReplicationPlan, ReplicationPolicy};
use storage::{
    AdminAuditEvent, ClientAuthState, DeviceAuthRecord, MediaCacheLookup, MediaCacheStatus,
    MediaGpsCoordinates, MetadataBackendKind, ObjectReadMode, PairingTokenRecord,
    PathMutationResult, PersistentStore, PutOptions, ReconcileVersionEntry, RepairAttemptRecord,
    StoreReadError, UploadChunkRef, VersionConsistencyState,
};

#[derive(Clone)]
struct ServerState {
    cluster_id: ClusterId,
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
    cluster: Arc<Mutex<ClusterService>>,
    client_auth: Arc<Mutex<ClientAuthState>>,
    public_ca_pem: Option<String>,
    cluster_ca_pem: Option<String>,
    rendezvous_urls: Vec<String>,
    rendezvous_control: Option<RendezvousControlClient>,
    relay_mode: RelayMode,
    metadata_commit_mode: MetadataCommitMode,
    internal_http: reqwest::Client,
    autonomous_replication_on_put_enabled: bool,
    inflight_requests: Arc<AtomicUsize>,
    replication_audit_interval_secs: u64,
    peer_heartbeat_config: PeerHeartbeatConfig,
    repair_config: RepairConfig,
    log_buffer: Arc<LogBuffer>,
    startup_repair_status: Arc<Mutex<StartupRepairStatus>>,
    repair_state: Arc<Mutex<RepairExecutorState>>,
    namespace_change_sequence: Arc<AtomicU64>,
    namespace_change_tx: watch::Sender<u64>,
    admin_control: AdminControl,
    client_auth_control: ClientAuthControl,
    client_auth_replay_cache: Arc<Mutex<ClientAuthReplayCache>>,
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

#[derive(Debug, Default)]
struct ClientAuthReplayCache {
    seen_requests: HashMap<String, u64>,
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

const CLIENT_AUTH_MAX_CLOCK_SKEW_SECS: u64 = 300;

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
        let auth_state = state.client_auth.lock().await;
        let Some(device) = auth_state.devices.iter().find(|device| {
            device.revoked_at_unix.is_none() && device.device_id == signed_headers.device_id
        }) else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let Some(public_key_pem) = device.public_key_pem.clone() else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let Some(issued_credential_pem) = device.issued_credential_pem.as_deref() else {
            return Err(StatusCode::UNAUTHORIZED);
        };
        let stored_credential_fingerprint =
            credential_fingerprint(issued_credential_pem).map_err(|_| StatusCode::UNAUTHORIZED)?;
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

fn generate_device_token() -> String {
    format!(
        "im-dev-{}{}",
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
}

#[derive(Debug, Clone)]
pub struct PublicTlsConfig {
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
    pub public_peer_api_enabled: bool,
    pub internal_tls: Option<InternalTlsConfig>,
    pub rendezvous_urls: Vec<String>,
    pub rendezvous_registration_enabled: bool,
    pub relay_mode: RelayMode,
    pub upstream_public_url: Option<String>,
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
}

#[derive(Debug, Clone, Copy)]
enum StartupRepairStatus {
    Disabled,
    Scheduled,
    Running,
    SkippedNoGaps,
    Completed,
}

fn startup_repair_status_label(status: StartupRepairStatus) -> &'static str {
    match status {
        StartupRepairStatus::Disabled => "disabled",
        StartupRepairStatus::Scheduled => "scheduled",
        StartupRepairStatus::Running => "running",
        StartupRepairStatus::SkippedNoGaps => "completed (no gaps)",
        StartupRepairStatus::Completed => "completed",
    }
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

impl ServerNodeConfig {
    pub fn from_env() -> Result<Self> {
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
            (Some(cert), Some(key)) => Some(PublicTlsConfig {
                cert_path: PathBuf::from(cert),
                key_path: PathBuf::from(key),
            }),
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
                Some(InternalTlsConfig {
                    bind_addr: internal_bind_addr,
                    internal_url: std::env::var("IRONMESH_INTERNAL_URL")
                        .ok()
                        .or_else(|| Some(format!("https://{internal_bind_addr}"))),
                    ca_cert_path: PathBuf::from(
                        std::env::var("IRONMESH_INTERNAL_TLS_CA_CERT")
                            .context("missing IRONMESH_INTERNAL_TLS_CA_CERT")?,
                    ),
                    cert_path: PathBuf::from(
                        std::env::var("IRONMESH_INTERNAL_TLS_CERT")
                            .context("missing IRONMESH_INTERNAL_TLS_CERT")?,
                    ),
                    key_path: PathBuf::from(
                        std::env::var("IRONMESH_INTERNAL_TLS_KEY")
                            .context("missing IRONMESH_INTERNAL_TLS_KEY")?,
                    ),
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

        let default_replication_factor = if mode == ServerNodeMode::LocalEdge {
            if std::env::var("IRONMESH_UPSTREAM_PUBLIC_URL")
                .ok()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
            {
                2
            } else {
                1
            }
        } else {
            3
        };

        let upstream_public_url = std::env::var("IRONMESH_UPSTREAM_PUBLIC_URL")
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty());
        let upstream_configured = upstream_public_url.is_some();
        let public_peer_api_enabled = std::env::var("IRONMESH_PUBLIC_PEER_API_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(mode == ServerNodeMode::LocalEdge && upstream_configured);
        let default_audit_interval_secs =
            if mode == ServerNodeMode::LocalEdge && upstream_configured {
                5
            } else {
                3600
            };
        let default_replication_repair_backoff_secs =
            if mode == ServerNodeMode::LocalEdge && upstream_configured {
                2
            } else {
                30
            };

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
            public_peer_api_enabled,
            internal_tls,
            rendezvous_urls,
            rendezvous_registration_enabled,
            relay_mode,
            upstream_public_url,
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
                ServerNodeMode::LocalEdge => upstream_configured,
            },
            replication_repair_enabled: match mode {
                ServerNodeMode::Cluster => std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
                    .ok()
                    .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                    .unwrap_or(false),
                ServerNodeMode::LocalEdge => upstream_configured,
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
                ServerNodeMode::LocalEdge => upstream_configured,
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
            public_peer_api_enabled: false,
            internal_tls: None,
            rendezvous_urls: vec![format!("http://{bind_addr}")],
            rendezvous_registration_enabled: false,
            relay_mode: RelayMode::Fallback,
            upstream_public_url: None,
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
            require_client_auth: false,
        }
    }

    pub fn local_edge_with_upstream(
        data_dir: impl Into<PathBuf>,
        bind_addr: SocketAddr,
        upstream_public_url: impl Into<String>,
    ) -> Self {
        let mut config = Self::local_edge(data_dir, bind_addr);
        config.upstream_public_url = Some(
            upstream_public_url
                .into()
                .trim()
                .trim_end_matches('/')
                .to_string(),
        );
        config.public_peer_api_enabled = true;
        config.replication_factor = 2;
        config.audit_interval_secs = 5;
        config.autonomous_replication_on_put_enabled = true;
        config.replication_repair_enabled = true;
        config.replication_repair_backoff_secs = 1;
        config.startup_repair_enabled = true;
        config
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

    pub fn start_local_edge_with_upstream(
        data_dir: impl Into<PathBuf>,
        upstream_public_url: impl Into<String>,
    ) -> Result<Self> {
        let bind_addr = local_loopback_bind_addr()?;
        let config =
            ServerNodeConfig::local_edge_with_upstream(data_dir, bind_addr, upstream_public_url);
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
    run_inner(ServerNodeConfig::from_env()?, Some(log_buffer)).await
}

pub async fn run(config: ServerNodeConfig) -> Result<()> {
    run_inner(config, None).await
}

async fn run_inner(config: ServerNodeConfig, log_buffer: Option<Arc<LogBuffer>>) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

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
        public_url: public_url.clone(),
        internal_url,
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

    let persisted_client_auth = {
        let store_guard = store.lock().await;
        match store_guard.load_client_auth_state().await {
            Ok(state) => state,
            Err(err) => {
                warn!(error = %err, "failed to load client auth state; starting empty");
                ClientAuthState::default()
            }
        }
    };

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
        .transpose()?;
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
        .transpose()?;
    let rendezvous_control = if config.rendezvous_registration_enabled {
        match RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id: config.cluster_id,
                rendezvous_urls: config.rendezvous_urls.clone(),
                heartbeat_interval_secs: config.peer_heartbeat_interval_secs.max(5),
            },
            public_ca_pem.as_deref().or(cluster_ca_pem.as_deref()),
        ) {
            Ok(client) => Some(client),
            Err(err) => {
                warn!(error = %err, "failed to initialize rendezvous control client");
                None
            }
        }
    } else {
        None
    };

    let state = ServerState {
        cluster_id: config.cluster_id,
        node_id: config.node_id,
        store,
        cluster: Arc::new(Mutex::new(cluster)),
        client_auth: Arc::new(Mutex::new(persisted_client_auth)),
        public_ca_pem,
        cluster_ca_pem,
        rendezvous_urls: config.rendezvous_urls.clone(),
        rendezvous_control,
        relay_mode: config.relay_mode,
        metadata_commit_mode: config.metadata_commit_mode,
        internal_http,
        autonomous_replication_on_put_enabled: config.autonomous_replication_on_put_enabled,
        inflight_requests: Arc::new(AtomicUsize::new(0)),
        replication_audit_interval_secs: config.audit_interval_secs,
        peer_heartbeat_config,
        repair_config,
        log_buffer: log_buffer.unwrap_or_else(|| Arc::new(LogBuffer::new(500))),
        startup_repair_status: Arc::new(Mutex::new(startup_repair_status)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
        namespace_change_sequence: Arc::new(AtomicU64::new(0)),
        namespace_change_tx: watch::channel(0).0,
        admin_control,
        client_auth_control,
        client_auth_replay_cache: Arc::new(Mutex::new(ClientAuthReplayCache::default())),
    };

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

    if let Some(client) = state.rendezvous_control.clone() {
        spawn_rendezvous_peer_discovery(
            state.clone(),
            client.clone(),
            config.replica_view_sync_interval_secs,
        );
        spawn_rendezvous_presence_heartbeat(
            state.clone(),
            client.clone(),
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
            && let Some(self_base_url) = relay_self_base_url {
                let self_http = if let Some(internal_tls) = config.internal_tls.as_ref() {
                    build_internal_mtls_http_client(
                        &internal_tls.ca_cert_path,
                        &internal_tls.cert_path,
                        &internal_tls.key_path,
                    )
                } else {
                    build_http_client_from_optional_pem(state.public_ca_pem.as_deref())
                };
                match self_http {
                    Ok(self_http) => {
                        spawn_rendezvous_relay_http_agent(
                            state.clone(),
                            client,
                            self_http,
                            self_base_url,
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to initialize relay self HTTP client");
                    }
                }
            }
    }

    let peer_sync_enabled = config.mode == ServerNodeMode::Cluster
        || config.upstream_public_url.is_some()
        || config.rendezvous_registration_enabled;

    if let Some(upstream_public_url) = config.upstream_public_url.clone() {
        if let Err(err) =
            refresh_upstream_peer(&state, &state.internal_http, upstream_public_url.as_str()).await
        {
            tracing::debug!(
                error = %err,
                upstream = %upstream_public_url,
                "initial upstream peer refresh failed"
            );
        }
        spawn_upstream_peer_bootstrap(
            state.clone(),
            upstream_public_url,
            config.replica_view_sync_interval_secs,
        );
    }

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

    let public_client_api = Router::new()
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store-chunks/upload", post(upload_store_chunk))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .delete(delete_object)
                .post(complete_chunked_upload),
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
        .route("/auth/devices", get(list_client_devices))
        .route(
            "/auth/devices/{device_id}",
            axum::routing::delete(revoke_client_device),
        )
        .route(
            "/auth/bootstrap-bundles/issue",
            post(issue_bootstrap_bundle),
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
        .route("/ui/qrcode.min.js", get(ui::qrcode_js))
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
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store-chunks/upload", post(upload_store_chunk))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .delete(delete_object)
                .post(complete_chunked_upload),
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
        let internal_tls = build_internal_mtls_rustls_config(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )?;
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

    info!(
        bind_addr = %config.bind_addr,
        node_id = %config.node_id,
        tls_enabled = config.public_tls.is_some(),
        mode = ?config.mode,
        "server node listening"
    );

    if let Some(public_tls) = config.public_tls.as_ref() {
        let tls_config = RustlsConfig::from_pem_file(&public_tls.cert_path, &public_tls.key_path)
            .await
            .with_context(|| {
                format!(
                    "failed building public TLS config from {} and {}",
                    public_tls.cert_path.display(),
                    public_tls.key_path.display()
                )
            })?;
        axum_server::bind_rustls(config.bind_addr, tls_config)
            .serve(public_app.into_make_service())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(config.bind_addr).await?;
        axum::serve(listener, public_app).await?;
    }

    Ok(())
}

fn spawn_rendezvous_presence_heartbeat(
    state: ServerState,
    client: RendezvousControlClient,
    public_url: Option<String>,
    internal_peer_url: Option<String>,
    public_peer_api_enabled: bool,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
        ticker.tick().await;

        loop {
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

            match client.register_presence(&registration).await {
                Ok(response) => {
                    tracing::debug!(
                        node_id = %state.node_id,
                        updated_at_unix = response.updated_at_unix,
                        "registered rendezvous presence"
                    );
                }
                Err(err) => {
                    warn!(
                        error = %err,
                        node_id = %state.node_id,
                        rendezvous_urls = ?client.config().rendezvous_urls,
                        "failed to register rendezvous presence"
                    );
                }
            }

            ticker.tick().await;
        }
    });
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

fn spawn_rendezvous_peer_discovery(
    state: ServerState,
    client: RendezvousControlClient,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));
        ticker.tick().await;

        loop {
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
        .capabilities.contains(&TransportCapability::RelayTunnel)
        || entry.registration.relay_mode != RelayMode::Disabled;
    if peer_api_url.is_none() && !has_relay_capability {
        return None;
    }
    let public_api_url = entry
        .registration
        .public_api_url
        .as_deref()
        .and_then(|value| normalize_optional_url(Some(value)))
        .or_else(|| peer_api_url.clone())
        .unwrap_or_default();

    Some(NodeDescriptor {
        node_id: *node_id,
        public_url: public_api_url,
        internal_url: peer_api_url.unwrap_or_default(),
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
        prefer_direct: true,
        allow_relay: state.relay_mode != RelayMode::Disabled,
    })
}

fn peer_connection_candidates(
    state: &ServerState,
    node: &NodeDescriptor,
) -> Vec<ConnectionCandidate> {
    let mut candidates = Vec::new();
    let mut seen_endpoints = BTreeSet::new();

    push_ranked_peer_candidate(
        &mut candidates,
        &mut seen_endpoints,
        normalize_optional_url(Some(node.internal_url.as_str())),
        Some(1),
    );
    push_ranked_peer_candidate(
        &mut candidates,
        &mut seen_endpoints,
        normalize_optional_url(Some(node.public_url.as_str())),
        Some(100),
    );
    if state.relay_mode != RelayMode::Disabled {
        for relay_url in &state.rendezvous_urls {
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
            "node {} requires relay peer transport, which is not implemented yet",
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
            execute_direct_peer_request(
                &state.internal_http,
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
    let rendezvous = state
        .rendezvous_control
        .clone()
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

fn spawn_rendezvous_relay_http_agent(
    state: ServerState,
    client: RendezvousControlClient,
    local_http: reqwest::Client,
    local_base_url: String,
) {
    tokio::spawn(async move {
        loop {
            match client
                .poll_relay_http_request(&RelayHttpPollRequest {
                    cluster_id: state.cluster_id,
                    target: PeerIdentity::Node(state.node_id),
                    wait_timeout_ms: Some(15_000),
                })
                .await
            {
                Ok(response) => {
                    let Some(request) = response.request else {
                        continue;
                    };

                    let relay_response = match execute_local_relay_http_request(
                        &local_http,
                        &local_base_url,
                        &request,
                    )
                    .await
                    {
                        Ok(response) => response,
                        Err(err) => RelayHttpResponse {
                            request_id: request.request_id.clone(),
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

                    if let Err(err) = client.respond_relay_http_request(&relay_response).await {
                        warn!(
                            error = %err,
                            request_id = %request.request_id,
                            "failed to submit relayed HTTP response"
                        );
                    }
                }
                Err(err) => {
                    warn!(error = %err, "relay HTTP poll failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
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
        request_id: request.request_id.clone(),
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

fn spawn_upstream_peer_bootstrap(
    state: ServerState,
    upstream_public_url: String,
    interval_secs: u64,
) {
    tokio::spawn(async move {
        let http = state.internal_http.clone();
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
        let upstream_public_url = upstream_public_url.trim().trim_end_matches('/').to_string();

        loop {
            ticker.tick().await;

            match refresh_upstream_peer(&state, &http, upstream_public_url.as_str()).await {
                Ok(node_id) => {
                    tracing::debug!(node_id = %node_id, upstream = %upstream_public_url, "refreshed upstream peer registration");
                }
                Err(err) => {
                    tracing::debug!(error = %err, upstream = %upstream_public_url, "failed refreshing upstream peer registration");
                }
            }
        }
    });
}

async fn refresh_upstream_peer(
    state: &ServerState,
    http: &reqwest::Client,
    upstream_public_url: &str,
) -> Result<NodeId> {
    let base = upstream_public_url.trim_end_matches('/');
    let health_url = format!("{base}/health");
    let health = http
        .get(health_url)
        .send()
        .await
        .context("failed calling upstream health endpoint")?
        .error_for_status()
        .context("upstream health endpoint returned error")?
        .json::<HealthStatus>()
        .await
        .context("failed decoding upstream health payload")?;

    let mut upstream_descriptor = match http.get(format!("{base}/cluster/nodes")).send().await {
        Ok(response) => match response.error_for_status() {
            Ok(response) => response
                .json::<Vec<NodeDescriptor>>()
                .await
                .ok()
                .and_then(|nodes| {
                    nodes
                        .into_iter()
                        .find(|node| node.node_id == health.node_id)
                })
                .unwrap_or_else(|| NodeDescriptor {
                    node_id: health.node_id,
                    public_url: base.to_string(),
                    internal_url: base.to_string(),
                    labels: HashMap::from([
                        ("region".to_string(), "upstream".to_string()),
                        ("dc".to_string(), "upstream".to_string()),
                        ("rack".to_string(), "upstream".to_string()),
                    ]),
                    capacity_bytes: 0,
                    free_bytes: 0,
                    last_heartbeat_unix: unix_ts(),
                    status: cluster::NodeStatus::Online,
                }),
            Err(_) => NodeDescriptor {
                node_id: health.node_id,
                public_url: base.to_string(),
                internal_url: base.to_string(),
                labels: HashMap::from([
                    ("region".to_string(), "upstream".to_string()),
                    ("dc".to_string(), "upstream".to_string()),
                    ("rack".to_string(), "upstream".to_string()),
                ]),
                capacity_bytes: 0,
                free_bytes: 0,
                last_heartbeat_unix: unix_ts(),
                status: cluster::NodeStatus::Online,
            },
        },
        Err(_) => NodeDescriptor {
            node_id: health.node_id,
            public_url: base.to_string(),
            internal_url: base.to_string(),
            labels: HashMap::from([
                ("region".to_string(), "upstream".to_string()),
                ("dc".to_string(), "upstream".to_string()),
                ("rack".to_string(), "upstream".to_string()),
            ]),
            capacity_bytes: 0,
            free_bytes: 0,
            last_heartbeat_unix: unix_ts(),
            status: cluster::NodeStatus::Online,
        },
    };
    upstream_descriptor.public_url = base.to_string();
    upstream_descriptor.internal_url = base.to_string();

    let mut cluster = state.cluster.lock().await;
    cluster.register_node(NodeDescriptor {
        node_id: upstream_descriptor.node_id,
        public_url: upstream_descriptor.public_url,
        internal_url: upstream_descriptor.internal_url,
        labels: upstream_descriptor.labels,
        capacity_bytes: upstream_descriptor.capacity_bytes,
        free_bytes: upstream_descriptor.free_bytes,
        last_heartbeat_unix: unix_ts(),
        status: cluster::NodeStatus::Online,
    });

    Ok(health.node_id)
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
    })
}

async fn list_snapshots(State(state): State<ServerState>) -> impl IntoResponse {
    let store = state.store.lock().await;
    match store.list_snapshots().await {
        Ok(snapshots) => (StatusCode::OK, Json(snapshots)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to list snapshots");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct ObjectGetQuery {
    snapshot: Option<String>,
    version: Option<String>,
    read_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StoreIndexQuery {
    prefix: Option<String>,
    depth: Option<usize>,
    snapshot: Option<String>,
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
struct StoreChunkUploadResponse {
    hash: String,
    size_bytes: usize,
    stored: bool,
}

#[derive(Debug, Deserialize)]
struct CompleteStoreUploadRequest {
    total_size_bytes: usize,
    chunks: Vec<UploadChunkRef>,
}

#[derive(Debug, Deserialize)]
struct CompleteStoreUploadQuery {
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    version_id: Option<String>,
    #[serde(default)]
    internal_replication: bool,
    complete: Option<String>,
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

async fn upload_store_chunk(State(state): State<ServerState>, payload: Bytes) -> impl IntoResponse {
    if payload.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let store = state.store.lock().await;
    match store.ingest_chunk_auto(&payload).await {
        Ok((hash, stored)) => (
            StatusCode::OK,
            Json(StoreChunkUploadResponse {
                hash,
                size_bytes: payload.len(),
                stored,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::warn!(error = %err, "failed to ingest store chunk upload");
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn complete_chunked_upload(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    Query(query): Query<CompleteStoreUploadQuery>,
    Json(payload): Json<CompleteStoreUploadRequest>,
) -> impl IntoResponse {
    if query.complete.is_none() {
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

    let mut store = state.store.lock().await;
    match store
        .put_object_from_chunks(
            &key,
            payload.total_size_bytes,
            &payload.chunks,
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
                warn!(
                    error = %err,
                    "failed to persist cluster replicas after chunked upload complete"
                );
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
                "stored object from chunked upload"
            );
            StatusCode::CREATED
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                key = %key,
                "failed to finalize chunked object upload"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
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
    let prefix = query.prefix.unwrap_or_default();
    let depth = query.depth.unwrap_or(1).max(1);

    let (keys, key_hashes, key_sizes) = {
        let store = state.store.lock().await;
        if let Some(snapshot_id) = query.snapshot.as_deref() {
            match store.snapshot_object_hashes(snapshot_id).await {
                Ok(Some(object_hashes)) => {
                    let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
                    keys.sort();
                    let sizes = match store.object_sizes_by_key(&object_hashes).await {
                        Ok(sizes) => sizes,
                        Err(err) => {
                            tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to compute snapshot key sizes");
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };
                    (keys, object_hashes, sizes)
                }
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(err) => {
                    tracing::error!(snapshot_id = %snapshot_id, error = %err, "failed to list snapshot key index");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        } else {
            let object_hashes = store.current_object_hashes();
            let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
            keys.sort();
            let sizes = match store.object_sizes_by_key(&object_hashes).await {
                Ok(sizes) => sizes,
                Err(err) => {
                    tracing::error!(error = %err, "failed to compute current key sizes");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            (keys, object_hashes, sizes)
        }
    };

    let mut entries = build_store_index_entries_with_hashes(
        &keys,
        &prefix,
        depth,
        Some(&key_hashes),
        Some(&key_sizes),
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
) -> MediaIndexResponse {
    let thumbnail_url = build_thumbnail_url(key, snapshot);
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

fn build_thumbnail_url(key: &str, snapshot: Option<&str>) -> String {
    let encoded_key = utf8_percent_encode(key, QUERY_COMPONENT_ENCODE_SET).to_string();
    match snapshot {
        Some(snapshot_id) => {
            let encoded_snapshot =
                utf8_percent_encode(snapshot_id, QUERY_COMPONENT_ENCODE_SET).to_string();
            format!("/media/thumbnail?key={encoded_key}&snapshot={encoded_snapshot}")
        }
        None => format!("/media/thumbnail?key={encoded_key}"),
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
    build_store_index_entries_with_hashes(keys, prefix, depth, None, None)
}

fn build_store_index_entries_with_hashes(
    keys: &[String],
    prefix: &str,
    depth: usize,
    hashes_by_key: Option<&HashMap<String, String>>,
    sizes_by_key: Option<&HashMap<String, u64>>,
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
            content_fingerprint: None,
            media: None,
        });
    }
    for path in file_entries {
        let content_hash = hashes_by_key.and_then(|values| values.get(&path)).cloned();
        let size_bytes = sizes_by_key.and_then(|values| values.get(&path)).copied();
        entries.push(StoreIndexEntry {
            path,
            entry_type: "key".to_string(),
            version: None,
            content_hash,
            size_bytes,
            content_fingerprint: None,
            media: None,
        });
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

async fn get_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    Query(query): Query<ObjectGetQuery>,
) -> impl IntoResponse {
    let read_mode = match parse_read_mode(query.read_mode.as_deref()) {
        Some(value) => value,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let store = state.store.lock().await;
    match store
        .get_object(
            &key,
            query.snapshot.as_deref(),
            query.version.as_deref(),
            read_mode,
        )
        .await
    {
        Ok(bytes) => (StatusCode::OK, bytes).into_response(),
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
    public_url: String,
    internal_url: String,
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
    device_token: String,
    label: Option<String>,
    public_key_pem: String,
    credential_pem: String,
    created_at_unix: u64,
    expires_at_unix: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ClientDeviceView {
    device_id: String,
    label: Option<String>,
    created_at_unix: u64,
    revoked_at_unix: Option<u64>,
}

async fn persist_client_auth_state(state: &ServerState) -> Result<()> {
    let snapshot = {
        let auth = state.client_auth.lock().await;
        auth.clone()
    };
    let store = state.store.lock().await;
    store.persist_client_auth_state(&snapshot).await
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
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let pairing_response = match issue_pairing_token_impl(&state, request).await {
        Ok(response) => response,
        Err(status) => return status.into_response(),
    };

    let endpoints = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        let mut urls = cluster
            .list_nodes()
            .into_iter()
            .filter(|node| !node.public_url.trim().is_empty())
            .map(|node| node.public_url)
            .collect::<Vec<_>>();
        urls.sort();
        urls.dedup();
        urls
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
            "label": pairing_response.label,
            "endpoint_count": endpoints.len(),
            "expires_at_unix": pairing_response.expires_at_unix,
        }),
    )
    .await;

    let bootstrap = TransportClientBootstrap {
        version: 1,
        cluster_id: state.cluster_id,
        rendezvous_urls: state.rendezvous_urls.clone(),
        direct_endpoints: endpoints
            .into_iter()
            .map(|url| BootstrapEndpoint {
                url,
                usage: Some(BootstrapEndpointUse::PublicApi),
            })
            .collect(),
        relay_mode: state.relay_mode,
        trust_roots: BootstrapTrustRoots {
            cluster_ca_pem: state.cluster_ca_pem.clone(),
            public_api_ca_pem: state.public_ca_pem.clone(),
        },
        pairing_token: Some(pairing_response.pairing_token),
        device_label: pairing_response.label,
        device_id: None,
    };

    (StatusCode::CREATED, Json(bootstrap)).into_response()
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
    let record = PairingTokenRecord {
        token_id: Uuid::now_v7().to_string(),
        token_hash: hash_token(&pairing_token),
        label: request.label.clone(),
        created_at_unix: now,
        expires_at_unix: now + expires_in_secs,
        used_at_unix: None,
        enrolled_device_id: None,
    };

    {
        let mut auth_state = state.client_auth.lock().await;
        auth_state
            .pairing_tokens
            .retain(|token| token.used_at_unix.is_none() && token.expires_at_unix > now);
        auth_state.pairing_tokens.push(record.clone());
    }

    if let Err(err) = persist_client_auth_state(state).await {
        warn!(error = %err, "failed to persist client auth state after pairing token issue");
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
    let device_token = generate_device_token();
    let device_token_hash = hash_token(&device_token);
    let credential_pem = generate_client_credential_pem(
        state.cluster_id,
        device_id.as_str(),
        public_key_pem,
        now,
        credential_expires_at_unix,
    );

    let response = {
        let mut auth_state = state.client_auth.lock().await;
        auth_state
            .pairing_tokens
            .retain(|token| token.used_at_unix.is_none() && token.expires_at_unix > now);

        if auth_state
            .devices
            .iter()
            .any(|device| device.device_id == device_id && device.revoked_at_unix.is_none())
        {
            return StatusCode::CONFLICT.into_response();
        }

        let Some(token_record) = auth_state.pairing_tokens.iter_mut().find(|token| {
            token.used_at_unix.is_none()
                && token.expires_at_unix > now
                && token_matches(token.token_hash.as_str(), Some(provided_hash.as_str()))
        }) else {
            return StatusCode::UNAUTHORIZED.into_response();
        };

        token_record.used_at_unix = Some(now);
        token_record.enrolled_device_id = Some(device_id.clone());

        let final_label = label.or_else(|| token_record.label.clone());
        let device = DeviceAuthRecord {
            device_id: device_id.clone(),
            label: final_label.clone(),
            token_hash: device_token_hash,
            public_key_pem: Some(public_key_pem.to_string()),
            issued_credential_pem: Some(credential_pem.clone()),
            created_at_unix: now,
            revoked_at_unix: None,
        };
        auth_state.devices.push(device);

        ClientDeviceEnrollResponse {
            cluster_id: state.cluster_id,
            device_id,
            device_token,
            label: final_label,
            public_key_pem: public_key_pem.to_string(),
            credential_pem,
            created_at_unix: now,
            expires_at_unix: credential_expires_at_unix,
        }
    };

    if let Err(err) = persist_client_auth_state(&state).await {
        warn!(error = %err, "failed to persist client auth state after enrollment");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn list_client_devices(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/devices/list";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let devices = {
        let auth_state = state.client_auth.lock().await;
        auth_state
            .devices
            .iter()
            .map(|device| ClientDeviceView {
                device_id: device.device_id.clone(),
                label: device.label.clone(),
                created_at_unix: device.created_at_unix,
                revoked_at_unix: device.revoked_at_unix,
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
        json!({ "devices": devices.len() }),
    )
    .await;

    (StatusCode::OK, Json(devices)).into_response()
}

async fn revoke_client_device(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    let action = "auth/devices/revoke";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "device_id": device_id }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let now = unix_ts();
    let revoked = {
        let mut auth_state = state.client_auth.lock().await;
        let Some(device) = auth_state
            .devices
            .iter_mut()
            .find(|device| device.device_id == device_id && device.revoked_at_unix.is_none())
        else {
            return StatusCode::NOT_FOUND.into_response();
        };
        device.revoked_at_unix = Some(now);
        true
    };

    if revoked && let Err(err) = persist_client_auth_state(&state).await {
        warn!(error = %err, "failed to persist client auth state after device revocation");
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
        json!({ "device_id": device_id }),
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
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.list_nodes())
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

    let mut cluster = state.cluster.lock().await;
    cluster.register_node(NodeDescriptor {
        node_id,
        public_url: request.public_url,
        internal_url: request.internal_url,
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
    node_internal_url: String,
    size_bytes: u64,
    node_free_bytes: u64,
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
                node_internal_url: node.internal_url.clone(),
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
        let http = state.internal_http.clone();
        for candidate in selected {
            attempted_deletions += 1;

            let request = http
                .post(format!(
                    "{}/cluster/replication/drop",
                    candidate.node_internal_url
                ))
                .query(&ReplicationDropQuery {
                    key: candidate.key.clone(),
                    version_id: Some(candidate.version_id.clone()),
                });

            let response = request.send().await;

            match response {
                Ok(resp) if resp.status().is_success() => {
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

fn build_internal_mtls_http_client(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<reqwest::Client> {
    let ca_pem =
        std::fs::read(ca_path).with_context(|| format!("failed reading {}", ca_path.display()))?;
    let ca_cert =
        reqwest::Certificate::from_pem(&ca_pem).context("failed parsing internal CA PEM")?;

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

    let identity = reqwest::Identity::from_pem(&identity_pem)
        .context("failed parsing internal node identity PEM")?;

    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .context("failed building internal mTLS http client")
}

fn build_internal_mtls_rustls_config(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<RustlsConfig> {
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

    Ok(RustlsConfig::from_config(Arc::new(config)))
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

async fn authorize_admin_request(
    state: &ServerState,
    headers: &HeaderMap,
    action: &str,
    dry_run: bool,
    approve: bool,
    details: serde_json::Value,
) -> std::result::Result<AdminRequestMetadata, StatusCode> {
    let request = admin_request_metadata(headers);

    if let Some(expected) = state.admin_control.admin_token.as_deref() {
        let provided = headers
            .get(ADMIN_TOKEN_HEADER)
            .and_then(|value| value.to_str().ok());
        if !token_matches(expected, provided) {
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
