use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::SocketAddr;
use std::path::{PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{Path, Query, Request, State};
use axum::extract::FromRequestParts;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_server::accept::Accept;
use axum_server::tls_rustls::RustlsConfig;
use bytes::Bytes;
use common::{HealthStatus, NodeId};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;
use tower::Service;
use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::{info, warn};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

mod cluster;
mod replication;
mod storage;
mod ui;

use cluster::{ClusterService, NodeDescriptor, ReplicationPlan, ReplicationPolicy};
use storage::{
    AdminAuditEvent, ObjectReadMode, PathMutationResult, PersistentStore, PutOptions,
    ReconcileVersionEntry, RepairAttemptRecord, StoreReadError, UploadChunkRef,
    VersionConsistencyState,
};

#[derive(Clone)]
struct ServerState {
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
    cluster: Arc<Mutex<ClusterService>>,
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
    admin_control: AdminControl,
}

#[derive(Debug, Clone)]
struct InternalCaller {
    node_id: NodeId,
}

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
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if let Some(node_id) = parse_node_id_from_san_uri(uri) {
                        return Ok(node_id);
                    }
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
enum MetadataCommitMode {
    Local,
    Quorum,
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

impl RepairConfig {
    fn from_env() -> Self {
        let enabled = std::env::var("IRONMESH_REPLICATION_REPAIR_ENABLED")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let batch_size = std::env::var("IRONMESH_REPLICATION_REPAIR_BATCH_SIZE")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(256);

        let max_retries = std::env::var("IRONMESH_REPLICATION_REPAIR_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        let backoff_secs = std::env::var("IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        let busy_throttle_enabled = std::env::var("IRONMESH_REPAIR_BUSY_THROTTLE_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(false);

        let busy_inflight_threshold = std::env::var("IRONMESH_REPAIR_BUSY_INFLIGHT_THRESHOLD")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(32);

        let busy_wait_millis = std::env::var("IRONMESH_REPAIR_BUSY_WAIT_MILLIS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100);

        let startup_repair_enabled = std::env::var("IRONMESH_STARTUP_REPAIR_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let startup_repair_delay_secs = std::env::var("IRONMESH_STARTUP_REPAIR_DELAY_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);

        Self {
            enabled,
            batch_size,
            max_retries,
            backoff_secs,
            busy_throttle_enabled,
            busy_inflight_threshold,
            busy_wait_millis,
            startup_repair_enabled,
            startup_repair_delay_secs,
        }
    }
}

impl PeerHeartbeatConfig {
    fn from_env() -> Self {
        let enabled = std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true);

        let interval_secs = std::env::var("IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(15);

        Self {
            enabled,
            interval_secs,
        }
    }
}

impl AdminControl {
    fn from_env() -> Self {
        let admin_token = std::env::var("IRONMESH_ADMIN_TOKEN")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self { admin_token }
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

#[tokio::main]
async fn main() -> Result<()> {
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

    let node_id = std::env::var("IRONMESH_NODE_ID")
        .ok()
        .and_then(|value| value.parse::<NodeId>().ok())
        .unwrap_or_else(NodeId::new_v4);

    let data_dir =
        std::env::var("IRONMESH_DATA_DIR").unwrap_or_else(|_| "./data/server-node".to_string());
    let bind_addr: SocketAddr = std::env::var("IRONMESH_SERVER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse()
        .context("invalid IRONMESH_SERVER_BIND")?;

    let internal_bind_addr: SocketAddr = std::env::var("IRONMESH_INTERNAL_BIND")
        .unwrap_or_else(|_| "127.0.0.1:18080".to_string())
        .parse()
        .context("invalid IRONMESH_INTERNAL_BIND")?;

    let mut initial_labels = HashMap::new();
    initial_labels.insert(
        "region".to_string(),
        std::env::var("IRONMESH_REGION").unwrap_or_else(|_| "local".to_string()),
    );
    initial_labels.insert(
        "dc".to_string(),
        std::env::var("IRONMESH_DC").unwrap_or_else(|_| "local-dc".to_string()),
    );
    initial_labels.insert(
        "rack".to_string(),
        std::env::var("IRONMESH_RACK").unwrap_or_else(|_| "local-rack".to_string()),
    );

    let public_url =
        std::env::var("IRONMESH_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind_addr}"));

    let internal_url = std::env::var("IRONMESH_INTERNAL_URL")
        .unwrap_or_else(|_| format!("https://{internal_bind_addr}"));

    let heartbeat_timeout_secs = std::env::var("IRONMESH_HEARTBEAT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(90);

    let audit_interval_secs = std::env::var("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);

    let replica_view_sync_interval_secs = std::env::var("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5);

    let replication_factor = std::env::var("IRONMESH_REPLICATION_FACTOR")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3);
    let accepted_over_replication_items = std::env::var("IRONMESH_ACCEPTED_OVER_REPLICATION_ITEMS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    let metadata_commit_mode = MetadataCommitMode::parse(
        std::env::var("IRONMESH_METADATA_COMMIT_MODE")
            .unwrap_or_else(|_| "local".to_string())
            .as_str(),
    )?;

    let internal_tls_ca_path = PathBuf::from(
        std::env::var("IRONMESH_INTERNAL_TLS_CA_CERT")
            .context("missing IRONMESH_INTERNAL_TLS_CA_CERT")?,
    );
    let internal_tls_cert_path = PathBuf::from(
        std::env::var("IRONMESH_INTERNAL_TLS_CERT").context("missing IRONMESH_INTERNAL_TLS_CERT")?,
    );
    let internal_tls_key_path = PathBuf::from(
        std::env::var("IRONMESH_INTERNAL_TLS_KEY").context("missing IRONMESH_INTERNAL_TLS_KEY")?,
    );

    let repair_config = RepairConfig::from_env();
    let autonomous_replication_on_put_enabled =
        std::env::var("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED")
            .ok()
            .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
            .unwrap_or(true);
    let peer_heartbeat_config = PeerHeartbeatConfig::from_env();
    let admin_control = AdminControl::from_env();
    let startup_repair_status = if repair_config.startup_repair_enabled {
        StartupRepairStatus::Scheduled
    } else {
        StartupRepairStatus::Disabled
    };

    let policy = ReplicationPolicy {
        replication_factor,
        accepted_over_replication_items,
        ..ReplicationPolicy::default()
    };

    let mut cluster = ClusterService::new(node_id, policy, heartbeat_timeout_secs);
    cluster.register_node(NodeDescriptor {
        node_id,
        public_url,
        internal_url,
        labels: initial_labels,
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    let store = Arc::new(Mutex::new(PersistentStore::init(data_dir).await?));

    let internal_http = build_internal_mtls_http_client(
        &internal_tls_ca_path,
        &internal_tls_cert_path,
        &internal_tls_key_path,
    )?;

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

    let state = ServerState {
        node_id,
        store,
        cluster: Arc::new(Mutex::new(cluster)),
        metadata_commit_mode,
        internal_http,
        autonomous_replication_on_put_enabled,
        inflight_requests: Arc::new(AtomicUsize::new(0)),
        replication_audit_interval_secs: audit_interval_secs,
        peer_heartbeat_config,
        repair_config,
        log_buffer,
        startup_repair_status: Arc::new(Mutex::new(startup_repair_status)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
        admin_control,
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

    spawn_replication_auditor(state.clone(), audit_interval_secs);
    spawn_replica_view_synchronizer(state.clone(), replica_view_sync_interval_secs);
    if state.repair_config.startup_repair_enabled {
        spawn_startup_replication_repair(
            state.clone(),
            state.repair_config.startup_repair_delay_secs,
        );
    }
    if peer_heartbeat_config.enabled {
        spawn_peer_heartbeat_emitter(state.clone(), peer_heartbeat_config.interval_secs);
    }

    let internal_tls = build_internal_mtls_rustls_config(
        &internal_tls_ca_path,
        &internal_tls_cert_path,
        &internal_tls_key_path,
    )?;

    let public_app = Router::new()
        .route("/", get(ui::index))
        .route("/ui/app.css", get(ui::app_css))
        .route("/ui/app.js", get(ui::app_js))
        .route("/logs", get(ui::list_logs))
        .route("/health", get(health))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
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
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            track_inflight_requests,
        ));

    let internal_app = Router::new()
        .route("/health", get(health))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
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

    info!(%bind_addr, %node_id, "server node listening");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, public_app).await?;

    Ok(())
}

fn spawn_replication_auditor(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(5)));

        loop {
            ticker.tick().await;

            let keys = {
                let store = state.store.lock().await;
                store
                    .list_replication_subjects()
                    .await
                    .unwrap_or_else(|_| store.current_keys())
            };

            let mut cluster = state.cluster.lock().await;
            let node_transitioned_offline = cluster.update_health_and_detect_offline_transition();
            let plan = cluster.replication_plan(&keys);

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

fn spawn_replica_view_synchronizer(state: ServerState, interval_secs: u64) {
    tokio::spawn(async move {
        let http = state.internal_http.clone();
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));

        loop {
            ticker.tick().await;

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
                let base = peer.internal_url.trim_end_matches('/');
                let url = format!("{base}/cluster/replication/subjects/local");

                match http.get(url).send().await {
                    Ok(response) if response.status().is_success() => {
                        match response.json::<LocalReplicationSubjectsResponse>().await {
                            Ok(payload) => {
                                let mut cluster = state.cluster.lock().await;
                                if cluster
                                    .replace_node_replica_view(payload.node_id, &payload.subjects)
                                {
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
                            status = %response.status(),
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

            if changed && let Err(err) = persist_cluster_replicas_state(&state).await {
                warn!(
                    error = %err,
                    "failed persisting cluster replicas after replica subject sync"
                );
            }
        }
    });
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

    let keys = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

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
        let http = state.internal_http.clone();
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
                let base = peer.internal_url.trim_end_matches('/');
                let url = format!("{base}/cluster/nodes/{}/heartbeat", state.node_id);

                match http.post(url).json(&payload).send().await {
                    Ok(response) if response.status().is_success() => {}
                    Ok(response) => {
                        tracing::debug!(
                            node_id = %peer.node_id,
                            status = %response.status(),
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

#[derive(Debug, Serialize)]
struct StoreIndexEntry {
    path: String,
    entry_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_hash: Option<String>,
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
        Ok(PathMutationResult::Applied) => StatusCode::NO_CONTENT.into_response(),
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
        Ok(PathMutationResult::Applied) => StatusCode::NO_CONTENT.into_response(),
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
    {
        Ok(version_id) => {
            drop(store);

            let mut cluster = state.cluster.lock().await;
            cluster.note_replica(&key, state.node_id);
            cluster.note_replica(format!("{}@{}", key, version_id), state.node_id);
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

            info!(key = %key, version_id = %version_id, "tombstoned object");
            StatusCode::CREATED
        }
        Err(err) => {
            tracing::error!(error = %err, key = %key, "failed to tombstone object");
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

    let (keys, key_hashes) = {
        let store = state.store.lock().await;
        if let Some(snapshot_id) = query.snapshot.as_deref() {
            match store.snapshot_object_hashes(snapshot_id).await {
                Ok(Some(object_hashes)) => {
                    let mut keys: Vec<String> = object_hashes.keys().cloned().collect();
                    keys.sort();
                    (keys, object_hashes)
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
            (keys, object_hashes)
        }
    };

    let entries = build_store_index_entries_with_hashes(&keys, &prefix, depth, Some(&key_hashes));

    (
        StatusCode::OK,
        Json(StoreIndexResponse {
            prefix,
            depth,
            entry_count: entries.len(),
            entries,
        }),
    )
        .into_response()
}

#[cfg(test)]
fn build_store_index_entries(keys: &[String], prefix: &str, depth: usize) -> Vec<StoreIndexEntry> {
    build_store_index_entries_with_hashes(keys, prefix, depth, None)
}

fn build_store_index_entries_with_hashes(
    keys: &[String],
    prefix: &str,
    depth: usize,
    hashes_by_key: Option<&HashMap<String, String>>,
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
        });
    }
    for path in file_entries {
        let content_hash = hashes_by_key.and_then(|values| values.get(&path)).cloned();
        entries.push(StoreIndexEntry {
            path,
            entry_type: "key".to_string(),
            version: None,
            content_hash,
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
    let read_mode = match query.read_mode.as_deref() {
        None | Some("preferred") => ObjectReadMode::Preferred,
        Some("confirmed_only") => ObjectReadMode::ConfirmedOnly,
        Some("provisional_allowed") => ObjectReadMode::ProvisionalAllowed,
        Some(_) => return StatusCode::BAD_REQUEST.into_response(),
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

async fn placement_for_key(
    State(state): State<ServerState>,
    Path(key): Path<String>,
) -> Json<cluster::PlacementDecision> {
    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.placement_for_key(&key))
}


async fn replication_plan(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.replication_plan(&keys))
}

async fn trigger_replication_audit(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

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

async fn local_replication_subjects(
    State(state): State<ServerState>,
) -> impl IntoResponse {
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

    let keys = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

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
    state: VersionConsistencyState,
    manifest_hash: String,
}

#[derive(Debug, Serialize)]
struct ReplicationChunkPushReport {
    stored: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct ReplicationManifestPushReport {
    version_id: String,
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
    let import_result = {
        let mut store = state.store.lock().await;
        store
            .import_replica_manifest(
                &query.key,
                query.version_id.as_deref(),
                query.state,
                &query.manifest_hash,
                &payload,
            )
            .await
    };

    match import_result {
        Ok(version_id) => {
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

fn build_internal_mtls_http_client(
    ca_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<reqwest::Client> {
    let ca_pem = std::fs::read(ca_path)
        .with_context(|| format!("failed reading {}", ca_path.display()))?;
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
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert = cert.context("failed parsing internal CA certificate")?;
        roots
            .add(cert)
            .context("failed adding internal CA certificate to trust store")?;
    }

    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("failed reading {}", cert_path.display()))?,
    );
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing internal node certificate chain")?;

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("failed reading {}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .context("failed parsing internal node private key")?
        .context("missing internal node private key")?;

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

    let remote_url = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();

        let Some(node) = cluster
            .list_nodes()
            .into_iter()
            .find(|entry| entry.node_id == source_node_id)
        else {
            return StatusCode::NOT_FOUND.into_response();
        };

        node.internal_url
    };

    let http = state.internal_http.clone();

    let export_url = format!("{remote_url}/cluster/reconcile/export/provisional");
    let remote_entries: Vec<ReconcileVersionEntry> = match http.get(export_url).send().await {
        Ok(response) => match response.error_for_status() {
            Ok(ok_response) => match ok_response.json::<Vec<ReconcileVersionEntry>>().await {
                Ok(entries) => entries,
                Err(err) => {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        error = %err,
                        "failed to parse reconciliation export payload"
                    );
                    return StatusCode::BAD_GATEWAY.into_response();
                }
            },
            Err(err) => {
                tracing::error!(
                    source_node_id = %source_node_id,
                    error = %err,
                    "reconciliation export endpoint returned error"
                );
                return StatusCode::BAD_GATEWAY.into_response();
            }
        },
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

        let object_url = format!(
            "{remote_url}/store/{}?version={}",
            entry.key, entry.version_id
        );
        let payload = match http.get(object_url).send().await {
            Ok(response) => match response.error_for_status() {
                Ok(ok_response) => match ok_response.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        tracing::error!(
                            source_node_id = %source_node_id,
                            key = %entry.key,
                            version_id = %entry.version_id,
                            error = %err,
                            "failed to read reconciliation object payload"
                        );
                        failed += 1;
                        continue;
                    }
                },
                Err(err) => {
                    tracing::error!(
                        source_node_id = %source_node_id,
                        key = %entry.key,
                        version_id = %entry.version_id,
                        error = %err,
                        "reconciliation object fetch returned error"
                    );
                    failed += 1;
                    continue;
                }
            },
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
