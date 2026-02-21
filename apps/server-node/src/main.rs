use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use bytes::{Bytes, BytesMut};
use common::{HealthStatus, NodeId};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{info, warn};

mod cluster;
mod storage;

use cluster::{ClusterService, NodeDescriptor, ReplicationPlan, ReplicationPolicy};
use storage::{
    ObjectReadMode, PersistentStore, PutOptions, ReconcileVersionEntry, RepairAttemptRecord,
    ReplicationExportBundle, SnapshotInfo, StoreReadError, VersionConsistencyState,
};

#[derive(Clone)]
struct ServerState {
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
    cluster: Arc<Mutex<ClusterService>>,
    metadata_commit_mode: MetadataCommitMode,
    internal_node_tokens: Arc<Mutex<HashMap<NodeId, String>>>,
    repair_config: RepairConfig,
    repair_state: Arc<Mutex<RepairExecutorState>>,
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
            .unwrap_or(32);

        let max_retries = std::env::var("IRONMESH_REPLICATION_REPAIR_MAX_RETRIES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        let backoff_secs = std::env::var("IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30);

        Self {
            enabled,
            batch_size,
            max_retries,
            backoff_secs,
        }
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
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .compact()
        .init();

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

    let heartbeat_timeout_secs = std::env::var("IRONMESH_HEARTBEAT_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(90);

    let audit_interval_secs = std::env::var("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(3600);

    let replication_factor = std::env::var("IRONMESH_REPLICATION_FACTOR")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3);

    let metadata_commit_mode = MetadataCommitMode::parse(
        std::env::var("IRONMESH_METADATA_COMMIT_MODE")
            .unwrap_or_else(|_| "local".to_string())
            .as_str(),
    )?;

    let env_node_tokens = std::env::var("IRONMESH_INTERNAL_NODE_TOKENS")
        .ok()
        .map(|raw| parse_internal_node_tokens(raw.as_str()))
        .transpose()?
        .unwrap_or_default();

    let repair_config = RepairConfig::from_env();

    let policy = ReplicationPolicy {
        replication_factor,
        ..ReplicationPolicy::default()
    };

    let mut cluster = ClusterService::new(node_id, policy, heartbeat_timeout_secs);
    cluster.register_node(NodeDescriptor {
        node_id,
        public_url,
        labels: initial_labels,
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    let store = Arc::new(Mutex::new(PersistentStore::init(data_dir).await?));
    let persisted_internal_node_tokens = {
        let store_guard = store.lock().await;
        store_guard
            .load_internal_node_tokens()
            .await
            .context("failed to load internal node token state")?
    };
    let internal_node_tokens = if persisted_internal_node_tokens.is_empty() {
        env_node_tokens
    } else {
        persisted_internal_node_tokens
    };

    if !internal_node_tokens.is_empty() && !internal_node_tokens.contains_key(&node_id) {
        return Err(anyhow::anyhow!(
            "internal node tokens are configured but have no token for local node {node_id}"
        ));
    }
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
        internal_node_tokens: Arc::new(Mutex::new(internal_node_tokens)),
        repair_config,
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
    };

    if let Err(err) = persist_internal_node_tokens_state(&state).await {
        warn!(
            error = %err,
            "failed to persist internal node tokens during startup"
        );
    }

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

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/snapshots", get(list_snapshots))
        .route("/store/{key}", put(put_object).get(get_object))
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
        .route("/cluster/nodes/{node_id}/heartbeat", post(node_heartbeat))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route(
            "/cluster/internal-auth/tokens",
            get(list_internal_node_tokens),
        )
        .route(
            "/cluster/internal-auth/tokens/rotate",
            post(rotate_internal_node_token),
        )
        .route(
            "/cluster/internal-auth/tokens/{node_id}",
            delete(revoke_internal_node_token),
        )
        .route("/cluster/replication/plan", get(replication_plan))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(execute_replication_repair),
        )
        .route(
            "/cluster/replication/cleanup",
            post(execute_replication_cleanup),
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
        .route("/cluster/reconcile/{node_id}", post(reconcile_from_node))
        .route("/maintenance/cleanup", post(run_cleanup))
        .with_state(state);

    info!(%bind_addr, %node_id, "server node listening");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

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
                let report = execute_replication_repair_inner(&state, None).await;
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

async fn health(State(state): State<ServerState>) -> Json<HealthStatus> {
    Json(HealthStatus {
        node_id: state.node_id,
        role: "server-node".to_string(),
        online: true,
    })
}

async fn index(State(state): State<ServerState>) -> Html<String> {
    let (storage_dir, object_count, snapshots) = {
        let store = state.store.lock().await;
        let snapshots = store
            .list_snapshots()
            .await
            .unwrap_or_else(|_| Vec::<SnapshotInfo>::new());
        (
            store.root_dir().display().to_string(),
            store.object_count(),
            snapshots,
        )
    };

    let (cluster_total, cluster_online, replication_factor) = {
        let cluster = state.cluster.lock().await;
        let summary = cluster.summary();
        (
            summary.total_nodes,
            summary.online_nodes,
            summary.policy.replication_factor,
        )
    };

    let latest_snapshot = snapshots
        .first()
        .map(|s| s.id.clone())
        .unwrap_or_else(|| "none".to_string());

    let body = format!(
        "<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>ironmesh Server Node</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
    main {{ max-width: 860px; margin: 0 auto; }}
    code {{ background: #f4f4f4; padding: 0.2rem 0.4rem; border-radius: 0.2rem; }}
    ul {{ line-height: 1.6; }}
  </style>
</head>
<body>
  <main>
    <h1>ironmesh Server Node</h1>
    <p>Node ID: <code>{}</code></p>
    <p>Stored objects (latest state): <code>{}</code></p>
    <p>Latest snapshot ID: <code>{}</code></p>
    <p>Data directory: <code>{}</code></p>
    <p>Cluster nodes online/total: <code>{}/{}</code></p>
    <p>Replication factor target: <code>{}</code></p>
    <h2>Available routes</h2>
    <ul>
      <li><code>GET /</code> — info page</li>
      <li><code>GET /health</code> — node health JSON</li>
      <li><code>GET /snapshots</code> — snapshot metadata</li>
      <li><code>PUT /store/{{key}}</code> — store object bytes</li>
      <li><code>GET /store/{{key}}</code> — fetch object bytes from latest state</li>
      <li><code>GET /store/{{key}}?snapshot=&lt;id&gt;</code> — fetch object from snapshot state</li>
    <li><code>GET /store/{{key}}?version=&lt;version_id&gt;</code> — fetch object by specific version</li>
    <li><code>GET /store/{{key}}?read_mode=preferred|confirmed_only|provisional_allowed</code> — read latest via explicit consistency mode</li>
    <li><code>GET /versions/{{key}}</code> — list version DAG metadata</li>
    <li><code>POST /versions/{{key}}/commit/{{version_id}}</code> — commit version (quorum policy aware)</li>
    <li><code>POST /versions/{{key}}/confirm/{{version_id}}</code> — compatibility alias for commit endpoint</li>
      <li><code>GET /cluster/status</code> — cluster summary</li>
      <li><code>GET /cluster/nodes</code> — known node list</li>
      <li><code>PUT /cluster/nodes/{{node_id}}</code> — register/update node metadata</li>
    <li><code>DELETE /cluster/nodes/{{node_id}}</code> — remove node from cluster membership</li>
      <li><code>POST /cluster/nodes/{{node_id}}/heartbeat</code> — refresh node liveness</li>
      <li><code>GET /cluster/placement/{{key}}</code> — deterministic placement decision</li>
      <li><code>GET /cluster/replication/plan</code> — current replication gaps/overages</li>
      <li><code>POST /cluster/replication/audit</code> — manual audit trigger</li>
    <li><code>POST /cluster/replication/repair</code> — execute one-pass replica repair for missing placements</li>
        <li><code>GET /cluster/reconcile/export/provisional</code> — export local provisional metadata for rejoin sync</li>
        <li><code>POST /cluster/reconcile/{{node_id}}</code> — import provisional commits from a peer node</li>
            <li><code>POST /maintenance/cleanup?retention_secs=&lt;n&gt;&amp;dry_run=true|false</code> — retention-safe orphan cleanup for manifests/chunks</li>
    </ul>
  </main>
</body>
</html>\n",
        state.node_id,
        object_count,
        latest_snapshot,
        storage_dir,
        cluster_online,
        cluster_total,
        replication_factor,
    );

    Html(body)
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
struct PutObjectQuery {
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
}

async fn put_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    Query(query): Query<PutObjectQuery>,
    payload: Bytes,
) -> impl IntoResponse {
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

            info!(
                key = %key,
                snapshot_id = %outcome.snapshot_id,
                version_id = %outcome.version_id,
                version_state = ?outcome.state,
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

#[derive(Debug, Deserialize)]
struct CleanupQuery {
    retention_secs: Option<u64>,
    dry_run: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct InternalNodeTokenRotateRequest {
    node_id: NodeId,
    token: String,
}

#[derive(Debug, Serialize)]
struct InternalNodeTokenListResponse {
    count: usize,
    node_ids: Vec<NodeId>,
}

#[derive(Debug, Serialize)]
struct InternalNodeTokenMutationResponse {
    node_id: NodeId,
    changed: bool,
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

    {
        let mut tokens = state.internal_node_tokens.lock().await;
        tokens.remove(&node_id);
    }

    if let Err(err) = persist_cluster_replicas_state(&state).await {
        warn!(
            error = %err,
            node_id = %node_id,
            "failed to persist cluster replicas after node removal"
        );
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    if let Err(err) = persist_internal_node_tokens_state(&state).await {
        warn!(
            error = %err,
            node_id = %node_id,
            "failed to persist internal tokens after node removal"
        );
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    StatusCode::NO_CONTENT
}

async fn node_heartbeat(
    State(state): State<ServerState>,
    Path(node_id): Path<String>,
    Json(request): Json<NodeHeartbeatRequest>,
) -> impl IntoResponse {
    let node_id = match node_id.parse::<NodeId>() {
        Ok(id) => id,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

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

async fn list_internal_node_tokens(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut node_ids = {
        let tokens = state.internal_node_tokens.lock().await;
        tokens.keys().cloned().collect::<Vec<_>>()
    };
    node_ids.sort_by_key(|node_id| node_id.to_string());

    (
        StatusCode::OK,
        Json(InternalNodeTokenListResponse {
            count: node_ids.len(),
            node_ids,
        }),
    )
        .into_response()
}

async fn rotate_internal_node_token(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<InternalNodeTokenRotateRequest>,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let token = request.token.trim();
    if token.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let previous = {
        let mut tokens = state.internal_node_tokens.lock().await;
        tokens.insert(request.node_id, token.to_string())
    };

    if let Err(err) = persist_internal_node_tokens_state(&state).await {
        warn!(
            error = %err,
            node_id = %request.node_id,
            "failed to persist internal token rotation"
        );

        let mut tokens = state.internal_node_tokens.lock().await;
        if let Some(previous) = previous {
            tokens.insert(request.node_id, previous);
        } else {
            tokens.remove(&request.node_id);
        }

        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (
        StatusCode::OK,
        Json(InternalNodeTokenMutationResponse {
            node_id: request.node_id,
            changed: true,
        }),
    )
        .into_response()
}

async fn revoke_internal_node_token(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Path(node_id): Path<String>,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let node_id = match node_id.parse::<NodeId>() {
        Ok(node_id) => node_id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    if node_id == state.node_id {
        return StatusCode::CONFLICT.into_response();
    }

    let removed = {
        let mut tokens = state.internal_node_tokens.lock().await;
        tokens.remove(&node_id)
    };

    let Some(removed) = removed else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if let Err(err) = persist_internal_node_tokens_state(&state).await {
        warn!(
            error = %err,
            node_id = %node_id,
            "failed to persist internal token revocation"
        );

        let mut tokens = state.internal_node_tokens.lock().await;
        tokens.insert(node_id, removed);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    (
        StatusCode::OK,
        Json(InternalNodeTokenMutationResponse {
            node_id,
            changed: true,
        }),
    )
        .into_response()
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

#[derive(Debug, Serialize)]
struct ReplicationRepairReport {
    attempted_transfers: usize,
    successful_transfers: usize,
    failed_transfers: usize,
    skipped_items: usize,
    skipped_backoff: usize,
    skipped_max_retries: usize,
    last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReplicationRepairQuery {
    batch_size: Option<usize>,
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
    headers: HeaderMap,
    Query(query): Query<ReplicationDropQuery>,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

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
    node_public_url: String,
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
                node_public_url: node.public_url.clone(),
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
        let http = reqwest::Client::new();
        for candidate in selected {
            attempted_deletions += 1;

            let mut request = http
                .post(format!(
                    "{}/cluster/replication/drop",
                    candidate.node_public_url
                ))
                .query(&ReplicationDropQuery {
                    key: candidate.key.clone(),
                    version_id: Some(candidate.version_id.clone()),
                });

            if let Some(token) = internal_outbound_token(&state).await {
                request = request.header("x-ironmesh-internal-token", token);
                request = request.header("x-ironmesh-node-id", state.node_id.to_string());
            }

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
    headers: HeaderMap,
    Path(hash): Path<String>,
    payload: Bytes,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

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
    headers: HeaderMap,
    Query(query): Query<ReplicationManifestPushQuery>,
    payload: Bytes,
) -> impl IntoResponse {
    if !is_internal_request_authorized(&state, &headers).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

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

async fn execute_replication_repair(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationRepairQuery>,
) -> impl IntoResponse {
    let batch_override = query.batch_size.filter(|v| *v > 0);
    let report = execute_replication_repair_inner(&state, batch_override).await;

    (StatusCode::OK, Json(report))
}

async fn execute_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ReplicationRepairReport {
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

    let mut attempted_transfers = 0usize;
    let mut successful_transfers = 0usize;
    let mut failed_transfers = 0usize;
    let mut skipped_items = 0usize;
    let mut skipped_backoff = 0usize;
    let mut skipped_max_retries = 0usize;
    let mut last_error = None;

    let max_attempts = state.repair_config.max_retries;
    let backoff_secs = state.repair_config.backoff_secs;
    let max_transfers = batch_size_override.unwrap_or(state.repair_config.batch_size);
    let now = unix_ts();

    let http = reqwest::Client::new();

    for item in plan.items {
        if attempted_transfers >= max_transfers {
            break;
        }

        let Some((key, version_id)) = parse_replication_subject(&item.key) else {
            skipped_items += 1;
            continue;
        };

        let bundle = {
            let store = state.store.lock().await;

            match store
                .export_replication_bundle(&key, version_id.as_deref(), ObjectReadMode::Preferred)
                .await
            {
                Ok(Some(bundle)) => bundle,
                _ => {
                    skipped_items += 1;
                    continue;
                }
            }
        };

        for target in item.missing_nodes {
            if attempted_transfers >= max_transfers {
                break;
            }

            let Some(node) = node_by_id.get(&target) else {
                failed_transfers += 1;
                continue;
            };

            if target == state.node_id {
                continue;
            }

            let transfer_key = format!("{}|{}", item.key, target);

            {
                let repair_state = state.repair_state.lock().await;
                if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                    if previous.attempts > max_attempts {
                        skipped_max_retries += 1;
                        continue;
                    }

                    let elapsed = now.saturating_sub(previous.last_failure_unix);
                    let required_backoff =
                        jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                    if elapsed < required_backoff {
                        skipped_backoff += 1;
                        continue;
                    }
                }
            }

            attempted_transfers += 1;
            let transfer_result = replicate_bundle_to_target(
                &http,
                &node.public_url,
                &bundle,
                &state.store,
                internal_outbound_token(state).await,
                state.node_id,
            )
            .await;

            match transfer_result {
                Ok(remote_version_id) => {
                    successful_transfers += 1;

                    let mut cluster = state.cluster.lock().await;
                    cluster.note_replica(&item.key, target);
                    if let Some(version_id) = &bundle.version_id {
                        cluster.note_replica(format!("{key}@{version_id}"), target);
                    } else {
                        cluster.note_replica(&key, target);
                    }
                    cluster.note_replica(format!("{key}@{remote_version_id}"), target);
                    drop(cluster);

                    if let Err(err) = persist_cluster_replicas_state(state).await {
                        warn!(
                            error = %err,
                            "failed to persist cluster replicas after repair success"
                        );
                    }

                    let mut repair_state = state.repair_state.lock().await;
                    repair_state.attempts.remove(&transfer_key);
                    drop(repair_state);

                    if let Err(err) = persist_repair_state(state).await {
                        warn!(error = %err, "failed persisting repair attempts after success");
                    }
                }
                Err(err) => {
                    failed_transfers += 1;
                    last_error = Some(err.to_string());

                    let mut repair_state = state.repair_state.lock().await;
                    let entry =
                        repair_state
                            .attempts
                            .entry(transfer_key)
                            .or_insert(RepairAttemptEntry {
                                attempts: 0,
                                last_failure_unix: now,
                            });
                    entry.attempts = entry.attempts.saturating_add(1);
                    entry.last_failure_unix = now;
                    drop(repair_state);

                    if let Err(err) = persist_repair_state(state).await {
                        warn!(error = %err, "failed persisting repair attempts after failure");
                    }
                }
            }
        }
    }

    ReplicationRepairReport {
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        last_error,
    }
}

async fn replicate_bundle_to_target(
    http: &reqwest::Client,
    target_base_url: &str,
    bundle: &ReplicationExportBundle,
    store: &Arc<Mutex<PersistentStore>>,
    internal_token: Option<String>,
    source_node_id: NodeId,
) -> Result<String> {
    let mut assembled = BytesMut::with_capacity(bundle.manifest.total_size_bytes);

    for chunk in &bundle.manifest.chunks {
        let payload = {
            let guard = store.lock().await;
            guard
                .read_chunk_payload(&chunk.hash)
                .await?
                .with_context(|| format!("missing local chunk {}", chunk.hash))?
        };

        assembled.extend_from_slice(&payload);
    }

    let state_query = match bundle.state {
        VersionConsistencyState::Confirmed => "confirmed",
        VersionConsistencyState::Provisional => "provisional",
    };

    let put_url = format!("{target_base_url}/store/{}?state={state_query}", bundle.key);
    http.put(put_url)
        .body(assembled.freeze())
        .send()
        .await?
        .error_for_status()?;

    let manifest_url = format!("{target_base_url}/cluster/replication/push/manifest");
    let mut request = http
        .post(manifest_url)
        .query(&ReplicationManifestPushQuery {
            key: bundle.key.clone(),
            version_id: bundle.version_id.clone(),
            state: bundle.state.clone(),
            manifest_hash: bundle.manifest_hash.clone(),
        })
        .body(bundle.manifest_bytes.clone());

    if let Some(token) = internal_token {
        request = request.header("x-ironmesh-internal-token", token);
        request = request.header("x-ironmesh-node-id", source_node_id.to_string());
    }

    let response = request.send().await?.error_for_status()?;

    let report = response.json::<ReplicationManifestPushReport>().await?;
    Ok(report.version_id)
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

async fn persist_internal_node_tokens_state(state: &ServerState) -> Result<()> {
    let tokens = {
        let tokens = state.internal_node_tokens.lock().await;
        tokens.clone()
    };

    let store = state.store.lock().await;
    store.persist_internal_node_tokens(&tokens).await
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

async fn is_internal_request_authorized(state: &ServerState, headers: &HeaderMap) -> bool {
    let (auth_enabled, expected_for_caller) = {
        let tokens = state.internal_node_tokens.lock().await;
        let auth_enabled = !tokens.is_empty();

        let node_id_header = headers
            .get("x-ironmesh-node-id")
            .and_then(|value| value.to_str().ok());
        let caller_node_id = node_id_header.and_then(|value| value.parse::<NodeId>().ok());
        let expected_for_caller = caller_node_id.and_then(|node_id| {
            expected_internal_token_for_node(&tokens, node_id).map(str::to_string)
        });

        (auth_enabled, expected_for_caller)
    };

    if !auth_enabled {
        return true;
    }

    let provided_token = headers
        .get("x-ironmesh-internal-token")
        .and_then(|value| value.to_str().ok());

    let node_id_header = headers
        .get("x-ironmesh-node-id")
        .and_then(|value| value.to_str().ok());

    if !internal_node_header_valid(node_id_header) {
        return false;
    }

    let Some(node_id_header) = node_id_header else {
        return false;
    };

    let Ok(caller_node_id) = node_id_header.parse::<NodeId>() else {
        return false;
    };

    let cluster = state.cluster.lock().await;
    let caller_is_registered = cluster
        .list_nodes()
        .iter()
        .any(|node| node.node_id == caller_node_id);
    drop(cluster);

    if !caller_is_registered {
        return false;
    }

    let Some(expected) = expected_for_caller else {
        return false;
    };

    internal_token_matches(expected.as_str(), provided_token)
}

async fn internal_outbound_token(state: &ServerState) -> Option<String> {
    let tokens = state.internal_node_tokens.lock().await;
    expected_internal_token_for_node(&tokens, state.node_id).map(ToString::to_string)
}

fn expected_internal_token_for_node(
    node_tokens: &HashMap<NodeId, String>,
    node_id: NodeId,
) -> Option<&str> {
    node_tokens.get(&node_id).map(|value| value.as_str())
}

fn parse_internal_node_tokens(raw: &str) -> Result<HashMap<NodeId, String>> {
    let mut parsed = HashMap::new();

    for pair in raw.split(',') {
        let entry = pair.trim();
        if entry.is_empty() {
            continue;
        }

        let Some((node_id_raw, token_raw)) = entry.split_once('=') else {
            return Err(anyhow::anyhow!(
                "invalid IRONMESH_INTERNAL_NODE_TOKENS entry '{entry}', expected '<node_id>=<token>'"
            ));
        };

        let node_id = node_id_raw.trim().parse::<NodeId>().with_context(|| {
            format!("invalid node id in IRONMESH_INTERNAL_NODE_TOKENS: {node_id_raw}")
        })?;
        let token = token_raw.trim();

        if token.is_empty() {
            return Err(anyhow::anyhow!(
                "empty token for node {node_id} in IRONMESH_INTERNAL_NODE_TOKENS"
            ));
        }

        if parsed.insert(node_id, token.to_string()).is_some() {
            return Err(anyhow::anyhow!(
                "duplicate node id {node_id} in IRONMESH_INTERNAL_NODE_TOKENS"
            ));
        }
    }

    Ok(parsed)
}

fn internal_token_matches(expected: &str, provided: Option<&str>) -> bool {
    provided
        .map(|token| constant_time_eq(expected.as_bytes(), token.as_bytes()))
        .unwrap_or(false)
}

fn internal_node_header_valid(provided: Option<&str>) -> bool {
    provided
        .and_then(|value| value.parse::<NodeId>().ok())
        .is_some()
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
mod tests {
    use super::{
        constant_time_eq, expected_internal_token_for_node, internal_node_header_valid,
        internal_token_matches, jittered_backoff_secs, parse_internal_node_tokens,
    };
    use common::NodeId;
    use std::collections::HashMap;

    #[test]
    fn jittered_backoff_is_deterministic_for_same_inputs() {
        let first = jittered_backoff_secs(30, "key@ver|node", 2);
        let second = jittered_backoff_secs(30, "key@ver|node", 2);
        assert_eq!(first, second);
    }

    #[test]
    fn jittered_backoff_stays_within_expected_range() {
        let value = jittered_backoff_secs(40, "another-key|node", 3);
        assert!(value >= 40);
        assert!(value <= 60);
    }

    #[test]
    fn constant_time_eq_compares_equal_and_non_equal_values() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"Secret"));
        assert!(!constant_time_eq(b"secret", b"secret-long"));
    }

    #[test]
    fn internal_token_auth_requires_exact_match_when_configured() {
        assert!(!internal_token_matches("secret", None));
        assert!(!internal_token_matches("secret", Some("wrong")));
        assert!(internal_token_matches("secret", Some("secret")));
    }

    #[test]
    fn internal_node_header_rules_match_token_mode() {
        assert!(!internal_node_header_valid(None));
        assert!(!internal_node_header_valid(Some("not-a-uuid")));
        assert!(internal_node_header_valid(Some(
            "00000000-0000-0000-0000-000000000001"
        )));
    }

    #[test]
    fn parse_internal_node_tokens_parses_multiple_entries() {
        let parsed = parse_internal_node_tokens(
            "00000000-0000-0000-0000-000000000001=tok-a,00000000-0000-0000-0000-000000000002=tok-b",
        )
        .unwrap();

        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_internal_node_tokens_rejects_duplicate_node_ids() {
        let duplicate =
            "00000000-0000-0000-0000-000000000001=tok-a,00000000-0000-0000-0000-000000000001=tok-b";
        assert!(parse_internal_node_tokens(duplicate).is_err());
    }

    #[test]
    fn expected_internal_token_returns_none_when_node_missing() {
        let node_tokens = HashMap::new();
        let expected = expected_internal_token_for_node(&node_tokens, NodeId::new_v4());
        assert_eq!(expected, None);
    }

    #[test]
    fn expected_internal_token_returns_node_token() {
        let node = NodeId::new_v4();
        let mut node_tokens = HashMap::new();
        node_tokens.insert(node, "node-token".to_string());

        let expected = expected_internal_token_for_node(&node_tokens, node);
        assert_eq!(expected, Some("node-token"));
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn run_cleanup(
    State(state): State<ServerState>,
    Query(query): Query<CleanupQuery>,
) -> impl IntoResponse {
    let retention_secs = query.retention_secs.unwrap_or(60 * 60 * 24);
    let dry_run = query.dry_run.unwrap_or(true);

    let store = state.store.lock().await;
    match store.cleanup_unreferenced(retention_secs, dry_run).await {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "maintenance cleanup failed");
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

        node.public_url
    };

    let http = reqwest::Client::new();

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
