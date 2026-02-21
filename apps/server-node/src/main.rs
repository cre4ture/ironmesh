use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use common::{HealthStatus, NodeId};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::info;

mod cluster;
mod storage;

use cluster::{ClusterService, NodeDescriptor, ReplicationPlan, ReplicationPolicy};
use storage::{
    PersistentStore, PutOptions, SnapshotInfo, StoreReadError, VersionConsistencyState,
};

#[derive(Clone)]
struct ServerState {
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
    cluster: Arc<Mutex<ClusterService>>,
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

    let data_dir = std::env::var("IRONMESH_DATA_DIR").unwrap_or_else(|_| "./data/server-node".to_string());
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

    let public_url = std::env::var("IRONMESH_PUBLIC_URL").unwrap_or_else(|_| format!("http://{bind_addr}"));

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

    let state = ServerState {
        node_id,
        store: Arc::new(Mutex::new(PersistentStore::init(data_dir).await?)),
        cluster: Arc::new(Mutex::new(cluster)),
    };

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
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route("/cluster/nodes/{node_id}", put(register_node))
        .route("/cluster/nodes/{node_id}/heartbeat", post(node_heartbeat))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route("/cluster/replication/plan", get(replication_plan))
        .route("/cluster/replication/audit", post(trigger_replication_audit))
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
                store.current_keys()
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
    <li><code>GET /versions/{{key}}</code> — list version DAG metadata</li>
    <li><code>POST /versions/{{key}}/confirm/{{version_id}}</code> — mark provisional version as confirmed</li>
      <li><code>GET /cluster/status</code> — cluster summary</li>
      <li><code>GET /cluster/nodes</code> — known node list</li>
      <li><code>PUT /cluster/nodes/{{node_id}}</code> — register/update node metadata</li>
      <li><code>POST /cluster/nodes/{{node_id}}/heartbeat</code> — refresh node liveness</li>
      <li><code>GET /cluster/placement/{{key}}</code> — deterministic placement decision</li>
      <li><code>GET /cluster/replication/plan</code> — current replication gaps/overages</li>
      <li><code>POST /cluster/replication/audit</code> — manual audit trigger</li>
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
            },
        )
        .await
    {
        Ok(outcome) => {
            drop(store);

            let mut cluster = state.cluster.lock().await;
            cluster.note_replica(&key, state.node_id);

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
    let store = state.store.lock().await;
    match store
        .get_object(&key, query.snapshot.as_deref(), query.version.as_deref())
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

async fn list_versions(State(state): State<ServerState>, Path(key): Path<String>) -> impl IntoResponse {
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
    let mut store = state.store.lock().await;
    match store.confirm_version(&key, &version_id).await {
        Ok(true) => StatusCode::NO_CONTENT,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(err) => {
            tracing::error!(key = %key, version_id = %version_id, error = %err, "failed to confirm version");
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

async fn replication_plan(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };

    let mut cluster = state.cluster.lock().await;
    cluster.update_health_and_detect_offline_transition();
    Json(cluster.replication_plan(&keys))
}

async fn trigger_replication_audit(State(state): State<ServerState>) -> Json<ReplicationPlan> {
    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
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
