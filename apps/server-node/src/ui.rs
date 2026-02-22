use super::*;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::response::Html;
use storage::SnapshotInfo;

const INDEX_HTML_TEMPLATE: &str = include_str!("ui/index.html");
const INDEX_CSS: &str = include_str!("ui/app.css");
const INDEX_JS: &str = include_str!("ui/app.js");

pub(crate) async fn index(State(state): State<ServerState>) -> Html<String> {
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

    let (replication_plan_items, under_replicated, over_replicated) = {
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
        (
            plan.items.len(),
            plan.under_replicated,
            plan.over_replicated,
        )
    };

    let startup_repair_status = {
        let status = state.startup_repair_status.lock().await;
        startup_repair_status_label(*status)
    };

    let current_inflight_requests = state.inflight_requests.load(Ordering::Relaxed);
    let repair_busy_throttle_status = if state.repair_config.busy_throttle_enabled {
        format!(
            "enabled (threshold={}, wait={}ms)",
            state.repair_config.busy_inflight_threshold.max(1),
            state.repair_config.busy_wait_millis.max(10)
        )
    } else {
        "disabled".to_string()
    };

    let peer_heartbeat_status = if state.peer_heartbeat_config.enabled {
        format!(
            "enabled (every {}s)",
            state.peer_heartbeat_config.interval_secs.max(1)
        )
    } else {
        "disabled".to_string()
    };

    let latest_snapshot = snapshots
        .first()
        .map(|s| s.id.clone())
        .unwrap_or_else(|| "none".to_string());

    let body = INDEX_HTML_TEMPLATE
        .replace("__NODE_ID__", &state.node_id.to_string())
        .replace("__OBJECT_COUNT__", &object_count.to_string())
        .replace("__LATEST_SNAPSHOT__", &latest_snapshot)
        .replace("__STORAGE_DIR__", &storage_dir)
        .replace("__CLUSTER_ONLINE__", &cluster_online.to_string())
        .replace("__CLUSTER_TOTAL__", &cluster_total.to_string())
        .replace("__REPLICATION_FACTOR__", &replication_factor.to_string())
        .replace(
            "__AUTONOMOUS_REPLICATION_ON_PUT__",
            if state.autonomous_replication_on_put_enabled {
                "enabled"
            } else {
                "disabled"
            },
        )
        .replace(
            "__REPLICATION_AUDIT_INTERVAL_SECS__",
            &state.replication_audit_interval_secs.max(5).to_string(),
        )
        .replace("__PEER_HEARTBEAT_STATUS__", &peer_heartbeat_status)
        .replace("__STARTUP_REPAIR_STATUS__", startup_repair_status)
        .replace(
            "__STARTUP_REPAIR_DELAY_SECS__",
            &state.repair_config.startup_repair_delay_secs.to_string(),
        )
        .replace(
            "__REPAIR_BUSY_THROTTLE_STATUS__",
            &repair_busy_throttle_status,
        )
        .replace(
            "__CURRENT_INFLIGHT_REQUESTS__",
            &current_inflight_requests.to_string(),
        )
        .replace(
            "__REPLICATION_PLAN_ITEMS__",
            &replication_plan_items.to_string(),
        )
        .replace("__UNDER_REPLICATED__", &under_replicated.to_string())
        .replace("__OVER_REPLICATED__", &over_replicated.to_string());

    Html(body)
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogsQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    entries: Vec<String>,
}

pub(crate) async fn list_logs(
    State(state): State<ServerState>,
    Query(query): Query<LogsQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    (
        StatusCode::OK,
        Json(LogsResponse {
            entries: state.log_buffer.recent(limit),
        }),
    )
        .into_response()
}

pub(crate) async fn app_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        INDEX_CSS,
    )
}

pub(crate) async fn app_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        INDEX_JS,
    )
}
