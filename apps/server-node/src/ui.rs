use super::*;
use axum::response::Html;
use storage::SnapshotInfo;

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
        #server-logs {{ background: #f4f4f4; padding: 0.75rem; border-radius: 0.2rem; min-height: 12rem; max-height: 24rem; overflow: auto; white-space: pre-wrap; }}
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
        <h2>Background work</h2>
        <ul>
            <li><strong>Autonomous post-write replication</strong>: <code>{}</code></li>
            <li><strong>Periodic replication audit</strong>: <code>enabled (every {}s)</code></li>
            <li><strong>Autonomous peer heartbeat emitter</strong>: <code>{}</code></li>
            <li><strong>Startup one-shot repair</strong>: <code>{}</code> (delay: <code>{}s</code>)</li>
            <li><strong>Repair busy-throttle</strong>: <code>{}</code>; in-flight requests now=<code>{}</code></li>
            <li><strong>Current replication backlog</strong>: plan items=<code>{}</code>, under-replicated=<code>{}</code>, over-replicated=<code>{}</code></li>
        </ul>
        <h2>Server logs</h2>
        <p>Recent in-memory log lines from this node.</p>
        <pre id=\"server-logs\">loading…</pre>
    <h2>Available routes</h2>
    <ul>
      <li><code>GET /</code> — info page</li>
            <li><code>GET /logs?limit=&lt;n&gt;</code> — latest server log lines</li>
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
    <script>
        async function refreshServerLogs() {{
            try {{
                const response = await fetch('/logs?limit=200', {{ cache: 'no-store' }});
                if (!response.ok) {{
                    throw new Error('HTTP ' + response.status);
                }}

                const payload = await response.json();
                const logs = Array.isArray(payload.entries) ? payload.entries : [];
                document.getElementById('server-logs').textContent = logs.join('\\n') || 'no logs yet';
            }} catch (error) {{
                document.getElementById('server-logs').textContent = 'failed to load logs: ' + error;
            }}
        }}

        refreshServerLogs();
        setInterval(refreshServerLogs, 2000);
    </script>
</body>
</html>\n",
        state.node_id,
        object_count,
        latest_snapshot,
        storage_dir,
        cluster_online,
        cluster_total,
        replication_factor,
        if state.autonomous_replication_on_put_enabled {
            "enabled"
        } else {
            "disabled"
        },
        state.replication_audit_interval_secs.max(5),
        peer_heartbeat_status,
        startup_repair_status,
        state.repair_config.startup_repair_delay_secs,
        repair_busy_throttle_status,
        current_inflight_requests,
        replication_plan_items,
        under_replicated,
        over_replicated,
    );

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
