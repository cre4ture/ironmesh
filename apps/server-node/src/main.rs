use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, put};
use axum::{Json, Router};
use bytes::Bytes;
use common::{HealthStatus, NodeId};
use serde::Deserialize;
use tokio::sync::Mutex;
use tracing::info;

mod storage;

use storage::{PersistentStore, SnapshotInfo, StoreReadError};

#[derive(Clone)]
struct ServerState {
    node_id: NodeId,
    store: Arc<Mutex<PersistentStore>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .compact()
        .init();

    let state = ServerState {
        node_id: NodeId::new_v4(),
        store: Arc::new(Mutex::new(
            PersistentStore::init(
                std::env::var("IRONMESH_DATA_DIR")
                    .unwrap_or_else(|_| "./data/server-node".to_string()),
            )
            .await?,
        )),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/snapshots", get(list_snapshots))
        .route("/store/{key}", put(put_object).get(get_object))
        .with_state(state);

    let bind_addr = std::env::var("IRONMESH_SERVER_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()?;
    info!(%bind_addr, "server node listening");

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
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

    let latest_snapshot = snapshots.first().map(|s| s.id.clone()).unwrap_or_else(|| "none".to_string());

        let body = format!(
                "<!doctype html>
<html lang=\"en\">
<head>
    <meta charset=\"utf-8\" />
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <title>ironmesh Server Node</title>
    <style>
        body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
        main {{ max-width: 760px; margin: 0 auto; }}
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
        <p>This endpoint serves basic server information.</p>
        <h2>Available routes</h2>
        <ul>
            <li><code>GET /</code> — this information page</li>
            <li><code>GET /health</code> — node health JSON</li>
          <li><code>GET /snapshots</code> — snapshot metadata</li>
            <li><code>PUT /store/{{key}}</code> — store object bytes</li>
          <li><code>GET /store/{{key}}</code> — fetch object bytes from latest state</li>
          <li><code>GET /store/{{key}}?snapshot=&lt;id&gt;</code> — fetch object from snapshot state</li>
        </ul>
        <p>Writes are chunked and content-addressed (deduplicated). Reads verify chunk hashes and detect corruption.</p>
    </main>
</body>
</html>\n",
            state.node_id,
            object_count,
            latest_snapshot,
            storage_dir,
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
    }

async fn put_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    payload: Bytes,
) -> impl IntoResponse {
        let mut store = state.store.lock().await;
        match store.put_object(&key, payload).await {
            Ok(outcome) => {
                info!(
                    key = %key,
                    snapshot_id = %outcome.snapshot_id,
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
        match store.get_object(&key, query.snapshot.as_deref()).await {
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
