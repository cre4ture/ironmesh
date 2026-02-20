use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, put};
use axum::{Json, Router};
use bytes::Bytes;
use common::{HealthStatus, NodeId};
use tokio::sync::RwLock;
use tracing::info;

#[derive(Clone)]
struct ServerState {
    node_id: NodeId,
    objects: Arc<RwLock<HashMap<String, Bytes>>>,
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
        objects: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
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
        <p>This endpoint serves basic server information.</p>
        <h2>Available routes</h2>
        <ul>
            <li><code>GET /</code> — this information page</li>
            <li><code>GET /health</code> — node health JSON</li>
            <li><code>PUT /store/{{key}}</code> — store object bytes</li>
            <li><code>GET /store/{{key}}</code> — fetch object bytes</li>
        </ul>
    </main>
</body>
</html>\n",
                state.node_id
        );

        Html(body)
}

async fn put_object(
    State(state): State<ServerState>,
    Path(key): Path<String>,
    payload: Bytes,
) -> impl IntoResponse {
    state.objects.write().await.insert(key, payload);
    StatusCode::CREATED
}

async fn get_object(State(state): State<ServerState>, Path(key): Path<String>) -> impl IntoResponse {
    match state.objects.read().await.get(&key).cloned() {
        Some(bytes) => (StatusCode::OK, bytes).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
