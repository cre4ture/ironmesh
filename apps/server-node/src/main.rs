use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
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
        .route("/health", get(health))
        .route("/store/{key}", put(put_object).get(get_object))
        .with_state(state);

    let bind_addr: SocketAddr = "127.0.0.1:8080".parse()?;
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
