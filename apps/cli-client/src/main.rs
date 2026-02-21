use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use client_sdk::ClientNode;
use reqwest::Client;
use serde::Deserialize;

#[derive(Clone)]
struct WebState {
    server_url: String,
    http: Client,
    client: ClientNode,
}

#[derive(Debug, Parser)]
#[command(name = "ironmesh")]
#[command(about = "CLI client for ironmesh distributed storage")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_url: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Put {
        key: String,
        value: String,
    },
    Get {
        key: String,
    },
    List {
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, default_value_t = 1)]
        depth: usize,
    },
    Health,
    ClusterStatus,
    Nodes,
    ReplicationPlan,
    CacheList,
    ServeWeb {
        #[arg(long, default_value = "127.0.0.1:8081")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = ClientNode::new(&cli.server_url);
    let http = Client::new();

    match cli.command {
        Commands::Put { key, value } => {
            let object = client.put(key, Bytes::from(value)).await?;
            println!("stored '{}' ({} bytes)", object.key, object.size_bytes);
        }
        Commands::Get { key } => {
            let payload = client.get_cached_or_fetch(&key).await?;
            println!("{}", String::from_utf8_lossy(&payload));
        }
        Commands::List { prefix, depth } => {
            let value = http
                .get(format!(
                    "{}/store/index",
                    cli.server_url.trim_end_matches('/')
                ))
                .query(&[("depth", depth.to_string())])
                .query(&prefix.as_ref().map(|value| ("prefix", value.as_str())))
                .send()
                .await
                .context("failed to request store index")?
                .error_for_status()
                .context("store index request failed")?
                .json::<serde_json::Value>()
                .await
                .context("failed to decode store index response")?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Commands::Health => {
            print_json_endpoint(&http, &cli.server_url, "/health").await?;
        }
        Commands::ClusterStatus => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/status").await?;
        }
        Commands::Nodes => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/nodes").await?;
        }
        Commands::ReplicationPlan => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/replication/plan").await?;
        }
        Commands::CacheList => {
            for entry in client.cache_entries().await {
                println!("{} ({} bytes)", entry.key, entry.size_bytes);
            }
        }
        Commands::ServeWeb { bind } => {
            let bind_addr: SocketAddr = bind.parse()?;
            let state = WebState {
                server_url: cli.server_url.clone(),
                http,
                client,
            };

            let app = Router::new()
                .route("/", get(|| async { Html(web_ui::app_html()) }))
                .route("/api/health", get(web_health))
                .route("/api/cluster/status", get(web_cluster_status))
                .route("/api/cluster/nodes", get(web_cluster_nodes))
                .route("/api/cluster/replication/plan", get(web_replication_plan))
                .route("/api/store/list", get(web_store_list))
                .route("/api/store/get", get(web_store_get))
                .route("/api/store/put", post(web_store_put))
                .route(
                    "/api/ping",
                    get(|| async {
                        Json(serde_json::json!({
                            "ok": true,
                            "service": "cli-client-web"
                        }))
                    }),
                )
                .with_state(state);

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
struct WebStoreListQuery {
    prefix: Option<String>,
    depth: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct WebStoreGetQuery {
    key: String,
}

#[derive(Debug, Deserialize)]
struct WebStorePutRequest {
    key: String,
    value: String,
}

async fn print_json_endpoint(http: &Client, server_url: &str, path: &str) -> Result<()> {
    let value = fetch_server_json(http, server_url, path).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn fetch_server_json(
    http: &Client,
    server_url: &str,
    path: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}{}", server_url.trim_end_matches('/'), path);
    let value = http
        .get(url)
        .send()
        .await
        .context("failed to contact server")?
        .error_for_status()
        .context("server returned error status")?
        .json::<serde_json::Value>()
        .await
        .context("failed to decode server response")?;
    Ok(value)
}

fn error_response(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn web_health(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state.http, &state.server_url, "/health").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_cluster_status(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state.http, &state.server_url, "/cluster/status").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_cluster_nodes(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state.http, &state.server_url, "/cluster/nodes").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_replication_plan(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state.http, &state.server_url, "/cluster/replication/plan").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_list(
    State(state): State<WebState>,
    Query(query): Query<WebStoreListQuery>,
) -> impl IntoResponse {
    let mut request = state
        .http
        .get(format!(
            "{}/store/index",
            state.server_url.trim_end_matches('/')
        ))
        .query(&[("depth", query.depth.unwrap_or(1).max(1).to_string())]);
    if let Some(prefix) = &query.prefix {
        request = request.query(&[("prefix", prefix)]);
    }

    match request.send().await {
        Ok(response) => match response.error_for_status() {
            Ok(ok) => match ok.json::<serde_json::Value>().await {
                Ok(value) => (StatusCode::OK, Json(value)).into_response(),
                Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
            },
            Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        },
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_get(
    State(state): State<WebState>,
    Query(query): Query<WebStoreGetQuery>,
) -> impl IntoResponse {
    match state.client.get_cached_or_fetch(&query.key).await {
        Ok(payload) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "key": query.key,
                "value": String::from_utf8_lossy(&payload)
            })),
        )
            .into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_put(
    State(state): State<WebState>,
    Json(payload): Json<WebStorePutRequest>,
) -> impl IntoResponse {
    if payload.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    match state
        .client
        .put(payload.key.clone(), Bytes::from(payload.value))
        .await
    {
        Ok(meta) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "key": meta.key,
                "size_bytes": meta.size_bytes
            })),
        )
            .into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}
