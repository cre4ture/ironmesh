use anyhow::{Context, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, IronMeshClient, UploadMode, build_http_client_from_pem,
    build_http_client_with_identity_from_pem,
};
use reqwest::Url;
use serde::Deserialize;

pub mod assets {
    pub fn app_html() -> String {
        include_str!("../static/index.html").to_string()
    }

    pub(crate) fn index_html() -> &'static str {
        include_str!("../static/index.html")
    }

    pub(crate) fn app_js() -> &'static str {
        include_str!("../static/app.js")
    }

    pub(crate) fn app_css() -> &'static str {
        include_str!("../static/app.css")
    }
}

#[derive(Clone)]
pub struct WebUiConfig {
    pub server_url: String,
    pub service_name: String,
    pub server_ca_pem: Option<String>,
    pub client_identity: Option<ClientIdentityMaterial>,
    pub transport_client: Option<IronMeshClient>,
}

impl WebUiConfig {
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            service_name: "ironmesh-web".to_string(),
            server_ca_pem: None,
            client_identity: None,
            transport_client: None,
        }
    }

    pub fn from_client(client: IronMeshClient) -> Self {
        Self {
            server_url: String::new(),
            service_name: "ironmesh-web".to_string(),
            server_ca_pem: None,
            client_identity: None,
            transport_client: Some(client),
        }
    }

    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }

    pub fn with_server_ca_pem(mut self, server_ca_pem: impl Into<String>) -> Self {
        self.server_ca_pem = Some(server_ca_pem.into());
        self
    }

    pub fn with_client_identity(mut self, client_identity: ClientIdentityMaterial) -> Self {
        self.client_identity = Some(client_identity);
        self
    }

    pub fn with_transport_client(mut self, client: IronMeshClient) -> Self {
        self.transport_client = Some(client);
        self
    }
}

#[derive(Clone)]
struct WebState {
    service_name: String,
    sdk: IronMeshClient,
    client: ClientNode,
}

pub fn router(config: WebUiConfig) -> Router {
    let sdk = match config.transport_client {
        Some(client) => client,
        None => {
            let server_url =
                Url::parse(config.server_url.trim_end_matches('/')).unwrap_or_else(|error| {
                    panic!("invalid web ui server url {}: {error}", config.server_url)
                });
            match config.client_identity.as_ref() {
                Some(identity) => build_http_client_with_identity_from_pem(
                    config.server_ca_pem.as_deref(),
                    server_url.as_str(),
                    identity,
                )
                .unwrap_or_else(|error| {
                    panic!("failed building web ui authenticated client: {error:#}")
                }),
                None => build_http_client_from_pem(
                    config.server_ca_pem.as_deref(),
                    server_url.as_str(),
                    &None,
                )
                .unwrap_or_else(|error| panic!("failed building web ui client: {error:#}")),
            }
        }
    };
    let state = WebState {
        service_name: config.service_name,
        sdk: sdk.clone(),
        client: ClientNode::with_client(sdk),
    };

    Router::new()
        .route("/", get(web_static_index))
        .route("/{*path}", get(web_static_file))
        .route("/api/health", get(web_health))
        .route("/api/snapshots", get(web_snapshots))
        .route("/api/versions", get(web_versions))
        .route("/api/cluster/status", get(web_cluster_status))
        .route("/api/cluster/nodes", get(web_cluster_nodes))
        .route("/api/cluster/replication/plan", get(web_replication_plan))
        .route("/api/store/list", get(web_store_list))
        .route("/api/store/get", get(web_store_get))
        .route("/api/store/put", post(web_store_put))
        .route("/api/store/delete", delete(web_store_delete))
        .route("/api/store/get-binary", get(web_store_get_binary))
        .route("/api/store/put-binary", post(web_store_put_binary))
        .route("/api/ping", get(web_ping))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct WebStoreListQuery {
    prefix: Option<String>,
    depth: Option<usize>,
    snapshot: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebStoreGetQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebStorePutRequest {
    key: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct WebStoreDeleteQuery {
    key: String,
}

#[derive(Debug, Deserialize)]
struct WebStoreBinaryGetQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebStoreBinaryPutQuery {
    key: String,
}

#[derive(Debug, Deserialize)]
struct WebVersionsQuery {
    key: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn fetch_server_json(state: &WebState, path: &str) -> Result<serde_json::Value> {
    state.sdk.get_json_path(path).await
}

fn build_relative_path(segments: &[&str], query: &[(&str, &str)]) -> Result<String> {
    let mut url = Url::parse("https://web-ui.invalid/")
        .context("failed to create placeholder URL for relative path building")?;
    {
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("placeholder URL cannot be a base"))?;
        path_segments.clear();
        for segment in segments {
            path_segments.push(segment);
        }
    }
    if !query.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in query {
            pairs.append_pair(key, value);
        }
    }

    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    Ok(path)
}

fn build_versions_request_path(key: &str) -> Result<String> {
    build_relative_path(&["versions", key], &[])
}

fn content_type_for(path: &str) -> &'static str {
    if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".js") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else {
        "text/html; charset=utf-8"
    }
}

async fn web_static_index() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/html; charset=utf-8")],
        assets::index_html().as_bytes().to_vec(),
    )
        .into_response()
}

async fn web_static_file(Path(path): Path<String>) -> Response {
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }

    if path.is_empty() || path == "index.html" {
        return web_static_index().await;
    }

    let body = match path.as_str() {
        "app.js" => Some(assets::app_js().as_bytes().to_vec()),
        "app.css" => Some(assets::app_css().as_bytes().to_vec()),
        _ => None,
    };

    match body {
        Some(bytes) => (
            StatusCode::OK,
            [("content-type", content_type_for(&path))],
            bytes,
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn web_ping(State(state): State<WebState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "service": state.service_name
        })),
    )
        .into_response()
}

async fn web_health(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state, "/health").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_snapshots(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state, "/snapshots").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_versions(
    State(state): State<WebState>,
    Query(query): Query<WebVersionsQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let versions_path = match build_versions_request_path(&query.key) {
        Ok(path) => path,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    match state.sdk.get_json_path(&versions_path).await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_cluster_status(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state, "/cluster/status").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_cluster_nodes(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state, "/cluster/nodes").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_replication_plan(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state, "/cluster/replication/plan").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_list(
    State(state): State<WebState>,
    Query(query): Query<WebStoreListQuery>,
) -> impl IntoResponse {
    match state
        .sdk
        .store_index(
            query.prefix.as_deref(),
            query.depth.unwrap_or(1).max(1),
            query.snapshot.as_deref(),
        )
        .await
    {
        Ok(value) => (StatusCode::OK, Json(serde_json::json!(value))).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_get(
    State(state): State<WebState>,
    Query(query): Query<WebStoreGetQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let payload_result = if query.snapshot.is_none() && query.version.is_none() {
        state.client.get_cached_or_fetch(&query.key).await
    } else {
        state
            .client
            .get_with_selector(
                &query.key,
                query.snapshot.as_deref(),
                query.version.as_deref(),
            )
            .await
    };

    match payload_result {
        Ok(payload) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "key": query.key,
                "snapshot": query.snapshot,
                "version": query.version,
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
    let WebStorePutRequest { key, value } = payload;

    if key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    match state.client.put(key, Bytes::from(value)).await {
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

async fn web_store_delete(
    State(state): State<WebState>,
    Query(query): Query<WebStoreDeleteQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    match state.client.delete_path(&query.key).await {
        Ok(()) => {
            let _ = state.client.remove_cached(&query.key).await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "key": query.key,
                    "deleted": true
                })),
            )
                .into_response()
        }
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_put_binary(
    State(state): State<WebState>,
    Query(query): Query<WebStoreBinaryPutQuery>,
    payload: Bytes,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    match state
        .client
        .put_large_aware(query.key.clone(), payload)
        .await
    {
        Ok(report) => {
            let upload_mode = match report.upload_mode {
                UploadMode::Direct => "direct",
                UploadMode::Chunked => "chunked",
            };

            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "key": report.meta.key,
                    "size_bytes": report.meta.size_bytes,
                    "upload_mode": upload_mode,
                    "chunk_size_bytes": report.chunk_size_bytes,
                    "chunk_count": report.chunk_count,
                })),
            )
                .into_response()
        }
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_get_binary(
    State(state): State<WebState>,
    Query(query): Query<WebStoreBinaryGetQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let payload = match state
        .client
        .get_with_selector(
            &query.key,
            query.snapshot.as_deref(),
            query.version.as_deref(),
        )
        .await
    {
        Ok(bytes) => bytes,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };

    let fallback_name = query
        .key
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("object.bin");
    let filename = fallback_name.replace('"', "_");
    let content_disposition = format!("attachment; filename=\"{filename}\"");

    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    match HeaderValue::from_str(&content_disposition) {
        Ok(value) => {
            headers.insert(CONTENT_DISPOSITION, value);
        }
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid content-disposition header: {err}"),
            );
        }
    }

    (StatusCode::OK, headers, payload).into_response()
}
