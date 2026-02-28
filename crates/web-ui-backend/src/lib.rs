use anyhow::{Context, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use client_sdk::{ClientNode, UploadMode};
use reqwest::Client;
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

#[derive(Debug, Clone)]
pub struct WebUiConfig {
    pub server_url: String,
    pub service_name: String,
}

impl WebUiConfig {
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            service_name: "ironmesh-web".to_string(),
        }
    }

    pub fn with_service_name(mut self, service_name: impl Into<String>) -> Self {
        self.service_name = service_name.into();
        self
    }
}

#[derive(Clone)]
struct WebState {
    server_url: String,
    service_name: String,
    http: Client,
    client: ClientNode,
}

pub fn router(config: WebUiConfig) -> Router {
    let state = WebState {
        server_url: config.server_url.clone(),
        service_name: config.service_name,
        http: Client::new(),
        client: ClientNode::new(config.server_url),
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

fn build_server_object_url(server_url: &str, key: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(server_url.trim_end_matches('/'))
        .with_context(|| format!("invalid server URL: {server_url}"))?;

    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow!("server URL cannot be a base"))?;
    segments.push("store");
    segments.push(key);
    drop(segments);

    Ok(url.to_string())
}

fn build_server_versions_url(server_url: &str, key: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(server_url.trim_end_matches('/'))
        .with_context(|| format!("invalid server URL: {server_url}"))?;

    let mut segments = url
        .path_segments_mut()
        .map_err(|_| anyhow!("server URL cannot be a base"))?;
    segments.push("versions");
    segments.push(key);
    drop(segments);

    Ok(url.to_string())
}

fn build_server_store_delete_url(server_url: &str, key: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(server_url.trim_end_matches('/'))
        .with_context(|| format!("invalid server URL: {server_url}"))?;

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("server URL cannot be a base"))?;
        segments.push("store");
        segments.push("delete");
    }
    url.query_pairs_mut().append_pair("key", key);

    Ok(url.to_string())
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
    match fetch_server_json(&state.http, &state.server_url, "/health").await {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_snapshots(State(state): State<WebState>) -> impl IntoResponse {
    match fetch_server_json(&state.http, &state.server_url, "/snapshots").await {
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

    let versions_url = match build_server_versions_url(&state.server_url, &query.key) {
        Ok(url) => url,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    match state.http.get(versions_url).send().await {
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
    if let Some(snapshot) = &query.snapshot {
        request = request.query(&[("snapshot", snapshot)]);
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

    let delete_url = match build_server_store_delete_url(&state.server_url, &query.key) {
        Ok(url) => url,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    let primary_result = state.http.post(delete_url).send().await;
    let fallback_to_legacy_delete = match primary_result {
        Ok(response) if response.status().is_success() => false,
        Ok(response)
            if response.status() == StatusCode::METHOD_NOT_ALLOWED
                || response.status() == StatusCode::NOT_FOUND =>
        {
            true
        }
        Ok(response) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!(
                    "delete endpoint rejected request: HTTP {} ({})",
                    response.status(),
                    response.url()
                ),
            );
        }
        Err(_) => true,
    };

    if !fallback_to_legacy_delete {
        let _ = state.client.remove_cached(&query.key).await;
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "key": query.key,
                "deleted": true
            })),
        )
            .into_response();
    }

    let object_url = match build_server_object_url(&state.server_url, &query.key) {
        Ok(url) => url,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    match state.http.delete(object_url).send().await {
        Ok(response) => match response.error_for_status() {
            Ok(_) => {
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
        },
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

    let payload = if query.snapshot.is_none() && query.version.is_none() {
        match state.client.get_cached_or_fetch(&query.key).await {
            Ok(bytes) => bytes,
            Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        }
    } else {
        let object_url = match build_server_object_url(&state.server_url, &query.key) {
            Ok(url) => url,
            Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
        };

        let mut request = state.http.get(object_url);
        if let Some(snapshot) = query.snapshot.as_deref() {
            request = request.query(&[("snapshot", snapshot)]);
        }
        if let Some(version) = query.version.as_deref() {
            request = request.query(&[("version", version)]);
        }

        match request.send().await {
            Ok(response) => match response.error_for_status() {
                Ok(ok) => match ok.bytes().await {
                    Ok(bytes) => bytes,
                    Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
                },
                Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
            },
            Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        }
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
