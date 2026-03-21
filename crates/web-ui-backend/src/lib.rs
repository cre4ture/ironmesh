use anyhow::{Context, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, IronMeshClient, RelayMode,
    RendezvousClientConfig, RendezvousControlClient, RendezvousEndpointConnectionState,
    RendezvousEndpointStatus, StoreIndexView, UploadMode, build_http_client_from_pem,
    build_http_client_with_identity_from_pem,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub mod assets {
    pub fn app_html() -> String {
        include_str!(concat!(env!("OUT_DIR"), "/client_ui_index.html")).to_string()
    }

    pub(crate) fn index_html() -> &'static str {
        include_str!(concat!(env!("OUT_DIR"), "/client_ui_index.html"))
    }

    pub(crate) fn app_js() -> &'static str {
        include_str!(concat!(env!("OUT_DIR"), "/client_ui_app.js"))
    }

    pub(crate) fn app_css() -> &'static str {
        include_str!(concat!(env!("OUT_DIR"), "/client_ui_app.css"))
    }
}

#[derive(Clone)]
pub struct WebUiConfig {
    pub server_url: String,
    pub service_name: String,
    pub server_ca_pem: Option<String>,
    pub client_identity: Option<ClientIdentityMaterial>,
    pub connection_bootstrap: Option<ConnectionBootstrap>,
    pub connection_bootstrap_persistence: Option<WebUiBootstrapPersistence>,
    pub transport_client: Option<IronMeshClient>,
}

type PersistBootstrapFn = dyn Fn(&ConnectionBootstrap) -> Result<()> + Send + Sync;

#[derive(Clone)]
pub struct WebUiBootstrapPersistence {
    source: &'static str,
    persist: Arc<PersistBootstrapFn>,
}

impl WebUiBootstrapPersistence {
    pub fn new<F>(source: &'static str, persist: F) -> Self
    where
        F: Fn(&ConnectionBootstrap) -> Result<()> + Send + Sync + 'static,
    {
        Self {
            source,
            persist: Arc::new(persist),
        }
    }

    fn persist(&self, bootstrap: &ConnectionBootstrap) -> Result<()> {
        (self.persist)(bootstrap)
    }

    fn source(&self) -> &'static str {
        self.source
    }
}

impl WebUiConfig {
    pub fn new(server_url: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            service_name: "ironmesh-web".to_string(),
            server_ca_pem: None,
            client_identity: None,
            connection_bootstrap: None,
            connection_bootstrap_persistence: None,
            transport_client: None,
        }
    }

    pub fn from_client(client: IronMeshClient) -> Self {
        Self {
            server_url: String::new(),
            service_name: "ironmesh-web".to_string(),
            server_ca_pem: None,
            client_identity: None,
            connection_bootstrap: None,
            connection_bootstrap_persistence: None,
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

    pub fn with_connection_bootstrap(mut self, bootstrap: ConnectionBootstrap) -> Self {
        self.connection_bootstrap = Some(bootstrap);
        self
    }

    pub fn with_connection_bootstrap_persistence(
        mut self,
        persistence: WebUiBootstrapPersistence,
    ) -> Self {
        self.connection_bootstrap_persistence = Some(persistence);
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
    runtime: Arc<RwLock<WebRuntime>>,
}

struct WebRuntime {
    sdk: IronMeshClient,
    client: ClientNode,
    rendezvous: Option<WebRendezvousRuntimeConfig>,
    last_rendezvous_probe_error: Option<String>,
    last_rendezvous_probe_statuses: Vec<RendezvousEndpointStatus>,
}

#[derive(Clone)]
struct WebRendezvousRuntimeConfig {
    bootstrap: ConnectionBootstrap,
    client_identity: Option<ClientIdentityMaterial>,
    persistence: Option<WebUiBootstrapPersistence>,
}

pub fn router(config: WebUiConfig) -> Router {
    let sdk = match config.transport_client {
        Some(client) => client,
        None if config.connection_bootstrap.is_some() => config
            .connection_bootstrap
            .as_ref()
            .unwrap()
            .build_client_with_optional_identity(config.client_identity.as_ref())
            .unwrap_or_else(|error| panic!("failed building web ui bootstrap client: {error:#}")),
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
                None => {
                    build_http_client_from_pem(config.server_ca_pem.as_deref(), server_url.as_str())
                        .unwrap_or_else(|error| panic!("failed building web ui client: {error:#}"))
                }
            }
        }
    };
    let state = WebState {
        service_name: config.service_name,
        runtime: Arc::new(RwLock::new(WebRuntime {
            sdk: sdk.clone(),
            client: ClientNode::with_client(sdk),
            rendezvous: config
                .connection_bootstrap
                .map(|bootstrap| WebRendezvousRuntimeConfig {
                    bootstrap,
                    client_identity: config.client_identity,
                    persistence: config.connection_bootstrap_persistence,
                }),
            last_rendezvous_probe_error: None,
            last_rendezvous_probe_statuses: Vec::new(),
        })),
    };

    Router::new()
        .route("/", get(web_static_index))
        .route("/media/thumbnail", get(web_media_thumbnail))
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
        .route(
            "/api/rendezvous",
            get(web_rendezvous).put(web_update_rendezvous),
        )
        .route("/api/rendezvous/refresh", post(web_refresh_rendezvous))
        .route("/api/ping", get(web_ping))
        .route("/{*path}", get(web_static_file))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
struct WebStoreListQuery {
    prefix: Option<String>,
    depth: Option<usize>,
    snapshot: Option<String>,
    view: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebStoreGetQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    preview_bytes: Option<usize>,
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
struct WebMediaThumbnailQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    read_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebVersionsQuery {
    key: String,
}

#[derive(Debug, Deserialize)]
struct WebRendezvousUpdateRequest {
    rendezvous_urls: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct WebClientRendezvousView {
    available: bool,
    editable: bool,
    transport_mode: &'static str,
    relay_mode: Option<RelayMode>,
    configured_urls: Vec<String>,
    active_url: Option<String>,
    active_target_node_id: Option<String>,
    mtls_required: bool,
    persistence_source: &'static str,
    last_probe_error: Option<String>,
    endpoint_statuses: Vec<WebClientRendezvousEndpointStatus>,
}

#[derive(Debug, Clone, Serialize)]
struct WebClientRendezvousEndpointStatus {
    url: String,
    status: &'static str,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    consecutive_failures: u64,
    last_error: Option<String>,
    active: bool,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

async fn fetch_server_json(state: &WebState, path: &str) -> Result<serde_json::Value> {
    current_sdk(state).await.get_json_path(path).await
}

async fn current_sdk(state: &WebState) -> IronMeshClient {
    state.runtime.read().await.sdk.clone()
}

async fn current_client(state: &WebState) -> ClientNode {
    state.runtime.read().await.client.clone()
}

fn normalize_rendezvous_urls(urls: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for url in urls {
        let trimmed = url.trim().trim_end_matches('/');
        if trimmed.is_empty() || normalized.iter().any(|existing| existing == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

fn endpoint_status_label(state: &RendezvousEndpointConnectionState) -> &'static str {
    match state {
        RendezvousEndpointConnectionState::Unknown => "unknown",
        RendezvousEndpointConnectionState::Connected => "connected",
        RendezvousEndpointConnectionState::Disconnected => "disconnected",
    }
}

fn map_endpoint_statuses(
    statuses: Vec<RendezvousEndpointStatus>,
) -> Vec<WebClientRendezvousEndpointStatus> {
    statuses
        .into_iter()
        .map(|status| WebClientRendezvousEndpointStatus {
            url: status.url,
            status: endpoint_status_label(&status.status),
            last_attempt_unix: status.last_attempt_unix,
            last_success_unix: status.last_success_unix,
            consecutive_failures: status.consecutive_failures,
            last_error: status.last_error,
            active: status.active,
        })
        .collect()
}

fn build_rendezvous_probe_client(
    config: &WebRendezvousRuntimeConfig,
) -> Result<Option<RendezvousControlClient>> {
    let rendezvous_urls = normalize_rendezvous_urls(&config.bootstrap.rendezvous_urls);
    if rendezvous_urls.is_empty() {
        return Ok(None);
    }

    let rendezvous_client_identity_pem = config
        .client_identity
        .as_ref()
        .and_then(|identity| identity.rendezvous_client_identity_pem.as_deref());
    if config.bootstrap.rendezvous_mtls_required && rendezvous_client_identity_pem.is_none() {
        return Err(anyhow!(
            "rendezvous probing requires rendezvous client identity material when mTLS is enabled"
        ));
    }

    Ok(Some(RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id: config.bootstrap.cluster_id,
            rendezvous_urls,
            heartbeat_interval_secs: 15,
        },
        config
            .bootstrap
            .trust_roots
            .rendezvous_ca_pem
            .as_deref()
            .or(config.bootstrap.trust_roots.cluster_ca_pem.as_deref()),
        rendezvous_client_identity_pem.map(str::as_bytes),
    )?))
}

async fn build_rendezvous_view(state: &WebState) -> WebClientRendezvousView {
    let runtime = state.runtime.read().await;
    let transport_mode = if runtime.sdk.uses_relay_transport() {
        "relay"
    } else {
        "direct"
    };

    let relay_client = runtime.sdk.rendezvous_client();
    let relay_runtime_state = relay_client
        .as_ref()
        .map(RendezvousControlClient::runtime_state);
    let relay_mode = runtime
        .rendezvous
        .as_ref()
        .map(|config| config.bootstrap.relay_mode);
    let configured_urls = runtime
        .rendezvous
        .as_ref()
        .map(|config| normalize_rendezvous_urls(&config.bootstrap.rendezvous_urls))
        .unwrap_or_else(|| {
            relay_client
                .as_ref()
                .map(|client| normalize_rendezvous_urls(&client.config().rendezvous_urls))
                .unwrap_or_default()
        });
    let active_url = relay_runtime_state
        .as_ref()
        .and_then(|snapshot| snapshot.active_url.clone());
    let endpoint_statuses = relay_runtime_state
        .map(|snapshot| map_endpoint_statuses(snapshot.endpoint_statuses))
        .unwrap_or_else(|| map_endpoint_statuses(runtime.last_rendezvous_probe_statuses.clone()));

    WebClientRendezvousView {
        available: runtime.rendezvous.is_some() || relay_client.is_some(),
        editable: runtime.rendezvous.is_some(),
        transport_mode,
        relay_mode,
        configured_urls,
        active_url,
        active_target_node_id: runtime
            .sdk
            .relay_target_node_id()
            .map(|node_id| node_id.to_string()),
        mtls_required: runtime
            .rendezvous
            .as_ref()
            .map(|config| config.bootstrap.rendezvous_mtls_required)
            .unwrap_or(false),
        persistence_source: runtime
            .rendezvous
            .as_ref()
            .and_then(|config| {
                config
                    .persistence
                    .as_ref()
                    .map(WebUiBootstrapPersistence::source)
            })
            .unwrap_or_else(|| {
                if runtime.rendezvous.is_some() {
                    "runtime_only"
                } else {
                    "unavailable"
                }
            }),
        last_probe_error: runtime.last_rendezvous_probe_error.clone(),
        endpoint_statuses,
    }
}

async fn probe_rendezvous_and_build_view(state: &WebState) -> WebClientRendezvousView {
    let (relay_client, rendezvous_config) = {
        let runtime = state.runtime.read().await;
        (runtime.sdk.rendezvous_client(), runtime.rendezvous.clone())
    };

    let probe_result = if let Some(relay_client) = relay_client {
        relay_client.probe_health_endpoints().await
    } else if let Some(rendezvous_config) = rendezvous_config {
        match build_rendezvous_probe_client(&rendezvous_config) {
            Ok(Some(client)) => client.probe_health_endpoints().await,
            Ok(None) => Ok(client_sdk::RendezvousRuntimeState {
                active_url: None,
                endpoint_statuses: Vec::new(),
            }),
            Err(error) => Err(error),
        }
    } else {
        Ok(client_sdk::RendezvousRuntimeState {
            active_url: None,
            endpoint_statuses: Vec::new(),
        })
    };

    {
        let mut runtime = state.runtime.write().await;
        match probe_result {
            Ok(snapshot) => {
                runtime.last_rendezvous_probe_statuses = snapshot.endpoint_statuses;
                runtime.last_rendezvous_probe_error = None;
            }
            Err(error) => {
                runtime.last_rendezvous_probe_error = Some(error.to_string());
            }
        }
    }

    build_rendezvous_view(state).await
}

async fn apply_runtime_client(
    state: &WebState,
    sdk: IronMeshClient,
    bootstrap: ConnectionBootstrap,
    client_identity: Option<ClientIdentityMaterial>,
    persistence: Option<WebUiBootstrapPersistence>,
) -> Result<()> {
    let mut runtime = state.runtime.write().await;
    runtime.sdk = sdk.clone();
    runtime.client = ClientNode::with_client(sdk);
    runtime.rendezvous = Some(WebRendezvousRuntimeConfig {
        bootstrap,
        client_identity,
        persistence,
    });
    runtime.last_rendezvous_probe_error = None;
    runtime.last_rendezvous_probe_statuses = Vec::new();
    Ok(())
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

fn build_media_thumbnail_request_path(query: &WebMediaThumbnailQuery) -> Result<String> {
    let mut query_pairs = vec![("key", query.key.as_str())];
    if let Some(snapshot) = query.snapshot.as_deref() {
        query_pairs.push(("snapshot", snapshot));
    }
    if let Some(version) = query.version.as_deref() {
        query_pairs.push(("version", version));
    }
    if let Some(read_mode) = query.read_mode.as_deref() {
        query_pairs.push(("read_mode", read_mode));
    }
    build_relative_path(&["media", "thumbnail"], &query_pairs)
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

    match current_sdk(&state)
        .await
        .get_json_path(&versions_path)
        .await
    {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_media_thumbnail(
    State(state): State<WebState>,
    Query(query): Query<WebMediaThumbnailQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let thumbnail_path = match build_media_thumbnail_request_path(&query) {
        Ok(path) => path,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    let response = match current_sdk(&state)
        .await
        .get_relative_path(&thumbnail_path)
        .await
    {
        Ok(response) => response,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };

    let mut headers = HeaderMap::new();
    if let Some(value) = response.headers.get(CONTENT_TYPE).cloned() {
        headers.insert(CONTENT_TYPE, value);
    }
    if let Some(value) = response.headers.get(CACHE_CONTROL).cloned() {
        headers.insert(CACHE_CONTROL, value);
    }

    (response.status, headers, response.body).into_response()
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
    let view = match query.view.as_deref() {
        None => None,
        Some("tree") => Some(StoreIndexView::Tree),
        Some("raw") => Some(StoreIndexView::Raw),
        Some(other) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                format!("unsupported store list view: {other}"),
            );
        }
    };

    match current_sdk(&state)
        .await
        .store_index_with_view(
            query.prefix.as_deref(),
            query.depth.unwrap_or(1).max(1),
            query.snapshot.as_deref(),
            view,
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

    let client = current_client(&state).await;
    let payload_result = if query.snapshot.is_none() && query.version.is_none() {
        client.get_cached_or_fetch(&query.key).await
    } else {
        client
            .get_with_selector(
                &query.key,
                query.snapshot.as_deref(),
                query.version.as_deref(),
            )
            .await
    };

    match payload_result {
        Ok(payload) => {
            let total_size_bytes = payload.len();
            let preview_size_bytes = query
                .preview_bytes
                .filter(|limit| *limit > 0)
                .map(|limit| limit.min(total_size_bytes));
            let truncated = preview_size_bytes
                .map(|preview_size_bytes| preview_size_bytes < total_size_bytes)
                .unwrap_or(false);
            let visible_payload = match preview_size_bytes {
                Some(preview_size_bytes) => &payload[..preview_size_bytes],
                None => payload.as_ref(),
            };

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "key": query.key,
                    "snapshot": query.snapshot,
                    "version": query.version,
                    "value": String::from_utf8_lossy(visible_payload),
                    "truncated": truncated,
                    "total_size_bytes": total_size_bytes,
                    "preview_size_bytes": preview_size_bytes,
                })),
            )
                .into_response()
        }
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

    match current_client(&state)
        .await
        .put(key, Bytes::from(value))
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

async fn web_store_delete(
    State(state): State<WebState>,
    Query(query): Query<WebStoreDeleteQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let client = current_client(&state).await;
    match client.delete_path(&query.key).await {
        Ok(()) => {
            let _ = client.remove_cached(&query.key).await;
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

    match current_client(&state)
        .await
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

    let payload = match current_client(&state)
        .await
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

async fn web_rendezvous(State(state): State<WebState>) -> impl IntoResponse {
    (StatusCode::OK, Json(build_rendezvous_view(&state).await)).into_response()
}

async fn web_refresh_rendezvous(State(state): State<WebState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(probe_rendezvous_and_build_view(&state).await),
    )
        .into_response()
}

async fn web_update_rendezvous(
    State(state): State<WebState>,
    Json(payload): Json<WebRendezvousUpdateRequest>,
) -> impl IntoResponse {
    let rendezvous = {
        let runtime = state.runtime.read().await;
        runtime.rendezvous.clone()
    };
    let Some(existing) = rendezvous else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "rendezvous configuration is only editable when the web UI was started from a bootstrap-based client",
        );
    };

    let mut bootstrap = existing.bootstrap.clone();
    bootstrap.rendezvous_urls = normalize_rendezvous_urls(&payload.rendezvous_urls);
    if let Err(error) = bootstrap.validate() {
        return error_response(StatusCode::BAD_REQUEST, error.to_string());
    }

    let build_bootstrap = bootstrap.clone();
    let build_identity = existing.client_identity.clone();
    let sdk_result = tokio::task::spawn_blocking(move || {
        build_bootstrap.build_client_with_optional_identity(build_identity.as_ref())
    })
    .await;
    let sdk = match sdk_result {
        Ok(Ok(client)) => client,
        Ok(Err(error)) => return error_response(StatusCode::BAD_GATEWAY, error.to_string()),
        Err(error) => {
            return error_response(
                StatusCode::BAD_GATEWAY,
                format!("client rebuild task panicked: {error}"),
            );
        }
    };

    if let Some(persistence) = existing.persistence.as_ref()
        && let Err(error) = persistence.persist(&bootstrap)
    {
        return error_response(StatusCode::BAD_GATEWAY, error.to_string());
    }

    if let Err(error) = apply_runtime_client(
        &state,
        sdk,
        bootstrap,
        existing.client_identity,
        existing.persistence,
    )
    .await
    {
        return error_response(StatusCode::BAD_GATEWAY, error.to_string());
    }

    (
        StatusCode::OK,
        Json(probe_rendezvous_and_build_view(&state).await),
    )
        .into_response()
}
