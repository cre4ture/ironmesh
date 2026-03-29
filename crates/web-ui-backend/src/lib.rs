use anyhow::{Context, Result, anyhow};
use axum::extract::{Path, Query, State};
use axum::http::header::{
    ACCEPT_RANGES, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH,
    CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE,
};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, IronMeshClient, RelayMode,
    RendezvousClientConfig, RendezvousControlClient, RendezvousEndpointConnectionState,
    RendezvousEndpointStatus, StoreIndexView, UploadMode, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, ironmesh_client::DownloadRangeRequest,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::info;

const BACKEND_VERSION: &str = env!("CARGO_PKG_VERSION");
const BACKEND_REVISION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);
const MAX_FULL_LOGICAL_FILE_GET_BYTES: u64 = 64 * 1024 * 1024;

mod mbtiles;

#[derive(Clone, Default)]
struct RequestCancellation {
    cancelled: Arc<AtomicBool>,
}

impl RequestCancellation {
    fn new() -> Self {
        Self::default()
    }

    fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    fn guard(&self) -> RequestCancellationGuard {
        RequestCancellationGuard {
            cancelled: Arc::clone(&self.cancelled),
        }
    }
}

struct RequestCancellationGuard {
    cancelled: Arc<AtomicBool>,
}

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

pub mod assets {
    mod generated_assets {
        include!(concat!(env!("OUT_DIR"), "/client_ui_assets.rs"));
    }

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

    pub(crate) fn favicon_svg() -> &'static str {
        include_str!("../../../docs/assets/ironmesh-favicon.svg")
    }

    pub(crate) fn extra_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
        generated_assets::asset(path)
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
    pub map_glyphs_root: Option<PathBuf>,
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
            map_glyphs_root: None,
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
            map_glyphs_root: None,
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

    pub fn with_map_glyphs_root(mut self, map_glyphs_root: impl Into<PathBuf>) -> Self {
        self.map_glyphs_root = Some(map_glyphs_root.into());
        self
    }
}

#[derive(Clone)]
struct WebState {
    map_perf_logging_enabled: bool,
    map_glyphs_root: Option<PathBuf>,
    service_name: String,
    mbtiles_sources: Arc<RwLock<HashMap<String, Arc<mbtiles::LogicalMbtilesSource>>>>,
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
    let map_perf_logging_enabled = env_flag_is_truthy("IRONMESH_MAP_PERF_LOG");
    if map_perf_logging_enabled {
        info!("map performance logging enabled via IRONMESH_MAP_PERF_LOG");
    }
    let state = WebState {
        map_perf_logging_enabled,
        map_glyphs_root: resolve_map_glyphs_root(config.map_glyphs_root),
        service_name: config.service_name,
        mbtiles_sources: Arc::new(RwLock::new(HashMap::new())),
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
        .route("/ironmesh-favicon.svg", get(web_static_favicon))
        .route("/media/thumbnail", get(web_media_thumbnail))
        .route("/api/maps/mbtiles-metadata", get(web_map_mbtiles_metadata))
        .route("/api/maps/logical-file", get(web_map_logical_file))
        .route("/api/maps/tiles/{z}/{x}/{y}", get(web_map_xyz_tile))
        .route(
            "/api/maps/vector-tiles/{z}/{x}/{y}",
            get(web_map_vector_tile),
        )
        .route(
            "/api/maps/fonts/{fontstack}/{range}",
            get(web_map_font_range),
        )
        .route("/api/health", get(web_health))
        .route("/api/snapshots", get(web_snapshots))
        .route("/api/versions", get(web_versions))
        .route("/api/cluster/status", get(web_cluster_status))
        .route("/api/cluster/nodes", get(web_cluster_nodes))
        .route("/api/cluster/replication/plan", get(web_replication_plan))
        .route("/api/store/list", get(web_store_list))
        .route("/api/store/get", get(web_store_get))
        .route("/api/store/put", post(web_store_put))
        .route("/api/store/rename", post(web_store_rename))
        .route("/api/store/delete", delete(web_store_delete))
        .route("/api/store/uploads/start", post(web_store_upload_start))
        .route(
            "/api/store/uploads/{upload_id}/chunk/{index}",
            put(web_store_upload_chunk),
        )
        .route(
            "/api/store/uploads/{upload_id}/complete",
            post(web_store_upload_complete),
        )
        .route("/api/store/get-binary", get(web_store_get_binary))
        .route("/api/store/stream-binary", get(web_store_stream_binary))
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

fn resolve_map_glyphs_root(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = explicit.filter(|path| path.is_dir()) {
        return Some(path);
    }

    if let Ok(value) = std::env::var("IRONMESH_MAP_GLYPHS_DIR") {
        let path = PathBuf::from(value);
        if path.is_dir() {
            return Some(path);
        }
    }

    let repo_relative = PathBuf::from("map/maptiler-server-map-styles-and-samples-3.15/fonts");
    if repo_relative.is_dir() {
        return Some(repo_relative);
    }

    None
}

fn env_flag_is_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
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
struct WebStoreRenameRequest {
    from_path: String,
    to_path: String,
    #[serde(default)]
    overwrite: bool,
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
struct WebStoreUploadSessionStartRequest {
    key: String,
    total_size_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct WebMediaThumbnailQuery {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    read_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebMapLogicalFileQuery {
    manifest_key: String,
}

#[derive(Debug, Serialize)]
struct WebMapMbtilesMetadataResponse {
    attribution: Option<String>,
    center: Option<[f64; 3]>,
    format: Option<String>,
    id: Option<String>,
    minzoom: Option<u8>,
    maxzoom: Option<u8>,
    name: Option<String>,
    version: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SplitLogicalFileManifest {
    manifest_version: u32,
    #[serde(rename = "type")]
    manifest_type: String,
    logical_format: String,
    logical_key: String,
    logical_size_bytes: u64,
    parts_count: usize,
    parts: Vec<SplitLogicalFilePart>,
}

#[derive(Clone, Debug, Deserialize)]
struct SplitLogicalFilePart {
    part_id: String,
    key: String,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Clone, Debug)]
struct LoadedSplitLogicalFileManifest {
    manifest: SplitLogicalFileManifest,
    etag: String,
}

#[derive(Clone, Copy, Debug)]
struct LogicalFileByteRange {
    start: u64,
    end_inclusive: u64,
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
    direct_url: Option<String>,
    direct_target_node_id: Option<String>,
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

fn normalize_runtime_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
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
    let direct_url = runtime
        .sdk
        .direct_server_base_url()
        .map(normalize_runtime_url);
    let direct_target_node_id = runtime.rendezvous.as_ref().and_then(|config| {
        let direct_url = direct_url.as_ref()?;
        config
            .bootstrap
            .direct_endpoints
            .iter()
            .find_map(|endpoint| {
                (normalize_runtime_url(&endpoint.url) == *direct_url)
                    .then(|| endpoint.node_id.map(|node_id| node_id.to_string()))
                    .flatten()
            })
    });
    let endpoint_statuses = relay_runtime_state
        .map(|snapshot| map_endpoint_statuses(snapshot.endpoint_statuses))
        .unwrap_or_else(|| map_endpoint_statuses(runtime.last_rendezvous_probe_statuses.clone()));

    WebClientRendezvousView {
        available: runtime.rendezvous.is_some() || relay_client.is_some(),
        editable: runtime.rendezvous.is_some(),
        transport_mode,
        relay_mode,
        configured_urls,
        direct_url,
        direct_target_node_id,
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

fn parse_logical_file_range(value: &str, total_size_bytes: u64) -> Option<LogicalFileByteRange> {
    if total_size_bytes == 0 {
        return None;
    }

    let trimmed = value.trim();
    let range_spec = trimmed.strip_prefix("bytes=")?.trim();
    if range_spec.contains(',') {
        return None;
    }

    let (start_raw, end_raw) = range_spec.split_once('-')?;
    if start_raw.is_empty() {
        let suffix_length = end_raw.parse::<u64>().ok()?;
        if suffix_length == 0 {
            return None;
        }

        let start = total_size_bytes.saturating_sub(suffix_length);
        return Some(LogicalFileByteRange {
            start,
            end_inclusive: total_size_bytes.saturating_sub(1),
        });
    }

    let start = start_raw.parse::<u64>().ok()?;
    if start >= total_size_bytes {
        return None;
    }

    let end_inclusive = if end_raw.is_empty() {
        total_size_bytes.saturating_sub(1)
    } else {
        let end = end_raw.parse::<u64>().ok()?;
        if end < start {
            return None;
        }
        end.min(total_size_bytes.saturating_sub(1))
    };

    Some(LogicalFileByteRange {
        start,
        end_inclusive,
    })
}

fn logical_file_content_type(logical_format: &str) -> &'static str {
    if logical_format.eq_ignore_ascii_case("mbtiles") {
        "application/vnd.sqlite3"
    } else {
        "application/octet-stream"
    }
}

fn file_name_from_key(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

fn inline_binary_content_type_for(key: &str) -> &str {
    mime_guess::from_path(key)
        .first_raw()
        .unwrap_or("application/octet-stream")
}

fn build_inline_content_disposition(key: &str) -> String {
    let filename = file_name_from_key(key).replace('"', "_");
    format!("inline; filename=\"{filename}\"")
}

fn validate_split_logical_file_manifest(
    mut manifest: SplitLogicalFileManifest,
) -> Result<SplitLogicalFileManifest> {
    if manifest.manifest_version != 1 {
        return Err(anyhow!(
            "unsupported split logical file manifest version: {}",
            manifest.manifest_version
        ));
    }
    if manifest.manifest_type != "split_file_manifest" {
        return Err(anyhow!(
            "unsupported split logical file manifest type: {}",
            manifest.manifest_type
        ));
    }
    if manifest.logical_key.trim().is_empty() {
        return Err(anyhow!("logical_key must not be empty"));
    }
    if manifest.parts_count != manifest.parts.len() {
        return Err(anyhow!(
            "parts_count mismatch: declared={} actual={}",
            manifest.parts_count,
            manifest.parts.len()
        ));
    }
    if manifest.parts.is_empty() {
        return Err(anyhow!(
            "split logical file manifest must contain at least one part"
        ));
    }

    manifest.parts.sort_by_key(|part| part.offset_bytes);
    let mut expected_offset = 0_u64;
    for part in &manifest.parts {
        if part.part_id.trim().is_empty() {
            return Err(anyhow!("manifest part_id must not be empty"));
        }
        if part.key.trim().is_empty() {
            return Err(anyhow!("manifest part key must not be empty"));
        }
        if part.size_bytes == 0 {
            return Err(anyhow!("manifest part {} has zero size", part.part_id));
        }
        if part.offset_bytes != expected_offset {
            return Err(anyhow!(
                "manifest part {} offset mismatch: expected={} actual={}",
                part.part_id,
                expected_offset,
                part.offset_bytes
            ));
        }
        expected_offset = expected_offset
            .checked_add(part.size_bytes)
            .ok_or_else(|| anyhow!("manifest logical size overflow"))?;
    }

    if expected_offset != manifest.logical_size_bytes {
        return Err(anyhow!(
            "manifest logical_size_bytes mismatch: declared={} actual={}",
            manifest.logical_size_bytes,
            expected_offset
        ));
    }

    Ok(manifest)
}

async fn load_split_logical_file_manifest(
    state: &WebState,
    manifest_key: &str,
) -> Result<LoadedSplitLogicalFileManifest> {
    let started = Instant::now();
    let manifest_payload = current_client(state)
        .await
        .get_with_selector(manifest_key, None, None)
        .await
        .with_context(|| format!("failed to fetch split logical file manifest {manifest_key}"))?;
    let manifest = serde_json::from_slice::<SplitLogicalFileManifest>(&manifest_payload)
        .with_context(|| format!("failed to parse split logical file manifest {manifest_key}"))?;
    let manifest = validate_split_logical_file_manifest(manifest)?;

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            parts = manifest.parts.len(),
            logical_size_bytes = manifest.logical_size_bytes,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: loaded split logical file manifest"
        );
    }

    Ok(LoadedSplitLogicalFileManifest {
        manifest,
        etag: format!("\"{}\"", blake3::hash(&manifest_payload).to_hex()),
    })
}

async fn get_or_create_mbtiles_source(
    state: &WebState,
    manifest_key: &str,
) -> Result<Arc<mbtiles::LogicalMbtilesSource>> {
    let started = Instant::now();
    if let Some(source) = state
        .mbtiles_sources
        .read()
        .await
        .get(manifest_key)
        .cloned()
    {
        if state.map_perf_logging_enabled {
            info!(
                manifest_key = %manifest_key,
                cache = "hit",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "map perf: reusing cached MBTiles source"
            );
        }
        return Ok(source);
    }

    let loaded_manifest = load_split_logical_file_manifest(state, manifest_key).await?;
    let sdk = current_sdk(state).await;
    let manifest_key_owned = manifest_key.to_string();
    let perf_logging_enabled = state.map_perf_logging_enabled;
    let source = tokio::task::spawn_blocking(move || {
        mbtiles::LogicalMbtilesSource::new(
            manifest_key_owned,
            sdk,
            loaded_manifest,
            perf_logging_enabled,
        )
    })
    .await
    .context("MBTiles source construction task join failed")??;
    let source = Arc::new(source);

    let mut sources = state.mbtiles_sources.write().await;
    if let Some(existing) = sources.get(manifest_key) {
        if state.map_perf_logging_enabled {
            info!(
                manifest_key = %manifest_key,
                cache = "race-hit",
                elapsed_ms = started.elapsed().as_millis() as u64,
                "map perf: reusing concurrently initialized MBTiles source"
            );
        }
        return Ok(existing.clone());
    }
    sources.insert(manifest_key.to_string(), source.clone());
    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            cache = "miss",
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: initialized MBTiles source"
        );
    }
    Ok(source)
}

struct ObjectRangeSelection {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    start: u64,
    length: u64,
}

struct ObjectRangeDownloadRequest {
    sdk: IronMeshClient,
    selection: ObjectRangeSelection,
    perf_logging_enabled: bool,
    cancelled: Arc<AtomicBool>,
}

async fn download_object_range_bytes(request: ObjectRangeDownloadRequest) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let ObjectRangeDownloadRequest {
            sdk,
            selection,
            perf_logging_enabled,
            cancelled,
        } = request;
        let ObjectRangeSelection {
            key,
            snapshot,
            version,
            start,
            length,
        } = selection;
        let started = Instant::now();
        let mut body = Vec::with_capacity(length.min(1024 * 1024) as usize);
        let mut on_progress = |_progress: client_sdk::ironmesh_client::DownloadProgress| {};
        let should_cancel = || cancelled.load(Ordering::Relaxed);
        sdk.download_range_to_writer_with_progress_blocking(
            DownloadRangeRequest {
                key: key.as_str(),
                snapshot: snapshot.as_deref(),
                version: version.as_deref(),
                start,
                length,
            },
            &mut body,
            &mut on_progress,
            &should_cancel,
        )
        .with_context(|| {
            format!(
                "failed to download logical file segment key={key} start={start} length={length}"
            )
        })?;
        if perf_logging_enabled {
            info!(
                key = %key,
                snapshot = snapshot.as_deref().unwrap_or("<current>"),
                version = version.as_deref().unwrap_or("<latest>"),
                start,
                length,
                bytes = body.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "map perf: downloaded logical file segment"
            );
        }
        Ok::<Vec<u8>, anyhow::Error>(body)
    })
    .await
    .context("logical file range download task join failed")?
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
        None => match assets::extra_asset(&path) {
            Some((bytes, content_type)) => (
                StatusCode::OK,
                [("content-type", content_type)],
                bytes.to_vec(),
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

async fn web_static_favicon() -> Response {
    (
        StatusCode::OK,
        [("content-type", "image/svg+xml; charset=utf-8")],
        assets::favicon_svg().as_bytes().to_vec(),
    )
        .into_response()
}

async fn web_ping(State(state): State<WebState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "service": state.service_name,
            "backend_version": BACKEND_VERSION,
            "backend_revision": BACKEND_REVISION,
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

async fn web_map_mbtiles_metadata(
    State(state): State<WebState>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let started = Instant::now();
    if query.manifest_key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "manifest_key must not be empty");
    }

    let source = match get_or_create_mbtiles_source(&state, query.manifest_key.trim()).await {
        Ok(source) => source,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };
    let metadata = source.metadata();
    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %query.manifest_key.trim(),
            minzoom = metadata.minzoom.unwrap_or_default(),
            maxzoom = metadata.maxzoom.unwrap_or_default(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served MBTiles metadata"
        );
    }

    (
        StatusCode::OK,
        Json(WebMapMbtilesMetadataResponse {
            attribution: metadata.attribution.clone(),
            center: metadata.center,
            format: metadata.format.clone(),
            id: metadata.id.clone(),
            minzoom: metadata.minzoom,
            maxzoom: metadata.maxzoom,
            name: metadata.name.clone(),
            version: metadata.version.clone(),
        }),
    )
        .into_response()
}

async fn web_map_logical_file(
    State(state): State<WebState>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let request_cancellation = RequestCancellation::new();
    let _request_cancellation_guard = request_cancellation.guard();
    let started = Instant::now();
    if query.manifest_key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "manifest_key must not be empty");
    }

    let loaded_manifest =
        match load_split_logical_file_manifest(&state, query.manifest_key.trim()).await {
            Ok(manifest) => manifest,
            Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        };

    let total_size_bytes = loaded_manifest.manifest.logical_size_bytes;
    let selected_range = match headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| parse_logical_file_range(value, total_size_bytes))
    {
        Some(Some(range)) => Some(range),
        Some(None) => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let headers = response.headers_mut();
            headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            headers.insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{total_size_bytes}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
            );
            headers.insert(
                ETAG,
                HeaderValue::from_str(&loaded_manifest.etag)
                    .unwrap_or_else(|_| HeaderValue::from_static("\"invalid-etag\"")),
            );
            return response;
        }
        None => None,
    };

    if method != Method::HEAD
        && selected_range.is_none()
        && total_size_bytes > MAX_FULL_LOGICAL_FILE_GET_BYTES
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            format!(
                "full logical file GET is disabled for files larger than {MAX_FULL_LOGICAL_FILE_GET_BYTES} bytes; use range requests"
            ),
        );
    }

    let mut response_headers = HeaderMap::new();
    response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    response_headers.insert(
        ETAG,
        HeaderValue::from_str(&loaded_manifest.etag)
            .unwrap_or_else(|_| HeaderValue::from_static("\"invalid-etag\"")),
    );
    response_headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(logical_file_content_type(
            &loaded_manifest.manifest.logical_format,
        )),
    );
    response_headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!(
            "inline; filename=\"{}\"",
            file_name_from_key(&loaded_manifest.manifest.logical_key)
        ))
        .unwrap_or_else(|_| HeaderValue::from_static("inline")),
    );

    let content_length = selected_range
        .map(|range| range.end_inclusive - range.start + 1)
        .unwrap_or(total_size_bytes);
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    if let Some(range) = selected_range {
        response_headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                range.start, range.end_inclusive, total_size_bytes
            ))
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
        );
    }

    if method == Method::HEAD {
        return (
            selected_range
                .map(|_| StatusCode::PARTIAL_CONTENT)
                .unwrap_or(StatusCode::OK),
            response_headers,
            Vec::<u8>::new(),
        )
            .into_response();
    }

    let range_start = selected_range.map(|range| range.start).unwrap_or(0);
    let range_end_exclusive = selected_range
        .map(|range| range.end_inclusive.saturating_add(1))
        .unwrap_or(total_size_bytes);
    let sdk = current_sdk(&state).await;
    let mut body = Vec::with_capacity(content_length.min(1024 * 1024) as usize);

    for part in &loaded_manifest.manifest.parts {
        let part_start = part.offset_bytes;
        let part_end_exclusive = part.offset_bytes + part.size_bytes;
        if part_end_exclusive <= range_start || part_start >= range_end_exclusive {
            continue;
        }

        let segment_start = range_start.max(part_start);
        let segment_end_exclusive = range_end_exclusive.min(part_end_exclusive);
        let local_start = segment_start - part_start;
        let segment_length = segment_end_exclusive - segment_start;
        if segment_length == 0 {
            continue;
        }

        match download_object_range_bytes(ObjectRangeDownloadRequest {
            sdk: sdk.clone(),
            selection: ObjectRangeSelection {
                key: part.key.clone(),
                snapshot: None,
                version: None,
                start: local_start,
                length: segment_length,
            },
            perf_logging_enabled: state.map_perf_logging_enabled,
            cancelled: request_cancellation.flag(),
        })
        .await
        {
            Ok(bytes) => body.extend_from_slice(&bytes),
            Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        }
    }

    if body.len() as u64 != content_length {
        return error_response(
            StatusCode::BAD_GATEWAY,
            format!(
                "logical file reconstruction produced {} bytes, expected {content_length}",
                body.len()
            ),
        );
    }

    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %query.manifest_key.trim(),
            method = %method,
            range_start,
            range_end_exclusive,
            content_length,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served logical file bytes"
        );
    }

    (
        selected_range
            .map(|_| StatusCode::PARTIAL_CONTENT)
            .unwrap_or(StatusCode::OK),
        response_headers,
        body,
    )
        .into_response()
}

async fn web_map_xyz_tile(
    State(state): State<WebState>,
    Path((z, x, y)): Path<(u32, u32, u32)>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let request_cancellation = RequestCancellation::new();
    let _request_cancellation_guard = request_cancellation.guard();
    let started = Instant::now();
    if query.manifest_key.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let source = match get_or_create_mbtiles_source(&state, query.manifest_key.trim()).await {
        Ok(source) => source,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let tile_lookup = tokio::task::spawn_blocking({
        let cancelled = request_cancellation.flag();
        move || source.lookup_tile_with_cancellation(z, x, y, cancelled)
    })
    .await;
    let tile = match tile_lookup {
        Ok(Ok(Some(tile))) => tile,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(_)) | Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %query.manifest_key.trim(),
            z,
            x,
            y,
            bytes = tile.bytes.len(),
            content_type = tile.content_type,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served raster XYZ tile"
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(tile.content_type));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );

    (StatusCode::OK, headers, tile.bytes).into_response()
}

async fn web_map_vector_tile(
    State(state): State<WebState>,
    Path((z, x, y)): Path<(u32, u32, u32)>,
    Query(query): Query<WebMapLogicalFileQuery>,
) -> impl IntoResponse {
    let request_cancellation = RequestCancellation::new();
    let _request_cancellation_guard = request_cancellation.guard();
    let started = Instant::now();
    if query.manifest_key.trim().is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let source = match get_or_create_mbtiles_source(&state, query.manifest_key.trim()).await {
        Ok(source) => source,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };

    let tile_lookup = tokio::task::spawn_blocking({
        let cancelled = request_cancellation.flag();
        move || source.lookup_vector_tile_with_cancellation(z, x, y, cancelled)
    })
    .await;
    let tile = match tile_lookup {
        Ok(Ok(Some(tile))) => tile,
        Ok(Ok(None)) => return StatusCode::NOT_FOUND.into_response(),
        Ok(Err(_)) | Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    if state.map_perf_logging_enabled {
        info!(
            manifest_key = %query.manifest_key.trim(),
            z,
            x,
            y,
            bytes = tile.bytes.len(),
            content_encoding = tile.content_encoding.unwrap_or("identity"),
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: served vector XYZ tile"
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(tile.content_type));
    if let Some(content_encoding) = tile.content_encoding {
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static(content_encoding));
    }
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600, stale-while-revalidate=86400"),
    );

    (StatusCode::OK, headers, tile.bytes).into_response()
}

async fn web_map_font_range(
    State(state): State<WebState>,
    Path((fontstack, range)): Path<(String, String)>,
) -> impl IntoResponse {
    let Some(glyphs_root) = state.map_glyphs_root.clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if !is_safe_fontstack_segment(&fontstack) || !is_safe_glyph_range_segment(&range) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let path = glyphs_root.join(&fontstack).join(&range);
    if !path.starts_with(&glyphs_root) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-protobuf"),
            );
            headers.insert(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=86400, stale-while-revalidate=604800"),
            );
            (StatusCode::OK, headers, bytes).into_response()
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(_) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

fn is_safe_fontstack_segment(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.split('.').any(|segment| segment == "..")
}

fn is_safe_glyph_range_segment(value: &str) -> bool {
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return false;
    }
    let Some((start, end)) = value.split_once('-') else {
        return false;
    };
    let Some(end) = end.strip_suffix(".pbf") else {
        return false;
    };
    !start.is_empty()
        && !end.is_empty()
        && start.chars().all(|ch| ch.is_ascii_digit())
        && end.chars().all(|ch| ch.is_ascii_digit())
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

async fn web_store_rename(
    State(state): State<WebState>,
    Json(request): Json<WebStoreRenameRequest>,
) -> impl IntoResponse {
    if request.from_path.trim().is_empty() || request.to_path.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "paths must not be empty");
    }

    match current_client(&state)
        .await
        .rename_path(
            request.from_path.clone(),
            request.to_path.clone(),
            request.overwrite,
        )
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "from_path": request.from_path,
                "to_path": request.to_path,
                "renamed": true
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

async fn web_store_upload_start(
    State(state): State<WebState>,
    Json(request): Json<WebStoreUploadSessionStartRequest>,
) -> impl IntoResponse {
    if request.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    match current_sdk(&state)
        .await
        .begin_upload_session(request.key.trim(), request.total_size_bytes)
        .await
    {
        Ok(session) => (StatusCode::CREATED, Json(session)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_upload_chunk(
    State(state): State<WebState>,
    Path((upload_id, index)): Path<(String, usize)>,
    payload: Bytes,
) -> impl IntoResponse {
    if upload_id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "upload_id must not be empty");
    }

    match current_sdk(&state)
        .await
        .upload_session_chunk_bytes(upload_id.trim(), index, payload.to_vec())
        .await
    {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

async fn web_store_upload_complete(
    State(state): State<WebState>,
    Path(upload_id): Path<String>,
) -> impl IntoResponse {
    if upload_id.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "upload_id must not be empty");
    }

    match current_sdk(&state)
        .await
        .finalize_upload_session(upload_id.trim())
        .await
    {
        Ok(response) => (StatusCode::CREATED, Json(response)).into_response(),
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

async fn web_store_stream_binary(
    State(state): State<WebState>,
    method: Method,
    headers: HeaderMap,
    Query(query): Query<WebStoreBinaryGetQuery>,
) -> impl IntoResponse {
    if query.key.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "key must not be empty");
    }

    let sdk = current_sdk(&state).await;
    let head = match sdk
        .head_object(
            &query.key,
            query.snapshot.as_deref(),
            query.version.as_deref(),
        )
        .await
    {
        Ok(head) => head,
        Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
    };

    let total_size_bytes = head.total_size_bytes;
    let selected_range = match headers
        .get(RANGE)
        .and_then(|value| value.to_str().ok())
        .map(|value| parse_logical_file_range(value, total_size_bytes))
    {
        Some(Some(range)) => Some(range),
        Some(None) => {
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let response_headers = response.headers_mut();
            response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            response_headers.insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{total_size_bytes}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
            );
            if let Some(etag) = head.etag.as_deref()
                && let Ok(value) = HeaderValue::from_str(etag)
            {
                response_headers.insert(ETAG, value);
            }
            return response;
        }
        None => None,
    };

    let mut response_headers = HeaderMap::new();
    response_headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(etag) = head.etag.as_deref()
        && let Ok(value) = HeaderValue::from_str(etag)
    {
        response_headers.insert(ETAG, value);
    }

    match HeaderValue::from_str(inline_binary_content_type_for(&query.key)) {
        Ok(value) => {
            response_headers.insert(CONTENT_TYPE, value);
        }
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid content-type header: {err}"),
            );
        }
    }

    match HeaderValue::from_str(&build_inline_content_disposition(&query.key)) {
        Ok(value) => {
            response_headers.insert(CONTENT_DISPOSITION, value);
        }
        Err(err) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("invalid content-disposition header: {err}"),
            );
        }
    }

    let content_length = selected_range
        .map(|range| {
            range
                .end_inclusive
                .saturating_sub(range.start)
                .saturating_add(1)
        })
        .unwrap_or(total_size_bytes);
    response_headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0")),
    );

    if let Some(range) = selected_range {
        response_headers.insert(
            CONTENT_RANGE,
            HeaderValue::from_str(&format!(
                "bytes {}-{}/{}",
                range.start, range.end_inclusive, total_size_bytes
            ))
            .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
        );
    }

    if method == Method::HEAD {
        return (
            selected_range
                .map(|_| StatusCode::PARTIAL_CONTENT)
                .unwrap_or(StatusCode::OK),
            response_headers,
            Vec::<u8>::new(),
        )
            .into_response();
    }

    let payload = if let Some(range) = selected_range {
        let range_length = range
            .end_inclusive
            .saturating_sub(range.start)
            .saturating_add(1);
        if head.accept_ranges {
            let request_cancellation = RequestCancellation::new();
            let _request_cancellation_guard = request_cancellation.guard();
            match download_object_range_bytes(ObjectRangeDownloadRequest {
                sdk,
                selection: ObjectRangeSelection {
                    key: query.key.clone(),
                    snapshot: query.snapshot.clone(),
                    version: query.version.clone(),
                    start: range.start,
                    length: range_length,
                },
                perf_logging_enabled: false,
                cancelled: request_cancellation.flag(),
            })
            .await
            {
                Ok(bytes) => bytes,
                Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
            }
        } else {
            let full_payload = match current_client(&state)
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
            full_payload[range.start as usize..=range.end_inclusive as usize].to_vec()
        }
    } else {
        match current_client(&state)
            .await
            .get_with_selector(
                &query.key,
                query.snapshot.as_deref(),
                query.version.as_deref(),
            )
            .await
        {
            Ok(bytes) => bytes.to_vec(),
            Err(err) => return error_response(StatusCode::BAD_GATEWAY, err.to_string()),
        }
    };

    (
        selected_range
            .map(|_| StatusCode::PARTIAL_CONTENT)
            .unwrap_or(StatusCode::OK),
        response_headers,
        payload,
    )
        .into_response()
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
