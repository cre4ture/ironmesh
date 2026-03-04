use super::*;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::{Arc, Mutex};

const INDEX_HTML: &str = include_str!("ui/index.html");
const APP_CSS: &str = include_str!("ui/app.css");
const APP_JS: &str = include_str!("ui/app.js");

#[derive(Clone)]
pub(crate) struct FolderAgentUiState {
    inner: Arc<FolderAgentUiStateInner>,
}

struct FolderAgentUiStateInner {
    root_dir: PathBuf,
    server_base_url: String,
    scope: PathScope,
    state_store: StartupStateStore,
    operation_lock: Mutex<()>,
}

impl FolderAgentUiState {
    pub(crate) fn new(
        root_dir: PathBuf,
        server_base_url: String,
        scope: PathScope,
        state_store: StartupStateStore,
    ) -> Self {
        Self {
            inner: Arc::new(FolderAgentUiStateInner {
                root_dir,
                server_base_url,
                scope,
                state_store,
                operation_lock: Mutex::new(()),
            }),
        }
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(serde_json::json!({ "error": message.into() }))).into_response()
}

pub(crate) fn spawn_ui_server(
    listener: std::net::TcpListener,
    state: FolderAgentUiState,
) -> std::thread::JoinHandle<()> {
    thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
        {
            Ok(value) => value,
            Err(err) => {
                eprintln!("ui: failed to build runtime: {err}");
                return;
            }
        };

        runtime.block_on(async move {
            let listener = match tokio::net::TcpListener::from_std(listener) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!("ui: failed to adopt listener: {err}");
                    return;
                }
            };

            let app = router(state);
            if let Err(err) = axum::serve(listener, app).await {
                eprintln!("ui: server stopped: {err}");
            }
        })
    })
}

fn router(state: FolderAgentUiState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/ui/app.css", get(app_css))
        .route("/ui/app.js", get(app_js))
        .route("/api/health", get(health))
        .route("/api/info", get(info))
        .route("/api/conflicts", get(list_conflicts))
        .route("/api/conflicts/resolve", post(resolve_conflict))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    StatusCode::OK
}

async fn index() -> Html<String> {
    Html(INDEX_HTML.to_string())
}

async fn app_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        APP_CSS,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        APP_JS,
    )
}

#[derive(Debug, Serialize)]
struct InfoResponse {
    root_dir: String,
    server_base_url: String,
    prefix: Option<String>,
    state_db_path: String,
}

async fn info(State(state): State<FolderAgentUiState>) -> impl IntoResponse {
    let inner = state.inner;
    (
        StatusCode::OK,
        Json(InfoResponse {
            root_dir: inner.root_dir.display().to_string(),
            server_base_url: inner.server_base_url.clone(),
            prefix: inner.scope.remote_prefix().map(ToString::to_string),
            state_db_path: inner.state_store.path.display().to_string(),
        }),
    )
}

#[derive(Debug, Serialize)]
struct ConflictsResponse {
    conflicts: Vec<ConflictItem>,
}

#[derive(Debug, Serialize)]
struct ConflictItem {
    path: String,
    reason: String,
    created_unix_ms: i64,
    details: serde_json::Value,
    supported_strategies: Vec<ConflictResolutionStrategy>,
}

fn keep_remote_supported(root_dir: &Path, conflict: &StoredConflict) -> bool {
    match conflict.reason.as_str() {
        "dual_modify_conflict" | "dual_modify_missing_baseline" => {
            newest_remote_conflict_copy(root_dir, conflict.path.as_str()).is_ok()
        }
        "modify_delete_conflict" | "add_delete_ambiguous_missing_baseline" => true,
        _ => false,
    }
}

async fn list_conflicts(State(state): State<FolderAgentUiState>) -> Response {
    let inner = state.inner.clone();

    let outcome = tokio::task::spawn_blocking(move || -> Result<Vec<ConflictItem>> {
        let conflicts = inner.state_store.load_conflicts()?;
        let mut items = Vec::with_capacity(conflicts.len());
        for conflict in conflicts {
            let details = serde_json::from_str::<serde_json::Value>(conflict.details_json.as_str())
                .unwrap_or_else(|_| serde_json::Value::String(conflict.details_json.clone()));
            let mut supported = vec![ConflictResolutionStrategy::KeepLocal];
            if keep_remote_supported(&inner.root_dir, &conflict) {
                supported.push(ConflictResolutionStrategy::KeepRemote);
            }
            items.push(ConflictItem {
                path: conflict.path,
                reason: conflict.reason,
                created_unix_ms: conflict.created_unix_ms,
                details,
                supported_strategies: supported,
            });
        }
        Ok(items)
    })
    .await;

    match outcome {
        Ok(Ok(conflicts)) => {
            (StatusCode::OK, Json(ConflictsResponse { conflicts })).into_response()
        }
        Ok(Err(err)) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ResolveRequest {
    path: String,
    strategy: ConflictResolutionStrategy,
    delete_conflict_copies: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ResolveResponse {
    result: ConflictResolutionResult,
}

async fn resolve_conflict(
    State(state): State<FolderAgentUiState>,
    Json(request): Json<ResolveRequest>,
) -> Response {
    let inner = state.inner.clone();
    let strategy = request.strategy;
    let path = request.path.clone();
    let delete_copies = request.delete_conflict_copies.unwrap_or(false);

    let outcome = tokio::task::spawn_blocking(move || -> Result<ConflictResolutionResult> {
        let _guard = inner
            .operation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        resolve_conflict_action(
            &inner.root_dir,
            inner.server_base_url.as_str(),
            &inner.scope,
            &inner.state_store,
            path.as_str(),
            strategy,
            delete_copies,
        )
    })
    .await;

    match outcome {
        Ok(Ok(result)) => (StatusCode::OK, Json(ResolveResponse { result })).into_response(),
        Ok(Err(err)) => error_response(StatusCode::BAD_REQUEST, err.to_string()),
        Err(err) => error_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}
