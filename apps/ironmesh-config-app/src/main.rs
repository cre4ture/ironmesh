#![cfg(windows)]
#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{Mutex, oneshot};
use windows_client_config::{
    FolderAgentInstance, LaunchReport, ManagedInstanceStore, OsIntegrationInstance,
    STARTUP_TASK_ID, default_instance_store_path, default_launch_report_path,
    generate_instance_id, launch_enabled_instances, load_last_launch_report,
    package_root_from_current_exe, save_launch_report,
};

#[derive(Debug, Parser)]
#[command(name = "ironmesh-config-app")]
#[command(about = "Local configuration UI for packaged IronMesh background services")]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    #[arg(long, default_value_t = false)]
    no_browser: bool,
}

#[derive(Clone)]
struct AppState {
    instance_store_path: PathBuf,
    launch_report_path: PathBuf,
    package_root: PathBuf,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

#[derive(Debug, Serialize)]
struct ConfigResponse {
    config_path: String,
    launch_report_path: String,
    package_root: String,
    startup_task_id: &'static str,
    store: ManagedInstanceStore,
    last_launch_report: Option<LaunchReport>,
}

#[derive(Debug, Deserialize)]
struct UpsertOsIntegrationInstanceRequest {
    id: Option<String>,
    label: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    sync_root_id: String,
    display_name: String,
    root_path: String,
    #[serde(default)]
    server_base_url: Option<Option<String>>,
    prefix: Option<String>,
    bootstrap_file: Option<String>,
    #[serde(default)]
    client_identity_file: Option<Option<String>>,
    #[serde(default)]
    server_ca_cert: Option<Option<String>>,
}

impl UpsertOsIntegrationInstanceRequest {
    fn into_instance(self, existing: Option<&OsIntegrationInstance>) -> Result<OsIntegrationInstance, ApiError> {
        let instance = OsIntegrationInstance {
            id: normalize_optional_string(self.id)
                .unwrap_or_else(|| generate_instance_id("os-integration")),
            label: required_field("os-integration label", self.label)?,
            enabled: self.enabled,
            sync_root_id: required_field("sync_root_id", self.sync_root_id)?,
            display_name: required_field("display_name", self.display_name)?,
            root_path: required_field("root_path", self.root_path)?,
            server_base_url: resolve_hidden_optional_string(
              self.server_base_url,
              existing.and_then(|candidate| candidate.server_base_url.as_deref()),
            ),
            prefix: normalize_optional_string(self.prefix),
            bootstrap_file: normalize_optional_string(self.bootstrap_file),
            client_identity_file: resolve_hidden_optional_string(
              self.client_identity_file,
              existing.and_then(|candidate| candidate.client_identity_file.as_deref()),
            ),
            server_ca_cert: resolve_hidden_optional_string(
              self.server_ca_cert,
              existing.and_then(|candidate| candidate.server_ca_cert.as_deref()),
            ),
        };
        instance
          .validate()
          .map_err(|error| ApiError::bad_request(error.to_string()))?;
        Ok(instance)
    }
}

#[derive(Debug, Deserialize)]
struct UpsertFolderAgentInstanceRequest {
    id: Option<String>,
    label: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    root_dir: String,
    state_root_dir: Option<String>,
    #[serde(default)]
    server_base_url: Option<Option<String>>,
    bootstrap_file: Option<String>,
    #[serde(default)]
    server_ca_pem_file: Option<Option<String>>,
    #[serde(default)]
    client_identity_file: Option<Option<String>>,
    prefix: Option<String>,
    ui_bind: Option<String>,
    #[serde(default)]
    run_once: bool,
    #[serde(default)]
    no_watch_local: bool,
}

impl UpsertFolderAgentInstanceRequest {
  fn into_instance(self, existing: Option<&FolderAgentInstance>) -> Result<FolderAgentInstance, ApiError> {
        let instance = FolderAgentInstance {
            id: normalize_optional_string(self.id)
                .unwrap_or_else(|| generate_instance_id("folder-agent")),
            label: required_field("folder-agent label", self.label)?,
            enabled: self.enabled,
            root_dir: required_field("root_dir", self.root_dir)?,
            state_root_dir: normalize_optional_string(self.state_root_dir),
            server_base_url: resolve_hidden_optional_string(
              self.server_base_url,
              existing.and_then(|candidate| candidate.server_base_url.as_deref()),
            ),
            bootstrap_file: normalize_optional_string(self.bootstrap_file),
            server_ca_pem_file: resolve_hidden_optional_string(
              self.server_ca_pem_file,
              existing.and_then(|candidate| candidate.server_ca_pem_file.as_deref()),
            ),
            client_identity_file: resolve_hidden_optional_string(
              self.client_identity_file,
              existing.and_then(|candidate| candidate.client_identity_file.as_deref()),
            ),
            prefix: normalize_optional_string(self.prefix),
            ui_bind: normalize_optional_string(self.ui_bind),
            run_once: self.run_once,
            no_watch_local: self.no_watch_local,
        };
        instance
          .validate()
          .map_err(|error| ApiError::bad_request(error.to_string()))?;
        Ok(instance)
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let bind_addr: SocketAddr = cli.bind.parse().context("failed parsing --bind address")?;
    let package_root = package_root_from_current_exe()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state = AppState {
        instance_store_path: default_instance_store_path(),
        launch_report_path: default_launch_report_path(),
        package_root,
        shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
    };

    let app = Router::new()
        .route("/", get(index_html))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/api/config", get(get_config))
        .route("/api/os-integration-instances", post(upsert_os_integration_instance))
        .route("/api/folder-agent-instances", post(upsert_folder_agent_instance))
        .route(
            "/api/os-integration-instances/{id}",
            delete(delete_os_integration_instance),
        )
        .route(
            "/api/folder-agent-instances/{id}",
            delete(delete_folder_agent_instance),
        )
        .route("/api/launch-enabled", post(launch_enabled_now))
        .route("/api/shutdown", post(shutdown_app))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context("failed binding config UI listener")?;
    let local_addr = listener.local_addr().context("failed reading local listener address")?;
    let local_url = format!("http://127.0.0.1:{}/", local_addr.port());

    if !cli.no_browser {
        let _ = open_browser(&local_url);
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .context("config UI server exited with error")?;

    Ok(())
}

async fn index_html() -> Html<&'static str> {
    Html(APP_HTML)
}

async fn app_css() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn app_js() -> impl IntoResponse {
    ([(CONTENT_TYPE, "application/javascript; charset=utf-8")], APP_JS)
}

async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, ApiError> {
    let payload = load_config_response(&state).map_err(ApiError::internal)?;
    Ok(Json(payload))
}

async fn upsert_os_integration_instance(
    State(state): State<AppState>,
    Json(request): Json<UpsertOsIntegrationInstanceRequest>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
  let existing = request
    .id
    .as_deref()
    .map(str::trim)
    .filter(|id| !id.is_empty())
    .and_then(|id| {
      store
        .os_integration_instances
        .iter()
        .find(|candidate| candidate.id == id)
    });
  let instance = request.into_instance(existing)?;
    store.upsert_os_integration(instance);
    store.save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(load_config_response(&state).map_err(ApiError::internal)?))
}

async fn upsert_folder_agent_instance(
    State(state): State<AppState>,
    Json(request): Json<UpsertFolderAgentInstanceRequest>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
  let existing = request
    .id
    .as_deref()
    .map(str::trim)
    .filter(|id| !id.is_empty())
    .and_then(|id| {
      store
        .folder_agent_instances
        .iter()
        .find(|candidate| candidate.id == id)
    });
  let instance = request.into_instance(existing)?;
    store.upsert_folder_agent(instance);
    store.save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(load_config_response(&state).map_err(ApiError::internal)?))
}

async fn delete_os_integration_instance(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    if !store.remove_os_integration(&id) {
        return Err(ApiError::bad_request(format!(
            "os-integration instance '{}' was not found",
            id
        )));
    }
    store.save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(load_config_response(&state).map_err(ApiError::internal)?))
}

async fn delete_folder_agent_instance(
    Path(id): Path<String>,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    if !store.remove_folder_agent(&id) {
        return Err(ApiError::bad_request(format!(
            "folder-agent instance '{}' was not found",
            id
        )));
    }
    store.save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(load_config_response(&state).map_err(ApiError::internal)?))
}

async fn launch_enabled_now(
    State(state): State<AppState>,
) -> Result<Json<LaunchReport>, ApiError> {
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    let report = launch_enabled_instances(&store, &state.package_root);
    save_launch_report(&state.launch_report_path, &report).map_err(ApiError::internal)?;
    Ok(Json(report))
}

async fn shutdown_app(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut shutdown_tx = state.shutdown_tx.lock().await;
    if let Some(sender) = shutdown_tx.take() {
        let _ = sender.send(());
    }

    Ok(Json(json!({ "status": "shutting_down" })))
}

fn load_config_response(state: &AppState) -> Result<ConfigResponse> {
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)?;
    let last_launch_report = load_last_launch_report(&state.launch_report_path)?;
    Ok(ConfigResponse {
        config_path: state.instance_store_path.display().to_string(),
        launch_report_path: state.launch_report_path.display().to_string(),
        package_root: state.package_root.display().to_string(),
        startup_task_id: STARTUP_TASK_ID,
        store,
        last_launch_report,
    })
}

fn required_field(field_name: &str, value: String) -> Result<String, ApiError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(format!(
            "{} must not be empty",
            field_name
        )));
    }
    Ok(trimmed.to_string())
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|candidate| candidate.trim().to_string())
        .filter(|candidate| !candidate.is_empty())
}

fn resolve_hidden_optional_string(
  requested_value: Option<Option<String>>,
  existing_value: Option<&str>,
) -> Option<String> {
  match requested_value {
    Some(value) => normalize_optional_string(value),
    None => existing_value.map(str::to_owned),
  }
}

fn default_enabled() -> bool {
    true
}

fn open_browser(url: &str) -> Result<()> {
    Command::new("explorer.exe")
        .arg(url)
        .spawn()
        .with_context(|| format!("failed opening browser at {}", url))?;
    Ok(())
}

const APP_HTML: &str = r###"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <script>
    try {
      const storageKey = "ironmesh-color-scheme";
      const storedColorScheme = window.localStorage.getItem(storageKey);
      const colorScheme =
        storedColorScheme === "light" || storedColorScheme === "dark" || storedColorScheme === "auto"
          ? storedColorScheme
          : "auto";
      const computedColorScheme =
        colorScheme === "auto"
          ? window.matchMedia("(prefers-color-scheme: dark)").matches
            ? "dark"
            : "light"
          : colorScheme;
      document.documentElement.setAttribute("data-mantine-color-scheme", computedColorScheme);
    } catch {}
  </script>
  <title>IronMesh Windows Config</title>
  <link rel="stylesheet" href="/app.css" />
</head>
<body>
  <div class="shell-root">
    <header class="shell-header">
      <div class="shell-header-bar">
        <div class="brand">
          <svg class="brand-mark" viewBox="0 0 256 256" role="img" aria-label="ironmesh mark">
            <defs>
              <linearGradient id="config-brand-panel" x1="36" y1="28" x2="214" y2="228" gradientUnits="userSpaceOnUse">
                <stop offset="0" stop-color="#112523" />
                <stop offset="0.52" stop-color="#163f3a" />
                <stop offset="1" stop-color="#0d6b5c" />
              </linearGradient>
              <linearGradient id="config-brand-mesh" x1="72" y1="68" x2="184" y2="188" gradientUnits="userSpaceOnUse">
                <stop offset="0" stop-color="#d9fff4" />
                <stop offset="0.45" stop-color="#74e4c8" />
                <stop offset="1" stop-color="#14b8a6" />
              </linearGradient>
            </defs>
            <rect x="28" y="28" width="200" height="200" rx="54" fill="url(#config-brand-panel)" />
            <rect x="28.75" y="28.75" width="198.5" height="198.5" rx="53.25" fill="none" stroke="#d9fff4" stroke-opacity="0.18" />
            <g fill="none" stroke="url(#config-brand-mesh)" stroke-width="10" stroke-linecap="round" stroke-linejoin="round">
              <path d="M128 68 L176 96 L176 160 L128 188 L80 160 L80 96 Z" />
              <path d="M128 68 L128 188" />
              <path d="M80 96 L176 160" />
              <path d="M176 96 L80 160" />
              <path d="M80 96 L176 96" />
              <path d="M80 160 L176 160" />
            </g>
            <g fill="#effff9">
              <circle cx="128" cy="68" r="10" />
              <circle cx="176" cy="96" r="10" />
              <circle cx="176" cy="160" r="10" />
              <circle cx="128" cy="188" r="10" />
              <circle cx="80" cy="160" r="10" />
              <circle cx="80" cy="96" r="10" />
              <circle cx="128" cy="128" r="12" fill="#14b8a6" />
            </g>
            <g fill="#0d3d37">
              <circle cx="128" cy="68" r="4" />
              <circle cx="176" cy="96" r="4" />
              <circle cx="176" cy="160" r="4" />
              <circle cx="128" cy="188" r="4" />
              <circle cx="80" cy="160" r="4" />
              <circle cx="80" cy="96" r="4" />
              <circle cx="128" cy="128" r="4" fill="#e9fff8" />
            </g>
          </svg>
          <div class="brand-copy">
            <span class="brand-name">ironmesh</span>
            <span class="brand-surface">Windows Config</span>
          </div>
        </div>

        <div class="header-actions">
          <div class="scheme-control" role="group" aria-label="Color scheme">
            <button type="button" data-color-scheme-option="auto" class="secondary">Auto</button>
            <button type="button" data-color-scheme-option="light" class="secondary">Light</button>
            <button type="button" data-color-scheme-option="dark" class="secondary">Dark</button>
          </div>
          <button id="refresh-button" class="secondary">Refresh</button>
          <button id="launch-button">Run Enabled Services</button>
          <button id="shutdown-button" class="secondary">Close</button>
        </div>
      </div>
    </header>

    <div class="shell-body">
      <aside class="shell-navbar">
        <nav class="shell-nav" aria-label="Configuration sections">
          <a class="shell-nav-link" href="#runtime-panel">
            <span class="nav-title">Runtime</span>
            <span class="nav-description">Package paths, startup task, and the last recorded launcher run.</span>
          </a>
          <a class="shell-nav-link" href="#os-panel">
            <span class="nav-title">Explorer Sync Roots</span>
            <span class="nav-description">Configure the packaged Windows Explorer integration instances.</span>
          </a>
          <a class="shell-nav-link" href="#folder-panel">
            <span class="nav-title">Folder Sync Jobs</span>
            <span class="nav-description">Configure background folder synchronization jobs and startup behavior.</span>
          </a>
          <a class="shell-nav-link" href="#status-panel">
            <span class="nav-title">Status</span>
            <span class="nav-description">Request results, validation errors, and last action output.</span>
          </a>
        </nav>
      </aside>

      <main class="shell-main">
        <div class="shell-content">
          <section class="page-header">
            <div class="page-copy">
              <p class="eyebrow">Packaged Windows Client</p>
              <h1>Configure background sync services</h1>
              <p class="lede">Define Explorer sync roots and folder sync jobs, then let the packaged background launcher restart enabled instances after login using the same visual shell style as the other IronMesh web surfaces.</p>
            </div>
            <div class="page-summary">
              <div class="summary-chip">
                <span class="summary-label">Explorer Sync Roots</span>
                <strong id="os-instance-count">0</strong>
              </div>
              <div class="summary-chip">
                <span class="summary-label">Folder Sync Jobs</span>
                <strong id="folder-instance-count">0</strong>
              </div>
            </div>
          </section>

          <section id="runtime-panel" class="panel">
            <div class="panel-header">
              <div>
                <h2>Runtime</h2>
                <p>Current package paths, startup task identity, and the last recorded background launch report.</p>
              </div>
            </div>
            <dl class="meta-grid">
              <div><dt>Config Store</dt><dd id="config-path">Loading...</dd></div>
              <div><dt>Launch Report</dt><dd id="launch-report-path">Loading...</dd></div>
              <div><dt>Package Root</dt><dd id="package-root">Loading...</dd></div>
              <div><dt>Startup Task</dt><dd id="startup-task-id">Loading...</dd></div>
            </dl>
            <pre id="launch-report">No background launch recorded yet.</pre>
          </section>

          <section id="os-panel" class="panel panel-split">
            <div class="panel-column">
              <div class="panel-header">
                <div>
                  <h2>Windows Explorer Sync Roots</h2>
                  <p>Each entry serves one packaged sync root in Explorer, including placeholder handling and Cloud Files integration.</p>
                </div>
                <button id="clear-os-form" class="secondary">New Instance</button>
              </div>
              <div id="os-instance-list" class="instance-list"></div>
            </div>
            <form id="os-form" class="instance-form panel-form">
              <h3>Configure Explorer Sync Root</h3>
              <input type="hidden" id="os-id" />
              <label>
                <span class="field-label">Instance Name</span>
                <span class="field-help">Used only inside this config app so you can tell instances apart.</span>
                <input id="os-label" required />
              </label>
              <label class="checkbox checkbox-field">
                <input type="checkbox" id="os-enabled" checked />
                <span class="checkbox-copy">
                  <span class="field-label">Start automatically after login</span>
                  <span class="field-help">The background launcher starts this sync root when you sign in to Windows.</span>
                </span>
              </label>
              <label>
                <span class="field-label">Sync Root Identifier</span>
                <span class="field-help">Stable unique identifier for this Windows Explorer sync root.</span>
                <input id="os-sync-root-id" required />
              </label>
              <label>
                <span class="field-label">Folder Name in Explorer</span>
                <span class="field-help">Name shown to the user for this sync root in Windows Explorer.</span>
                <input id="os-display-name" required />
              </label>
              <label>
                <span class="field-label">Local Folder Location</span>
                <span class="field-help">Local folder path where this sync root is mounted.</span>
                <input id="os-root-path" required />
              </label>
              <label>
                <span class="field-label">Remote Folder Prefix</span>
                <span class="field-help">Optional remote subfolder or namespace prefix for this instance.</span>
                <input id="os-prefix" />
              </label>
              <label>
                <span class="field-label">Initial Setup File</span>
                <span class="field-help">Optional bootstrap JSON file used for first-time setup.</span>
                <input id="os-bootstrap-file" />
              </label>
              <button type="submit">Save Explorer Sync Root</button>
            </form>
          </section>

          <section id="folder-panel" class="panel panel-split">
            <div class="panel-column">
              <div class="panel-header">
                <div>
                  <h2>Folder Sync Jobs</h2>
                  <p>Each entry runs one background folder agent for local folder synchronization outside the Explorer surface.</p>
                </div>
                <button id="clear-folder-form" class="secondary">New Instance</button>
              </div>
              <div id="folder-instance-list" class="instance-list"></div>
            </div>
            <form id="folder-form" class="instance-form panel-form">
              <h3>Configure Folder Sync Job</h3>
              <input type="hidden" id="folder-id" />
              <label>
                <span class="field-label">Instance Name</span>
                <span class="field-help">Used only inside this config app so you can tell sync jobs apart.</span>
                <input id="folder-label" required />
              </label>
              <label class="checkbox checkbox-field">
                <input type="checkbox" id="folder-enabled" checked />
                <span class="checkbox-copy">
                  <span class="field-label">Start automatically after login</span>
                  <span class="field-help">The background launcher starts this sync job when you sign in to Windows.</span>
                </span>
              </label>
              <label>
                <span class="field-label">Folder to Sync</span>
                <span class="field-help">Local folder that this sync job watches and synchronizes.</span>
                <input id="folder-root-dir" required />
              </label>
              <label>
                <span class="field-label">Local State Storage</span>
                <span class="field-help">Optional folder for agent state, caches, and local bookkeeping.</span>
                <input id="folder-state-root-dir" />
              </label>
              <label>
                <span class="field-label">Remote Folder Prefix</span>
                <span class="field-help">Optional remote subfolder or namespace prefix for this sync job.</span>
                <input id="folder-prefix" />
              </label>
              <label>
                <span class="field-label">Initial Setup File</span>
                <span class="field-help">Optional bootstrap JSON file used for first-time setup.</span>
                <input id="folder-bootstrap-file" />
              </label>
              <label>
                <span class="field-label">Local Status UI Address</span>
                <span class="field-help">Optional local address for the agent status UI, for example 127.0.0.1:3030.</span>
                <input id="folder-ui-bind" placeholder="127.0.0.1:3030" />
              </label>
              <label class="checkbox checkbox-field">
                <input type="checkbox" id="folder-run-once" />
                <span class="checkbox-copy">
                  <span class="field-label">Run one sync pass and exit</span>
                  <span class="field-help">Useful for testing or one-shot repair runs.</span>
                </span>
              </label>
              <label class="checkbox checkbox-field">
                <input type="checkbox" id="folder-no-watch-local" />
                <span class="checkbox-copy">
                  <span class="field-label">Use polling only</span>
                  <span class="field-help">Turns off filesystem watch events and relies on periodic scans instead.</span>
                </span>
              </label>
              <button type="submit">Save Folder Sync Job</button>
            </form>
          </section>

          <section id="status-panel" class="panel">
            <div class="panel-header">
              <div>
                <h2>Status</h2>
                <p>Recent request results, validation problems, and operational feedback from this configuration surface.</p>
              </div>
            </div>
            <pre id="status-output">Ready.</pre>
          </section>
        </div>
      </main>
    </div>
  </div>
  <script src="/app.js"></script>
</body>
</html>
"###;

const APP_CSS: &str = r###"
html {
  min-height: 100%;
  scroll-behavior: smooth;
}

body {
  min-height: 100%;
}

:root {
  color-scheme: light dark;
  --accent: #12b886;
  --accent-strong: #0d6b5c;
  --radius-panel: 24px;
  --radius-card: 20px;
  --radius-input: 12px;
  --shell-max-width: 1600px;
}

:root[data-mantine-color-scheme="light"] {
  --shell-body-background:
    radial-gradient(circle at top right, rgba(18, 184, 134, 0.1), transparent 30%),
    linear-gradient(180deg, #f8fafb 0%, #eef3f5 100%);
  --shell-header-background: linear-gradient(180deg, rgba(249, 251, 252, 0.94) 0%, rgba(242, 246, 248, 0.92) 100%);
  --shell-header-border: rgba(23, 39, 49, 0.08);
  --shell-navbar-background: linear-gradient(180deg, rgba(249, 251, 252, 0.92) 0%, rgba(240, 245, 247, 0.9) 100%);
  --shell-navbar-border: rgba(23, 39, 49, 0.08);
  --shell-navbar-shadow: 0 18px 40px rgba(31, 60, 71, 0.08);
  --panel-background: rgba(255, 255, 255, 0.88);
  --panel-muted-background: rgba(248, 251, 252, 0.92);
  --panel-border: rgba(23, 39, 49, 0.1);
  --panel-shadow: 0 18px 40px rgba(31, 60, 71, 0.08);
  --text: #172731;
  --muted: #63727c;
  --surface-muted: rgba(244, 247, 248, 0.94);
  --input-background: #ffffff;
  --input-border: rgba(23, 39, 49, 0.16);
  --input-border-focus: rgba(18, 184, 134, 0.92);
  --accent-soft: rgba(18, 184, 134, 0.16);
  --secondary-button-background: rgba(240, 245, 247, 0.96);
  --secondary-button-border: rgba(23, 39, 49, 0.08);
  --nav-link-hover: rgba(18, 184, 134, 0.1);
  --nav-link-border: rgba(18, 184, 134, 0.16);
  --status-background: #f4f7f8;
  --status-foreground: #173039;
}

:root[data-mantine-color-scheme="dark"] {
  --shell-body-background:
    radial-gradient(circle at top right, rgba(18, 184, 134, 0.18), transparent 28%),
    linear-gradient(180deg, #081313 0%, #0b181c 48%, #0d1318 100%);
  --shell-header-background: linear-gradient(180deg, rgba(11, 23, 27, 0.96) 0%, rgba(13, 26, 31, 0.92) 100%);
  --shell-header-border: rgba(116, 228, 200, 0.12);
  --shell-navbar-background: linear-gradient(180deg, rgba(10, 21, 26, 0.98) 0%, rgba(8, 18, 23, 0.94) 100%);
  --shell-navbar-border: rgba(116, 228, 200, 0.1);
  --shell-navbar-shadow: 0 22px 48px rgba(1, 10, 12, 0.42);
  --panel-background: rgba(14, 26, 31, 0.88);
  --panel-muted-background: rgba(16, 30, 36, 0.92);
  --panel-border: rgba(116, 228, 200, 0.1);
  --panel-shadow: 0 22px 48px rgba(1, 10, 12, 0.42);
  --text: #ecf8f5;
  --muted: #9fb5b7;
  --surface-muted: rgba(15, 28, 34, 0.96);
  --input-background: rgba(12, 23, 28, 0.96);
  --input-border: rgba(116, 228, 200, 0.16);
  --input-border-focus: rgba(18, 184, 134, 0.96);
  --accent-soft: rgba(18, 184, 134, 0.22);
  --secondary-button-background: rgba(13, 29, 34, 0.96);
  --secondary-button-border: rgba(116, 228, 200, 0.1);
  --nav-link-hover: rgba(18, 184, 134, 0.14);
  --nav-link-border: rgba(116, 228, 200, 0.14);
  --status-background: #0d171b;
  --status-foreground: #dff8f1;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100dvh;
  overflow-x: hidden;
  background: var(--shell-body-background);
  color: var(--text);
  font-family: "Space Grotesk", system-ui, sans-serif;
}

a {
  color: inherit;
  text-decoration: none;
}

button,
input {
  font: inherit;
}

.shell-root {
  min-height: 100dvh;
}

.shell-header {
  position: sticky;
  top: 0;
  z-index: 20;
  backdrop-filter: blur(20px);
  background: var(--shell-header-background);
  border-bottom: 1px solid var(--shell-header-border);
}

.shell-header-bar {
  min-height: 68px;
  max-width: var(--shell-max-width);
  margin: 0 auto;
  padding: 0 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.brand {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-mark {
  width: 42px;
  height: 42px;
  flex: 0 0 auto;
  display: block;
}

.brand-copy {
  display: grid;
  gap: 2px;
}

.brand-name {
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent);
}

.brand-surface {
  font-size: 15px;
  font-weight: 700;
}

.header-actions,
.actions,
.section-title,
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.scheme-control {
  display: inline-flex;
  gap: 4px;
  padding: 4px;
  border-radius: 999px;
  background: var(--panel-background);
  border: 1px solid var(--panel-border);
  box-shadow: var(--panel-shadow);
}

.scheme-control button {
  border-radius: 999px;
  padding: 9px 14px;
}

.scheme-control button[data-active="true"] {
  background: var(--accent);
  color: #ffffff;
  border-color: transparent;
}

button {
  border: 1px solid transparent;
  border-radius: 999px;
  padding: 11px 18px;
  font-weight: 600;
  background: var(--accent-strong);
  color: #ffffff;
  cursor: pointer;
  transition: transform 0.15s ease, background-color 0.15s ease, border-color 0.15s ease;
}

button:hover {
  transform: translateY(-1px);
}

button.secondary {
  background: var(--secondary-button-background);
  color: var(--text);
  border-color: var(--secondary-button-border);
}

.shell-body {
  max-width: var(--shell-max-width);
  margin: 0 auto;
  padding: 24px 20px 40px;
  display: grid;
  grid-template-columns: 280px minmax(0, 1fr);
  gap: 24px;
  align-items: start;
}

.shell-navbar {
  position: sticky;
  top: 92px;
  background: var(--shell-navbar-background);
  border: 1px solid var(--shell-navbar-border);
  box-shadow: var(--shell-navbar-shadow);
  border-radius: var(--radius-panel);
  padding: 16px;
}

.shell-nav {
  display: grid;
  gap: 10px;
}

.shell-nav-link {
  display: grid;
  gap: 4px;
  padding: 14px 16px;
  border-radius: 18px;
  border: 1px solid transparent;
  transition: background-color 0.15s ease, border-color 0.15s ease, transform 0.15s ease;
}

.shell-nav-link:hover {
  background: var(--nav-link-hover);
  border-color: var(--nav-link-border);
  transform: translateY(-1px);
}

.nav-title {
  font-weight: 700;
}

.nav-description {
  font-size: 12px;
  line-height: 1.45;
  color: var(--muted);
}

.shell-main {
  min-width: 0;
}

.shell-content {
  display: grid;
  gap: 24px;
}

.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
}

.page-copy {
  display: grid;
  gap: 10px;
}

.page-header h1,
.panel h2,
.panel h3 {
  margin: 0;
}

.page-header h1 {
  font-size: clamp(2rem, 3vw, 2.8rem);
  line-height: 1.05;
  letter-spacing: -0.03em;
}

.eyebrow {
  margin: 0;
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--accent);
}

.lede {
  margin: 0;
  max-width: 900px;
  color: var(--muted);
  line-height: 1.6;
}

.page-summary {
  display: grid;
  grid-template-columns: repeat(2, minmax(150px, 1fr));
  gap: 12px;
  min-width: 320px;
}

.summary-chip {
  padding: 16px 18px;
  border-radius: var(--radius-card);
  background: var(--panel-background);
  border: 1px solid var(--panel-border);
  box-shadow: var(--panel-shadow);
}

.summary-label {
  display: block;
  margin-bottom: 8px;
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}

.summary-chip strong {
  font-size: 30px;
  line-height: 1;
}

.panel {
  padding: 24px;
  border-radius: var(--radius-panel);
  background: var(--panel-background);
  border: 1px solid var(--panel-border);
  box-shadow: var(--panel-shadow);
  backdrop-filter: blur(18px);
}

.panel-header {
  margin-bottom: 18px;
}

.panel-header p {
  margin: 6px 0 0;
  color: var(--muted);
  line-height: 1.5;
}

.panel-split {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(320px, 440px);
  gap: 24px;
}

.panel-column {
  display: grid;
  gap: 14px;
  min-width: 0;
  align-content: start;
}

.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin: 0 0 20px;
}

.meta-grid div,
.instance-card,
.panel-form {
  border-radius: var(--radius-card);
  border: 1px solid var(--panel-border);
  background: var(--surface-muted);
}

.meta-grid div {
  padding: 16px 18px;
}

dt {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}

dd {
  margin: 8px 0 0;
  word-break: break-word;
}

.instance-list {
  display: grid;
  gap: 14px;
}

.instance-card {
  padding: 18px;
}

.instance-form {
  display: grid;
  gap: 14px;
  align-content: start;
}

.panel-form {
  padding: 20px;
}

.instance-form h3 {
  margin: 0 0 4px;
  font-size: 22px;
}

.instance-form label {
  display: grid;
  gap: 6px;
  font-size: 14px;
}

.field-label {
  font-weight: 700;
}

.field-help {
  color: var(--muted);
  font-size: 12px;
  line-height: 1.45;
}

.instance-form input {
  width: 100%;
  padding: 12px 14px;
  border-radius: var(--radius-input);
  border: 1px solid var(--input-border);
  background: var(--input-background);
  color: var(--text);
  transition: border-color 0.15s ease, box-shadow 0.15s ease, background-color 0.15s ease;
}

.instance-form input:focus {
  outline: none;
  border-color: var(--input-border-focus);
  box-shadow: 0 0 0 4px var(--accent-soft);
}

.checkbox {
  display: flex !important;
  gap: 12px !important;
  align-items: flex-start;
}

.checkbox input {
  width: 18px;
  height: 18px;
  min-width: 18px;
  margin-top: 2px;
  accent-color: var(--accent);
  box-shadow: none;
}

.checkbox-copy {
  display: grid;
  gap: 4px;
}

.instance-meta {
  margin: 10px 0 0;
  display: grid;
  gap: 6px;
  color: var(--muted);
  font-size: 14px;
}

pre {
  margin: 0;
  overflow: auto;
  white-space: pre-wrap;
  word-break: break-word;
  background: var(--status-background);
  color: var(--status-foreground);
  border: 1px solid var(--panel-border);
  border-radius: 18px;
  padding: 18px;
  font-family: "Cascadia Code", "Aptos Mono", monospace;
  font-size: 13px;
  line-height: 1.55;
}

.empty {
  margin: 0;
  padding: 18px;
  color: var(--muted);
  font-style: italic;
  border-radius: 18px;
  border: 1px dashed var(--panel-border);
  background: var(--surface-muted);
}

@media (max-width: 1200px) {
  .shell-body {
    grid-template-columns: 1fr;
  }

  .shell-navbar {
    position: static;
  }

  .shell-nav {
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  }

  .page-header {
    flex-direction: column;
  }

  .page-summary {
    min-width: 0;
    width: 100%;
  }
}

@media (max-width: 980px) {
  .panel-split {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 720px) {
  .shell-header-bar,
  .shell-body {
    padding-left: 16px;
    padding-right: 16px;
  }

  .header-actions {
    width: 100%;
    justify-content: flex-start;
  }

  .scheme-control {
    width: 100%;
    justify-content: stretch;
  }

  .scheme-control button {
    flex: 1 1 0;
  }

  .page-summary {
    grid-template-columns: 1fr;
  }
}
"###;

const APP_JS: &str = r###"
let currentConfig = null;
const colorSchemeStorageKey = 'ironmesh-color-scheme';

function getPreferredColorScheme() {
  try {
    const storedColorScheme = window.localStorage.getItem(colorSchemeStorageKey);
    if (storedColorScheme === 'light' || storedColorScheme === 'dark' || storedColorScheme === 'auto') {
      return storedColorScheme;
    }
  } catch {}
  return 'auto';
}

function resolveAppliedColorScheme(preferredColorScheme) {
  if (preferredColorScheme === 'auto') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  return preferredColorScheme;
}

function applyColorScheme(preferredColorScheme) {
  document.documentElement.setAttribute(
    'data-mantine-color-scheme',
    resolveAppliedColorScheme(preferredColorScheme)
  );
}

function updateColorSchemeControls() {
  const preferredColorScheme = getPreferredColorScheme();
  document.querySelectorAll('[data-color-scheme-option]').forEach((button) => {
    button.dataset.active = button.dataset.colorSchemeOption === preferredColorScheme ? 'true' : 'false';
  });
}

function setPreferredColorScheme(preferredColorScheme) {
  try {
    window.localStorage.setItem(colorSchemeStorageKey, preferredColorScheme);
  } catch {}
  applyColorScheme(preferredColorScheme);
  updateColorSchemeControls();
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || JSON.stringify(payload));
  }
  return payload;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showStatus(value) {
  document.getElementById('status-output').textContent =
    typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function renderLaunchReport(report) {
  const target = document.getElementById('launch-report');
  if (!report) {
    target.textContent = 'No background launch recorded yet.';
    return;
  }
  target.textContent = JSON.stringify(report, null, 2);
}

function renderInstanceCard(instance, kind, onEdit, onDelete) {
  const details = kind === 'os'
    ? [
        ['Sync Root Identifier', instance.sync_root_id],
        ['Folder Name in Explorer', instance.display_name],
        ['Local Folder Location', instance.root_path],
        ['Initial Setup File', instance.bootstrap_file || ''],
      ]
    : [
        ['Folder to Sync', instance.root_dir],
        ['Local State Storage', instance.state_root_dir || ''],
        ['Initial Setup File', instance.bootstrap_file || ''],
        ['Local Status UI Address', instance.ui_bind || ''],
      ];

  return `
    <article class="instance-card">
      <div class="actions">
        <div>
          <strong>${escapeHtml(instance.label)}</strong>
          <div class="instance-meta">${instance.enabled ? 'Enabled after login' : 'Disabled after login'}</div>
        </div>
        <div class="actions">
          <button type="button" class="secondary" onclick="${onEdit}('${encodeURIComponent(instance.id)}')">Edit</button>
          <button type="button" class="secondary" onclick="${onDelete}('${encodeURIComponent(instance.id)}')">Delete</button>
        </div>
      </div>
      <dl class="instance-meta">
        ${details.map(([label, value]) => `<div><strong>${escapeHtml(label)}:</strong> ${escapeHtml(value || '-')}</div>`).join('')}
      </dl>
    </article>
  `;
}

function renderConfig(config) {
  currentConfig = config;
  document.getElementById('config-path').textContent = config.config_path;
  document.getElementById('launch-report-path').textContent = config.launch_report_path;
  document.getElementById('package-root').textContent = config.package_root;
  document.getElementById('startup-task-id').textContent = config.startup_task_id;
  document.getElementById('os-instance-count').textContent = String(config.store.os_integration_instances.length);
  document.getElementById('folder-instance-count').textContent = String(config.store.folder_agent_instances.length);
  renderLaunchReport(config.last_launch_report);

  const osTarget = document.getElementById('os-instance-list');
  osTarget.innerHTML = config.store.os_integration_instances.length
    ? config.store.os_integration_instances.map((instance) => renderInstanceCard(instance, 'os', 'editOsInstance', 'deleteOsInstance')).join('')
    : '<p class="empty">No os-integration instances configured yet.</p>';

  const folderTarget = document.getElementById('folder-instance-list');
  folderTarget.innerHTML = config.store.folder_agent_instances.length
    ? config.store.folder_agent_instances.map((instance) => renderInstanceCard(instance, 'folder', 'editFolderInstance', 'deleteFolderInstance')).join('')
    : '<p class="empty">No folder-agent instances configured yet.</p>';
}

async function refreshConfig() {
  const payload = await fetchJson('/api/config');
  renderConfig(payload);
  showStatus('Loaded configuration store.');
}

function clearOsForm() {
  document.getElementById('os-id').value = '';
  document.getElementById('os-label').value = '';
  document.getElementById('os-enabled').checked = true;
  document.getElementById('os-sync-root-id').value = '';
  document.getElementById('os-display-name').value = '';
  document.getElementById('os-root-path').value = '';
  document.getElementById('os-prefix').value = '';
  document.getElementById('os-bootstrap-file').value = '';
}

function clearFolderForm() {
  document.getElementById('folder-id').value = '';
  document.getElementById('folder-label').value = '';
  document.getElementById('folder-enabled').checked = true;
  document.getElementById('folder-root-dir').value = '';
  document.getElementById('folder-state-root-dir').value = '';
  document.getElementById('folder-prefix').value = '';
  document.getElementById('folder-bootstrap-file').value = '';
  document.getElementById('folder-ui-bind').value = '';
  document.getElementById('folder-run-once').checked = false;
  document.getElementById('folder-no-watch-local').checked = false;
}

function findOsInstance(id) {
  return currentConfig?.store?.os_integration_instances?.find((instance) => instance.id === id);
}

function findFolderInstance(id) {
  return currentConfig?.store?.folder_agent_instances?.find((instance) => instance.id === id);
}

window.editOsInstance = function(encodedId) {
  const instance = findOsInstance(decodeURIComponent(encodedId));
  if (!instance) return;
  document.getElementById('os-id').value = instance.id;
  document.getElementById('os-label').value = instance.label;
  document.getElementById('os-enabled').checked = !!instance.enabled;
  document.getElementById('os-sync-root-id').value = instance.sync_root_id;
  document.getElementById('os-display-name').value = instance.display_name;
  document.getElementById('os-root-path').value = instance.root_path;
  document.getElementById('os-prefix').value = instance.prefix || '';
  document.getElementById('os-bootstrap-file').value = instance.bootstrap_file || '';
};

window.editFolderInstance = function(encodedId) {
  const instance = findFolderInstance(decodeURIComponent(encodedId));
  if (!instance) return;
  document.getElementById('folder-id').value = instance.id;
  document.getElementById('folder-label').value = instance.label;
  document.getElementById('folder-enabled').checked = !!instance.enabled;
  document.getElementById('folder-root-dir').value = instance.root_dir;
  document.getElementById('folder-state-root-dir').value = instance.state_root_dir || '';
  document.getElementById('folder-prefix').value = instance.prefix || '';
  document.getElementById('folder-bootstrap-file').value = instance.bootstrap_file || '';
  document.getElementById('folder-ui-bind').value = instance.ui_bind || '';
  document.getElementById('folder-run-once').checked = !!instance.run_once;
  document.getElementById('folder-no-watch-local').checked = !!instance.no_watch_local;
};

window.deleteOsInstance = async function(encodedId) {
  const id = decodeURIComponent(encodedId);
  if (!confirm(`Delete os-integration instance ${id}?`)) return;
  const payload = await fetchJson(`/api/os-integration-instances/${encodeURIComponent(id)}`, { method: 'DELETE' });
  renderConfig(payload);
  clearOsForm();
  showStatus(`Deleted os-integration instance ${id}.`);
};

window.deleteFolderInstance = async function(encodedId) {
  const id = decodeURIComponent(encodedId);
  if (!confirm(`Delete folder-agent instance ${id}?`)) return;
  const payload = await fetchJson(`/api/folder-agent-instances/${encodeURIComponent(id)}`, { method: 'DELETE' });
  renderConfig(payload);
  clearFolderForm();
  showStatus(`Deleted folder-agent instance ${id}.`);
};

async function submitOsForm(event) {
  event.preventDefault();
  const payload = {
    id: document.getElementById('os-id').value || null,
    label: document.getElementById('os-label').value,
    enabled: document.getElementById('os-enabled').checked,
    sync_root_id: document.getElementById('os-sync-root-id').value,
    display_name: document.getElementById('os-display-name').value,
    root_path: document.getElementById('os-root-path').value,
    prefix: document.getElementById('os-prefix').value,
    bootstrap_file: document.getElementById('os-bootstrap-file').value,
  };
  const config = await fetchJson('/api/os-integration-instances', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  renderConfig(config);
  clearOsForm();
  showStatus('Saved os-integration instance.');
}

async function submitFolderForm(event) {
  event.preventDefault();
  const payload = {
    id: document.getElementById('folder-id').value || null,
    label: document.getElementById('folder-label').value,
    enabled: document.getElementById('folder-enabled').checked,
    root_dir: document.getElementById('folder-root-dir').value,
    state_root_dir: document.getElementById('folder-state-root-dir').value,
    prefix: document.getElementById('folder-prefix').value,
    bootstrap_file: document.getElementById('folder-bootstrap-file').value,
    ui_bind: document.getElementById('folder-ui-bind').value,
    run_once: document.getElementById('folder-run-once').checked,
    no_watch_local: document.getElementById('folder-no-watch-local').checked,
  };
  const config = await fetchJson('/api/folder-agent-instances', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  renderConfig(config);
  clearFolderForm();
  showStatus('Saved folder-agent instance.');
}

async function launchEnabledNow() {
  const report = await fetchJson('/api/launch-enabled', { method: 'POST' });
  renderLaunchReport(report);
  showStatus(report);
}

async function shutdownApp() {
  await fetchJson('/api/shutdown', { method: 'POST' });
  showStatus('Configuration app is shutting down. You can close this browser tab.');
}

window.addEventListener('DOMContentLoaded', async () => {
  applyColorScheme(getPreferredColorScheme());
  updateColorSchemeControls();
  document.querySelectorAll('[data-color-scheme-option]').forEach((button) => {
    button.addEventListener('click', () => {
      setPreferredColorScheme(button.dataset.colorSchemeOption || 'auto');
    });
  });
  const colorSchemeMedia = window.matchMedia('(prefers-color-scheme: dark)');
  colorSchemeMedia.addEventListener('change', () => {
    if (getPreferredColorScheme() === 'auto') {
      applyColorScheme('auto');
      updateColorSchemeControls();
    }
  });
  document.getElementById('os-form').addEventListener('submit', (event) => {
    submitOsForm(event).catch((error) => showStatus({ error: error.message }));
  });
  document.getElementById('folder-form').addEventListener('submit', (event) => {
    submitFolderForm(event).catch((error) => showStatus({ error: error.message }));
  });
  document.getElementById('refresh-button').addEventListener('click', () => {
    refreshConfig().catch((error) => showStatus({ error: error.message }));
  });
  document.getElementById('launch-button').addEventListener('click', () => {
    launchEnabledNow().catch((error) => showStatus({ error: error.message }));
  });
  document.getElementById('shutdown-button').addEventListener('click', () => {
    shutdownApp().catch((error) => showStatus({ error: error.message }));
  });
  document.getElementById('clear-os-form').addEventListener('click', clearOsForm);
  document.getElementById('clear-folder-form').addEventListener('click', clearFolderForm);
  clearOsForm();
  clearFolderForm();
  try {
    await refreshConfig();
  } catch (error) {
    showStatus({ error: error.message });
  }
});
"###;