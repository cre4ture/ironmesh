#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod windows_tray;

use anyhow::{Context, Result};
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::http::header::CONTENT_TYPE;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use client_sdk::enroll_connection_input_blocking;
#[cfg(windows)]
use desktop_client_config::default_desktop_status_file_path;
use desktop_client_config::{
    ClientIdentityConfig, FolderAgentInstance, LaunchOutcome, LaunchReport, ManagedInstanceStore,
    OS_INTEGRATION_MANAGEMENT_SUPPORTED, OsIntegrationInstance, PLATFORM_KIND,
    STARTUP_INTEGRATION_LABEL, STARTUP_INTEGRATION_NOTE, STARTUP_INTEGRATION_VALUE,
    ServiceRuntimeStatus, StopOutcome, default_instance_store_path, default_launch_report_path,
    default_service_log_dir, generate_instance_id, launch_enabled_instances,
    launch_folder_agent_instance, launch_os_integration_instance,
    launch_report_with_updated_outcome, load_last_launch_report, migrate_legacy_state_paths,
    package_root_from_current_exe, save_launch_report, service_desktop_status_file_path,
    service_runtime_statuses, stop_service_from_report,
};
use desktop_status::{
    DesktopServiceStatus, DesktopStatusDocument, GNOME_EXTENSION_UUID, StatusFacet, StatusSnapshot,
    build_status_document, default_gnome_status_file_path, install_gnome_extension_from,
    overall_status_facet, read_status_document, write_status_document,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug, Parser)]
#[command(name = "ironmesh-config-app")]
#[command(about = "Local configuration UI for packaged IronMesh background services")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: String,
    #[arg(long, default_value_t = false)]
    no_browser: bool,
    #[arg(long, default_value_t = false)]
    background: bool,
    #[arg(long, default_value_t = false)]
    launch_enabled_on_start: bool,
    #[arg(long, default_value_t = false)]
    no_desktop_status: bool,
    #[arg(long, global = true)]
    desktop_status_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install or inspect the native GNOME Shell indicator integration.
    Gnome {
        #[command(subcommand)]
        command: GnomeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GnomeCommand {
    /// Copy the GNOME Shell extension into ~/.local/share/gnome-shell/extensions and try to enable it.
    InstallExtension,
    /// Print the JSON path consumed by the GNOME Shell extension.
    PrintStatusPath,
}

#[derive(Clone)]
struct AppState {
    instance_store_path: PathBuf,
    launch_report_path: PathBuf,
    package_root: PathBuf,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

struct ServiceStatusTelemetry {
    instance_kind: String,
    id: String,
    document: DesktopStatusDocument,
}

#[derive(Debug, Serialize)]
struct ConfigResponse {
    platform: &'static str,
    supports_os_integration: bool,
    config_path: String,
    launch_report_path: String,
    service_log_dir: String,
    package_root: String,
    startup_integration_label: &'static str,
    startup_integration_value: &'static str,
    startup_integration_note: &'static str,
    store: ManagedInstanceStore,
    service_statuses: Vec<ServiceRuntimeStatus>,
    last_launch_report: Option<LaunchReport>,
}

#[derive(Debug, Deserialize)]
struct UpsertClientIdentityRequest {
    id: Option<String>,
    bootstrap_content: String,
    #[serde(default)]
    enroll: bool,
}

impl UpsertClientIdentityRequest {
    fn into_identity(
        self,
        existing: Option<&ClientIdentityConfig>,
        instance_store_path: &Path,
    ) -> Result<(ClientIdentityConfig, Option<String>, bool), ApiError> {
        let id = normalize_optional_string(self.id)
            .unwrap_or_else(|| generate_instance_id("client-identity"));
        let bootstrap_content = normalize_optional_string(Some(self.bootstrap_content));
        if bootstrap_content.is_none() && existing.is_none() {
            return Err(ApiError::bad_request(
                "bootstrap content must not be empty when creating a client identity",
            ));
        }
        let bootstrap_file = existing
            .map(|identity| identity.bootstrap_file.to_string())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| default_managed_client_bootstrap_path(instance_store_path, &id));
        let client_identity_file = existing
            .map(|identity| identity.client_identity_file.to_string())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| default_managed_client_identity_path(instance_store_path, &id));
        let label = bootstrap_content
            .as_deref()
            .map(client_identity_label_from_bootstrap_content)
            .transpose()?
            .or_else(|| existing.map(|identity| identity.label.to_string()))
            .ok_or_else(|| {
                ApiError::bad_request(
                    "bootstrap content must include device_label so the identity name can be derived",
                )
            })?;
        let identity = ClientIdentityConfig {
            id,
            label,
            bootstrap_file,
            client_identity_file,
            server_ca_pem_file: existing.and_then(|identity| identity.server_ca_pem_file.clone()),
            cluster_id: existing.and_then(|identity| identity.cluster_id.clone()),
            device_id: existing.and_then(|identity| identity.device_id.clone()),
            device_label: existing.and_then(|identity| identity.device_label.clone()),
            issued_at_unix: existing.and_then(|identity| identity.issued_at_unix),
            expires_at_unix: existing.and_then(|identity| identity.expires_at_unix),
            last_enrolled_at_unix_ms: existing
                .and_then(|identity| identity.last_enrolled_at_unix_ms),
        };
        identity
            .validate()
            .map_err(|error| ApiError::bad_request(error.to_string()))?;
        Ok((identity, bootstrap_content, self.enroll))
    }
}

#[derive(Debug, Serialize)]
struct UpsertClientIdentityResponse {
    config: ConfigResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment: Option<ClientIdentityEnrollmentReport>,
}

#[derive(Debug, Serialize)]
struct ClientIdentityEnrollmentReport {
    identity_file: String,
    cluster_id: String,
    device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_base_url: Option<String>,
}

#[derive(Debug, Serialize)]
struct ServiceActionResponse {
    config: ConfigResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    launch: Option<LaunchOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<StopOutcome>,
}

#[derive(Debug, Deserialize)]
struct UpsertOsIntegrationInstanceRequest {
    id: Option<String>,
    label: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    sync_root_id: Option<String>,
    display_name: Option<String>,
    root_path: String,
    server_base_url: Option<String>,
    prefix: Option<String>,
    bootstrap_file: Option<String>,
    client_identity_id: Option<String>,
    snapshot_file: Option<String>,
    client_identity_file: Option<String>,
    server_ca_path: Option<String>,
    client_edge_state_dir: Option<String>,
    fs_name: Option<String>,
    #[serde(default)]
    allow_other: bool,
    #[serde(default)]
    publish_gnome_status: bool,
    gnome_status_file: Option<String>,
    remote_refresh_interval_ms: Option<String>,
    remote_status_poll_interval_ms: Option<String>,
    depth: Option<String>,
}

impl UpsertOsIntegrationInstanceRequest {
    fn into_instance(
        self,
        _existing: Option<&OsIntegrationInstance>,
        store: &ManagedInstanceStore,
    ) -> Result<OsIntegrationInstance, ApiError> {
        let client_identity_id = normalize_optional_string(self.client_identity_id);
        let managed_identity = resolve_client_identity(store, client_identity_id.as_deref())?;
        let bootstrap_file = managed_identity
            .map(|identity| identity.bootstrap_file.clone())
            .or_else(|| normalize_optional_string(self.bootstrap_file));
        let client_identity_file = managed_identity
            .map(|identity| identity.client_identity_file.clone())
            .or_else(|| normalize_optional_string(self.client_identity_file));
        let server_ca_path = managed_identity
            .and_then(|identity| identity.server_ca_pem_file.clone())
            .or_else(|| normalize_optional_string(self.server_ca_path));
        let server_base_url = if managed_identity.is_some() {
            None
        } else {
            normalize_optional_string(self.server_base_url)
        };
        let instance = OsIntegrationInstance {
            id: normalize_optional_string(self.id)
                .unwrap_or_else(|| generate_instance_id("os-integration")),
            label: required_field("os-integration label", self.label)?,
            enabled: self.enabled,
            sync_root_id: normalize_optional_string(self.sync_root_id),
            display_name: normalize_optional_string(self.display_name),
            root_path: required_field("root_path", self.root_path)?,
            server_base_url,
            prefix: normalize_optional_string(self.prefix),
            bootstrap_file,
            client_identity_id,
            snapshot_file: normalize_optional_string(self.snapshot_file),
            client_identity_file,
            server_ca_path,
            client_edge_state_dir: normalize_optional_string(self.client_edge_state_dir),
            fs_name: normalize_optional_string(self.fs_name),
            allow_other: self.allow_other,
            publish_gnome_status: self.publish_gnome_status,
            gnome_status_file: normalize_optional_string(self.gnome_status_file),
            remote_refresh_interval_ms: parse_optional_u64_field(
                "remote_refresh_interval_ms",
                self.remote_refresh_interval_ms,
            )?,
            remote_status_poll_interval_ms: parse_optional_u64_field(
                "remote_status_poll_interval_ms",
                self.remote_status_poll_interval_ms,
            )?,
            depth: parse_optional_usize_field("depth", self.depth)?,
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
    client_identity_id: Option<String>,
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
    fn into_instance(
        self,
        existing: Option<&FolderAgentInstance>,
        store: &ManagedInstanceStore,
    ) -> Result<FolderAgentInstance, ApiError> {
        let client_identity_id = normalize_optional_string(self.client_identity_id);
        let managed_identity = resolve_client_identity(store, client_identity_id.as_deref())?;
        let bootstrap_file = managed_identity
            .map(|identity| identity.bootstrap_file.clone())
            .or_else(|| normalize_optional_string(self.bootstrap_file));
        let server_base_url = if managed_identity.is_some() {
            None
        } else {
            resolve_hidden_optional_string(
                self.server_base_url,
                existing.and_then(|candidate| candidate.server_base_url.as_deref()),
            )
        };
        let server_ca_pem_file = managed_identity
            .and_then(|identity| identity.server_ca_pem_file.clone())
            .or_else(|| {
                resolve_hidden_optional_string(
                    self.server_ca_pem_file,
                    existing.and_then(|candidate| candidate.server_ca_pem_file.as_deref()),
                )
            });
        let client_identity_file = managed_identity
            .map(|identity| identity.client_identity_file.clone())
            .or_else(|| {
                resolve_hidden_optional_string(
                    self.client_identity_file,
                    existing.and_then(|candidate| candidate.client_identity_file.as_deref()),
                )
            });
        let instance = FolderAgentInstance {
            id: normalize_optional_string(self.id)
                .unwrap_or_else(|| generate_instance_id("folder-agent")),
            label: required_field("folder-agent label", self.label)?,
            enabled: self.enabled,
            root_dir: required_field("root_dir", self.root_dir)?,
            state_root_dir: normalize_optional_string(self.state_root_dir),
            server_base_url,
            bootstrap_file,
            server_ca_pem_file,
            client_identity_id,
            client_identity_file,
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
    if let Some(command) = cli.command.as_ref() {
        return run_command(&cli, command);
    }

    let bind_addr: SocketAddr = cli.bind.parse().context("failed parsing --bind address")?;
    let package_root = package_root_from_current_exe()?;
    migrate_legacy_state_paths()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let state = AppState {
        instance_store_path: default_instance_store_path(),
        launch_report_path: default_launch_report_path(),
        package_root,
        shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
    };

    if cli.background || cli.launch_enabled_on_start {
        let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
            .context("failed loading managed instances before launch")?;
        let report = launch_enabled_instances(&store, &state.package_root);
        save_launch_report(&state.launch_report_path, &report)
            .context("failed saving launch report before config app startup")?;
    }

    let app = Router::new()
        .route("/", get(index_html))
        .route("/app.css", get(app_css))
        .route("/app.js", get(app_js))
        .route("/api/config", get(get_config))
        .route("/api/client-identities", post(upsert_client_identity))
        .route(
            "/api/os-integration-instances",
            post(upsert_os_integration_instance),
        )
        .route(
            "/api/folder-agent-instances",
            post(upsert_folder_agent_instance),
        )
        .route(
            "/api/os-integration-instances/{id}",
            delete(delete_os_integration_instance),
        )
        .route(
            "/api/folder-agent-instances/{id}",
            delete(delete_folder_agent_instance),
        )
        .route(
            "/api/client-identities/{id}",
            delete(delete_client_identity),
        )
        .route(
            "/api/services/{kind}/{id}/start",
            post(start_service_instance),
        )
        .route(
            "/api/services/{kind}/{id}/stop",
            post(stop_service_instance),
        )
        .route(
            "/api/services/{kind}/{id}/restart",
            post(restart_service_instance),
        )
        .route("/api/launch-enabled", post(launch_enabled_now))
        .route("/api/shutdown", post(shutdown_app))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .context("failed binding config UI listener")?;
    let local_addr = listener
        .local_addr()
        .context("failed reading local listener address")?;
    let local_url = format!("http://127.0.0.1:{}/", local_addr.port());

    if !cli.no_browser && !cli.background {
        let _ = open_browser(&local_url);
    }

    let _tray_handle;
    if !cli.no_desktop_status
        && let Some(status_file) = resolve_desktop_status_file(&cli)
    {
        spawn_desktop_status_task(state.clone(), local_url.clone(), status_file.clone());
        #[cfg(windows)]
        {
            _tray_handle = match windows_tray::WindowsConfigTrayHandle::spawn(
                status_file,
                local_url.clone(),
            ) {
                Ok(handle) => Some(handle),
                Err(error) => {
                    eprintln!("windows-tray: failed to start config app tray icon: {error:#}");
                    None
                }
            };
        }
        #[cfg(not(windows))]
        {
            _tray_handle = None::<()>;
        }
    } else {
        #[cfg(windows)]
        {
            _tray_handle = None::<windows_tray::WindowsConfigTrayHandle>;
        }
        #[cfg(not(windows))]
        {
            _tray_handle = None::<()>;
        }
    }

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await
        .context("config UI server exited with error")?;

    Ok(())
}

fn run_command(cli: &Cli, command: &Command) -> Result<()> {
    match command {
        Command::Gnome { command } => run_gnome_command(cli, command),
    }
}

fn run_gnome_command(cli: &Cli, command: &GnomeCommand) -> Result<()> {
    match command {
        GnomeCommand::InstallExtension => {
            let outcome = install_gnome_extension_from(&extension_source_dir(), true)?;
            println!(
                "gnome: installed extension {} to {}",
                GNOME_EXTENSION_UUID,
                outcome.install_dir.display()
            );
            if let Some(note) = outcome.enable_note {
                println!("gnome: {note}");
            }
            Ok(())
        }
        GnomeCommand::PrintStatusPath => {
            let path = cli
                .desktop_status_file
                .clone()
                .map(Ok)
                .unwrap_or_else(default_gnome_status_file_path)?;
            println!("{}", path.display());
            Ok(())
        }
    }
}

fn resolve_desktop_status_file(cli: &Cli) -> Option<PathBuf> {
    if let Some(path) = cli.desktop_status_file.clone() {
        return Some(path);
    }

    #[cfg(windows)]
    {
        Some(default_desktop_status_file_path())
    }

    #[cfg(not(windows))]
    {
        default_gnome_status_file_path().ok()
    }
}

fn spawn_desktop_status_task(state: AppState, web_ui_url: String, status_file: PathBuf) {
    tokio::spawn(async move {
        loop {
            if let Err(error) =
                publish_config_app_desktop_status(&state, web_ui_url.as_str(), &status_file)
            {
                eprintln!("desktop-status: failed to publish config app status: {error:#}");
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

fn publish_config_app_desktop_status(
    state: &AppState,
    web_ui_url: &str,
    status_file: &Path,
) -> Result<()> {
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)?;
    let last_launch_report = load_last_launch_report(&state.launch_report_path)?;
    let runtime_statuses = service_runtime_statuses(&store, last_launch_report.as_ref());
    let service_documents = load_service_status_documents(&runtime_statuses);
    let services = merged_service_statuses(&store, &runtime_statuses, service_documents.as_slice());
    let snapshot = StatusSnapshot {
        connection: aggregate_facet(
            service_documents
                .iter()
                .map(|telemetry| &telemetry.document.connection),
            "Connection status pending",
            "Waiting for service telemetry from managed services",
            "network-transmit-receive-symbolic",
            "connected",
            "network-transmit-receive-symbolic",
        ),
        sync: aggregate_service_sync_facet(services.as_slice()),
        replication: aggregate_facet(
            service_documents
                .iter()
                .map(|telemetry| &telemetry.document.replication),
            "Replication status pending",
            "Waiting for service telemetry from managed services",
            "dialog-question-symbolic",
            "running",
            "emblem-ok-symbolic",
        ),
    };
    let mut document = build_status_document(
        "IronMesh",
        &state.instance_store_path,
        web_ui_url.to_string(),
        &snapshot,
    );
    document.web_ui_url = Some(web_ui_url.to_string());
    document.services = services;
    document.overall = overall_status_facet(&snapshot);
    write_status_document(status_file, &document)
}

fn load_service_status_documents(
    runtime_statuses: &[ServiceRuntimeStatus],
) -> Vec<ServiceStatusTelemetry> {
    runtime_statuses
        .iter()
        .filter(|status| status.running)
        .filter_map(|status| {
            let path = service_desktop_status_file_path(&status.instance_kind, &status.id);
            let document = read_status_document(&path).ok()?;
            (!desktop_status_document_is_stale(&document)).then_some(ServiceStatusTelemetry {
                instance_kind: status.instance_kind.clone(),
                id: status.id.clone(),
                document,
            })
        })
        .collect()
}

fn merged_service_statuses(
    store: &ManagedInstanceStore,
    runtime_statuses: &[ServiceRuntimeStatus],
    service_documents: &[ServiceStatusTelemetry],
) -> Vec<DesktopServiceStatus> {
    let mut services = Vec::new();
    for instance in &store.os_integration_instances {
        services.push(merged_service_status(
            "os-integration",
            &instance.id,
            &instance.label,
            instance.enabled,
            runtime_statuses,
            service_documents,
        ));
    }
    for instance in &store.folder_agent_instances {
        services.push(merged_service_status(
            "folder-agent",
            &instance.id,
            &instance.label,
            instance.enabled,
            runtime_statuses,
            service_documents,
        ));
    }
    services
}

fn merged_service_status(
    instance_kind: &str,
    id: &str,
    label: &str,
    enabled: bool,
    runtime_statuses: &[ServiceRuntimeStatus],
    service_documents: &[ServiceStatusTelemetry],
) -> DesktopServiceStatus {
    let runtime = runtime_statuses
        .iter()
        .find(|status| status.instance_kind == instance_kind && status.id == id);
    let running = runtime.is_some_and(|status| status.running);

    if running
        && let Some(telemetry) = service_documents
            .iter()
            .find(|telemetry| telemetry.instance_kind == instance_kind && telemetry.id == id)
    {
        let document = &telemetry.document;
        let overall = &document.overall;
        return DesktopServiceStatus {
            instance_kind: instance_kind.to_string(),
            id: id.to_string(),
            label: label.to_string(),
            state: overall.state.clone(),
            summary: overall.summary.clone(),
            detail: overall.detail.clone(),
            icon_name: overall.icon_name.clone(),
            updated_unix_ms: document.generated_unix_ms,
        };
    }

    if !enabled && !running {
        return desktop_service_status(
            instance_kind,
            id,
            label,
            "disabled",
            "Service disabled",
            "This service is configured but not enabled for background launch",
            "media-playback-stop-symbolic",
        );
    }

    if let Some(error) = runtime
        .and_then(|status| status.last_launch.as_ref())
        .and_then(|launch| launch.error.as_deref())
    {
        return desktop_service_status(
            instance_kind,
            id,
            label,
            "error",
            "Launch failed",
            error,
            "network-error-symbolic",
        );
    }

    if running {
        return desktop_service_status(
            instance_kind,
            id,
            label,
            "running",
            "Process running",
            "Waiting for detailed service telemetry",
            "emblem-ok-symbolic",
        );
    }

    desktop_service_status(
        instance_kind,
        id,
        label,
        "stopped",
        "Service stopped",
        "The service is enabled but no running process is recorded",
        "media-playback-stop-symbolic",
    )
}

fn desktop_service_status(
    instance_kind: &str,
    id: &str,
    label: &str,
    state: &str,
    summary: &str,
    detail: &str,
    icon_name: &str,
) -> DesktopServiceStatus {
    DesktopServiceStatus {
        instance_kind: instance_kind.to_string(),
        id: id.to_string(),
        label: label.to_string(),
        state: state.to_string(),
        summary: summary.to_string(),
        detail: detail.to_string(),
        icon_name: icon_name.to_string(),
        updated_unix_ms: unix_ts_ms(),
    }
}

fn aggregate_facet<'a>(
    facets: impl Iterator<Item = &'a StatusFacet>,
    empty_summary: &str,
    empty_detail: &str,
    empty_icon: &str,
    healthy_state: &str,
    healthy_icon: &str,
) -> StatusFacet {
    let facets = facets.collect::<Vec<_>>();
    if facets.is_empty() {
        return StatusFacet::new("unknown", empty_summary, empty_detail, empty_icon);
    }

    let error_count = facets.iter().filter(|facet| facet.state == "error").count();
    if error_count > 0 {
        return StatusFacet::new(
            "error",
            format!("{error_count} service(s) need attention"),
            facets
                .iter()
                .filter(|facet| facet.state == "error")
                .map(|facet| facet.summary.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            "network-error-symbolic",
        );
    }

    let warning_count = facets
        .iter()
        .filter(|facet| facet.state == "warning")
        .count();
    if warning_count > 0 {
        return StatusFacet::new(
            "warning",
            format!("{warning_count} service(s) degraded"),
            facets
                .iter()
                .filter(|facet| facet.state == "warning")
                .map(|facet| facet.summary.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            "dialog-warning-symbolic",
        );
    }

    let connected_count = facets
        .iter()
        .filter(|facet| matches!(facet.state.as_str(), "connected" | "running"))
        .count();
    if connected_count > 0 {
        return StatusFacet::new(
            healthy_state,
            format!("{connected_count} service(s) reporting healthy"),
            facets
                .iter()
                .map(|facet| facet.detail.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            healthy_icon,
        );
    }

    StatusFacet::new(
        "unknown",
        "Service status pending",
        "Managed services have not published a detailed status yet",
        "dialog-question-symbolic",
    )
}

fn aggregate_service_sync_facet(services: &[DesktopServiceStatus]) -> StatusFacet {
    if services.is_empty() {
        return StatusFacet::new(
            "stopped",
            "No managed services",
            "Add a background service in the config app to start publishing status",
            "media-playback-stop-symbolic",
        );
    }

    let enabled_services = services
        .iter()
        .filter(|service| service.state != "disabled")
        .collect::<Vec<_>>();
    if enabled_services.is_empty() {
        return StatusFacet::new(
            "stopped",
            "No enabled services",
            "Configured services are disabled",
            "media-playback-stop-symbolic",
        );
    }

    let error_count = enabled_services
        .iter()
        .filter(|service| service.state == "error")
        .count();
    if error_count > 0 {
        return StatusFacet::new(
            "error",
            format!("{error_count} service(s) need attention"),
            enabled_services
                .iter()
                .filter(|service| service.state == "error")
                .map(|service| format!("{}: {}", service.label, service.summary))
                .collect::<Vec<_>>()
                .join("; "),
            "network-error-symbolic",
        );
    }

    let stopped_count = enabled_services
        .iter()
        .filter(|service| service.state == "stopped")
        .count();
    if stopped_count > 0 {
        return StatusFacet::new(
            "warning",
            format!("{stopped_count} enabled service(s) stopped"),
            enabled_services
                .iter()
                .filter(|service| service.state == "stopped")
                .map(|service| service.label.as_str())
                .collect::<Vec<_>>()
                .join("; "),
            "dialog-warning-symbolic",
        );
    }

    let active_count = enabled_services
        .iter()
        .filter(|service| matches!(service.state.as_str(), "running" | "syncing" | "starting"))
        .count();
    let syncing_count = enabled_services
        .iter()
        .filter(|service| matches!(service.state.as_str(), "syncing" | "starting"))
        .count();
    if syncing_count > 0 {
        return StatusFacet::new(
            "syncing",
            format!("{syncing_count} service(s) active"),
            format!(
                "{active_count} of {} enabled service(s) are running",
                enabled_services.len()
            ),
            "view-refresh-symbolic",
        );
    }

    if active_count == enabled_services.len() {
        return StatusFacet::new(
            "running",
            "Managed services running",
            format!("{active_count} enabled service(s) are running"),
            "emblem-ok-symbolic",
        );
    }

    StatusFacet::new(
        "unknown",
        "Waiting for managed services",
        format!(
            "{active_count} of {} enabled service(s) are running",
            enabled_services.len()
        ),
        "dialog-question-symbolic",
    )
}

fn desktop_status_document_is_stale(document: &DesktopStatusDocument) -> bool {
    let generated = document.generated_unix_ms;
    generated == 0 || unix_ts_ms().saturating_sub(generated) > 30_000
}

fn extension_source_dir() -> PathBuf {
    if let Some(package_dir) = packaged_extension_source_dir() {
        return package_dir;
    }

    source_tree_extension_source_dir()
}

fn packaged_extension_source_dir() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let package_root = current_exe.parent()?;
    let candidate = package_root
        .join("gnome-shell-extension")
        .join(GNOME_EXTENSION_UUID);
    candidate.is_dir().then_some(candidate)
}

fn source_tree_extension_source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/folder-agent/gnome-shell-extension")
        .join(GNOME_EXTENSION_UUID)
}

async fn index_html() -> Html<&'static str> {
    Html(APP_HTML)
}

async fn app_css() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/css; charset=utf-8")], APP_CSS)
}

async fn app_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "application/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn get_config(State(state): State<AppState>) -> Result<Json<ConfigResponse>, ApiError> {
    let payload = load_config_response(&state).map_err(ApiError::internal)?;
    Ok(Json(payload))
}

async fn upsert_client_identity(
    State(state): State<AppState>,
    Json(request): Json<UpsertClientIdentityRequest>,
) -> Result<Json<UpsertClientIdentityResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    let existing = request
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .and_then(|id| store.client_identity(id));
    let (mut identity, bootstrap_content, enroll) =
        request.into_identity(existing, &state.instance_store_path)?;
    if let Some(bootstrap_content) = bootstrap_content.as_deref() {
        write_managed_text_file(&identity.bootstrap_file, bootstrap_content)?;
    }
    let enrollment = if enroll {
        let report = enroll_client_identity(identity.clone()).await?;
        refresh_client_identity_metadata(&mut identity);
        identity.last_enrolled_at_unix_ms = Some(unix_ts_ms());
        Some(report)
    } else {
        refresh_client_identity_metadata(&mut identity);
        None
    };

    store.upsert_client_identity(identity);
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(UpsertClientIdentityResponse {
        config: load_config_response(&state).map_err(ApiError::internal)?,
        enrollment,
    }))
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
    let instance = request.into_instance(existing, &store)?;
    store.upsert_os_integration(instance);
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(
        load_config_response(&state).map_err(ApiError::internal)?,
    ))
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
    let instance = request.into_instance(existing, &store)?;
    store.upsert_folder_agent(instance);
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(
        load_config_response(&state).map_err(ApiError::internal)?,
    ))
}

async fn delete_os_integration_instance(
    AxumPath(id): AxumPath<String>,
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
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(
        load_config_response(&state).map_err(ApiError::internal)?,
    ))
}

async fn delete_folder_agent_instance(
    AxumPath(id): AxumPath<String>,
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
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(
        load_config_response(&state).map_err(ApiError::internal)?,
    ))
}

async fn delete_client_identity(
    AxumPath(id): AxumPath<String>,
    State(state): State<AppState>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let mut store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    if !store.remove_client_identity(&id) {
        return Err(ApiError::bad_request(format!(
            "client identity '{}' was not found",
            id
        )));
    }
    store
        .save(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    Ok(Json(
        load_config_response(&state).map_err(ApiError::internal)?,
    ))
}

async fn start_service_instance(
    AxumPath((kind, id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<ServiceActionResponse>, ApiError> {
    let kind = normalize_service_kind(&kind)?;
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    ensure_service_instance_exists(&store, kind, &id)?;
    let existing_report =
        load_last_launch_report(&state.launch_report_path).map_err(ApiError::internal)?;
    let already_running = service_runtime_statuses(&store, existing_report.as_ref())
        .iter()
        .any(|status| status.instance_kind == kind && status.id == id && status.running);
    if already_running {
        return Ok(Json(ServiceActionResponse {
            config: load_config_response(&state).map_err(ApiError::internal)?,
            launch: None,
            stop: None,
        }));
    }

    let launch = launch_configured_service(&store, kind, &id, &state.package_root)?;
    let updated_report =
        launch_report_with_updated_outcome(existing_report, &state.package_root, launch.clone());
    save_launch_report(&state.launch_report_path, &updated_report).map_err(ApiError::internal)?;

    Ok(Json(ServiceActionResponse {
        config: load_config_response(&state).map_err(ApiError::internal)?,
        launch: Some(launch),
        stop: None,
    }))
}

async fn stop_service_instance(
    AxumPath((kind, id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<ServiceActionResponse>, ApiError> {
    let kind = normalize_service_kind(&kind)?;
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    ensure_service_instance_exists(&store, kind, &id)?;
    let report = load_last_launch_report(&state.launch_report_path).map_err(ApiError::internal)?;
    let stop = stop_service_from_report(report.as_ref(), kind, &id);

    Ok(Json(ServiceActionResponse {
        config: load_config_response(&state).map_err(ApiError::internal)?,
        launch: None,
        stop: Some(stop),
    }))
}

async fn restart_service_instance(
    AxumPath((kind, id)): AxumPath<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<ServiceActionResponse>, ApiError> {
    let kind = normalize_service_kind(&kind)?;
    let store = ManagedInstanceStore::load_or_default(&state.instance_store_path)
        .map_err(ApiError::internal)?;
    ensure_service_instance_exists(&store, kind, &id)?;
    let existing_report =
        load_last_launch_report(&state.launch_report_path).map_err(ApiError::internal)?;
    let stop = stop_service_from_report(existing_report.as_ref(), kind, &id);
    let launch = if stop.was_running && !stop.stopped {
        None
    } else {
        let launch = launch_configured_service(&store, kind, &id, &state.package_root)?;
        let updated_report = launch_report_with_updated_outcome(
            existing_report,
            &state.package_root,
            launch.clone(),
        );
        save_launch_report(&state.launch_report_path, &updated_report)
            .map_err(ApiError::internal)?;
        Some(launch)
    };

    Ok(Json(ServiceActionResponse {
        config: load_config_response(&state).map_err(ApiError::internal)?,
        launch,
        stop: Some(stop),
    }))
}

async fn launch_enabled_now(State(state): State<AppState>) -> Result<Json<LaunchReport>, ApiError> {
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
    let service_statuses = service_runtime_statuses(&store, last_launch_report.as_ref());
    Ok(ConfigResponse {
        platform: PLATFORM_KIND,
        supports_os_integration: OS_INTEGRATION_MANAGEMENT_SUPPORTED,
        config_path: state.instance_store_path.display().to_string(),
        launch_report_path: state.launch_report_path.display().to_string(),
        service_log_dir: default_service_log_dir().display().to_string(),
        package_root: state.package_root.display().to_string(),
        startup_integration_label: STARTUP_INTEGRATION_LABEL,
        startup_integration_value: STARTUP_INTEGRATION_VALUE,
        startup_integration_note: STARTUP_INTEGRATION_NOTE,
        store,
        service_statuses,
        last_launch_report,
    })
}

fn normalize_service_kind(kind: &str) -> Result<&'static str, ApiError> {
    match kind.trim() {
        "os" | "os-integration" => Ok("os-integration"),
        "folder" | "folder-agent" => Ok("folder-agent"),
        other => Err(ApiError::bad_request(format!(
            "unsupported service kind '{other}'"
        ))),
    }
}

fn ensure_service_instance_exists(
    store: &ManagedInstanceStore,
    kind: &str,
    id: &str,
) -> Result<(), ApiError> {
    let exists = match kind {
        "os-integration" => store
            .os_integration_instances
            .iter()
            .any(|candidate| candidate.id == id),
        "folder-agent" => store
            .folder_agent_instances
            .iter()
            .any(|candidate| candidate.id == id),
        _ => false,
    };
    if exists {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "{kind} instance '{id}' was not found"
        )))
    }
}

fn launch_configured_service(
    store: &ManagedInstanceStore,
    kind: &str,
    id: &str,
    package_root: &Path,
) -> Result<LaunchOutcome, ApiError> {
    match kind {
        "os-integration" => store
            .os_integration_instances
            .iter()
            .find(|candidate| candidate.id == id)
            .map(|instance| launch_os_integration_instance(instance, package_root))
            .ok_or_else(|| ApiError::bad_request(format!("{kind} instance '{id}' was not found"))),
        "folder-agent" => store
            .folder_agent_instances
            .iter()
            .find(|candidate| candidate.id == id)
            .map(|instance| launch_folder_agent_instance(instance, package_root))
            .ok_or_else(|| ApiError::bad_request(format!("{kind} instance '{id}' was not found"))),
        _ => Err(ApiError::bad_request(format!(
            "unsupported service kind '{kind}'"
        ))),
    }
}

async fn enroll_client_identity(
    identity: ClientIdentityConfig,
) -> Result<ClientIdentityEnrollmentReport, ApiError> {
    tokio::task::spawn_blocking(move || enroll_client_identity_blocking(&identity))
        .await
        .map_err(|error| ApiError::internal(anyhow::anyhow!("enrollment task panicked: {error}")))?
}

fn enroll_client_identity_blocking(
    identity: &ClientIdentityConfig,
) -> Result<ClientIdentityEnrollmentReport, ApiError> {
    let bootstrap_content = std::fs::read_to_string(&identity.bootstrap_file).map_err(|error| {
        ApiError::internal(anyhow::anyhow!(
            "failed reading managed bootstrap file {}: {error}",
            identity.bootstrap_file
        ))
    })?;
    let enrolled =
        enroll_connection_input_blocking(&bootstrap_content, None, Some(identity.label.as_str()))
            .map_err(|error| {
            ApiError::bad_request(format!("client identity enrollment failed: {error}"))
        })?;
    let material = enrolled.client_identity_material().map_err(|error| {
        ApiError::internal(error.context("failed building client identity material"))
    })?;
    material
        .write_to_path(Path::new(&identity.client_identity_file))
        .map_err(|error| {
            ApiError::internal(error.context(format!(
                "failed writing client identity {}",
                identity.client_identity_file
            )))
        })?;

    Ok(ClientIdentityEnrollmentReport {
        identity_file: identity.client_identity_file.clone(),
        cluster_id: material.cluster_id.to_string(),
        device_id: material.device_id.to_string(),
        server_base_url: enrolled.server_base_url,
    })
}

fn refresh_client_identity_metadata(identity: &mut ClientIdentityConfig) {
    let Ok(raw) = std::fs::read_to_string(&identity.client_identity_file) else {
        return;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };

    identity.cluster_id = json_string_field(&value, "cluster_id").or(identity.cluster_id.clone());
    identity.device_id = json_string_field(&value, "device_id").or(identity.device_id.clone());
    identity.device_label = json_string_field(&value, "label").or(identity.device_label.clone());
    identity.issued_at_unix = json_u64_field(&value, "issued_at_unix").or(identity.issued_at_unix);
    identity.expires_at_unix =
        json_u64_field(&value, "expires_at_unix").or(identity.expires_at_unix);
}

fn client_identity_label_from_bootstrap_content(raw: &str) -> Result<String, ApiError> {
    let value = serde_json::from_str::<serde_json::Value>(raw).map_err(|error| {
        ApiError::bad_request(format!("bootstrap content must be valid JSON: {error}"))
    })?;
    for path in [
        &["device_label"][..],
        &["label"][..],
        &["bootstrap", "device_label"][..],
        &["bootstrap", "label"][..],
        &["bootstrap_bundle", "device_label"][..],
        &["bootstrap_bundle", "label"][..],
    ] {
        if let Some(label) = json_string_path(&value, path) {
            return Ok(label);
        }
    }

    Err(ApiError::bad_request(
        "bootstrap content must include device_label so the identity name can be derived",
    ))
}

fn json_string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_string_path(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn json_u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    value.get(field).and_then(serde_json::Value::as_u64)
}

fn resolve_client_identity<'a>(
    store: &'a ManagedInstanceStore,
    id: Option<&str>,
) -> Result<Option<&'a ClientIdentityConfig>, ApiError> {
    let Some(id) = id else {
        return Ok(None);
    };
    store
        .client_identity(id)
        .map(Some)
        .ok_or_else(|| ApiError::bad_request(format!("client identity '{}' was not found", id)))
}

fn write_managed_text_file(path: &str, content: &str) -> Result<(), ApiError> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            ApiError::internal(anyhow::anyhow!(
                "failed creating managed client identity directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let payload = if content.ends_with('\n') {
        content.to_string()
    } else {
        format!("{content}\n")
    };
    std::fs::write(path, payload).map_err(|error| {
        ApiError::internal(anyhow::anyhow!(
            "failed writing managed bootstrap file {}: {error}",
            path.display()
        ))
    })
}

fn default_managed_client_bootstrap_path(instance_store_path: &Path, id: &str) -> String {
    instance_store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("client-identities")
        .join(format!("{id}.bootstrap.json"))
        .display()
        .to_string()
}

fn default_managed_client_identity_path(instance_store_path: &Path, id: &str) -> String {
    instance_store_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("client-identities")
        .join(format!("{id}.client-identity.json"))
        .display()
        .to_string()
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

fn parse_optional_u64_field(
    field_name: &str,
    value: Option<String>,
) -> Result<Option<u64>, ApiError> {
    let Some(value) = normalize_optional_string(value) else {
        return Ok(None);
    };

    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| ApiError::bad_request(format!("{} must be a whole number", field_name)))
}

fn parse_optional_usize_field(
    field_name: &str,
    value: Option<String>,
) -> Result<Option<usize>, ApiError> {
    let Some(value) = normalize_optional_string(value) else {
        return Ok(None);
    };

    value
        .parse::<usize>()
        .map(Some)
        .map_err(|_| ApiError::bad_request(format!("{} must be a whole number", field_name)))
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

fn unix_ts_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn open_browser(url: &str) -> Result<()> {
    #[cfg(windows)]
    let mut command = {
        let mut command = ProcessCommand::new("explorer.exe");
        command.arg(url);
        command
    };

    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = ProcessCommand::new("xdg-open");
        command.arg(url);
        command
    };

    #[cfg(not(any(windows, target_os = "linux")))]
    let mut command = {
        let mut command = ProcessCommand::new("open");
        command.arg(url);
        command
    };

    command
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
  <title>IronMesh Desktop Config</title>
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
            <span class="brand-surface">Desktop Config</span>
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
            <span class="nav-description">Package paths, startup integration, and the last recorded launcher run.</span>
          </a>
          <a class="shell-nav-link" href="#identity-panel">
            <span class="nav-title">Client Identities</span>
            <span class="nav-description">Enroll and manage reusable device identities for sync profiles.</span>
          </a>
          <a id="os-nav-link" class="shell-nav-link" href="#os-panel">
            <span id="os-nav-title" class="nav-title">OS Integration</span>
            <span id="os-nav-description" class="nav-description">Configure platform-specific filesystem integration instances.</span>
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
              <p class="eyebrow">Packaged Desktop Client</p>
              <h1>Configure background sync services</h1>
              <p class="lede">Define managed background services, review launcher output, and restart enabled instances from the same desktop configuration surface on Windows and Linux.</p>
            </div>
            <div class="page-summary">
              <div class="summary-chip">
                <span class="summary-label">Client Identities</span>
                <strong id="identity-count">0</strong>
              </div>
              <div id="os-summary-chip" class="summary-chip">
                <span id="os-summary-label" class="summary-label">OS Integration</span>
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
                <p>Current package paths, startup integration state, and the last recorded background launch report.</p>
              </div>
            </div>
            <dl class="meta-grid">
              <div><dt>Config Store</dt><dd id="config-path">Loading...</dd></div>
              <div><dt>Launch Report</dt><dd id="launch-report-path">Loading...</dd></div>
              <div><dt>Service Logs</dt><dd id="service-log-dir">Loading...</dd></div>
              <div><dt>Package Root</dt><dd id="package-root">Loading...</dd></div>
              <div><dt id="startup-integration-label">Startup Integration</dt><dd id="startup-integration-value">Loading...</dd></div>
            </dl>
            <p id="startup-integration-note" class="panel-note">Loading...</p>
            <pre id="launch-report">No launcher run recorded yet.</pre>
          </section>

          <section id="identity-panel" class="panel panel-split">
            <div class="panel-column">
              <div class="panel-header">
                <div>
                  <h2>Client Identities</h2>
                  <p>Reusable bootstrap and device identity files for authenticated sync profiles.</p>
                </div>
                <button id="clear-identity-form" class="secondary">New Identity</button>
              </div>
              <div id="identity-list" class="instance-list"></div>
            </div>
            <form id="identity-form" class="instance-form panel-form">
              <h3>Configure Client Identity</h3>
              <input type="hidden" id="identity-id" />
              <label class="wide-field">
                <span class="field-label">Bootstrap File</span>
                <span class="field-help">Paste the bootstrap JSON from the server. The identity name is derived from its device_label.</span>
                <textarea id="identity-bootstrap-content" spellcheck="false"></textarea>
              </label>
              <label class="checkbox checkbox-field">
                <input type="checkbox" id="identity-enroll" checked />
                <span class="checkbox-copy">
                  <span class="field-label">Enroll using this bootstrap file</span>
                  <span class="field-help">Enrolls this device identity and writes the managed client identity file.</span>
                </span>
              </label>
              <button type="submit">Save Client Identity</button>
            </form>
          </section>

          <section id="os-panel" class="panel panel-split">
            <div class="panel-column">
              <div class="panel-header">
                <div>
                  <h2 id="os-panel-title">OS Integration Instances</h2>
                  <p id="os-panel-description">Each entry serves one packaged filesystem integration runtime for the current desktop platform.</p>
                </div>
                <button id="clear-os-form" class="secondary">New Instance</button>
              </div>
              <div id="os-instance-list" class="instance-list"></div>
            </div>
            <form id="os-form" class="instance-form panel-form">
              <h3 id="os-form-title">Configure OS Integration</h3>
              <p id="os-platform-note" class="panel-note">Loading...</p>
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
                  <span class="field-help">The launcher will try to restart this instance when platform startup integration is available.</span>
                </span>
              </label>
              <div id="os-windows-fields" class="form-section" hidden>
                <h4>Windows Explorer</h4>
                <label>
                  <span class="field-label">Sync Root Identifier</span>
                  <span class="field-help">Stable unique identifier for this Windows Explorer sync root.</span>
                  <input id="os-sync-root-id" />
                </label>
                <label>
                  <span class="field-label">Folder Name in Explorer</span>
                  <span class="field-help">Name shown to the user for this sync root in Windows Explorer.</span>
                  <input id="os-display-name" />
                </label>
              </div>
              <label>
                <span id="os-root-path-label" class="field-label">Local Folder Location</span>
                <span id="os-root-path-help" class="field-help">Local folder path where this sync root is mounted.</span>
                <input id="os-root-path" required />
              </label>
              <div class="form-section">
                <h4>Connection</h4>
                <label>
                  <span class="field-label">Server Base URL</span>
                  <span class="field-help">Optional explicit server-node base URL when not relying solely on bootstrap material.</span>
                  <input id="os-server-base-url" placeholder="https://node.example" />
                </label>
                <label>
                  <span class="field-label">Initial Setup File</span>
                  <span class="field-help">Optional bootstrap JSON file used for first-time setup or live connection bootstrap.</span>
                  <input id="os-bootstrap-file" />
                </label>
                <label>
                  <span class="field-label">Managed Client Identity</span>
                  <span class="field-help">Select a saved identity to fill the bootstrap and identity file paths for this profile.</span>
                  <select id="os-client-identity-id"></select>
                </label>
                <input type="hidden" id="os-client-identity-file" />
                <input type="hidden" id="os-server-ca-path" />
                <label>
                  <span class="field-label">Remote Folder Prefix</span>
                  <span class="field-help">Optional remote subfolder or namespace prefix for this instance.</span>
                  <input id="os-prefix" />
                </label>
              </div>
              <div id="os-linux-fields" class="form-section" hidden>
                <h4>Linux FUSE Options</h4>
                <label>
                  <span class="field-label">Snapshot File</span>
                  <span class="field-help">Optional SyncSnapshot JSON file for offline or demo mounts. Leave Server Base URL and Initial Setup File empty when using this.</span>
                  <input id="os-snapshot-file" />
                </label>
                <label>
                  <span class="field-label">Client Edge State Directory</span>
                  <span class="field-help">Optional persistent state directory for the live rights edge and hydrated-object cache.</span>
                  <input id="os-client-edge-state-dir" />
                </label>
                <label>
                  <span class="field-label">Filesystem Name</span>
                  <span class="field-help">Optional mount name shown by FUSE tooling. The runtime defaults to ironmesh.</span>
                  <input id="os-fs-name" placeholder="ironmesh" />
                </label>
                <label>
                  <span class="field-label">Namespace Depth</span>
                  <span class="field-help">Optional namespace traversal depth for live refreshes. Leave empty to use the runtime default.</span>
                  <input id="os-depth" type="number" min="1" placeholder="64" />
                </label>
                <label>
                  <span class="field-label">Remote Refresh Interval (ms)</span>
                  <span class="field-help">Optional interval for refreshing live namespace state. Leave empty to use the runtime default.</span>
                  <input id="os-remote-refresh-interval-ms" type="number" min="1" placeholder="3000" />
                </label>
                <label>
                  <span class="field-label">GNOME Status File Override</span>
                  <span class="field-help">Legacy direct-publisher override. Managed launches publish per-service telemetry for the config app.</span>
                  <input id="os-gnome-status-file" />
                </label>
                <label>
                  <span class="field-label">GNOME Status Poll Interval (ms)</span>
                  <span class="field-help">Optional poll interval for service connection and replication telemetry.</span>
                  <input id="os-remote-status-poll-interval-ms" type="number" min="1" placeholder="3000" />
                </label>
                <label class="checkbox checkbox-field">
                  <input type="checkbox" id="os-allow-other" />
                  <span class="checkbox-copy">
                    <span class="field-label">Allow other local users</span>
                    <span class="field-help">Passes --allow-other to FUSE so other local users can access the mount when the system FUSE policy allows it.</span>
                  </span>
                </label>
                <label class="checkbox checkbox-field">
                  <input type="checkbox" id="os-publish-gnome-status" />
                  <span class="checkbox-copy">
                    <span class="field-label">Legacy direct GNOME status</span>
                    <span class="field-help">Managed launches ignore this and let the config app publish the merged indicator status.</span>
                  </span>
                </label>
              </div>
              <button id="os-submit-button" type="submit">Save OS Integration</button>
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
                  <span class="field-help">The launcher will try to restart this sync job when platform startup integration is available.</span>
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
                <span class="field-label">Managed Client Identity</span>
                <span class="field-help">Select a saved identity to use its bootstrap and client identity files.</span>
                <select id="folder-client-identity-id"></select>
              </label>
              <label>
                <span class="field-label">Initial Setup File</span>
                <span class="field-help">Optional bootstrap JSON file used for first-time setup.</span>
                <input id="folder-bootstrap-file" />
              </label>
              <input type="hidden" id="folder-client-identity-file" />
              <input type="hidden" id="folder-server-ca-pem-file" />
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

[hidden] {
  display: none !important;
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

button:disabled,
button:disabled:hover {
  opacity: 0.5;
  cursor: not-allowed;
  transform: none;
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
  grid-template-columns: repeat(3, minmax(150px, 1fr));
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

.panel-note {
  margin: 0 0 20px;
  color: var(--muted);
  line-height: 1.5;
}

.panel-header p {
  margin: 6px 0 0;
  color: var(--muted);
  line-height: 1.5;
}

.panel-split {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(420px, 720px);
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
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px 16px;
  align-content: start;
}

.instance-form > h3,
.instance-form > .panel-note,
.instance-form > .wide-field,
.instance-form > .form-section,
.instance-form > button {
  grid-column: 1 / -1;
}

.panel-form {
  padding: 20px;
}

.instance-form h3 {
  margin: 0 0 4px;
  font-size: 22px;
}

.form-section {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px 16px;
  padding-top: 14px;
  border-top: 1px solid var(--panel-border);
}

.form-section h4 {
  grid-column: 1 / -1;
  margin: 0;
  font-size: 15px;
  letter-spacing: 0.03em;
  text-transform: uppercase;
  color: var(--muted);
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

.instance-form input,
.instance-form select,
.instance-form textarea {
  width: 100%;
  padding: 12px 14px;
  border-radius: var(--radius-input);
  border: 1px solid var(--input-border);
  background: var(--input-background);
  color: var(--text);
  transition: border-color 0.15s ease, box-shadow 0.15s ease, background-color 0.15s ease;
}

.instance-form textarea {
  min-height: 180px;
  resize: vertical;
  font-family: "Cascadia Code", "Aptos Mono", monospace;
  line-height: 1.5;
}

.instance-form select {
  min-height: 45px;
}

.instance-form input:focus,
.instance-form select:focus,
.instance-form textarea:focus {
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

.runtime-pill {
  width: fit-content;
  padding: 4px 9px;
  border-radius: 999px;
  border: 1px solid var(--panel-border);
  color: var(--muted);
}

.runtime-pill[data-running="true"] {
  color: var(--accent);
  border-color: var(--accent-soft);
  background: var(--accent-soft);
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

  .instance-form,
  .form-section {
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

function clientIdentities() {
  return currentConfig?.store?.client_identities || [];
}

function findClientIdentity(id) {
  return clientIdentities().find((identity) => identity.id === id);
}

function identityLabelForProfile(instance) {
  const identity = instance.client_identity_id ? findClientIdentity(instance.client_identity_id) : null;
  if (identity) {
    return identity.label;
  }
  return instance.client_identity_file || '';
}

function serviceStatuses() {
  return currentConfig?.service_statuses || [];
}

function serviceStatusFor(instanceKind, id) {
  return serviceStatuses().find((status) => status.instance_kind === instanceKind && status.id === id);
}

function runtimeLabel(status) {
  if (!status?.running) {
    return 'Stopped';
  }
  return status.pid ? `Running · PID ${status.pid}` : 'Running';
}

function renderIdentityOptions(selectId, selectedId) {
  const target = document.getElementById(selectId);
  const options = ['<option value="">Manual or no managed identity</option>'];
  for (const identity of clientIdentities()) {
    const selected = identity.id === selectedId ? ' selected' : '';
    options.push(`<option value="${escapeHtml(identity.id)}"${selected}>${escapeHtml(identity.label)}</option>`);
  }
  target.innerHTML = options.join('');
}

function resolveProfileIdentityId(instance) {
  if (instance.client_identity_id && findClientIdentity(instance.client_identity_id)) {
    return instance.client_identity_id;
  }
  const match = clientIdentities().find((identity) =>
    identity.client_identity_file && identity.client_identity_file === instance.client_identity_file
  );
  return match?.id || '';
}

function applySelectedIdentityToProfile(kind) {
  const identity = findClientIdentity(document.getElementById(`${kind}-client-identity-id`).value);
  if (!identity) return;
  document.getElementById(`${kind}-bootstrap-file`).value = identity.bootstrap_file || '';
  if (kind === 'os') {
    document.getElementById('os-client-identity-file').value = identity.client_identity_file || '';
    document.getElementById('os-server-ca-path').value = identity.server_ca_pem_file || '';
    document.getElementById('os-server-base-url').value = '';
  } else if (kind === 'folder') {
    document.getElementById('folder-client-identity-file').value = identity.client_identity_file || '';
    document.getElementById('folder-server-ca-pem-file').value = identity.server_ca_pem_file || '';
  }
}

function renderClientIdentityCard(identity) {
  const details = [
    ['Bootstrap File', identity.bootstrap_file],
    ['Cluster ID', identity.cluster_id || ''],
  ];
  return `
    <article class="instance-card">
      <div class="actions">
        <div>
          <strong>${escapeHtml(identity.label)}</strong>
          <div class="instance-meta">${escapeHtml(identity.device_label || 'Managed client identity')}</div>
        </div>
        <div class="actions">
          <button type="button" class="secondary" onclick="editClientIdentity('${encodeURIComponent(identity.id)}')">Edit</button>
          <button type="button" class="secondary" onclick="deleteClientIdentity('${encodeURIComponent(identity.id)}')">Delete</button>
        </div>
      </div>
      <dl class="instance-meta">
        ${details.map(([label, value]) => `<div><strong>${escapeHtml(label)}:</strong> ${escapeHtml(value || '-')}</div>`).join('')}
      </dl>
    </article>
  `;
}

function renderInstanceCard(instance, kind, onEdit, onDelete) {
  const serviceKind = kind === 'os' ? 'os-integration' : 'folder-agent';
  const runtime = serviceStatusFor(serviceKind, instance.id);
  const running = !!runtime?.running;
  const encodedId = encodeURIComponent(instance.id);
  const logFile = runtime?.log_file || runtime?.last_launch?.log_file || '';
  const details = kind === 'os'
    ? currentConfig?.platform === 'linux'
      ? [
          ['Mountpoint', instance.root_path],
          ['Connection Source', instance.snapshot_file || instance.bootstrap_file || instance.server_base_url || ''],
          ['Client Identity', identityLabelForProfile(instance)],
          ['Remote Folder Prefix', instance.prefix || ''],
          ['Desktop Status', 'Collected by config app'],
        ]
      : [
          ['Sync Root Identifier', instance.sync_root_id],
          ['Folder Name in Explorer', instance.display_name],
          ['Local Folder Location', instance.root_path],
          ['Initial Setup File', instance.bootstrap_file || ''],
          ['Client Identity', identityLabelForProfile(instance)],
          ['Remote Folder Prefix', instance.prefix || ''],
        ]
    : [
        ['Folder to Sync', instance.root_dir],
        ['Local State Storage', instance.state_root_dir || ''],
        ['Initial Setup File', instance.bootstrap_file || ''],
        ['Client Identity', identityLabelForProfile(instance)],
        ['Local Status UI Address', instance.ui_bind || ''],
      ];
  details.push(['Local Log File', logFile]);
  if (runtime?.last_launch?.error) {
    details.push(['Last Launch Error', runtime.last_launch.error]);
  }

  return `
    <article class="instance-card">
      <div class="actions">
        <div>
          <strong>${escapeHtml(instance.label)}</strong>
          <div class="instance-meta">
            <span>${instance.enabled ? 'Enabled' : 'Disabled'}</span>
            <span class="runtime-pill" data-running="${running ? 'true' : 'false'}">${escapeHtml(runtimeLabel(runtime))}</span>
          </div>
        </div>
        <div class="actions">
          <button type="button" class="secondary" onclick="controlService('${serviceKind}', '${encodedId}', 'start')" ${running ? 'disabled' : ''}>Start</button>
          <button type="button" class="secondary" onclick="controlService('${serviceKind}', '${encodedId}', 'stop')" ${running ? '' : 'disabled'}>Stop</button>
          <button type="button" class="secondary" onclick="controlService('${serviceKind}', '${encodedId}', 'restart')">Restart</button>
          <button type="button" class="secondary" onclick="${onEdit}('${encodedId}')">Edit</button>
          <button type="button" class="secondary" onclick="${onDelete}('${encodedId}')">Delete</button>
        </div>
      </div>
      <dl class="instance-meta">
        ${details.map(([label, value]) => `<div><strong>${escapeHtml(label)}:</strong> ${escapeHtml(value || '-')}</div>`).join('')}
      </dl>
    </article>
  `;
}

function applyOsPlatformUi(platform) {
  const isWindows = platform === 'windows';
  const isLinux = platform === 'linux';

  document.getElementById('os-nav-title').textContent = isWindows
    ? 'Explorer Sync Roots'
    : isLinux
      ? 'Linux FUSE Mounts'
      : 'OS Integration';
  document.getElementById('os-nav-description').textContent = isWindows
    ? 'Configure packaged Windows Explorer sync-root instances.'
    : isLinux
      ? 'Configure packaged Linux FUSE mount instances.'
      : 'Configure platform-specific filesystem integration instances.';
  document.getElementById('os-summary-label').textContent = isWindows
    ? 'Explorer Sync Roots'
    : isLinux
      ? 'Linux FUSE Mounts'
      : 'OS Integration';
  document.getElementById('os-panel-title').textContent = isWindows
    ? 'Windows Explorer Sync Roots'
    : isLinux
      ? 'Linux FUSE Mounts'
      : 'OS Integration Instances';
  document.getElementById('os-panel-description').textContent = isWindows
    ? 'Each entry serves one packaged Windows Explorer sync root with the current client package.'
    : isLinux
      ? 'Each entry launches one packaged Linux FUSE mount runtime with its own mountpoint and connection settings.'
      : 'Each entry serves one packaged filesystem integration runtime for the current desktop platform.';
  document.getElementById('os-form-title').textContent = isWindows
    ? 'Configure Explorer Sync Root'
    : isLinux
      ? 'Configure Linux FUSE Mount'
      : 'Configure OS Integration';
  document.getElementById('os-platform-note').textContent = isWindows
    ? 'Windows instances register packaged Explorer sync roots. Sync Root Identifier and Folder Name in Explorer are required.'
    : isLinux
      ? 'Linux instances launch the packaged FUSE mount runtime. Set a mountpoint and provide either a snapshot file, a bootstrap file, or a server base URL.'
      : 'OS integration management is unavailable on this platform.';
  document.getElementById('os-root-path-label').textContent = isWindows ? 'Local Folder Location' : 'Mountpoint';
  document.getElementById('os-root-path-help').textContent = isWindows
    ? 'Local folder path where this sync root is mounted.'
    : 'Directory where the IronMesh FUSE filesystem should be mounted.';
  document.getElementById('os-submit-button').textContent = isWindows
    ? 'Save Explorer Sync Root'
    : isLinux
      ? 'Save Linux FUSE Mount'
      : 'Save OS Integration';
  document.getElementById('os-windows-fields').hidden = !isWindows;
  document.getElementById('os-linux-fields').hidden = !isLinux;
}

function renderConfig(config) {
  currentConfig = config;
  document.title = config.platform === 'windows'
    ? 'IronMesh Windows Config'
    : config.platform === 'linux'
      ? 'IronMesh Linux Config'
      : 'IronMesh Desktop Config';
  document.getElementById('config-path').textContent = config.config_path;
  document.getElementById('launch-report-path').textContent = config.launch_report_path;
  document.getElementById('service-log-dir').textContent = config.service_log_dir;
  document.getElementById('package-root').textContent = config.package_root;
  document.getElementById('startup-integration-label').textContent = config.startup_integration_label;
  document.getElementById('startup-integration-value').textContent = config.startup_integration_value;
  document.getElementById('startup-integration-note').textContent = config.startup_integration_note;
  document.getElementById('identity-count').textContent = String(config.store.client_identities.length);
  document.getElementById('os-instance-count').textContent = String(config.store.os_integration_instances.length);
  document.getElementById('folder-instance-count').textContent = String(config.store.folder_agent_instances.length);
  renderLaunchReport(config.last_launch_report);
  applyOsPlatformUi(config.platform);
  renderIdentityOptions('os-client-identity-id', document.getElementById('os-client-identity-id')?.value || '');
  renderIdentityOptions('folder-client-identity-id', document.getElementById('folder-client-identity-id')?.value || '');

  const identityTarget = document.getElementById('identity-list');
  identityTarget.innerHTML = config.store.client_identities.length
    ? config.store.client_identities.map(renderClientIdentityCard).join('')
    : '<p class="empty">No client identities configured yet.</p>';

  const supportsOsIntegration = !!config.supports_os_integration;
  document.getElementById('os-nav-link').hidden = !supportsOsIntegration;
  document.getElementById('os-summary-chip').hidden = !supportsOsIntegration;
  document.getElementById('os-panel').hidden = !supportsOsIntegration;

  const osTarget = document.getElementById('os-instance-list');
  if (supportsOsIntegration) {
    osTarget.innerHTML = config.store.os_integration_instances.length
      ? config.store.os_integration_instances.map((instance) => renderInstanceCard(instance, 'os', 'editOsInstance', 'deleteOsInstance')).join('')
      : '<p class="empty">No os-integration instances configured yet.</p>';
  } else {
    osTarget.innerHTML = '';
  }

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

function clearIdentityForm() {
  document.getElementById('identity-id').value = '';
  document.getElementById('identity-bootstrap-content').value = '';
  document.getElementById('identity-enroll').checked = true;
}

function clearOsForm() {
  document.getElementById('os-id').value = '';
  document.getElementById('os-label').value = '';
  document.getElementById('os-enabled').checked = true;
  document.getElementById('os-sync-root-id').value = '';
  document.getElementById('os-display-name').value = '';
  document.getElementById('os-root-path').value = '';
  document.getElementById('os-server-base-url').value = '';
  document.getElementById('os-prefix').value = '';
  document.getElementById('os-bootstrap-file').value = '';
  renderIdentityOptions('os-client-identity-id', '');
  document.getElementById('os-snapshot-file').value = '';
  document.getElementById('os-client-identity-file').value = '';
  document.getElementById('os-server-ca-path').value = '';
  document.getElementById('os-client-edge-state-dir').value = '';
  document.getElementById('os-fs-name').value = '';
  document.getElementById('os-depth').value = '';
  document.getElementById('os-remote-refresh-interval-ms').value = '';
  document.getElementById('os-gnome-status-file').value = '';
  document.getElementById('os-remote-status-poll-interval-ms').value = '';
  document.getElementById('os-allow-other').checked = false;
  document.getElementById('os-publish-gnome-status').checked = false;
}

function clearFolderForm() {
  document.getElementById('folder-id').value = '';
  document.getElementById('folder-label').value = '';
  document.getElementById('folder-enabled').checked = true;
  document.getElementById('folder-root-dir').value = '';
  document.getElementById('folder-state-root-dir').value = '';
  document.getElementById('folder-prefix').value = '';
  document.getElementById('folder-bootstrap-file').value = '';
  renderIdentityOptions('folder-client-identity-id', '');
  document.getElementById('folder-client-identity-file').value = '';
  document.getElementById('folder-server-ca-pem-file').value = '';
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

window.editClientIdentity = function(encodedId) {
  const identity = findClientIdentity(decodeURIComponent(encodedId));
  if (!identity) return;
  document.getElementById('identity-id').value = identity.id;
  document.getElementById('identity-bootstrap-content').value = '';
  document.getElementById('identity-enroll').checked = false;
};

window.editOsInstance = function(encodedId) {
  const instance = findOsInstance(decodeURIComponent(encodedId));
  if (!instance) return;
  document.getElementById('os-id').value = instance.id;
  document.getElementById('os-label').value = instance.label;
  document.getElementById('os-enabled').checked = !!instance.enabled;
  document.getElementById('os-sync-root-id').value = instance.sync_root_id || '';
  document.getElementById('os-display-name').value = instance.display_name || '';
  document.getElementById('os-root-path').value = instance.root_path;
  document.getElementById('os-server-base-url').value = instance.server_base_url || '';
  document.getElementById('os-prefix').value = instance.prefix || '';
  document.getElementById('os-bootstrap-file').value = instance.bootstrap_file || '';
  renderIdentityOptions('os-client-identity-id', resolveProfileIdentityId(instance));
  document.getElementById('os-snapshot-file').value = instance.snapshot_file || '';
  document.getElementById('os-client-identity-file').value = instance.client_identity_file || '';
  document.getElementById('os-server-ca-path').value = instance.server_ca_path || '';
  document.getElementById('os-client-edge-state-dir').value = instance.client_edge_state_dir || '';
  document.getElementById('os-fs-name').value = instance.fs_name || '';
  document.getElementById('os-depth').value = instance.depth || '';
  document.getElementById('os-remote-refresh-interval-ms').value = instance.remote_refresh_interval_ms || '';
  document.getElementById('os-gnome-status-file').value = instance.gnome_status_file || '';
  document.getElementById('os-remote-status-poll-interval-ms').value = instance.remote_status_poll_interval_ms || '';
  document.getElementById('os-allow-other').checked = !!instance.allow_other;
  document.getElementById('os-publish-gnome-status').checked = !!instance.publish_gnome_status;
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
  renderIdentityOptions('folder-client-identity-id', resolveProfileIdentityId(instance));
  document.getElementById('folder-client-identity-file').value = instance.client_identity_file || '';
  document.getElementById('folder-server-ca-pem-file').value = instance.server_ca_pem_file || '';
  document.getElementById('folder-ui-bind').value = instance.ui_bind || '';
  document.getElementById('folder-run-once').checked = !!instance.run_once;
  document.getElementById('folder-no-watch-local').checked = !!instance.no_watch_local;
};

window.deleteClientIdentity = async function(encodedId) {
  const id = decodeURIComponent(encodedId);
  if (!confirm(`Delete client identity ${id}?`)) return;
  const payload = await fetchJson(`/api/client-identities/${encodeURIComponent(id)}`, { method: 'DELETE' });
  renderConfig(payload);
  clearIdentityForm();
  showStatus(`Deleted client identity ${id}.`);
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

window.controlService = async function(serviceKind, encodedId, action) {
  const id = decodeURIComponent(encodedId);
  const response = await fetchJson(
    `/api/services/${encodeURIComponent(serviceKind)}/${encodeURIComponent(id)}/${action}`,
    { method: 'POST' }
  );
  renderConfig(response.config);
  showStatus({
    action,
    service: serviceKind,
    id,
    launch: response.launch || null,
    stop: response.stop || null,
  });
};

async function submitIdentityForm(event) {
  event.preventDefault();
  const payload = {
    id: document.getElementById('identity-id').value || null,
    bootstrap_content: document.getElementById('identity-bootstrap-content').value,
    enroll: document.getElementById('identity-enroll').checked,
  };
  const response = await fetchJson('/api/client-identities', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  renderConfig(response.config);
  clearIdentityForm();
  showStatus(response.enrollment ? response.enrollment : 'Saved client identity.');
}

async function submitOsForm(event) {
  event.preventDefault();
  const payload = {
    id: document.getElementById('os-id').value || null,
    label: document.getElementById('os-label').value,
    enabled: document.getElementById('os-enabled').checked,
    sync_root_id: document.getElementById('os-sync-root-id').value,
    display_name: document.getElementById('os-display-name').value,
    root_path: document.getElementById('os-root-path').value,
    server_base_url: document.getElementById('os-server-base-url').value,
    prefix: document.getElementById('os-prefix').value,
    bootstrap_file: document.getElementById('os-bootstrap-file').value,
    client_identity_id: document.getElementById('os-client-identity-id').value,
    snapshot_file: document.getElementById('os-snapshot-file').value,
    client_identity_file: document.getElementById('os-client-identity-file').value,
    server_ca_path: document.getElementById('os-server-ca-path').value,
    client_edge_state_dir: document.getElementById('os-client-edge-state-dir').value,
    fs_name: document.getElementById('os-fs-name').value,
    allow_other: document.getElementById('os-allow-other').checked,
    publish_gnome_status: document.getElementById('os-publish-gnome-status').checked,
    gnome_status_file: document.getElementById('os-gnome-status-file').value,
    remote_refresh_interval_ms: document.getElementById('os-remote-refresh-interval-ms').value,
    remote_status_poll_interval_ms: document.getElementById('os-remote-status-poll-interval-ms').value,
    depth: document.getElementById('os-depth').value,
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
    client_identity_id: document.getElementById('folder-client-identity-id').value,
    client_identity_file: document.getElementById('folder-client-identity-file').value,
    server_ca_pem_file: document.getElementById('folder-server-ca-pem-file').value,
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
  const config = await fetchJson('/api/config');
  renderConfig(config);
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
  document.getElementById('identity-form').addEventListener('submit', (event) => {
    submitIdentityForm(event).catch((error) => showStatus({ error: error.message }));
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
  document.getElementById('clear-identity-form').addEventListener('click', clearIdentityForm);
  document.getElementById('clear-os-form').addEventListener('click', clearOsForm);
  document.getElementById('clear-folder-form').addEventListener('click', clearFolderForm);
  document.getElementById('os-client-identity-id').addEventListener('change', () => {
    applySelectedIdentityToProfile('os');
  });
  document.getElementById('folder-client-identity-id').addEventListener('change', () => {
    applySelectedIdentityToProfile('folder');
  });
  clearIdentityForm();
  clearOsForm();
  clearFolderForm();
  try {
    await refreshConfig();
  } catch (error) {
    showStatus({ error: error.message });
  }
});
"###;
