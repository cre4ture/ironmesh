use anyhow::{Context, Result, anyhow};
use client_sdk::IronMeshClient;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_agent_core::{
    FolderAgentRuntimeOptions, FolderAgentRuntimeStatus, build_configured_client,
    run_folder_agent_with_control,
};

pub const GNOME_EXTENSION_UUID: &str = "ironmesh-status@ironmesh.io";

const DEFAULT_REMOTE_STATUS_POLL_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone)]
pub struct GnomeRunOptions {
    pub profile_label: String,
    pub root_dir: PathBuf,
    pub connection_target: String,
    pub server_base_url: Option<String>,
    pub client_bootstrap_json: Option<String>,
    pub server_ca_pem: Option<String>,
    pub client_identity_json: Option<String>,
    pub status_file: PathBuf,
    pub remote_status_poll_interval_ms: u64,
}

#[derive(Debug)]
pub struct GnomeExtensionInstallOutcome {
    pub install_dir: PathBuf,
    pub enable_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GnomeStatusDocument {
    schema_version: u32,
    generated_unix_ms: u64,
    profile_label: String,
    root_dir: String,
    connection_target: String,
    overall: StatusFacet,
    connection: StatusFacet,
    sync: StatusFacet,
    replication: StatusFacet,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusFacet {
    state: String,
    summary: String,
    detail: String,
    icon_name: String,
    updated_unix_ms: u64,
}

impl StatusFacet {
    fn new(
        state: impl Into<String>,
        summary: impl Into<String>,
        detail: impl Into<String>,
        icon_name: impl Into<String>,
    ) -> Self {
        Self {
            state: state.into(),
            summary: summary.into(),
            detail: detail.into(),
            icon_name: icon_name.into(),
            updated_unix_ms: now_unix_ms(),
        }
    }
}

#[derive(Debug, Clone)]
struct PublisherSnapshot {
    connection: StatusFacet,
    sync: StatusFacet,
    replication: StatusFacet,
}

struct GnomeStatusPublisher {
    profile_label: String,
    root_dir: PathBuf,
    connection_target: String,
    status_file: PathBuf,
    snapshot: Mutex<PublisherSnapshot>,
}

impl GnomeStatusPublisher {
    fn new(options: &GnomeRunOptions) -> Result<Self> {
        let publisher = Self {
            profile_label: options.profile_label.clone(),
            root_dir: options.root_dir.clone(),
            connection_target: options.connection_target.clone(),
            status_file: options.status_file.clone(),
            snapshot: Mutex::new(PublisherSnapshot {
                connection: StatusFacet::new(
                    "starting",
                    "Connecting to IronMesh",
                    format!("Preparing status for {}", options.connection_target),
                    "network-transmit-receive-symbolic",
                ),
                sync: StatusFacet::new(
                    "starting",
                    "Starting folder sync",
                    format!("Preparing local sync for {}", options.root_dir.display()),
                    "view-refresh-symbolic",
                ),
                replication: StatusFacet::new(
                    "starting",
                    "Waiting for replication status",
                    "Replication polling has not completed yet",
                    "view-refresh-symbolic",
                ),
            }),
        };
        publisher.persist()?;
        Ok(publisher)
    }

    fn update_sync(&self, status: &FolderAgentRuntimeStatus) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.sync = sync_status_facet(status);
        self.persist_locked(&snapshot)
    }

    fn update_remote(&self, update: &RemoteStatusUpdate) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = update.connection.clone();
        snapshot.replication = update.replication.clone();
        self.persist_locked(&snapshot)
    }

    fn update_remote_error(&self, error: &anyhow::Error) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = StatusFacet::new(
            "error",
            "Connection unavailable",
            format!("{error:#}"),
            "network-error-symbolic",
        );
        snapshot.replication = StatusFacet::new(
            "unknown",
            "Replication unavailable",
            "Waiting for a successful server connection",
            "dialog-question-symbolic",
        );
        self.persist_locked(&snapshot)
    }

    fn persist(&self) -> Result<()> {
        let snapshot = self.lock_snapshot()?.clone();
        self.persist_locked(&snapshot)
    }

    fn lock_snapshot(&self) -> Result<std::sync::MutexGuard<'_, PublisherSnapshot>> {
        self.snapshot
            .lock()
            .map_err(|_| anyhow!("GNOME status snapshot lock poisoned"))
    }

    fn persist_locked(&self, snapshot: &PublisherSnapshot) -> Result<()> {
        let document = GnomeStatusDocument {
            schema_version: 1,
            generated_unix_ms: now_unix_ms(),
            profile_label: self.profile_label.clone(),
            root_dir: self.root_dir.display().to_string(),
            connection_target: self.connection_target.clone(),
            overall: overall_status_facet(snapshot),
            connection: snapshot.connection.clone(),
            sync: snapshot.sync.clone(),
            replication: snapshot.replication.clone(),
        };
        write_status_document(&self.status_file, &document)
    }
}

#[derive(Debug, Clone)]
struct RemoteStatusUpdate {
    connection: StatusFacet,
    replication: StatusFacet,
}

#[derive(Debug, Deserialize)]
struct ClusterSummaryView {
    total_nodes: usize,
    online_nodes: usize,
    offline_nodes: usize,
}

#[derive(Debug, Deserialize)]
struct ReplicationPlanView {
    under_replicated: usize,
    over_replicated: usize,
    cleanup_deferred_items: usize,
}

#[derive(Debug, Deserialize)]
struct HealthStatusView {
    role: String,
    online: bool,
}

pub fn derive_profile_label(prefix: Option<&str>, root_dir: &Path) -> String {
    prefix
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            root_dir
                .file_name()
                .and_then(|value| value.to_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "IronMesh".to_string())
}

pub fn default_remote_status_poll_interval_ms() -> u64 {
    DEFAULT_REMOTE_STATUS_POLL_INTERVAL_MS
}

pub fn default_status_file_path() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| anyhow!("XDG_RUNTIME_DIR is not set; pass --gnome-status-file"))?;
    Ok(PathBuf::from(runtime_dir)
        .join("ironmesh")
        .join("gnome-status.json"))
}

pub fn install_extension(enable: bool) -> Result<GnomeExtensionInstallOutcome> {
    let source_dir = extension_source_dir();
    if !source_dir.exists() {
        return Err(anyhow!(
            "GNOME extension assets are missing at {}",
            source_dir.display()
        ));
    }

    let install_dir = extension_install_dir()?;
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir)
            .with_context(|| format!("failed to remove {}", install_dir.display()))?;
    }

    copy_directory_recursive(&source_dir, &install_dir)?;

    let enable_note = if enable {
        Some(enable_extension_command()?)
    } else {
        None
    };

    Ok(GnomeExtensionInstallOutcome {
        install_dir,
        enable_note,
    })
}

pub fn run_with_gnome_status(
    runtime_options: &FolderAgentRuntimeOptions,
    gnome_options: &GnomeRunOptions,
) -> Result<()> {
    let publisher = Arc::new(GnomeStatusPublisher::new(gnome_options)?);
    let running = Arc::new(AtomicBool::new(true));

    let remote_thread =
        spawn_remote_status_thread(running.clone(), publisher.clone(), gnome_options.clone())?;

    let callback_publisher = publisher.clone();
    let status_callback = Arc::new(move |status: FolderAgentRuntimeStatus| {
        if let Err(error) = callback_publisher.update_sync(&status) {
            tracing::warn!("gnome-status: failed to persist sync status: {error:#}");
        }
    });

    let result = run_folder_agent_with_control(
        runtime_options,
        running.clone(),
        true,
        Some(status_callback),
    );

    running.store(false, Ordering::SeqCst);
    if let Err(error) = remote_thread.join() {
        tracing::warn!("gnome-status: remote status thread join failed: {error:?}");
    }

    if let Err(error) = publisher.persist() {
        tracing::warn!("gnome-status: final persist failed: {error:#}");
    }

    result
}

fn spawn_remote_status_thread(
    running: Arc<AtomicBool>,
    publisher: Arc<GnomeStatusPublisher>,
    options: GnomeRunOptions,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("ironmesh-gnome-status".to_string())
        .spawn(move || {
            let poll_interval =
                Duration::from_millis(options.remote_status_poll_interval_ms.max(1_000));

            let client = match build_configured_client(
                options.server_base_url.as_deref(),
                options.client_bootstrap_json.as_deref(),
                options.server_ca_pem.as_deref(),
                options.client_identity_json.as_deref(),
            ) {
                Ok(client) => client,
                Err(error) => {
                    if let Err(persist_error) = publisher.update_remote_error(&error) {
                        tracing::warn!(
                            "gnome-status: failed to persist client-build error: {persist_error:#}"
                        );
                    }
                    return;
                }
            };

            while running.load(Ordering::SeqCst) {
                match poll_remote_status(&client) {
                    Ok(update) => {
                        if let Err(error) = publisher.update_remote(&update) {
                            tracing::warn!(
                                "gnome-status: failed to persist remote status: {error:#}"
                            );
                        }
                    }
                    Err(error) => {
                        if let Err(persist_error) = publisher.update_remote_error(&error) {
                            tracing::warn!(
                                "gnome-status: failed to persist remote error: {persist_error:#}"
                            );
                        }
                    }
                }

                sleep_with_stop(&running, poll_interval);
            }
        })
        .context("failed to spawn GNOME remote status thread")
}

fn poll_remote_status(client: &IronMeshClient) -> Result<RemoteStatusUpdate> {
    let cluster_status = client
        .get_json_path_blocking("/cluster/status")
        .and_then(|value| serde_json::from_value::<ClusterSummaryView>(value).map_err(Into::into));
    let replication_plan = client
        .get_json_path_blocking("/cluster/replication/plan")
        .and_then(|value| serde_json::from_value::<ReplicationPlanView>(value).map_err(Into::into));

    let connection = match cluster_status {
        Ok(cluster) => cluster_connection_facet(&cluster),
        Err(cluster_error) => match client
            .get_json_path_blocking("/health")
            .and_then(|value| serde_json::from_value::<HealthStatusView>(value).map_err(Into::into))
        {
            Ok(health) => health_connection_facet(&health),
            Err(health_error) => {
                return Err(anyhow!(
                    "failed to load cluster status: {cluster_error:#}; failed to load health: {health_error:#}"
                ));
            }
        },
    };

    let replication = match replication_plan {
        Ok(plan) => replication_facet_from_plan(&plan),
        Err(error) => StatusFacet::new(
            "unknown",
            "Replication status unavailable",
            format!("{error:#}"),
            "dialog-question-symbolic",
        ),
    };

    Ok(RemoteStatusUpdate {
        connection,
        replication,
    })
}

fn cluster_connection_facet(cluster: &ClusterSummaryView) -> StatusFacet {
    let summary = format!(
        "{} of {} cluster node(s) online",
        cluster.online_nodes, cluster.total_nodes
    );
    if cluster.offline_nodes > 0 {
        StatusFacet::new(
            "warning",
            "Cluster connectivity degraded",
            format!("{summary}; {} node(s) offline", cluster.offline_nodes),
            "dialog-warning-symbolic",
        )
    } else {
        StatusFacet::new(
            "connected",
            "Connected to IronMesh",
            summary,
            "network-transmit-receive-symbolic",
        )
    }
}

fn health_connection_facet(health: &HealthStatusView) -> StatusFacet {
    if health.online {
        StatusFacet::new(
            "connected",
            "Connected to IronMesh",
            format!("Connected to {} endpoint", health.role),
            "network-transmit-receive-symbolic",
        )
    } else {
        StatusFacet::new(
            "warning",
            "Connected but server is not online",
            format!("{} endpoint reported online=false", health.role),
            "dialog-warning-symbolic",
        )
    }
}

fn replication_facet_from_plan(plan: &ReplicationPlanView) -> StatusFacet {
    let summary = format!(
        "{} under-replicated, {} over-replicated",
        plan.under_replicated, plan.over_replicated
    );
    if plan.under_replicated > 0 || plan.over_replicated > 0 {
        let detail = if plan.cleanup_deferred_items > 0 {
            format!(
                "{summary}; {} cleanup item(s) deferred",
                plan.cleanup_deferred_items
            )
        } else {
            summary.clone()
        };
        StatusFacet::new(
            "warning",
            "Replication needs attention",
            detail,
            "dialog-warning-symbolic",
        )
    } else {
        let detail = if plan.cleanup_deferred_items > 0 {
            format!(
                "Replication healthy; {} cleanup item(s) deferred",
                plan.cleanup_deferred_items
            )
        } else {
            "Replication healthy".to_string()
        };
        StatusFacet::new(
            "running",
            "Replication healthy",
            detail,
            "emblem-ok-symbolic",
        )
    }
}

fn sync_status_facet(status: &FolderAgentRuntimeStatus) -> StatusFacet {
    let (summary, icon_name) = match status.state.as_str() {
        "starting" => ("Starting local sync", "view-refresh-symbolic"),
        "syncing" => ("Syncing local changes", "view-refresh-symbolic"),
        "running" => ("Watching for local changes", "folder-saved-search-symbolic"),
        "stopped" => ("Folder sync stopped", "media-playback-stop-symbolic"),
        "error" => ("Folder sync error", "network-error-symbolic"),
        _ => ("Folder sync update", "dialog-information-symbolic"),
    };
    StatusFacet::new(
        status.state.clone(),
        summary,
        status.message.clone(),
        icon_name,
    )
}

fn overall_status_facet(snapshot: &PublisherSnapshot) -> StatusFacet {
    if facet_is_error(&snapshot.connection)
        || facet_is_error(&snapshot.sync)
        || facet_is_error(&snapshot.replication)
    {
        return StatusFacet::new(
            "error",
            "IronMesh needs attention",
            format!(
                "Connection: {}; Sync: {}; Replication: {}",
                snapshot.connection.summary, snapshot.sync.summary, snapshot.replication.summary
            ),
            "network-error-symbolic",
        );
    }

    if facet_is_warning(&snapshot.connection) || facet_is_warning(&snapshot.replication) {
        return StatusFacet::new(
            "warning",
            "IronMesh is degraded",
            format!(
                "Connection: {}; Replication: {}",
                snapshot.connection.detail, snapshot.replication.detail
            ),
            "dialog-warning-symbolic",
        );
    }

    if matches!(snapshot.sync.state.as_str(), "starting" | "syncing") {
        return StatusFacet::new(
            "syncing",
            snapshot.sync.summary.clone(),
            snapshot.sync.detail.clone(),
            "view-refresh-symbolic",
        );
    }

    if snapshot.sync.state == "stopped" {
        return StatusFacet::new(
            "stopped",
            "IronMesh is idle",
            "Folder sync is not currently running",
            "media-playback-stop-symbolic",
        );
    }

    if snapshot.connection.state == "connected"
        && snapshot.sync.state == "running"
        && matches!(snapshot.replication.state.as_str(), "running" | "unknown")
    {
        return StatusFacet::new(
            "running",
            "IronMesh is healthy",
            format!(
                "Connection: {}; Sync: {}; Replication: {}",
                snapshot.connection.detail, snapshot.sync.detail, snapshot.replication.detail
            ),
            "emblem-ok-symbolic",
        );
    }

    StatusFacet::new(
        "unknown",
        "Waiting for IronMesh status",
        format!(
            "Connection: {}; Sync: {}; Replication: {}",
            snapshot.connection.summary, snapshot.sync.summary, snapshot.replication.summary
        ),
        "dialog-question-symbolic",
    )
}

fn facet_is_error(facet: &StatusFacet) -> bool {
    facet.state == "error"
}

fn facet_is_warning(facet: &StatusFacet) -> bool {
    facet.state == "warning"
}

fn write_status_document(path: &Path, document: &GnomeStatusDocument) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let bytes =
        serde_json::to_vec_pretty(document).context("failed to serialize GNOME status JSON")?;
    let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&temp_path, bytes)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            temp_path.display(),
            path.display()
        )
    })
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn sleep_with_stop(running: &AtomicBool, total: Duration) {
    let slice = Duration::from_millis(250);
    let mut elapsed = Duration::ZERO;
    while elapsed < total && running.load(Ordering::SeqCst) {
        let remaining = total.saturating_sub(elapsed);
        thread::sleep(remaining.min(slice));
        elapsed += slice;
    }
}

fn extension_source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("gnome-shell-extension")
        .join(GNOME_EXTENSION_UUID)
}

fn extension_install_dir() -> Result<PathBuf> {
    let home_dir =
        std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set for GNOME install"))?;
    Ok(PathBuf::from(home_dir)
        .join(".local")
        .join("share")
        .join("gnome-shell")
        .join("extensions")
        .join(GNOME_EXTENSION_UUID))
}

fn enable_extension_command() -> Result<String> {
    match Command::new("gnome-extensions")
        .arg("enable")
        .arg(GNOME_EXTENSION_UUID)
        .output()
    {
        Ok(output) if output.status.success() => Ok(format!(
            "Enabled extension {}; if the top bar does not update immediately, restart GNOME Shell or log out and back in.",
            GNOME_EXTENSION_UUID
        )),
        Ok(output) => {
            let detail = failure_output_detail(&output.stdout, &output.stderr);
            Ok(format!(
                "Extension copied, but `gnome-extensions enable {}` exited with status {}{}. Enable it manually from Extensions or with `gnome-extensions enable {}`.",
                GNOME_EXTENSION_UUID,
                output.status,
                detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default(),
                GNOME_EXTENSION_UUID
            ))
        }
        Err(error) => Ok(format!(
            "Extension copied, but automatic enabling failed: {error}. Enable it manually from Extensions or with `gnome-extensions enable {}`.",
            GNOME_EXTENSION_UUID
        )),
    }
}

fn failure_output_detail(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    if !stdout.is_empty() {
        return Some(stdout);
    }

    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    if !stderr.is_empty() {
        return Some(stderr);
    }

    None
}

fn copy_directory_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;

    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry = entry.with_context(|| format!("failed to enumerate {}", source.display()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        if file_type.is_dir() {
            copy_directory_recursive(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ClusterSummaryView, PublisherSnapshot, ReplicationPlanView, StatusFacet,
        derive_profile_label, overall_status_facet, replication_facet_from_plan,
    };
    use std::path::Path;

    #[test]
    fn derive_profile_label_prefers_prefix() {
        assert_eq!(
            derive_profile_label(Some("team/docs"), Path::new("/tmp/ironmesh-root")),
            "team/docs"
        );
    }

    #[test]
    fn derive_profile_label_falls_back_to_root_name() {
        assert_eq!(
            derive_profile_label(None, Path::new("/tmp/ironmesh-root")),
            "ironmesh-root"
        );
    }

    #[test]
    fn overall_status_prefers_error() {
        let snapshot = PublisherSnapshot {
            connection: StatusFacet::new("connected", "Connected", "Connected", "ok"),
            sync: StatusFacet::new("error", "Sync error", "Boom", "err"),
            replication: StatusFacet::new("running", "Healthy", "Healthy", "ok"),
        };
        assert_eq!(overall_status_facet(&snapshot).state, "error");
    }

    #[test]
    fn replication_plan_marks_warning_when_under_replicated() {
        let facet = replication_facet_from_plan(&ReplicationPlanView {
            under_replicated: 2,
            over_replicated: 0,
            cleanup_deferred_items: 1,
        });
        assert_eq!(facet.state, "warning");
    }

    #[test]
    fn cluster_struct_deserializes_expected_fields() {
        let payload = serde_json::json!({
            "total_nodes": 3,
            "online_nodes": 2,
            "offline_nodes": 1
        });
        let cluster: ClusterSummaryView =
            serde_json::from_value(payload).expect("cluster summary should parse");
        assert_eq!(cluster.total_nodes, 3);
        assert_eq!(cluster.online_nodes, 2);
        assert_eq!(cluster.offline_nodes, 1);
    }
}
