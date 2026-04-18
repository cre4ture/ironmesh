mod gnome;
mod publisher;

use anyhow::{Context, Result, anyhow};
use client_sdk::IronMeshClient;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub use gnome::{
    GNOME_EXTENSION_UUID, GnomeExtensionInstallOutcome, default_gnome_status_file_path,
    install_gnome_extension_from,
};
pub use publisher::{
    DesktopStatusPublisher, DesktopStatusPublisherOptions, spawn_remote_status_thread,
};

const DEFAULT_REMOTE_STATUS_POLL_INTERVAL_MS: u64 = 5_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DesktopStatusDocument {
    pub schema_version: u32,
    pub generated_unix_ms: u64,
    pub profile_label: String,
    pub root_dir: String,
    pub connection_target: String,
    pub overall: StatusFacet,
    pub connection: StatusFacet,
    pub sync: StatusFacet,
    pub replication: StatusFacet,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusFacet {
    pub state: String,
    pub summary: String,
    pub detail: String,
    pub icon_name: String,
    pub updated_unix_ms: u64,
}

impl StatusFacet {
    #[must_use]
    pub fn new(
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub connection: StatusFacet,
    pub sync: StatusFacet,
    pub replication: StatusFacet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStatusUpdate {
    pub connection: StatusFacet,
    pub replication: StatusFacet,
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

#[must_use]
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

#[must_use]
pub fn default_remote_status_poll_interval_ms() -> u64 {
    DEFAULT_REMOTE_STATUS_POLL_INTERVAL_MS
}

#[must_use]
pub fn starting_snapshot(root_dir: &Path, connection_target: &str) -> StatusSnapshot {
    StatusSnapshot {
        connection: StatusFacet::new(
            "starting",
            "Connecting to IronMesh",
            format!("Preparing status for {connection_target}"),
            "network-transmit-receive-symbolic",
        ),
        sync: StatusFacet::new(
            "starting",
            "Starting folder sync",
            format!("Preparing local sync for {}", root_dir.display()),
            "view-refresh-symbolic",
        ),
        replication: StatusFacet::new(
            "starting",
            "Waiting for replication status",
            "Replication polling has not completed yet",
            "view-refresh-symbolic",
        ),
    }
}

#[must_use]
pub fn build_status_document(
    profile_label: impl Into<String>,
    root_dir: &Path,
    connection_target: impl Into<String>,
    snapshot: &StatusSnapshot,
) -> DesktopStatusDocument {
    DesktopStatusDocument {
        schema_version: 1,
        generated_unix_ms: now_unix_ms(),
        profile_label: profile_label.into(),
        root_dir: root_dir.display().to_string(),
        connection_target: connection_target.into(),
        overall: overall_status_facet(snapshot),
        connection: snapshot.connection.clone(),
        sync: snapshot.sync.clone(),
        replication: snapshot.replication.clone(),
    }
}

pub fn write_status_document(path: &Path, document: &DesktopStatusDocument) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let bytes =
        serde_json::to_vec_pretty(document).context("failed to serialize desktop status JSON")?;
    let temp_path = temp_status_path(path);
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

pub fn poll_remote_status(client: &IronMeshClient) -> Result<RemoteStatusUpdate> {
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

#[must_use]
pub fn sync_status_facet_from_runtime_state(state: &str, message: &str) -> StatusFacet {
    let (summary, icon_name) = match state {
        "starting" => ("Starting local sync", "view-refresh-symbolic"),
        "syncing" => ("Syncing local changes", "view-refresh-symbolic"),
        "running" => ("Watching for local changes", "folder-saved-search-symbolic"),
        "stopped" => ("Folder sync stopped", "media-playback-stop-symbolic"),
        "error" => ("Folder sync error", "network-error-symbolic"),
        _ => ("Folder sync update", "dialog-information-symbolic"),
    };
    StatusFacet::new(state, summary, message, icon_name)
}

#[must_use]
pub fn overall_status_facet(snapshot: &StatusSnapshot) -> StatusFacet {
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

#[must_use]
pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn sleep_with_stop(running: &AtomicBool, total: Duration) {
    let slice = Duration::from_millis(250);
    let mut elapsed = Duration::ZERO;
    while elapsed < total && running.load(Ordering::SeqCst) {
        let remaining = total.saturating_sub(elapsed);
        thread::sleep(remaining.min(slice));
        elapsed += slice;
    }
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

fn facet_is_error(facet: &StatusFacet) -> bool {
    facet.state == "error"
}

fn facet_is_warning(facet: &StatusFacet) -> bool {
    facet.state == "warning"
}

fn temp_status_path(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::{
        ClusterSummaryView, ReplicationPlanView, StatusFacet, StatusSnapshot, derive_profile_label,
        overall_status_facet, replication_facet_from_plan,
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
        let snapshot = StatusSnapshot {
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
