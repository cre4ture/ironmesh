#![cfg(not(windows))]

use anyhow::Result;
use client_sdk::IronMeshClient;
use desktop_status::{
    DesktopStatusPublisher, DesktopStatusPublisherOptions, StatusFacet,
    default_gnome_status_file_path, install_gnome_extension_from, spawn_remote_status_thread,
};
pub use desktop_status::{
    GNOME_EXTENSION_UUID, GnomeExtensionInstallOutcome, default_remote_status_poll_interval_ms,
    derive_profile_label,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone)]
pub struct GnomeStatusOptions {
    pub profile_label: String,
    pub root_dir: PathBuf,
    pub connection_target: String,
    pub status_file: PathBuf,
    pub remote_status_poll_interval_ms: u64,
}

pub struct GnomeStatusRuntime {
    running: Arc<AtomicBool>,
    publisher: Arc<DesktopStatusPublisher>,
    remote_thread: Option<std::thread::JoinHandle<()>>,
}

impl GnomeStatusRuntime {
    pub fn start(options: &GnomeStatusOptions, client: Option<IronMeshClient>) -> Result<Self> {
        let publisher = Arc::new(DesktopStatusPublisher::new(
            &DesktopStatusPublisherOptions {
                profile_label: options.profile_label.clone(),
                root_dir: options.root_dir.clone(),
                connection_target: options.connection_target.clone(),
                status_file: options.status_file.clone(),
            },
        )?);
        let running = Arc::new(AtomicBool::new(true));
        let remote_thread = match client {
            Some(client) => Some(spawn_remote_status_thread(
                running.clone(),
                publisher.clone(),
                client,
                options.remote_status_poll_interval_ms,
                "ironmesh-linux-fuse-gnome-status",
            )?),
            None => None,
        };

        Ok(Self {
            running,
            publisher,
            remote_thread,
        })
    }

    pub fn update_connection(&self, facet: StatusFacet) -> Result<()> {
        self.publisher.update_connection(facet)
    }

    pub fn update_sync(&self, facet: StatusFacet) -> Result<()> {
        self.publisher.update_sync(facet)
    }

    pub fn update_replication(&self, facet: StatusFacet) -> Result<()> {
        self.publisher.update_replication(facet)
    }

    pub fn shutdown(self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(remote_thread) = self.remote_thread
            && let Err(error) = remote_thread.join()
        {
            tracing::warn!("gnome-status: Linux FUSE remote status thread join failed: {error:?}");
        }
        if let Err(error) = self.publisher.persist() {
            tracing::warn!("gnome-status: Linux FUSE final persist failed: {error:#}");
        }
    }
}

pub fn default_status_file_path() -> Result<PathBuf> {
    default_gnome_status_file_path()
}

pub fn install_extension(enable: bool) -> Result<GnomeExtensionInstallOutcome> {
    install_gnome_extension_from(&extension_source_dir(), enable)
}

pub fn starting_mount_sync_facet(mountpoint: &Path) -> StatusFacet {
    StatusFacet::new(
        "starting",
        "Preparing FUSE mount",
        format!("Preparing IronMesh mount at {}", mountpoint.display()),
        "view-refresh-symbolic",
    )
}

pub fn mounted_sync_facet(mountpoint: &Path) -> StatusFacet {
    StatusFacet::new(
        "running",
        "Watching mounted namespace",
        format!("IronMesh FUSE mount active at {}", mountpoint.display()),
        "folder-saved-search-symbolic",
    )
}

pub fn stopped_mount_sync_facet(mountpoint: &Path) -> StatusFacet {
    StatusFacet::new(
        "stopped",
        "FUSE mount stopped",
        format!("IronMesh mount stopped at {}", mountpoint.display()),
        "media-playback-stop-symbolic",
    )
}

pub fn failed_mount_sync_facet(mountpoint: &Path, error: &anyhow::Error) -> StatusFacet {
    StatusFacet::new(
        "error",
        "FUSE mount failed",
        format!("{}: {error:#}", mountpoint.display()),
        "network-error-symbolic",
    )
}

pub fn snapshot_connection_facet(snapshot_file: &Path) -> StatusFacet {
    StatusFacet::new(
        "unknown",
        "Static snapshot mode",
        format!("Using snapshot file {}", snapshot_file.display()),
        "dialog-question-symbolic",
    )
}

pub fn snapshot_replication_facet() -> StatusFacet {
    StatusFacet::new(
        "unknown",
        "Replication unavailable",
        "Static snapshot mounts do not poll live replication state",
        "dialog-question-symbolic",
    )
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
