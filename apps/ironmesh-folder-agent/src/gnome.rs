use anyhow::{Context, Result, anyhow};
use desktop_status::{
    RemoteStatusUpdate, StatusFacet, StatusSnapshot, build_status_document, poll_remote_status,
    sleep_with_stop, starting_snapshot, sync_status_facet_from_runtime_state,
    write_status_document,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use sync_agent_core::{
    FolderAgentRuntimeOptions, FolderAgentRuntimeStatus, build_configured_client,
    run_folder_agent_with_control,
};

pub const GNOME_EXTENSION_UUID: &str = "ironmesh-status@ironmesh.io";
pub use desktop_status::{default_remote_status_poll_interval_ms, derive_profile_label};

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

struct GnomeStatusPublisher {
    profile_label: String,
    root_dir: PathBuf,
    connection_target: String,
    status_file: PathBuf,
    snapshot: Mutex<StatusSnapshot>,
}

impl GnomeStatusPublisher {
    fn new(options: &GnomeRunOptions) -> Result<Self> {
        let publisher = Self {
            profile_label: options.profile_label.clone(),
            root_dir: options.root_dir.clone(),
            connection_target: options.connection_target.clone(),
            status_file: options.status_file.clone(),
            snapshot: Mutex::new(starting_snapshot(
                &options.root_dir,
                &options.connection_target,
            )),
        };
        publisher.persist()?;
        Ok(publisher)
    }

    fn update_sync(&self, status: &FolderAgentRuntimeStatus) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.sync =
            sync_status_facet_from_runtime_state(status.state.as_str(), status.message.as_str());
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

    fn lock_snapshot(&self) -> Result<std::sync::MutexGuard<'_, StatusSnapshot>> {
        self.snapshot
            .lock()
            .map_err(|_| anyhow!("GNOME status snapshot lock poisoned"))
    }

    fn persist_locked(&self, snapshot: &StatusSnapshot) -> Result<()> {
        let document = build_status_document(
            self.profile_label.clone(),
            &self.root_dir,
            self.connection_target.clone(),
            snapshot,
        );
        write_status_document(&self.status_file, &document)
    }
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
