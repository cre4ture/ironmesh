use anyhow::Result;
use desktop_status::{
    DesktopStatusPublisher, DesktopStatusPublisherOptions, default_gnome_status_file_path,
    install_gnome_extension_from, spawn_remote_status_thread, sync_status_facet_from_runtime_state,
};
pub use desktop_status::{
    GNOME_EXTENSION_UUID, GnomeExtensionInstallOutcome, default_remote_status_poll_interval_ms,
    derive_profile_label,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use sync_agent_core::{
    FolderAgentRuntimeOptions, FolderAgentRuntimeStatus, build_configured_client,
    run_folder_agent_with_control,
};

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

pub fn default_status_file_path() -> Result<PathBuf> {
    default_gnome_status_file_path()
}

pub fn install_extension(enable: bool) -> Result<GnomeExtensionInstallOutcome> {
    install_gnome_extension_from(&extension_source_dir(), enable)
}

pub fn run_with_gnome_status(
    runtime_options: &FolderAgentRuntimeOptions,
    gnome_options: &GnomeRunOptions,
) -> Result<()> {
    let publisher = Arc::new(DesktopStatusPublisher::new(
        &DesktopStatusPublisherOptions {
            profile_label: gnome_options.profile_label.clone(),
            root_dir: gnome_options.root_dir.clone(),
            connection_target: gnome_options.connection_target.clone(),
            status_file: gnome_options.status_file.clone(),
        },
    )?);
    let running = Arc::new(AtomicBool::new(true));

    let remote_thread = match build_configured_client(
        gnome_options.server_base_url.as_deref(),
        gnome_options.client_bootstrap_json.as_deref(),
        gnome_options.server_ca_pem.as_deref(),
        gnome_options.client_identity_json.as_deref(),
    ) {
        Ok(client) => Some(spawn_remote_status_thread(
            running.clone(),
            publisher.clone(),
            client,
            gnome_options.remote_status_poll_interval_ms,
            "ironmesh-gnome-status",
        )?),
        Err(error) => {
            if let Err(persist_error) = publisher.update_remote_error(&error) {
                tracing::warn!(
                    "gnome-status: failed to persist client-build error: {persist_error:#}"
                );
            }
            None
        }
    };

    let callback_publisher = publisher.clone();
    let status_callback = Arc::new(move |status: FolderAgentRuntimeStatus| {
        if let Err(error) = callback_publisher.update_sync(sync_status_facet_from_runtime_state(
            status.state.as_str(),
            status.message.as_str(),
        )) {
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
    if let Some(remote_thread) = remote_thread
        && let Err(error) = remote_thread.join()
    {
        tracing::warn!("gnome-status: remote status thread join failed: {error:?}");
    }

    if let Err(error) = publisher.persist() {
        tracing::warn!("gnome-status: final persist failed: {error:#}");
    }

    result
}

fn extension_source_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("gnome-shell-extension")
        .join(GNOME_EXTENSION_UUID)
}
