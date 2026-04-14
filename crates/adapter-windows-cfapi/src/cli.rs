#![cfg(windows)]

use clap::{Parser, Subcommand};
use client_sdk::{RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope};
use desktop_status::default_remote_status_poll_interval_ms;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::adapter::{CfapiAction, CfapiActionPlan, WindowsCfapiAdapter};
use crate::auth::{
    ClientEnrollmentOptions, persist_local_appdata_client_identity,
    resolve_or_enroll_client_identity,
};
use crate::cfapi::{cf_get_placeholder_standard_info, cf_hydrate_placeholder, cf_set_pin_state};
use crate::connection_config::{
    persist_connection_config, persist_local_appdata_connection_config, resolve_connection_config,
};
use crate::helpers::{normalize_path, path_to_relative};
use crate::hydration_control::{is_active_hydration_marked, request_hydration_cancel};
use crate::live::ServerNodeHydrator;
use crate::local_state::local_appdata_desktop_status_path;
use crate::monitor::SyncRootMonitor;
use crate::placeholder_metadata::{
    RemoteDeleteReconcileReport, reconcile_remote_delete_state, record_in_sync_remote_file_state,
};
use crate::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root,
    reconcile_sync_states, register_sync_root, unregister_sync_root,
};
use crate::sync_root_identity::load_registered_sync_root_context;
use crate::windows_status::{
    WindowsStatusOptions, WindowsStatusPublisher, WindowsTrayIconHandle, spawn_remote_status_thread,
};
use sync_core::SyncPolicy;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

fn log_action_plan_summary(label: &str, plan: &CfapiActionPlan) {
    let mut ensure_directories = 0usize;
    let mut ensure_placeholders = 0usize;
    let mut hydrate_on_demand = 0usize;
    let mut queue_uploads = 0usize;
    let mut conflicts = 0usize;
    let mut hydrate_sample = Vec::new();
    let mut dirty_sample = Vec::new();
    let mut conflict_sample = Vec::new();

    for action in &plan.actions {
        match action {
            CfapiAction::EnsureDirectory { .. } => {
                ensure_directories += 1;
            }
            CfapiAction::EnsurePlaceholder { .. } => {
                ensure_placeholders += 1;
            }
            CfapiAction::HydrateOnDemand { path, .. } => {
                hydrate_on_demand += 1;
                if hydrate_sample.len() < 8 {
                    hydrate_sample.push(path.clone());
                }
            }
            CfapiAction::QueueUploadOnClose { path, .. } => {
                queue_uploads += 1;
                if dirty_sample.len() < 8 {
                    dirty_sample.push(path.clone());
                }
            }
            CfapiAction::MarkConflict { path, .. } => {
                conflicts += 1;
                if conflict_sample.len() < 8 {
                    conflict_sample.push(path.clone());
                }
            }
        }
    }

    tracing::info!(
        "plan-summary: {} total={} directories={} placeholders={} hydrate_on_demand={} queue_uploads={} conflicts={}",
        label,
        plan.actions.len(),
        ensure_directories,
        ensure_placeholders,
        hydrate_on_demand,
        queue_uploads,
        conflicts
    );
    if !hydrate_sample.is_empty() || !dirty_sample.is_empty() || !conflict_sample.is_empty() {
        tracing::info!(
            "plan-summary: {} hydrate_sample={:?} dirty_sample={:?} conflict_sample={:?}",
            label,
            hydrate_sample,
            dirty_sample,
            conflict_sample
        );
    }
}

fn log_remote_delete_reconcile_summary(label: &str, report: &RemoteDeleteReconcileReport) {
    if report.deleted_paths.is_empty()
        && report.preserved_paths.is_empty()
        && report.suppressed_startup_paths.is_empty()
    {
        return;
    }

    tracing::info!(
        "remote-delete-reconcile: {} deleted={} preserved={} suppressed={}",
        label,
        report.deleted_paths.len(),
        report.preserved_paths.len(),
        report.suppressed_startup_paths.len()
    );
    tracing::info!(
        "remote-delete-reconcile: {} deleted_sample={:?} preserved_sample={:?} suppressed_sample={:?}",
        label,
        report
            .deleted_paths
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>(),
        report
            .preserved_paths
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>(),
        report
            .suppressed_startup_paths
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>(),
    );
}

#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi")]
#[command(about = "Combined CLI for register, unregister, serve, and pin")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Commands {
    Serve(ServeArgs),
    Register(RegisterArgs),
    Unregister(UnregisterArgs),
    Pin(PinArgs),
    CancelHydration(CancelHydrationArgs),
}

#[derive(Debug, Parser)]
struct ServeArgs {
    #[arg(long)]
    sync_root_id: String,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    root_path: String,
    #[arg(long)]
    server_base_url: Option<String>,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64)]
    depth: usize,
    #[arg(long, default_value_t = 3000)]
    remote_refresh_interval_ms: u64,
    #[arg(long)]
    pairing_token: Option<String>,
    #[arg(long)]
    device_id: Option<String>,
    #[arg(long)]
    device_label: Option<String>,
    #[arg(long)]
    client_identity_file: Option<PathBuf>,
    #[arg(long)]
    server_ca_cert: Option<PathBuf>,
    #[arg(long)]
    bootstrap_file: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    tray_status: bool,
    #[arg(long)]
    tray_status_file: Option<PathBuf>,
    #[arg(long, default_value_t = default_remote_status_poll_interval_ms())]
    tray_status_poll_interval_ms: u64,
}

#[derive(Debug, Parser)]
struct RegisterArgs {
    #[arg(long)]
    sync_root_id: String,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    root_path: String,
    #[arg(long)]
    cluster_id: uuid::Uuid,
    #[arg(long)]
    prefix: Option<String>,
}

#[derive(Debug, Parser)]
struct UnregisterArgs {
    #[arg(long)]
    root_path: String,
}

#[derive(Debug, Parser)]
struct PinArgs {
    #[arg(long)]
    root_path: String,
    #[arg(long)]
    path: String,
    #[arg(long, default_value_t = false)]
    wait: bool,
    #[arg(long, default_value_t = 30_000)]
    timeout_ms: u64,
    #[arg(long, default_value_t = 250)]
    poll_interval_ms: u64,
}

#[derive(Debug, Parser)]
struct CancelHydrationArgs {
    #[arg(long)]
    root_path: String,
    #[arg(long)]
    path: String,
}

pub fn cli_main() -> anyhow::Result<()> {
    common::logging::init_compact_tracing_default("info");
    let cli = Cli::parse();

    match cli.command {
        Commands::Register(args) => {
            let registration = SyncRootRegistration::new(
                args.sync_root_id,
                args.display_name,
                args.root_path,
                args.cluster_id,
                args.prefix.as_deref(),
            );
            register_sync_root(&registration).map(|_| ())
        }
        Commands::Unregister(args) => unregister_sync_root(&PathBuf::from(args.root_path)),
        Commands::Pin(args) => pin_placeholder_locally(args),
        Commands::CancelHydration(args) => cancel_placeholder_hydration(args),

        Commands::Serve(args) => serve_sync_root(args),
    }
}

fn serve_sync_root(args: ServeArgs) -> anyhow::Result<()> {
    let ServeArgs {
        sync_root_id,
        display_name,
        root_path: root_path_arg,
        server_base_url,
        prefix,
        depth,
        remote_refresh_interval_ms,
        pairing_token,
        device_id,
        device_label,
        client_identity_file,
        server_ca_cert,
        bootstrap_file,
        tray_status,
        tray_status_file,
        tray_status_poll_interval_ms,
    } = args;

    let root_path = PathBuf::from(&root_path_arg);
    let connection = resolve_connection_config(
        &root_path,
        server_base_url.as_deref(),
        server_ca_cert.as_deref(),
        bootstrap_file.as_deref(),
        pairing_token.as_deref(),
        device_id.as_deref(),
        device_label.as_deref(),
    )?;
    let registration = SyncRootRegistration::new(
        sync_root_id,
        display_name,
        root_path,
        connection.cluster_id,
        prefix.as_deref(),
    );
    let running = Arc::new(AtomicBool::new(true));
    let status_publisher = if tray_status {
        let status_file = tray_status_file
            .clone()
            .unwrap_or_else(|| local_appdata_desktop_status_path(&registration.root_path));
        Some(Arc::new(WindowsStatusPublisher::new(
            &WindowsStatusOptions {
                profile_label: registration.display_name.clone(),
                root_dir: registration.root_path.clone(),
                connection_target: connection.connection_target.clone(),
                status_file,
            },
        )?))
    } else {
        None
    };
    let mut tray_handle = match status_publisher.as_ref() {
        Some(publisher) => Some(WindowsTrayIconHandle::spawn(
            running.clone(),
            registration.root_path.clone(),
            publisher.clone(),
        )?),
        None => None,
    };

    if let Some(publisher) = status_publisher.as_ref() {
        let _ = publisher.update_sync_state(
            "starting",
            "Preparing Windows sync root",
            format!("Connecting {}", registration.root_path.display()),
            "view-refresh-symbolic",
        );
    }

    let mut remote_status_thread = None;
    let result = (|| -> anyhow::Result<()> {
        let sync_root_identity = register_sync_root(&registration)?;
        tracing::info!("using connection target {}", connection.connection_target);
        let refresh_interval = Duration::from_millis(remote_refresh_interval_ms.max(250));
        let refresh_poller =
            RemoteSnapshotPoller::server_notifications(Duration::from_secs(25), refresh_interval);
        let client_identity = resolve_or_enroll_client_identity(
            connection.enrollment_base_url.as_ref(),
            &registration.root_path,
            bootstrap_file.as_deref(),
            &ClientEnrollmentOptions {
                cluster_id: connection.cluster_id,
                pairing_token: connection.pairing_token.clone(),
                force_reenroll: connection.force_reenroll,
                device_id: connection.device_id.clone(),
                device_label: connection.device_label.clone(),
                client_identity_file: client_identity_file.clone(),
                server_ca_pem: connection.server_ca_pem.clone(),
            },
        )?;
        if let Some(identity) = client_identity.as_ref() {
            tracing::info!("using enrolled client identity for {}", identity.device_id);
        }
        let client = connection.build_client(client_identity.as_ref())?;
        if let Some(publisher) = status_publisher.as_ref() {
            remote_status_thread = Some(spawn_remote_status_thread(
                running.clone(),
                publisher.clone(),
                client.clone(),
                tray_status_poll_interval_ms,
            )?);
        }

        let persisted_device_id = client_identity
            .as_ref()
            .map(|identity| identity.device_id.to_string());
        persist_connection_config(
            &connection.bootstrap_path,
            &connection.bootstrap,
            connection.server_ca_pem.as_deref(),
            persisted_device_id.as_deref(),
            client_identity
                .as_ref()
                .and_then(|identity| identity.label.as_deref())
                .or(connection.device_label.as_deref()),
        )?;
        if let Err(err) = persist_local_appdata_connection_config(
            &registration.root_path,
            &connection.bootstrap,
            connection.server_ca_pem.as_deref(),
            persisted_device_id.as_deref(),
            client_identity
                .as_ref()
                .and_then(|identity| identity.label.as_deref())
                .or(connection.device_label.as_deref()),
        ) {
            tracing::warn!(
                "failed to persist connection bootstrap into local app data for {}: {err:#}",
                registration.root_path.display()
            );
        }
        if let Some(identity) = client_identity.as_ref()
            && let Err(err) =
                persist_local_appdata_client_identity(&registration.root_path, identity)
        {
            tracing::warn!(
                "failed to persist client identity into local app data for {}: {err:#}",
                registration.root_path.display()
            );
        }

        let adapter = WindowsCfapiAdapter::new(registration.display_name.clone());
        let fetcher = RemoteSnapshotFetcher::new(
            client.clone(),
            RemoteSnapshotScope::new(prefix.clone(), depth, None),
        );
        let initial_snapshot = fetcher.fetch_snapshot_blocking()?;
        let startup_delete_report = match reconcile_remote_delete_state(
            &registration.root_path,
            &initial_snapshot,
            sync_root_identity.provider_instance_id,
        ) {
            Ok(report) => {
                log_remote_delete_reconcile_summary("startup", &report);
                report
            }
            Err(err) => {
                tracing::warn!("startup remote-delete reconciliation failed: {err:#}");
                RemoteDeleteReconcileReport::default()
            }
        };
        let action_plan = adapter.plan_actions(&initial_snapshot, &SyncPolicy::default());
        log_action_plan_summary("startup", &action_plan);

        if let Some(publisher) = status_publisher.as_ref() {
            let _ = publisher.update_sync_state(
                "starting",
                "Applying initial sync root snapshot",
                format!(
                    "Materializing {} planned entries",
                    action_plan.actions.len()
                ),
                "view-refresh-symbolic",
            );
        }

        let runtime = Arc::new(CfapiRuntime::from_action_plan(&action_plan));
        let download_stage_root =
            crate::live::windows_download_stage_root_for_sync_root(&registration.root_path)?;
        let hydrator = Box::new(ServerNodeHydrator::with_client(
            client.clone(),
            download_stage_root.clone(),
        ));
        let uploader = Arc::new(ServerNodeHydrator::with_client(
            client.clone(),
            download_stage_root,
        ));
        let connection_guard = connect_sync_root(
            &registration,
            sync_root_identity.provider_instance_id,
            runtime.clone(),
            hydrator,
            uploader.clone(),
        )?;

        apply_action_plan(
            &registration.root_path,
            &action_plan,
            sync_root_identity.provider_instance_id,
            true,
        )?;
        let _ = runtime.sync_from_action_plan(&action_plan);
        let sync_state_stats = reconcile_sync_states(&registration.root_path, &action_plan);
        tracing::info!(
            "sync-state: startup reconcile stats: {:?}",
            sync_state_stats
        );
        tracing::info!(
            "materialized {} planned entries under sync root",
            action_plan.actions.len()
        );

        tracing::info!(
            "startup-scan: scanning {} for pre-existing files",
            registration.root_path.display()
        );
        let mut monitor = SyncRootMonitor::new(
            "monitor",
            registration.root_path.clone(),
            sync_root_identity.provider_instance_id,
            uploader.clone(),
        );
        let remote_applied_tracker = monitor.remote_applied_tracker();
        let refresh_gate = monitor.refresh_gate();
        monitor.seed_remote_entries_with_suppressed_paths(
            &action_plan,
            &startup_delete_report.suppressed_startup_paths,
        );
        std::thread::spawn(move || {
            monitor.run();
        });

        tracing::info!("connected to CFAPI callbacks; serving hydration requests");
        if let Some(publisher) = status_publisher.as_ref() {
            let _ = publisher.update_sync_state(
                "running",
                "Watching for local changes",
                format!("Serving sync root {}", registration.root_path.display()),
                "folder-saved-search-symbolic",
            );
        }

        {
            let r = running.clone();
            ctrlc::set_handler(move || {
                tracing::info!("received Ctrl+C, shutting down");
                r.store(false, Ordering::SeqCst);
            })?;
        }

        let refresh_registration = registration.clone();
        let refresh_adapter = adapter.clone();
        let refresh_runtime = runtime.clone();
        let refresh_running = running.clone();
        let refresh_provider_instance_id = sync_root_identity.provider_instance_id;
        let refresh_remote_applied_tracker = remote_applied_tracker.clone();
        let refresh_monitor_gate = refresh_gate.clone();
        let refresh_status_publisher = status_publisher.clone();
        refresh_poller.spawn_fetcher_loop(
            refresh_running,
            Some(initial_snapshot),
            fetcher,
            move |update| {
                if let Some(publisher) = refresh_status_publisher.as_ref() {
                    let _ = publisher.update_sync_state(
                        "syncing",
                        "Applying remote updates",
                        format!("Refreshing {} changed remote path(s)", update.changed_paths.len()),
                        "view-refresh-symbolic",
                    );
                }

                let plan = refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
                let summary_label = format!("remote-refresh changed_paths={}", update.changed_paths.len());
                log_action_plan_summary(&summary_label, &plan);
                let remote_delete_report = {
                    let _monitor_gate = refresh_monitor_gate
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let report = match reconcile_remote_delete_state(
                        &refresh_registration.root_path,
                        &update.snapshot,
                        refresh_provider_instance_id,
                    ) {
                        Ok(report) => report,
                        Err(err) => {
                            tracing::warn!(
                                "remote-refresh: remote-delete reconciliation failed: {err:#}"
                            );
                            RemoteDeleteReconcileReport::default()
                        }
                    };
                    if let Err(err) = apply_action_plan(
                        &refresh_registration.root_path,
                        &plan,
                        refresh_provider_instance_id,
                        false,
                    ) {
                        tracing::info!("remote-refresh: apply_action_plan error: {err}");
                        return;
                    }
                    refresh_remote_applied_tracker.record_plan(&plan);
                    report
                };
                log_remote_delete_reconcile_summary(&summary_label, &remote_delete_report);
                let reconciled_paths = refresh_runtime.sync_from_action_plan(&plan);
                let sync_state_stats =
                    reconcile_sync_states(&refresh_registration.root_path, &plan);
                if reconciled_paths > 0 {
                    tracing::info!(
                        "remote-refresh: reconciled {} changed paths; sync-state={:?}",
                        reconciled_paths, sync_state_stats
                    );
                } else {
                    tracing::info!(
                        "remote-refresh: detected {} changed remote paths; no local plan delta; sync-state={:?}",
                        update.changed_paths.len(),
                        sync_state_stats
                    );
                }
                if !remote_delete_report.suppressed_startup_paths.is_empty() {
                    tracing::info!(
                        "remote-refresh: preserved {} stale local path(s) after delete because local bytes could not be removed",
                        remote_delete_report.suppressed_startup_paths.len()
                    );
                }
                if let Some(publisher) = refresh_status_publisher.as_ref() {
                    let _ = publisher.update_sync_state(
                        "running",
                        "Watching for local changes",
                        format!("Serving sync root {}", refresh_registration.root_path.display()),
                        "folder-saved-search-symbolic",
                    );
                }
            },
        );

        while running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(1));
        }

        tracing::info!("shutting down; dropping connection and exiting");
        drop(connection_guard);
        Ok(())
    })();

    running.store(false, Ordering::SeqCst);
    if let Some(thread) = remote_status_thread.take() {
        let _ = thread.join();
    }
    if let Some(publisher) = status_publisher.as_ref() {
        match &result {
            Ok(()) => {
                let _ = publisher.update_sync_state(
                    "stopped",
                    "Windows sync root stopped",
                    format!("Stopped serving {}", registration.root_path.display()),
                    "media-playback-stop-symbolic",
                );
            }
            Err(error) => {
                let _ = publisher.update_sync_state(
                    "error",
                    "Windows sync root error",
                    format!("{error:#}"),
                    "network-error-symbolic",
                );
            }
        }
        let _ = publisher.persist();
    }
    if let Some(handle) = tray_handle.take() {
        handle.shutdown();
    }

    result
}

fn pin_placeholder_locally(args: PinArgs) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_PINNED, CF_SET_PIN_FLAG_NONE,
    };

    let root_path = PathBuf::from(&args.root_path);
    let target_path = if PathBuf::from(&args.path).is_absolute() {
        PathBuf::from(&args.path)
    } else {
        root_path.join(args.path.replace('/', "\\"))
    };

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_path)?;
    cf_set_pin_state(&file, CF_PIN_STATE_PINNED, CF_SET_PIN_FLAG_NONE)?;
    tracing::info!("requested pin for {}", target_path.display());

    if !args.wait {
        return Ok(());
    }

    let timeout = Duration::from_millis(args.timeout_ms.max(1));
    let poll_interval = Duration::from_millis(args.poll_interval_ms.max(50));
    let started = std::time::Instant::now();
    let total_size = file.metadata()?.len() as i64;
    let normalized_relative_path = resolve_cli_relative_path(&root_path, &args.path);
    let mut previous_snapshot = None;
    let mut last_hydrate_error = None;

    loop {
        // Reopen the file for each poll so CFAPI progress reflects the latest placeholder state.
        let poll_file = OpenOptions::new().read(true).open(&target_path)?;
        let info = cf_get_placeholder_standard_info(&poll_file)?;
        let snapshot = PinHydrationSnapshot {
            on_disk_data_size: info.OnDiskDataSize,
            validated_data_size: info.ValidatedDataSize,
            modified_data_size: info.ModifiedDataSize,
            in_sync_state: info.InSyncState,
            pin_state: info.PinState,
            provider_hydration_active: !normalized_relative_path.is_empty()
                && is_active_hydration_marked(&root_path, &normalized_relative_path),
        };
        tracing::info!(
            "pin progress: on_disk={} validated={} modified={} total={} pin_state={} in_sync={} provider_hydration_active={}",
            snapshot.on_disk_data_size,
            snapshot.validated_data_size,
            snapshot.modified_data_size,
            total_size,
            snapshot.pin_state,
            snapshot.in_sync_state,
            snapshot.provider_hydration_active,
        );

        if snapshot.on_disk_data_size >= total_size && snapshot.modified_data_size == 0 {
            match load_registered_sync_root_context(&root_path) {
                Ok(Some(context)) => {
                    if let Err(err) = record_in_sync_remote_file_state(
                        &root_path,
                        &args.path,
                        context.identity.provider_instance_id,
                    ) {
                        tracing::warn!(
                            "failed to record in-sync remote clean fingerprint for pinned placeholder {}: {err:#}",
                            target_path.display()
                        );
                    }
                }
                Ok(None) => {
                    tracing::warn!(
                        "skipping in-sync local hash capture for pinned placeholder {} because {} is not currently registered",
                        target_path.display(),
                        root_path.display()
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        "failed to query sync root identity for pinned placeholder {}: {err:#}",
                        target_path.display()
                    );
                }
            }
            return Ok(());
        }

        let can_still_hydrate = snapshot.pin_state == CF_PIN_STATE_PINNED
            && snapshot.in_sync_state == CF_IN_SYNC_STATE_IN_SYNC
            && snapshot.modified_data_size == 0;
        let should_retry_explicit_hydrate = should_request_pin_hydration(
            previous_snapshot,
            snapshot,
            total_size,
            last_hydrate_error.is_some(),
        );
        if should_retry_explicit_hydrate && can_still_hydrate {
            let hydrate_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&target_path)?;
            match cf_hydrate_placeholder(&hydrate_file) {
                Ok(()) => {
                    tracing::info!(
                        "requested local hydration for {} snapshot={} ",
                        target_path.display(),
                        snapshot.to_log_string()
                    );
                    last_hydrate_error = None;
                }
                Err(err) => {
                    tracing::info!(
                        "pin hydration request for {} failed: {:#} snapshot={}",
                        target_path.display(),
                        err,
                        snapshot.to_log_string()
                    );
                    last_hydrate_error = Some(err);
                }
            }
        }

        previous_snapshot = Some(snapshot);

        if started.elapsed() >= timeout {
            let last_hydrate_error = last_hydrate_error
                .as_ref()
                .map(|err| format!(" last_hydrate_error={err:#}"))
                .unwrap_or_default();
            anyhow::bail!(
                "timed out waiting for local pin hydration at {} ({}) total={}{}",
                target_path.display(),
                snapshot.to_log_string(),
                total_size,
                last_hydrate_error
            );
        }

        thread::sleep(poll_interval);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PinHydrationSnapshot {
    on_disk_data_size: i64,
    validated_data_size: i64,
    modified_data_size: i64,
    in_sync_state: i32,
    pin_state: i32,
    provider_hydration_active: bool,
}

impl PinHydrationSnapshot {
    fn to_log_string(self) -> String {
        format!(
            "on_disk={} validated={} modified={} in_sync={} pin={} provider_hydration_active={}",
            self.on_disk_data_size,
            self.validated_data_size,
            self.modified_data_size,
            self.in_sync_state,
            self.pin_state,
            self.provider_hydration_active
        )
    }
}

fn should_request_pin_hydration(
    previous_snapshot: Option<PinHydrationSnapshot>,
    current_snapshot: PinHydrationSnapshot,
    total_size: i64,
    last_request_failed: bool,
) -> bool {
    if current_snapshot.provider_hydration_active
        || current_snapshot.modified_data_size != 0
        || current_snapshot.on_disk_data_size >= total_size
    {
        return false;
    }

    let Some(previous_snapshot) = previous_snapshot else {
        return true;
    };

    if last_request_failed {
        return true;
    }

    previous_snapshot.provider_hydration_active
        || previous_snapshot.on_disk_data_size != current_snapshot.on_disk_data_size
        || previous_snapshot.validated_data_size != current_snapshot.validated_data_size
        || previous_snapshot.modified_data_size != current_snapshot.modified_data_size
        || previous_snapshot.in_sync_state != current_snapshot.in_sync_state
        || previous_snapshot.pin_state != current_snapshot.pin_state
}

fn cancel_placeholder_hydration(args: CancelHydrationArgs) -> anyhow::Result<()> {
    let root_path = PathBuf::from(&args.root_path);
    let normalized_relative_path = resolve_cli_relative_path(&root_path, &args.path);
    if normalized_relative_path.is_empty() {
        anyhow::bail!(
            "failed to resolve a relative path from {} under {}",
            args.path,
            root_path.display()
        );
    }

    if request_hydration_cancel(&root_path, &normalized_relative_path)? {
        tracing::info!(
            "requested hydration cancel for {} under {}",
            normalized_relative_path,
            root_path.display()
        );
        return Ok(());
    }

    anyhow::bail!(
        "no active hydration found for {} under {}",
        normalized_relative_path,
        root_path.display()
    )
}

fn resolve_cli_relative_path(root_path: &std::path::Path, requested_path: &str) -> String {
    let candidate = PathBuf::from(requested_path);
    if candidate.is_absolute() {
        return path_to_relative(root_path, requested_path);
    }
    normalize_path(requested_path)
}

#[cfg(test)]
mod tests {
    use super::{PinHydrationSnapshot, should_request_pin_hydration};

    #[test]
    fn pin_hydration_requests_initial_explicit_hydrate() {
        let snapshot = PinHydrationSnapshot {
            on_disk_data_size: 0,
            validated_data_size: 0,
            modified_data_size: 0,
            in_sync_state: 1,
            pin_state: 1,
            provider_hydration_active: false,
        };

        assert!(should_request_pin_hydration(None, snapshot, 4096, false));
    }

    #[test]
    fn pin_hydration_defers_while_provider_hydration_is_active() {
        let snapshot = PinHydrationSnapshot {
            on_disk_data_size: 0,
            validated_data_size: 0,
            modified_data_size: 0,
            in_sync_state: 1,
            pin_state: 1,
            provider_hydration_active: true,
        };

        assert!(!should_request_pin_hydration(None, snapshot, 4096, false));
    }

    #[test]
    fn pin_hydration_retries_after_provider_hydration_clears() {
        let previous = PinHydrationSnapshot {
            on_disk_data_size: 1024,
            validated_data_size: 1024,
            modified_data_size: 0,
            in_sync_state: 1,
            pin_state: 1,
            provider_hydration_active: true,
        };
        let current = PinHydrationSnapshot {
            provider_hydration_active: false,
            ..previous
        };

        assert!(should_request_pin_hydration(
            Some(previous),
            current,
            4096,
            false
        ));
    }

    #[test]
    fn pin_hydration_retries_after_progress_changes() {
        let previous = PinHydrationSnapshot {
            on_disk_data_size: 0,
            validated_data_size: 0,
            modified_data_size: 0,
            in_sync_state: 1,
            pin_state: 1,
            provider_hydration_active: false,
        };
        let current = PinHydrationSnapshot {
            on_disk_data_size: 2048,
            validated_data_size: 2048,
            ..previous
        };

        assert!(should_request_pin_hydration(
            Some(previous),
            current,
            4096,
            false
        ));
    }

    #[test]
    fn pin_hydration_retries_after_request_failure() {
        let snapshot = PinHydrationSnapshot {
            on_disk_data_size: 0,
            validated_data_size: 0,
            modified_data_size: 0,
            in_sync_state: 1,
            pin_state: 1,
            provider_hydration_active: false,
        };

        assert!(should_request_pin_hydration(
            Some(snapshot),
            snapshot,
            4096,
            true
        ));
    }
}
