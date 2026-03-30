#![cfg(windows)]

use clap::{Parser, Subcommand};
use client_sdk::{RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope};
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::adapter::{CfapiAction, CfapiActionPlan, WindowsCfapiAdapter};
use crate::auth::{ClientEnrollmentOptions, resolve_or_enroll_client_identity};
use crate::cfapi::{cf_get_placeholder_standard_info, cf_set_pin_state};
use crate::connection_config::{persist_connection_config, resolve_connection_config};
use crate::live::ServerNodeHydrator;
use crate::monitor::SyncRootMonitor;
use crate::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root,
    reconcile_sync_states, register_sync_root, unregister_sync_root,
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
}

#[derive(Debug, Parser)]
struct RegisterArgs {
    #[arg(long)]
    sync_root_id: String,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    root_path: String,
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

pub fn cli_main() -> anyhow::Result<()> {
    common::logging::init_compact_tracing_default("info");
    let cli = Cli::parse();

    match cli.command {
        Commands::Register(args) => {
            let registration =
                SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);
            register_sync_root(&registration)
        }
        Commands::Unregister(args) => unregister_sync_root(&PathBuf::from(args.root_path)),
        Commands::Pin(args) => pin_placeholder_locally(args),

        Commands::Serve(args) => {
            let registration =
                SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);
            register_sync_root(&registration)?;

            let connection = resolve_connection_config(
                &registration.root_path,
                args.server_base_url.as_deref(),
                args.server_ca_cert.as_deref(),
                args.bootstrap_file.as_deref(),
                args.pairing_token.as_deref(),
                args.device_id.as_deref(),
                args.device_label.as_deref(),
            )?;
            tracing::info!("using connection target {}", connection.connection_target);
            let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
            let refresh_poller = RemoteSnapshotPoller::server_notifications(
                Duration::from_secs(25),
                refresh_interval,
            );
            let client_identity = resolve_or_enroll_client_identity(
                connection.enrollment_base_url.as_ref(),
                &registration.root_path,
                &ClientEnrollmentOptions {
                    cluster_id: connection.cluster_id,
                    pairing_token: connection.pairing_token.clone(),
                    force_reenroll: connection.force_reenroll,
                    device_id: connection.device_id.clone(),
                    device_label: connection.device_label.clone(),
                    client_identity_file: args.client_identity_file.clone(),
                    server_ca_pem: connection.server_ca_pem.clone(),
                },
            )?;
            if let Some(identity) = client_identity.as_ref() {
                tracing::info!("using enrolled client identity for {}", identity.device_id);
            }
            let client = connection.build_client(client_identity.as_ref())?;
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

            let adapter = WindowsCfapiAdapter::new(registration.display_name.clone());
            let fetcher = RemoteSnapshotFetcher::new(
                client.clone(),
                RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
            );
            let initial_snapshot = fetcher.fetch_snapshot_blocking()?;
            let action_plan = adapter.plan_actions(&initial_snapshot, &SyncPolicy::default());
            log_action_plan_summary("startup", &action_plan);

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
            let _connection =
                connect_sync_root(&registration, runtime.clone(), hydrator, uploader.clone())?;

            apply_action_plan(&registration.root_path, &action_plan)?;
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
            let mut monitor =
                SyncRootMonitor::new("monitor", registration.root_path.clone(), uploader.clone());
            monitor.seed_remote_entries(&action_plan);
            std::thread::spawn(move || {
                monitor.run();
            });

            tracing::info!("connected to CFAPI callbacks; serving hydration requests");
            let running = std::sync::Arc::new(AtomicBool::new(true));
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
            refresh_poller.spawn_fetcher_loop(
                refresh_running,
                Some(initial_snapshot),
                fetcher,
                move |update| {
                    let plan =
                        refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
                    let summary_label =
                        format!("remote-refresh changed_paths={}", update.changed_paths.len());
                    log_action_plan_summary(&summary_label, &plan);
                    if let Err(err) = apply_action_plan(&refresh_registration.root_path, &plan) {
                        tracing::info!("remote-refresh: apply_action_plan error: {err}");
                        return;
                    }
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
                },
            );

            while running.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_secs(1));
            }

            tracing::info!("shutting down; dropping connection and exiting");
            drop(_connection);
            Ok(())
        }
    }
}

fn pin_placeholder_locally(args: PinArgs) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{CF_PIN_STATE_PINNED, CF_SET_PIN_FLAG_NONE};

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

    loop {
        // Reopen the file for each poll so CFAPI progress reflects the latest placeholder state.
        let poll_file = OpenOptions::new().read(true).open(&target_path)?;
        let info = cf_get_placeholder_standard_info(&poll_file)?;
        tracing::info!(
            "pin progress: on_disk={} validated={} modified={} total={} pin_state={}",
            info.OnDiskDataSize,
            info.ValidatedDataSize,
            info.ModifiedDataSize,
            total_size,
            info.PinState
        );

        if info.OnDiskDataSize >= total_size && info.ModifiedDataSize == 0 {
            return Ok(());
        }

        if started.elapsed() >= timeout {
            anyhow::bail!(
                "timed out waiting for local pin hydration at {} (on_disk={} total={})",
                target_path.display(),
                info.OnDiskDataSize,
                total_size
            );
        }

        thread::sleep(poll_interval);
    }
}
