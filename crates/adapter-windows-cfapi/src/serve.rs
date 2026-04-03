#![cfg(windows)]

use crate::adapter::WindowsCfapiAdapter;
use crate::auth::{ClientEnrollmentOptions, resolve_or_enroll_client_identity};
use crate::connection_config::{persist_connection_config, resolve_connection_config};
use crate::live::ServerNodeHydrator;
use crate::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root,
    reconcile_sync_states, register_sync_root,
};
use crate::snapshot_cache::{
    RemoteDeleteReconcileReport, RemoteSnapshotCache, load_remote_snapshot_cache,
    persist_remote_snapshot_cache,
    reconcile_remote_delete_state,
};
use clap::Parser;
use client_sdk::{RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use sync_core::SyncPolicy;

#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi-serve")]
#[command(about = "Connect CFAPI callbacks and serve on-demand hydration from server-node")]
struct Args {
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

pub fn serve_main() -> anyhow::Result<()> {
    common::logging::init_compact_tracing_default("info");
    let args = Args::parse();
    let root_path = PathBuf::from(&args.root_path);

    let connection = resolve_connection_config(
        &root_path,
        args.server_base_url.as_deref(),
        args.server_ca_cert.as_deref(),
        args.bootstrap_file.as_deref(),
        args.pairing_token.as_deref(),
        args.device_id.as_deref(),
        args.device_label.as_deref(),
    )?;
    let registration = SyncRootRegistration::new(
        args.sync_root_id,
        args.display_name,
        root_path,
        connection.cluster_id,
        args.prefix.as_deref(),
    );
    let _sync_root_identity = register_sync_root(&registration)?;
    tracing::info!("using connection target {}", connection.connection_target);
    let client_identity = resolve_or_enroll_client_identity(
        connection.enrollment_base_url.as_ref(),
        &registration.root_path,
        args.bootstrap_file.as_deref(),
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
    let cached_remote_snapshot = match load_remote_snapshot_cache(&registration.root_path) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::warn!("failed to load remote snapshot cache: {err:#}");
            None
        }
    };
    let initial_snapshot = fetcher.fetch_snapshot_blocking()?;
    let startup_delete_report = match reconcile_remote_delete_state(
        &registration.root_path,
        cached_remote_snapshot.as_ref(),
        &initial_snapshot,
    ) {
        Ok(report) => report,
        Err(err) => {
            tracing::warn!("startup remote-delete reconciliation failed: {err:#}");
            RemoteDeleteReconcileReport::default()
        }
    };
    if !startup_delete_report.deleted_paths.is_empty()
        || !startup_delete_report.preserved_paths.is_empty()
        || !startup_delete_report.suppressed_startup_paths.is_empty()
    {
        tracing::info!(
            "remote-delete-reconcile: startup deleted={} preserved={} suppressed={}",
            startup_delete_report.deleted_paths.len(),
            startup_delete_report.preserved_paths.len(),
            startup_delete_report.suppressed_startup_paths.len()
        );
    }
    let action_plan = adapter.plan_actions(&initial_snapshot, &SyncPolicy::default());
    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let refresh_poller =
        RemoteSnapshotPoller::server_notifications(Duration::from_secs(25), refresh_interval);

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
    let _connection = connect_sync_root(&registration, runtime.clone(), hydrator, uploader)?;

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
    let mut previous_remote_snapshot = match persist_remote_snapshot_cache(
        &registration.root_path,
        &initial_snapshot,
    ) {
        Ok(cache) => cache,
        Err(err) => {
            tracing::warn!("failed to persist remote snapshot cache: {err:#}");
            RemoteSnapshotCache::from_snapshot(initial_snapshot.clone())
        }
    };

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
            if let Err(err) = reconcile_remote_delete_state(
                &refresh_registration.root_path,
                Some(&previous_remote_snapshot),
                &update.snapshot,
            ) {
                tracing::warn!("remote-refresh: remote-delete reconciliation failed: {err:#}");
            }
            let plan = refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
            if let Err(err) = apply_action_plan(&refresh_registration.root_path, &plan) {
                tracing::info!("remote-refresh: apply_action_plan error: {err}");
                return;
            }
            let reconciled_paths = refresh_runtime.sync_from_action_plan(&plan);
            let sync_state_stats = reconcile_sync_states(&refresh_registration.root_path, &plan);
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
            previous_remote_snapshot = match persist_remote_snapshot_cache(
                &refresh_registration.root_path,
                &update.snapshot,
            ) {
                Ok(cache) => cache,
                Err(err) => {
                    tracing::warn!("remote-refresh: failed to persist remote snapshot cache: {err:#}");
                    previous_remote_snapshot.with_snapshot(update.snapshot.clone())
                }
            };
        },
    );

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    tracing::info!("shutting down; dropping connection and exiting");
    drop(_connection);
    Ok(())
}
