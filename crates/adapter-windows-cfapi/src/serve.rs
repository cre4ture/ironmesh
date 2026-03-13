#![cfg(windows)]

use crate::adapter::WindowsCfapiAdapter;
use crate::auth::{DeviceEnrollmentOptions, resolve_or_enroll_device_auth};
use crate::connection_config::{persist_connection_config, resolve_connection_config};
use crate::live::{ServerNodeHydrator, normalize_base_url};
use crate::runtime::{CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root};
use clap::Parser;
use client_sdk::{
    RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope, build_http_client_from_pem,
};
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
    device_token_file: Option<PathBuf>,
    #[arg(long)]
    server_ca_cert: Option<PathBuf>,
    #[arg(long)]
    bootstrap_file: Option<PathBuf>,
}

pub fn serve_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let registration =
        SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);

    let connection = resolve_connection_config(
        &registration.root_path,
        args.server_base_url.as_deref(),
        args.server_ca_cert.as_deref(),
        args.bootstrap_file.as_deref(),
        args.pairing_token.as_deref(),
        args.device_id.as_deref(),
        args.device_label.as_deref(),
    )?;
    let base_url = normalize_base_url(connection.base_url.as_str())?;
    let device_auth = resolve_or_enroll_device_auth(
        &base_url,
        &registration.root_path,
        &DeviceEnrollmentOptions {
            pairing_token: connection.pairing_token.clone(),
            device_id: connection.device_id.clone(),
            device_label: connection.device_label.clone(),
            device_token_file: args.device_token_file.clone(),
            server_ca_pem: connection.server_ca_pem.clone(),
        },
    )?;
    if let Some(auth) = device_auth.as_ref() {
        eprintln!("using enrolled device auth for {}", auth.device_id);
    }
    let bearer_token = device_auth.as_ref().map(|auth| auth.device_token.clone());
    let client = build_http_client_from_pem(
        connection.server_ca_pem.as_deref(),
        base_url.as_str(),
        &bearer_token,
    )?;
    persist_connection_config(
        &connection.bootstrap_path,
        &base_url,
        connection.server_ca_pem.as_deref(),
        device_auth.as_ref().map(|auth| auth.device_id.as_str()),
        device_auth
            .as_ref()
            .and_then(|auth| auth.label.as_deref())
            .or(connection.device_label.as_deref()),
    )?;

    let adapter = WindowsCfapiAdapter::new(registration.display_name.clone());
    let fetcher = RemoteSnapshotFetcher::new(
        client,
        RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
    );
    let initial_snapshot = fetcher.fetch_snapshot_blocking()?;
    let action_plan = adapter.plan_actions(&initial_snapshot, &SyncPolicy::default());
    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);

    let runtime = Arc::new(CfapiRuntime::from_action_plan(&action_plan));
    let hydrator = Box::new(ServerNodeHydrator::new(
        base_url.clone(),
        bearer_token.clone(),
        connection.server_ca_pem.as_deref(),
    )?);
    let uploader = Arc::new(ServerNodeHydrator::new(
        base_url,
        bearer_token,
        connection.server_ca_pem.as_deref(),
    )?);
    let _connection = connect_sync_root(&registration, runtime.clone(), hydrator, uploader)?;

    apply_action_plan(&registration.root_path, &action_plan)?;
    let _ = runtime.sync_from_action_plan(&action_plan);
    eprintln!(
        "materialized {} planned entries under sync root",
        action_plan.actions.len()
    );

    eprintln!("connected to CFAPI callbacks; serving hydration requests");
    let running = std::sync::Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            eprintln!("received Ctrl+C, shutting down");
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
            let plan = refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
            if let Err(err) = apply_action_plan(&refresh_registration.root_path, &plan) {
                eprintln!("remote-refresh: apply_action_plan error: {err}");
                return;
            }
            let reconciled_paths = refresh_runtime.sync_from_action_plan(&plan);
            if reconciled_paths > 0 {
                eprintln!(
                    "remote-refresh: reconciled {} changed paths",
                    reconciled_paths
                );
            } else {
                eprintln!(
                    "remote-refresh: detected {} changed remote paths; no local plan delta",
                    update.changed_paths.len()
                );
            }
        },
    );

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    eprintln!("shutting down; dropping connection and exiting");
    drop(_connection);
    Ok(())
}
