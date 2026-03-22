#![cfg(windows)]

use clap::{Parser, Subcommand};
use client_sdk::{RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::adapter::WindowsCfapiAdapter;
use crate::auth::{ClientEnrollmentOptions, resolve_or_enroll_client_identity};
use crate::connection_config::{persist_connection_config, resolve_connection_config};
use crate::live::ServerNodeHydrator;
use crate::monitor::SyncRootMonitor;
use crate::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root, register_sync_root,
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

#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi")]
#[command(about = "Combined CLI for register and serve")]
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

pub fn cli_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Register(args) => {
            let registration =
                SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);
            register_sync_root(&registration)
        }

        Commands::Serve(args) => {
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
            eprintln!("using connection target {}", connection.connection_target);
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
                eprintln!("using enrolled client identity for {}", identity.device_id);
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

            let runtime = Arc::new(CfapiRuntime::from_action_plan(&action_plan));
            let hydrator = Box::new(ServerNodeHydrator::with_client(client.clone()));
            let uploader = Arc::new(ServerNodeHydrator::with_client(client.clone()));
            let _connection =
                connect_sync_root(&registration, runtime.clone(), hydrator, uploader.clone())?;

            apply_action_plan(&registration.root_path, &action_plan)?;
            let _ = runtime.sync_from_action_plan(&action_plan);
            eprintln!(
                "materialized {} planned entries under sync root",
                action_plan.actions.len()
            );

            eprintln!(
                "startup-scan: scanning {} for pre-existing files",
                registration.root_path.display()
            );
            let mut monitor =
                SyncRootMonitor::new("monitor", registration.root_path.clone(), uploader.clone());
            monitor.walk();
            std::thread::spawn(move || {
                monitor.run();
            });

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
                    let plan =
                        refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
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
    }
}
