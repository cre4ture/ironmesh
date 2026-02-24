#![cfg(windows)]

use crate::adapter::WindowsCfapiAdapter;
use crate::live::{
    ServerNodeHydrator, load_snapshot_from_server, normalize_base_url,
};
use crate::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root,
};
use clap::Parser;
use reqwest::blocking::Client;
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
    server_base_url: String,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64)]
    depth: usize,
}

pub fn serve_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let registration =
        SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);

    let base_url = normalize_base_url(&args.server_base_url)?;
    let client = Client::new();

    let snapshot =
        load_snapshot_from_server(&client, &base_url, args.prefix.as_deref(), args.depth)?;
    let adapter = WindowsCfapiAdapter::new(registration.display_name.clone());
    let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    apply_action_plan(&registration.root_path, &action_plan)?;
    eprintln!(
        "materialized {} planned entries under sync root",
        action_plan.actions.len()
    );

    let runtime = CfapiRuntime::from_action_plan(&action_plan);
    let hydrator = Box::new(ServerNodeHydrator::new(client.clone(), base_url.clone()));
    use std::sync::Arc;
    let uploader = Arc::new(ServerNodeHydrator::new(client, base_url));
    let _connection = connect_sync_root(&registration, runtime, hydrator, uploader)?;

    eprintln!("connected to CFAPI callbacks; serving hydration requests");
    let running = std::sync::Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            eprintln!("received Ctrl+C, shutting down");
            r.store(false, Ordering::SeqCst);
        })?;
    }

    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_secs(1));
    }

    eprintln!("shutting down; dropping connection and exiting");
    drop(_connection);
    Ok(())
}
