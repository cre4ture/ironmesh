#[cfg(feature = "cfapi-runtime")]
use adapter_windows_cfapi::WindowsCfapiAdapter;
#[cfg(feature = "cfapi-runtime")]
use adapter_windows_cfapi::live::{ServerNodeHydrator, load_snapshot_from_server, normalize_base_url};
#[cfg(feature = "cfapi-runtime")]
use adapter_windows_cfapi::runtime::{
    CfapiRuntime, SyncRootRegistration, apply_action_plan, connect_sync_root, register_sync_root,
};
#[cfg(feature = "cfapi-runtime")]
use clap::Parser;
#[cfg(feature = "cfapi-runtime")]
use reqwest::blocking::Client;
#[cfg(feature = "cfapi-runtime")]
use std::thread;
#[cfg(feature = "cfapi-runtime")]
use std::time::Duration;
#[cfg(feature = "cfapi-runtime")]
use sync_core::SyncPolicy;

#[cfg(feature = "cfapi-runtime")]
#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi-register")]
#[command(about = "Register a Windows sync root (MVP validation utility)")]
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
    #[arg(long, default_value_t = false)]
    connect: bool,
}

#[cfg(feature = "cfapi-runtime")]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let registration = SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);
    register_sync_root(&registration)?;

    let Some(server_base_url) = args.server_base_url.as_deref() else {
        eprintln!("sync root registered (no server sync requested)");
        return Ok(());
    };

    let base_url = normalize_base_url(server_base_url)?;
    let client = Client::new();

    let snapshot = load_snapshot_from_server(&client, &base_url, args.prefix.as_deref(), args.depth)?;
    let adapter = WindowsCfapiAdapter::new(registration.display_name.clone());
    let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    apply_action_plan(&registration.root_path, &action_plan)?;
    eprintln!("materialized {} planned entries under sync root", action_plan.actions.len());

    if !args.connect {
        return Ok(());
    }

    let runtime = CfapiRuntime::from_action_plan(&action_plan);
    let hydrator = Box::new(ServerNodeHydrator::new(client, base_url));
    let _connection = connect_sync_root(&registration, runtime, hydrator)?;

    eprintln!("connected to CFAPI callbacks; process will stay alive for hydration requests");
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

#[cfg(not(feature = "cfapi-runtime"))]
fn main() {
    eprintln!("binary requires the `cfapi-runtime` feature");
    std::process::exit(1);
}
