#![cfg(windows)]

use crate::runtime::{SyncRootRegistration, register_sync_root};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi-register")]
#[command(about = "Register a Windows sync root")]
struct Args {
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

pub fn register_main() -> anyhow::Result<()> {
    let args = Args::parse();
    let registration = SyncRootRegistration::new(
        args.sync_root_id,
        args.display_name,
        args.root_path,
        args.cluster_id,
        args.prefix.as_deref(),
    );
    register_sync_root(&registration).map(|_| ())
}
