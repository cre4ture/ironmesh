#![cfg(feature = "fuse-runtime")]

use adapter_linux_fuse::LinuxFuseAdapter;
use adapter_linux_fuse::runtime::{DemoHydrator, FuseMountConfig, mount_action_plan};
use anyhow::{Context, Result};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use sync_core::{SyncPolicy, SyncSnapshot};

#[derive(Debug, Parser)]
#[command(name = "adapter-linux-fuse-mount")]
#[command(about = "Mount a read-only Ironmesh FUSE view from a SyncSnapshot JSON")]
struct Args {
    #[arg(long)]
    snapshot_file: PathBuf,
    #[arg(long)]
    mountpoint: PathBuf,
    #[arg(long, default_value = "ironmesh")]
    fs_name: String,
    #[arg(long, default_value_t = false)]
    allow_other: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let json = fs::read_to_string(&args.snapshot_file)
        .with_context(|| format!("failed to read {}", args.snapshot_file.display()))?;
    let snapshot: SyncSnapshot = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse {}", args.snapshot_file.display()))?;

    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let actions = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    let mut config = FuseMountConfig::new(args.mountpoint, args.fs_name);
    config.allow_other = args.allow_other;

    mount_action_plan(&config, actions, Box::new(DemoHydrator))
}
