#![cfg(not(windows))]

use crate::LinuxFuseAdapter;
use crate::runtime::{
    DemoHydrator, DemoUploader, FuseMountConfig, Hydrator, Uploader, mount_action_plan,
};
use anyhow::{Context, Result};
use clap::Parser;
use client_sdk::{IronMeshClient, normalize_server_base_url};
use std::fs;
use std::path::PathBuf;
use sync_core::{SyncPolicy, SyncSnapshot};

#[derive(Debug, Parser)]
#[command(name = "adapter-linux-fuse-mount")]
#[command(about = "Mount an Ironmesh FUSE view from a SyncSnapshot JSON or a live server-node")]
struct Args {
    #[arg(long)]
    snapshot_file: Option<PathBuf>,
    #[arg(long)]
    server_base_url: Option<String>,
    #[arg(long)]
    mountpoint: PathBuf,
    #[arg(long, default_value = "ironmesh")]
    fs_name: String,
    #[arg(long, default_value_t = false)]
    allow_other: bool,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64)]
    depth: usize,
}

pub fn mount_main() -> Result<()> {
    let args = Args::parse();

    let mode_count =
        usize::from(args.snapshot_file.is_some()) + usize::from(args.server_base_url.is_some());
    if mode_count != 1 {
        anyhow::bail!("exactly one of --snapshot-file or --server-base-url must be set");
    }

    let (snapshot, hydrator, uploader): (SyncSnapshot, Box<dyn Hydrator>, Box<dyn Uploader>) =
        if let Some(snapshot_file) = &args.snapshot_file {
            let json = fs::read_to_string(snapshot_file)
                .with_context(|| format!("failed to read {}", snapshot_file.display()))?;
            let snapshot: SyncSnapshot = serde_json::from_str(&json)
                .with_context(|| format!("failed to parse {}", snapshot_file.display()))?;
            (snapshot, Box::new(DemoHydrator), Box::new(DemoUploader))
        } else {
            let base_url =
                normalize_server_base_url(args.server_base_url.as_deref().unwrap_or_default())?;
            let sdk = IronMeshClient::new(base_url.as_str());
            let snapshot =
                sdk.load_snapshot_from_server_blocking(args.prefix.as_deref(), args.depth, None)?;

            let io = ServerNodeIo::new(base_url.as_str());
            (snapshot, Box::new(io.clone()), Box::new(io))
        };

    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let actions = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    let mut config = FuseMountConfig::new(args.mountpoint, args.fs_name);
    config.allow_other = args.allow_other;

    mount_action_plan(&config, actions, hydrator, uploader)
}

#[derive(Clone)]
struct ServerNodeIo {
    sdk: IronMeshClient,
}

impl ServerNodeIo {
    fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            sdk: IronMeshClient::new(server_base_url),
        }
    }
}

impl Hydrator for ServerNodeIo {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        self.sdk
            .get_with_selector_writer(path, None, None, &mut payload)
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        Ok(payload)
    }
}

impl Uploader for ServerNodeIo {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>> {
        self.sdk
            .put_large_aware_reader(path.to_string(), reader, length)
            .with_context(|| format!("failed to upload object for path {path}"))?;
        Ok(Some("server-head".to_string()))
    }
}
