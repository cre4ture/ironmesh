#![cfg(feature = "fuse-runtime")]

use adapter_linux_fuse::LinuxFuseAdapter;
use adapter_linux_fuse::runtime::{FuseMountConfig, Hydrator, mount_action_plan};
use anyhow::{Context, Result};
use clap::Parser;
use reqwest::Url;
use reqwest::blocking::Client;
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use sync_core::{NamespaceEntry, SyncPolicy, SyncSnapshot};

#[derive(Debug, Parser)]
#[command(name = "adapter-linux-fuse-mount")]
#[command(
    about = "Mount a read-only Ironmesh FUSE view from a SyncSnapshot JSON or a live server-node"
)]
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
    depth: i32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mode_count =
        usize::from(args.snapshot_file.is_some()) + usize::from(args.server_base_url.is_some());
    if mode_count != 1 {
        anyhow::bail!("exactly one of --snapshot-file or --server-base-url must be set");
    }

    let client = Client::new();

    let (snapshot, hydrator): (SyncSnapshot, Box<dyn Hydrator>) =
        if let Some(snapshot_file) = &args.snapshot_file {
            let json = fs::read_to_string(snapshot_file)
                .with_context(|| format!("failed to read {}", snapshot_file.display()))?;
            let snapshot: SyncSnapshot = serde_json::from_str(&json)
                .with_context(|| format!("failed to parse {}", snapshot_file.display()))?;
            (snapshot, Box::new(DemoHydrator))
        } else {
            let base_url = normalize_base_url(args.server_base_url.as_deref().unwrap_or_default())?;
            let snapshot =
                load_snapshot_from_server(&client, &base_url, args.prefix.clone(), args.depth)?;
            (
                snapshot,
                Box::new(ServerNodeHydrator {
                    client: client.clone(),
                    base_url,
                }),
            )
        };

    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let actions = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    let mut config = FuseMountConfig::new(args.mountpoint, args.fs_name);
    config.allow_other = args.allow_other;

    mount_action_plan(&config, actions, hydrator)
}

#[derive(Debug, Default, Clone)]
struct DemoHydrator;

impl Hydrator for DemoHydrator {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>> {
        Ok(
            format!("ironmesh placeholder hydrated: path={path} version={remote_version}\n")
                .into_bytes(),
        )
    }
}

#[derive(Debug, Clone)]
struct ServerNodeHydrator {
    client: Client,
    base_url: Url,
}

impl Hydrator for ServerNodeHydrator {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        let object_url = build_store_object_url(&self.base_url, path)?;
        let response = self
            .client
            .get(object_url)
            .send()
            .with_context(|| format!("failed to fetch object for path {path}"))?
            .error_for_status()
            .with_context(|| format!("server returned error for path {path}"))?;

        let bytes = response.bytes().context("failed reading object bytes")?;
        Ok(bytes.to_vec())
    }
}

#[derive(Debug, Deserialize)]
struct StoreIndexResponse {
    entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct StoreIndexEntry {
    path: String,
    entry_type: String,
}

fn normalize_base_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let url = if with_scheme.ends_with('/') {
        with_scheme
    } else {
        format!("{with_scheme}/")
    };
    Url::parse(&url).with_context(|| format!("invalid server base url: {input}"))
}

fn load_snapshot_from_server(
    client: &Client,
    base_url: &Url,
    prefix: Option<String>,
    depth: i32,
) -> Result<SyncSnapshot> {
    let endpoint = base_url
        .join("store/index")
        .context("failed to compose store/index url")?;

    let response = client
        .get(endpoint)
        .query(&[("depth", depth.to_string())])
        .query(&[("prefix", prefix.unwrap_or_default())])
        .send()
        .context("failed calling /store/index")?
        .error_for_status()
        .context("/store/index returned non-success status")?;

    let payload: StoreIndexResponse = response
        .json()
        .context("failed parsing /store/index response")?;

    let mut remote = Vec::with_capacity(payload.entries.len());
    for entry in payload.entries {
        if entry.entry_type == "prefix" {
            let directory_path = entry.path.trim_end_matches('/').to_string();
            if !directory_path.is_empty() {
                remote.push(NamespaceEntry::directory(directory_path));
            }
        } else {
            remote.push(NamespaceEntry::file(
                entry.path.clone(),
                "server-head",
                format!("server-head:{}", entry.path),
            ));
        }
    }

    Ok(SyncSnapshot {
        local: Vec::new(),
        remote,
    })
}

fn build_store_object_url(base_url: &Url, key: &str) -> Result<Url> {
    let mut url = base_url
        .join("store/")
        .context("failed to compose object base url")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("base url cannot be used for path segments"))?;
        for segment in key.split('/').filter(|segment| !segment.is_empty()) {
            segments.push(segment);
        }
    }
    Ok(url)
}
