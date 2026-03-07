#![cfg(not(windows))]

use crate::runtime::{
    DemoHydrator, DemoUploader, FuseMountConfig, Hydrator, Uploader,
    mount_action_plan_until_shutdown, mount_action_plan_until_shutdown_with_updates,
};
use crate::{FuseAction, FuseActionPlan, LinuxFuseAdapter};
use anyhow::{Context, Result};
use clap::Parser;
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, normalize_server_base_url,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
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
    #[arg(long, default_value_t = 3000)]
    remote_refresh_interval_ms: u64,
}

pub fn mount_main() -> Result<()> {
    let args = Args::parse();

    let mode_count =
        usize::from(args.snapshot_file.is_some()) + usize::from(args.server_base_url.is_some());
    if mode_count != 1 {
        anyhow::bail!("exactly one of --snapshot-file or --server-base-url must be set");
    }

    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let mut config = FuseMountConfig::new(args.mountpoint, args.fs_name);
    config.allow_other = args.allow_other;

    if let Some(snapshot_file) = &args.snapshot_file {
        let json = fs::read_to_string(snapshot_file)
            .with_context(|| format!("failed to read {}", snapshot_file.display()))?;
        let snapshot: SyncSnapshot = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse {}", snapshot_file.display()))?;
        let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());
        return mount_action_plan_until_shutdown(
            &config,
            action_plan,
            Box::new(DemoHydrator),
            Box::new(DemoUploader),
        );
    }

    let base_url = normalize_server_base_url(args.server_base_url.as_deref().unwrap_or_default())?;
    let initial_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        args.prefix.clone(),
        args.depth,
        None,
    );
    let snapshot = initial_fetcher.fetch_snapshot_blocking()?;
    let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        args.prefix.clone(),
        args.depth,
        None,
    );
    let refresh_adapter = adapter.clone();
    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel();
    let refresh_running = Arc::new(AtomicBool::new(true));
    let refresh_stop_signal = refresh_running.clone();
    let refresh_thread = refresh_poller.spawn_fetcher_loop(
        refresh_running.clone(),
        Some(snapshot),
        refresh_fetcher,
        move |update| {
            let full_plan = refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
            let plan = filter_refresh_action_plan(full_plan, &update.changed_paths);
            if plan.actions.is_empty() {
                eprintln!(
                    "remote-refresh: detected {} changed remote paths; no local plan delta",
                    update.changed_paths.len()
                );
                return;
            }

            if refresh_tx.send(plan).is_err() {
                refresh_stop_signal.store(false, Ordering::SeqCst);
                return;
            }
            eprintln!(
                "remote-refresh: reconciled {} changed paths",
                update.changed_paths.len()
            );
        },
    );

    let io = ServerNodeIo::new(base_url.as_str());
    let result = mount_action_plan_until_shutdown_with_updates(
        &config,
        action_plan,
        Box::new(io.clone()),
        Box::new(io),
        Some(refresh_rx),
    );

    refresh_running.store(false, Ordering::SeqCst);
    let _ = refresh_thread.join();

    result
}

fn filter_refresh_action_plan(plan: FuseActionPlan, changed_paths: &[String]) -> FuseActionPlan {
    if changed_paths.is_empty() {
        return FuseActionPlan::default();
    }

    let mut changed = std::collections::HashSet::new();
    for path in changed_paths {
        changed.insert(path.as_str());
    }

    let mut planned_paths = std::collections::HashSet::new();
    let mut actions: Vec<FuseAction> = plan
        .actions
        .into_iter()
        .filter(|action| {
            let path = match action {
                FuseAction::EnsureDirectory { path }
                | FuseAction::EnsurePlaceholder { path, .. }
                | FuseAction::HydrateOnRead { path, .. }
                | FuseAction::UploadOnFlush { path, .. }
                | FuseAction::MarkConflict { path, .. }
                | FuseAction::RemovePath { path } => path,
            };
            planned_paths.insert(path.clone());
            changed.contains(path.as_str())
        })
        .collect();

    for path in changed_paths {
        if planned_paths.contains(path) {
            continue;
        }
        actions.push(FuseAction::RemovePath { path: path.clone() });
    }

    FuseActionPlan { actions }
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

    fn rename_path(&self, from_path: &str, to_path: &str, overwrite: bool) -> Result<()> {
        self.sdk
            .rename_path_blocking(from_path.to_string(), to_path.to_string(), overwrite)
            .with_context(|| format!("failed to rename object {from_path} -> {to_path}"))
    }

    fn delete_path(&self, path: &str) -> Result<()> {
        self.sdk
            .delete_path_blocking(path)
            .with_context(|| format!("failed to delete object {path}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_refresh_action_plan_keeps_only_changed_paths() {
        let plan = FuseActionPlan {
            actions: vec![
                FuseAction::EnsureDirectory {
                    path: "docs".to_string(),
                },
                FuseAction::EnsurePlaceholder {
                    path: "docs/new.txt".to_string(),
                    remote_version: "v1".to_string(),
                },
                FuseAction::EnsurePlaceholder {
                    path: "notes/todo.txt".to_string(),
                    remote_version: "v3".to_string(),
                },
            ],
        };

        let filtered = filter_refresh_action_plan(plan, &["docs/new.txt".to_string()]);

        assert_eq!(
            filtered.actions,
            vec![FuseAction::EnsurePlaceholder {
                path: "docs/new.txt".to_string(),
                remote_version: "v1".to_string(),
            }],
        );
    }

    #[test]
    fn filter_refresh_action_plan_marks_deleted_paths_for_removal() {
        let plan = FuseActionPlan {
            actions: vec![FuseAction::EnsurePlaceholder {
                path: "docs/new.txt".to_string(),
                remote_version: "v2".to_string(),
            }],
        };

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/new.txt".to_string(), "docs/old.txt".to_string()],
        );

        assert_eq!(
            filtered.actions,
            vec![
                FuseAction::EnsurePlaceholder {
                    path: "docs/new.txt".to_string(),
                    remote_version: "v2".to_string(),
                },
                FuseAction::RemovePath {
                    path: "docs/old.txt".to_string(),
                },
            ],
        );
    }
}
