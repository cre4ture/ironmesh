#![cfg(not(windows))]

use crate::runtime::{
    DemoHydrator, DemoUploader, FuseMountConfig, Hydrator, Uploader,
    mount_action_plan_until_shutdown, mount_action_plan_until_shutdown_with_updates,
};
use crate::{FuseAction, FuseActionPlan, LinuxFuseAdapter};
use anyhow::{Context, Result};
use clap::Parser;
use client_sdk::{
    ClientIdentityMaterial, ConnectionBootstrap, IronMeshClient, RemoteSnapshotFetcher,
    RemoteSnapshotPoller, RemoteSnapshotScope, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use client_sdk::ironmesh_client::{DownloadProgress, DownloadRangeRequest};
use server_node_sdk::LocalNodeHandle;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use sync_core::{SyncPolicy, SyncSnapshot};

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
#[command(name = "adapter-linux-fuse-mount")]
#[command(about = "Mount an Ironmesh FUSE view from a SyncSnapshot JSON or a live server-node")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Args {
    #[arg(long)]
    snapshot_file: Option<PathBuf>,
    #[arg(long)]
    server_base_url: Option<String>,
    #[arg(long)]
    bootstrap_file: Option<PathBuf>,
    #[arg(long)]
    server_ca_pem_file: Option<PathBuf>,
    #[arg(long)]
    client_identity_file: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = false,
        help = "Spawn a persistent local edge node and mount against it"
    )]
    local_edge: bool,
    #[arg(long)]
    local_edge_data_dir: Option<PathBuf>,
    #[arg(long, hide = true)]
    local_edge_base_url_file: Option<PathBuf>,
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

struct ResolvedUpstreamTarget {
    client: IronMeshClient,
}

pub fn mount_main() -> Result<()> {
    common::logging::init_compact_tracing_default("info");
    let args = Args::parse();
    let client_identity = read_optional_client_identity(args.client_identity_file.as_deref())?;

    let effective_local_edge_data_dir = effective_local_edge_data_dir(&args)?;
    let upstream_target = resolve_upstream_target(&args, client_identity.as_ref())?;

    if args.snapshot_file.is_some() {
        if args.server_base_url.is_some()
            || args.bootstrap_file.is_some()
            || args.local_edge_data_dir.is_some()
            || args.local_edge
        {
            anyhow::bail!(
                "--snapshot-file cannot be combined with --server-base-url, --bootstrap-file, --local-edge, or --local-edge-data-dir"
            );
        }
    } else if upstream_target.is_none() && effective_local_edge_data_dir.is_none() {
        anyhow::bail!(
            "set either --snapshot-file, --server-base-url, --bootstrap-file, --local-edge, or --local-edge-data-dir"
        );
    }

    if effective_local_edge_data_dir.is_some() && upstream_target.is_some() {
        anyhow::bail!(
            "--local-edge no longer supports direct upstream wiring; mount the remote target directly or provision a local edge node separately via node bootstrap/enrollment"
        );
    }

    if args.local_edge_base_url_file.is_some() && effective_local_edge_data_dir.is_none() {
        anyhow::bail!("--local-edge-base-url-file requires --local-edge or --local-edge-data-dir");
    }

    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let download_stage_root = download_stage_root(&args)?;
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

    let local_node = if let Some(data_dir) = effective_local_edge_data_dir.as_ref() {
        Some(
            LocalNodeHandle::start_local_edge(data_dir).with_context(|| {
                format!("failed to start local edge node in {}", data_dir.display())
            })?,
        )
    } else {
        None
    };

    let local_edge_base_url = local_node
        .as_ref()
        .map(|local_node| normalize_server_base_url(local_node.base_url()))
        .transpose()?;
    if let (Some(local_node), Some(output_path)) =
        (local_node.as_ref(), args.local_edge_base_url_file.as_ref())
    {
        fs::write(output_path, local_node.base_url()).with_context(|| {
            format!(
                "failed to write local edge base URL to {}",
                output_path.display()
            )
        })?;
    }
    let client = if local_node.is_none() {
        upstream_target
            .as_ref()
            .map(|target| target.client.clone())
            .ok_or_else(|| anyhow::anyhow!("missing upstream target for live mount"))?
    } else {
        build_configured_client(
            local_edge_base_url
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing local edge base URL"))?
                .as_str(),
            None,
            client_identity.as_ref(),
        )?
    };
    let initial_fetcher = RemoteSnapshotFetcher::new(
        client.clone(),
        RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
    );
    let snapshot = initial_fetcher.fetch_snapshot_blocking()?;
    let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());

    let refresh_enabled = upstream_target.is_some();
    let (refresh_rx, refresh_thread, refresh_running) = if refresh_enabled {
        let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
        let wait_timeout = Duration::from_secs(2).max(refresh_interval);
        let refresh_poller =
            RemoteSnapshotPoller::server_notifications(wait_timeout, refresh_interval);
        let refresh_fetcher = RemoteSnapshotFetcher::new(
            client.clone(),
            RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
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
                let full_plan =
                    refresh_adapter.plan_actions(&update.snapshot, &SyncPolicy::default());
                let plan = filter_refresh_action_plan(full_plan, &update.changed_paths);
                if plan.actions.is_empty() {
                    tracing::info!(
                        "remote-refresh: detected {} changed remote paths; no local plan delta",
                        update.changed_paths.len()
                    );
                    return;
                }

                if refresh_tx.send(plan).is_err() {
                    refresh_stop_signal.store(false, Ordering::SeqCst);
                    return;
                }
                tracing::info!(
                    "remote-refresh: reconciled {} changed paths",
                    update.changed_paths.len()
                );
            },
        );
        (
            Some(refresh_rx),
            Some(refresh_thread),
            Some(refresh_running),
        )
    } else {
        (None, None, None)
    };

    let io = ServerNodeIo::with_client(client, download_stage_root);
    let result = mount_action_plan_until_shutdown_with_updates(
        &config,
        action_plan,
        Box::new(io.clone()),
        Box::new(io),
        refresh_rx,
    );

    if let Some(refresh_running) = refresh_running {
        refresh_running.store(false, Ordering::SeqCst);
    }
    if let Some(refresh_thread) = refresh_thread {
        let _ = refresh_thread.join();
    }
    drop(local_node);

    result
}

fn effective_local_edge_data_dir(args: &Args) -> Result<Option<PathBuf>> {
    if let Some(path) = args.local_edge_data_dir.clone() {
        return Ok(Some(path));
    }

    if !args.local_edge {
        return Ok(None);
    }

    default_local_edge_data_dir(args)
}

fn default_local_edge_data_dir(args: &Args) -> Result<Option<PathBuf>> {
    let state_home = xdg_state_home().unwrap_or_else(std::env::temp_dir);
    let mut path = state_home
        .join("ironmesh")
        .join("os-integration")
        .join("local-edge");
    let scope = local_edge_scope_label(args);
    if scope.is_empty() {
        anyhow::bail!("failed to derive local-edge storage scope");
    }
    path.push(scope);
    Ok(Some(path))
}

fn xdg_state_home() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }

    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(".local").join("state"))
}

fn local_edge_scope_label(args: &Args) -> String {
    let mountpoint = args.mountpoint.to_string_lossy().to_string();
    let mut parts: Vec<String> = Vec::new();
    if let Some(base_url) = args.server_base_url.as_deref() {
        parts.push(base_url.to_string());
    } else if let Some(bootstrap_file) = args.bootstrap_file.as_ref() {
        parts.push(bootstrap_file.to_string_lossy().into_owned());
    }
    if let Some(prefix) = args.prefix.as_deref() {
        parts.push(prefix.to_string());
    }
    parts.push(mountpoint);

    sanitize_path_component(&parts.join("__"))
}

fn download_stage_root(args: &Args) -> Result<PathBuf> {
    let state_home = xdg_state_home().unwrap_or_else(std::env::temp_dir);
    let path = state_home
        .join("ironmesh")
        .join("os-integration")
        .join("downloads")
        .join(download_scope_label(args));
    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create download stage root {}", path.display()))?;
    Ok(path)
}

fn download_scope_label(args: &Args) -> String {
    let mut hasher = blake3::Hasher::new();
    if let Some(base_url) = args.server_base_url.as_deref() {
        hasher.update(base_url.as_bytes());
    }
    hasher.update(&[0]);
    if let Some(bootstrap_file) = args.bootstrap_file.as_ref() {
        hasher.update(bootstrap_file.to_string_lossy().as_bytes());
    }
    hasher.update(&[0]);
    if let Some(prefix) = args.prefix.as_deref() {
        hasher.update(prefix.as_bytes());
    }
    hasher.update(&[0]);
    hasher.update(args.mountpoint.to_string_lossy().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn resolve_upstream_target(
    args: &Args,
    client_identity: Option<&ClientIdentityMaterial>,
) -> Result<Option<ResolvedUpstreamTarget>> {
    if args.server_base_url.is_some() && args.bootstrap_file.is_some() {
        anyhow::bail!("use either --server-base-url or --bootstrap-file, not both");
    }

    let server_ca_override = read_optional_utf8_file(args.server_ca_pem_file.as_deref())?;
    if let Some(bootstrap_path) = args.bootstrap_file.as_deref() {
        let mut bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
        if let Some(server_ca_override) = server_ca_override.as_ref() {
            bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_override.clone());
        }
        let client = bootstrap.build_client_with_optional_identity(client_identity)?;
        return Ok(Some(ResolvedUpstreamTarget { client }));
    }

    let Some(server_base_url) = args.server_base_url.as_deref() else {
        return Ok(None);
    };
    let base_url = normalize_server_base_url(server_base_url)?;
    let client = build_configured_client(
        base_url.as_str(),
        server_ca_override.as_deref(),
        client_identity,
    )?;
    Ok(Some(ResolvedUpstreamTarget { client }))
}

fn sanitize_path_component(raw: &str) -> String {
    let sanitized = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    sanitized
        .trim_matches('_')
        .chars()
        .take(120)
        .collect::<String>()
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
    let mut actions = Vec::new();

    for action in plan.actions {
        let (path, keeps_remote_presence) = match &action {
            FuseAction::EnsureDirectory { path }
            | FuseAction::EnsurePlaceholder { path, .. }
            | FuseAction::HydrateOnRead { path, .. }
            | FuseAction::MarkConflict { path, .. }
            | FuseAction::RemovePath { path } => (path, true),
            FuseAction::UploadOnFlush { path, .. } => {
                // Remote refresh is authoritative for missing remote paths. A local-only upload
                // action here means the path disappeared remotely, so it must not suppress the
                // synthetic RemovePath we emit below.
                (path, false)
            }
        };

        if keeps_remote_presence {
            planned_paths.insert(path.clone());
        }

        if changed.contains(path.as_str()) && keeps_remote_presence {
            actions.push(action);
        }
    }

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
    download_stage_root: PathBuf,
}

impl ServerNodeIo {
    fn with_client(sdk: IronMeshClient, download_stage_root: PathBuf) -> Self {
        Self {
            sdk,
            download_stage_root,
        }
    }
}

impl Hydrator for ServerNodeIo {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        self.sdk
            .download_to_writer_resumable_staged(
                path,
                None,
                None,
                &mut payload,
                &self.download_stage_root,
            )
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        Ok(payload)
    }

    fn hydrate_range(
        &self,
        path: &str,
        _remote_version: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let mut payload = Vec::new();
        let mut on_progress = |_progress: DownloadProgress| {};
        let should_cancel = || false;
        self.sdk
            .download_range_to_writer_with_progress_blocking(
                DownloadRangeRequest {
                    key: path,
                    snapshot: None,
                    version: None,
                    start: offset,
                    length,
                },
                &mut payload,
                &mut on_progress,
                &should_cancel,
            )
            .with_context(|| format!("failed to fetch ranged object for path {path}"))?;
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

fn build_configured_client(
    server_base_url: &str,
    server_ca_pem: Option<&str>,
    client_identity: Option<&ClientIdentityMaterial>,
) -> Result<IronMeshClient> {
    match client_identity {
        Some(identity) => {
            build_http_client_with_identity_from_pem(server_ca_pem, server_base_url, identity)
        }
        None => build_http_client_from_pem(server_ca_pem, server_base_url),
    }
}

fn read_optional_utf8_file(path: Option<&std::path::Path>) -> Result<Option<String>> {
    path.map(|path| {
        std::fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context(format!("failed to read UTF-8 file {}", path.display())))
    })
    .transpose()
    .map(|value| value.filter(|value| !value.is_empty()))
}

fn read_optional_client_identity(
    path: Option<&std::path::Path>,
) -> Result<Option<ClientIdentityMaterial>> {
    path.map(ClientIdentityMaterial::from_path).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_args() -> Args {
        Args {
            snapshot_file: None,
            server_base_url: Some("http://127.0.0.1:8080".to_string()),
            bootstrap_file: None,
            server_ca_pem_file: None,
            client_identity_file: None,
            local_edge: false,
            local_edge_data_dir: None,
            local_edge_base_url_file: None,
            mountpoint: PathBuf::from("/tmp/mount"),
            fs_name: "ironmesh".to_string(),
            allow_other: false,
            prefix: None,
            depth: 64,
            remote_refresh_interval_ms: 3000,
        }
    }

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
                    remote_size: Some(12),
                },
                FuseAction::EnsurePlaceholder {
                    path: "notes/todo.txt".to_string(),
                    remote_version: "v3".to_string(),
                    remote_size: Some(8),
                },
            ],
        };

        let filtered = filter_refresh_action_plan(plan, &["docs/new.txt".to_string()]);

        assert_eq!(
            filtered.actions,
            vec![FuseAction::EnsurePlaceholder {
                path: "docs/new.txt".to_string(),
                remote_version: "v1".to_string(),
                remote_size: Some(12),
            }],
        );
    }

    #[test]
    fn filter_refresh_action_plan_marks_deleted_paths_for_removal() {
        let plan = FuseActionPlan {
            actions: vec![FuseAction::EnsurePlaceholder {
                path: "docs/new.txt".to_string(),
                remote_version: "v2".to_string(),
                remote_size: Some(14),
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
                    remote_size: Some(14),
                },
                FuseAction::RemovePath {
                    path: "docs/old.txt".to_string(),
                },
            ],
        );
    }

    #[test]
    fn filter_refresh_action_plan_treats_upload_only_paths_as_removed() {
        let plan = FuseActionPlan {
            actions: vec![
                FuseAction::UploadOnFlush {
                    path: "docs/old.txt".to_string(),
                    local_version: Some("v1".to_string()),
                },
                FuseAction::EnsureDirectory {
                    path: "docs/sub".to_string(),
                },
                FuseAction::EnsurePlaceholder {
                    path: "docs/sub/new.txt".to_string(),
                    remote_version: "v2".to_string(),
                    remote_size: Some(14),
                },
            ],
        };

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/old.txt".to_string(), "docs/sub/new.txt".to_string()],
        );

        assert_eq!(
            filtered.actions,
            vec![
                FuseAction::EnsurePlaceholder {
                    path: "docs/sub/new.txt".to_string(),
                    remote_version: "v2".to_string(),
                    remote_size: Some(14),
                },
                FuseAction::RemovePath {
                    path: "docs/old.txt".to_string(),
                },
            ],
        );
    }

    #[test]
    fn effective_local_edge_data_dir_is_none_without_edge_flags() {
        let args = sample_args();
        assert_eq!(effective_local_edge_data_dir(&args).unwrap(), None);
    }

    #[test]
    fn effective_local_edge_data_dir_derives_persistent_default_for_local_edge_mode() {
        let mut args = sample_args();
        args.local_edge = true;
        args.prefix = Some("photos/2026".to_string());

        let derived = effective_local_edge_data_dir(&args)
            .unwrap()
            .expect("local-edge path should be derived");

        assert!(derived.ends_with("http___127.0.0.1_8080__photos_2026___tmp_mount"));
    }
}
