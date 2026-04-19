#![cfg(not(windows))]

use crate::client_rights_edge::{
    ClientRightsEdgeState, OfflineObjectCacheMode, RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES,
};
use crate::gnome::{
    GNOME_EXTENSION_UUID, GnomeStatusOptions, GnomeStatusRuntime,
    default_remote_status_poll_interval_ms, default_status_file_path, failed_mount_sync_facet,
    install_extension, mounted_sync_facet, snapshot_connection_facet, snapshot_replication_facet,
    starting_mount_sync_facet, stopped_mount_sync_facet,
};
use crate::runtime::{
    DemoHydrator, DemoUploader, FuseMountConfig, Hydrator, IronmeshFuseFs, Uploader,
    mount_action_plan_until_shutdown, mount_fs_until_shutdown,
};
use crate::{FuseAction, FuseActionPlan, LinuxFuseAdapter};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use client_sdk::ironmesh_client::{DownloadProgress, DownloadRangeRequest};
use client_sdk::{
    ClientIdentityMaterial, ConnectionBootstrap, IronMeshClient, RemoteSnapshotFetcher,
    RemoteSnapshotPoller, RemoteSnapshotScope, RequestedRange, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
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
#[command(name = "ironmesh-os-integration")]
#[command(about = "Mount an Ironmesh FUSE view from a SyncSnapshot JSON or a live server-node")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
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
    #[arg(long)]
    client_edge_state_dir: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = CliOfflineObjectCacheMode::On)]
    offline_object_cache: CliOfflineObjectCacheMode,
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
    #[arg(long, default_value_t = false, global = true)]
    publish_gnome_status: bool,
    #[arg(long, global = true)]
    gnome_status_file: Option<PathBuf>,
    #[arg(
        long,
        default_value_t = default_remote_status_poll_interval_ms(),
        global = true
    )]
    remote_status_poll_interval_ms: u64,
}

struct ResolvedUpstreamTarget {
    client: IronMeshClient,
    connection_target: String,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install or inspect the native GNOME Shell indicator integration.
    Gnome {
        #[command(subcommand)]
        command: GnomeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GnomeCommand {
    /// Copy the GNOME Shell extension into ~/.local/share/gnome-shell/extensions and try to enable it.
    InstallExtension,
    /// Print the JSON path consumed by the GNOME Shell extension.
    PrintStatusPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CliOfflineObjectCacheMode {
    On,
    Off,
}

impl From<CliOfflineObjectCacheMode> for OfflineObjectCacheMode {
    fn from(value: CliOfflineObjectCacheMode) -> Self {
        match value {
            CliOfflineObjectCacheMode::On => OfflineObjectCacheMode::On,
            CliOfflineObjectCacheMode::Off => OfflineObjectCacheMode::Off,
        }
    }
}

pub fn mount_main() -> Result<()> {
    common::logging::init_compact_tracing_default("info");
    let args = Args::parse();
    if let Some(command) = args.command.as_ref() {
        return run_command(&args, command);
    }

    run_mount(&args)
}

fn run_command(args: &Args, command: &Command) -> Result<()> {
    match command {
        Command::Gnome { command } => run_gnome_command(args, command),
    }
}

fn run_gnome_command(args: &Args, command: &GnomeCommand) -> Result<()> {
    match command {
        GnomeCommand::InstallExtension => {
            let outcome = install_extension(true)?;
            println!(
                "gnome: installed extension {} to {}",
                GNOME_EXTENSION_UUID,
                outcome.install_dir.display()
            );
            if let Some(note) = outcome.enable_note {
                println!("gnome: {note}");
            }
            Ok(())
        }
        GnomeCommand::PrintStatusPath => {
            let path = match args.gnome_status_file.as_ref() {
                Some(path) => path.clone(),
                None => default_status_file_path()?,
            };
            println!("{}", path.display());
            Ok(())
        }
    }
}

fn run_mount(args: &Args) -> Result<()> {
    let client_identity = resolve_client_identity(args)?;
    let upstream_target = resolve_upstream_target(args, client_identity.as_ref())?;

    if args.snapshot_file.is_some() {
        if args.server_base_url.is_some() || args.bootstrap_file.is_some() {
            anyhow::bail!(
                "--snapshot-file cannot be combined with --server-base-url or --bootstrap-file"
            );
        }
    } else if upstream_target.is_none() {
        anyhow::bail!("set either --snapshot-file, --server-base-url, or --bootstrap-file");
    }

    let connection_target = upstream_target
        .as_ref()
        .map(|target| target.connection_target.clone())
        .unwrap_or_else(|| snapshot_connection_target_label(args));
    let gnome_status = if args.publish_gnome_status {
        Some(start_gnome_status(
            args,
            connection_target,
            upstream_target.as_ref().map(|target| target.client.clone()),
        )?)
    } else {
        None
    };

    if let Some(status) = gnome_status.as_ref() {
        update_gnome_sync(status, starting_mount_sync_facet(&args.mountpoint));
        if let Some(snapshot_file) = args.snapshot_file.as_ref() {
            update_gnome_connection(status, snapshot_connection_facet(snapshot_file));
            update_gnome_replication(status, snapshot_replication_facet());
        }
    }

    let result = run_mount_inner(
        args,
        upstream_target,
        client_identity.is_some(),
        gnome_status.as_ref(),
    );

    if let Some(status) = gnome_status {
        if let Err(error) = &result {
            update_gnome_sync(&status, failed_mount_sync_facet(&args.mountpoint, error));
        } else {
            update_gnome_sync(&status, stopped_mount_sync_facet(&args.mountpoint));
        }
        status.shutdown();
    }

    result
}

fn run_mount_inner(
    args: &Args,
    upstream_target: Option<ResolvedUpstreamTarget>,
    has_client_identity: bool,
    gnome_status: Option<&GnomeStatusRuntime>,
) -> Result<()> {
    let adapter = LinuxFuseAdapter::new(args.fs_name.clone());
    let download_stage_root = download_stage_root(args)?;
    let mut config = FuseMountConfig::new(args.mountpoint.clone(), args.fs_name.clone());
    config.allow_other = args.allow_other;

    if let Some(snapshot_file) = &args.snapshot_file {
        let json = fs::read_to_string(snapshot_file)
            .with_context(|| format!("failed to read {}", snapshot_file.display()))?;
        let snapshot: SyncSnapshot = serde_json::from_str(&json)
            .with_context(|| format!("failed to parse {}", snapshot_file.display()))?;
        let action_plan = adapter.plan_actions(&snapshot, &SyncPolicy::default());
        if let Some(status) = gnome_status {
            update_gnome_sync(status, mounted_sync_facet(&args.mountpoint));
        }
        return mount_action_plan_until_shutdown(
            &config,
            action_plan,
            Box::new(DemoHydrator),
            Box::new(DemoUploader),
        );
    }

    let client = upstream_target
        .as_ref()
        .map(|target| target.client.clone())
        .ok_or_else(|| anyhow::anyhow!("missing upstream target for live mount"))?;
    let client_edge_state_dir = effective_client_edge_state_dir(args)?;
    let client_edge_state = Arc::new(ClientRightsEdgeState::new(
        client_edge_state_dir,
        args.offline_object_cache.into(),
    )?);
    let initial_fetcher = RemoteSnapshotFetcher::new(
        client.clone(),
        RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
    );
    let remote_snapshot = match initial_fetcher.fetch_snapshot_blocking() {
        Ok(snapshot) => {
            client_edge_state.persist_snapshot(&snapshot)?;
            snapshot
        }
        Err(error) => {
            if is_unauthorized_store_index_error(&error) {
                let auth_hint = live_mount_auth_hint(args, has_client_identity);
                return Err(error).context(format!(
                    "initial remote snapshot fetch was unauthorized; {auth_hint}"
                ));
            }
            if let Some(snapshot) = client_edge_state.load_cached_snapshot()? {
                tracing::warn!(
                    "client-rights-edge: failed to fetch initial snapshot; using cached snapshot: {error}"
                );
                snapshot
            } else {
                tracing::warn!(
                    "client-rights-edge: failed to fetch initial snapshot and no cache exists; starting from empty namespace: {error}"
                );
                SyncSnapshot::default()
            }
        }
    };
    let planning_snapshot = client_edge_state.planning_snapshot(&remote_snapshot)?;
    let action_plan = adapter.plan_actions(&planning_snapshot, &SyncPolicy::default());
    let replay_actions = client_edge_state.replay_actions()?;

    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let wait_timeout = Duration::from_secs(2).max(refresh_interval);
    let refresh_poller = RemoteSnapshotPoller::server_notifications(wait_timeout, refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::new(
        client.clone(),
        RemoteSnapshotScope::new(args.prefix.clone(), args.depth, None),
    );
    let refresh_adapter = adapter.clone();
    let refresh_state = Arc::clone(&client_edge_state);
    let (refresh_tx, refresh_rx) = std::sync::mpsc::channel();
    let refresh_running = Arc::new(AtomicBool::new(true));
    let refresh_stop_signal = refresh_running.clone();
    let refresh_thread = refresh_poller.spawn_fetcher_loop(
        refresh_running.clone(),
        Some(remote_snapshot.clone()),
        refresh_fetcher,
        move |update| {
            if let Err(error) = refresh_state.persist_snapshot(&update.snapshot) {
                tracing::warn!("client-rights-edge: failed to persist refreshed snapshot: {error}");
            }

            let planning_snapshot = match refresh_state.planning_snapshot(&update.snapshot) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    tracing::warn!(
                        "client-rights-edge: failed to build refresh planning snapshot: {error}"
                    );
                    return;
                }
            };
            let full_plan =
                refresh_adapter.plan_actions(&planning_snapshot, &SyncPolicy::default());
            let overlay_paths = match refresh_state.overlay_file_paths() {
                Ok(paths) => paths,
                Err(error) => {
                    tracing::warn!(
                        "client-rights-edge: failed to inspect overlay file paths during refresh: {error}"
                    );
                    std::collections::BTreeSet::new()
                }
            };
            let plan = filter_refresh_action_plan(full_plan, &update.changed_paths, &overlay_paths);
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
    let sync_thread = client_edge_state.spawn_sync_loop(
        refresh_running.clone(),
        client.clone(),
        refresh_interval,
    );

    let io = ClientRightsEdgeIo::with_client(
        client,
        download_stage_root,
        Arc::clone(&client_edge_state),
    );
    let mut fs = IronmeshFuseFs::from_action_plan(
        &action_plan,
        Box::new(io.clone()),
        Box::new(io),
        Some(refresh_rx),
    );
    fs.apply_replay_actions(&replay_actions)?;
    if let Some(status) = gnome_status {
        update_gnome_sync(status, mounted_sync_facet(&args.mountpoint));
    }
    let result = mount_fs_until_shutdown(&config, fs);

    refresh_running.store(false, Ordering::SeqCst);
    let _ = refresh_thread.join();
    let _ = sync_thread.join();

    result
}

fn start_gnome_status(
    args: &Args,
    connection_target: String,
    client: Option<IronMeshClient>,
) -> Result<GnomeStatusRuntime> {
    let status_file = match args.gnome_status_file.as_ref() {
        Some(path) => path.clone(),
        None => default_status_file_path()?,
    };
    GnomeStatusRuntime::start(
        &GnomeStatusOptions {
            profile_label: crate::gnome::derive_profile_label(
                args.prefix.as_deref(),
                &args.mountpoint,
            ),
            root_dir: args.mountpoint.clone(),
            connection_target,
            status_file,
            remote_status_poll_interval_ms: args.remote_status_poll_interval_ms,
        },
        client,
    )
}

fn snapshot_connection_target_label(args: &Args) -> String {
    args.snapshot_file
        .as_ref()
        .map(|path| format!("snapshot:{}", path.display()))
        .unwrap_or_else(|| "snapshot".to_string())
}

fn update_gnome_connection(status: &GnomeStatusRuntime, facet: desktop_status::StatusFacet) {
    if let Err(error) = status.update_connection(facet) {
        tracing::warn!("gnome-status: failed to persist Linux FUSE connection status: {error:#}");
    }
}

fn update_gnome_sync(status: &GnomeStatusRuntime, facet: desktop_status::StatusFacet) {
    if let Err(error) = status.update_sync(facet) {
        tracing::warn!("gnome-status: failed to persist Linux FUSE sync status: {error:#}");
    }
}

fn update_gnome_replication(status: &GnomeStatusRuntime, facet: desktop_status::StatusFacet) {
    if let Err(error) = status.update_replication(facet) {
        tracing::warn!("gnome-status: failed to persist Linux FUSE replication status: {error:#}");
    }
}

fn effective_client_edge_state_dir(args: &Args) -> Result<PathBuf> {
    if let Some(path) = args.client_edge_state_dir.clone() {
        return Ok(path);
    }

    default_client_edge_state_dir(args)
}

fn default_client_edge_state_dir(args: &Args) -> Result<PathBuf> {
    let state_home = xdg_state_home().unwrap_or_else(std::env::temp_dir);
    let mut path = state_home
        .join("ironmesh")
        .join("os-integration")
        .join("client-rights-edge");
    let scope = client_edge_scope_label(args);
    if scope.is_empty() {
        anyhow::bail!("failed to derive client-rights edge storage scope");
    }
    path.push(scope);
    Ok(path)
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

fn client_edge_scope_label(args: &Args) -> String {
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
        let connection_target = bootstrap.connection_target_label()?;
        return Ok(Some(ResolvedUpstreamTarget {
            client,
            connection_target,
        }));
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
    Ok(Some(ResolvedUpstreamTarget {
        client,
        connection_target: base_url.to_string(),
    }))
}

fn default_client_identity_path(bootstrap_path: &std::path::Path) -> PathBuf {
    if let Some(stem) = bootstrap_path.file_stem() {
        let mut file_name = stem.to_os_string();
        file_name.push(".client-identity.json");
        return bootstrap_path.with_file_name(file_name);
    }
    bootstrap_path.with_file_name("ironmesh-client-identity.json")
}

fn resolve_client_identity(args: &Args) -> Result<Option<ClientIdentityMaterial>> {
    if let Some(path) = args.client_identity_file.as_deref() {
        return Ok(Some(ClientIdentityMaterial::from_path(path)?));
    }

    let Some(bootstrap_path) = args.bootstrap_file.as_deref() else {
        return Ok(None);
    };

    let inferred_path = default_client_identity_path(bootstrap_path);
    if !inferred_path.exists() {
        return Ok(None);
    }

    tracing::info!(
        inferred_path = %inferred_path.display(),
        bootstrap_path = %bootstrap_path.display(),
        "client-rights-edge: using client identity inferred from bootstrap path"
    );
    Ok(Some(
        ClientIdentityMaterial::from_path(&inferred_path).with_context(|| {
            format!(
                "failed to load client identity inferred from bootstrap path {}",
                inferred_path.display()
            )
        })?,
    ))
}

fn is_unauthorized_store_index_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("/store/index returned non-success status: 401 Unauthorized")
            || message
                .contains("/store/index/changes/wait returned non-success status: 401 Unauthorized")
    })
}

fn live_mount_auth_hint(args: &Args, has_client_identity: bool) -> String {
    if has_client_identity {
        return "the loaded client identity was rejected by the server or is no longer valid"
            .to_string();
    }

    if let Some(bootstrap_path) = args.bootstrap_file.as_deref() {
        let inferred_path = default_client_identity_path(bootstrap_path);
        return format!(
            "live mounts now require client auth; pass --client-identity-file {} or place a client identity next to the bootstrap file",
            inferred_path.display()
        );
    }

    "live mounts now require client auth; pass --client-identity-file <path-to-client-identity.json>".to_string()
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

fn paths_overlap(lhs: &str, rhs: &str) -> bool {
    lhs == rhs
        || lhs
            .strip_prefix(rhs)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || rhs
            .strip_prefix(lhs)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn filter_refresh_action_plan(
    plan: FuseActionPlan,
    changed_paths: &[String],
    overlay_paths: &std::collections::BTreeSet<String>,
) -> FuseActionPlan {
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

        let suppressed_by_overlay = overlay_paths
            .iter()
            .any(|overlay_path| paths_overlap(path, overlay_path));

        if changed.contains(path.as_str()) && keeps_remote_presence && !suppressed_by_overlay {
            actions.push(action);
        }
    }

    for path in changed_paths {
        let suppressed_by_overlay = overlay_paths
            .iter()
            .any(|overlay_path| paths_overlap(path, overlay_path));
        if planned_paths.contains(path) || suppressed_by_overlay {
            continue;
        }
        actions.push(FuseAction::RemovePath { path: path.clone() });
    }

    FuseActionPlan { actions }
}

#[derive(Clone)]
struct ClientRightsEdgeIo {
    sdk: IronMeshClient,
    download_stage_root: PathBuf,
    edge_state: Arc<ClientRightsEdgeState>,
}

impl ClientRightsEdgeIo {
    fn with_client(
        sdk: IronMeshClient,
        download_stage_root: PathBuf,
        edge_state: Arc<ClientRightsEdgeState>,
    ) -> Self {
        Self {
            sdk,
            download_stage_root,
            edge_state,
        }
    }

    fn download_version_selector(remote_version: &str) -> Option<&str> {
        let base_version = remote_version
            .rsplit_once(":size=")
            .map(|(base, _)| base)
            .unwrap_or(remote_version)
            .trim();
        if base_version.is_empty() || base_version == "server-head" {
            None
        } else {
            Some(base_version)
        }
    }
}

impl Hydrator for ClientRightsEdgeIo {
    fn hydrate(
        &self,
        path: &str,
        remote_version: &str,
        remote_content_hash: &str,
    ) -> Result<Vec<u8>> {
        if let Some(payload) = self.edge_state.read_cached_object(remote_content_hash)? {
            return Ok(payload);
        }

        let mut payload = Vec::new();
        let version_selector = Self::download_version_selector(remote_version);
        self.sdk
            .download_to_writer_resumable_staged(
                path,
                None,
                version_selector,
                &mut payload,
                &self.download_stage_root,
            )
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        self.edge_state
            .cache_full_object(remote_content_hash, &payload)?;
        Ok(payload)
    }

    fn hydrate_range(
        &self,
        path: &str,
        remote_version: &str,
        remote_content_hash: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }

        if let Some(payload) = self.edge_state.read_cached_object(remote_content_hash)? {
            let start = offset.min(payload.len() as u64) as usize;
            let end = offset.saturating_add(length).min(payload.len() as u64) as usize;
            return Ok(payload[start..end].to_vec());
        }

        let version_selector = Self::download_version_selector(remote_version);
        let range_end_exclusive = offset.saturating_add(length);
        let chunk_size = RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES as u64;
        let first_chunk_index = offset / chunk_size;
        let last_chunk_index = range_end_exclusive.saturating_sub(1) / chunk_size;
        let mut payload = Vec::with_capacity(length.min(usize::MAX as u64) as usize);

        for chunk_index in first_chunk_index..=last_chunk_index {
            let chunk_start = chunk_index.saturating_mul(chunk_size);
            let chunk = if let Some(chunk) = self
                .edge_state
                .read_cached_range_chunk(remote_content_hash, chunk_index)?
            {
                chunk
            } else {
                let mut downloaded = Vec::new();
                let mut on_progress = |_progress: DownloadProgress| {};
                let should_cancel = || false;
                self.sdk
                    .download_range_to_writer_with_progress_blocking(
                        DownloadRangeRequest {
                            key: path,
                            snapshot: None,
                            version: version_selector,
                            range: RequestedRange {
                                offset: chunk_start,
                                length: chunk_size,
                            },
                        },
                        &mut downloaded,
                        &mut on_progress,
                        &should_cancel,
                    )
                    .with_context(|| {
                        format!(
                            "failed to fetch ranged object chunk for path {path} chunk_index={chunk_index}"
                        )
                    })?;
                self.edge_state
                    .cache_range_chunk(remote_content_hash, chunk_index, downloaded)?
            };

            let slice_start = offset.saturating_sub(chunk_start) as usize;
            let slice_end = range_end_exclusive
                .min(chunk_start.saturating_add(chunk.len() as u64))
                .saturating_sub(chunk_start) as usize;
            if slice_start < slice_end {
                payload.extend_from_slice(&chunk[slice_start..slice_end]);
            }

            if chunk.len() < RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES {
                break;
            }
        }

        Ok(payload)
    }
}

impl Uploader for ClientRightsEdgeIo {
    fn upload_reader(
        &self,
        path: &str,
        base_remote_version: Option<&str>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>> {
        self.edge_state
            .enqueue_upload(path, base_remote_version, reader, length)
            .with_context(|| format!("failed to persist queued upload for path {path}"))?;
        Ok(None)
    }

    fn rename_path(
        &self,
        from_path: &str,
        to_path: &str,
        overwrite: bool,
        base_remote_version: Option<&str>,
    ) -> Result<()> {
        let started = Instant::now();
        tracing::info!(
            from_path,
            to_path,
            overwrite,
            base_remote_version = base_remote_version.unwrap_or("<none>"),
            "client-rights-edge: direct remote rename attempt start"
        );
        match self
            .sdk
            .rename_path_blocking(from_path.to_string(), to_path.to_string(), overwrite)
        {
            Ok(()) => {
                tracing::info!(
                    from_path,
                    to_path,
                    overwrite,
                    elapsed_ms = started.elapsed().as_millis(),
                    "client-rights-edge: direct remote rename attempt finished"
                );
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    from_path,
                    to_path,
                    overwrite,
                    elapsed_ms = started.elapsed().as_millis(),
                    "client-rights-edge: remote rename {from_path} -> {to_path} failed, queueing for retry: {error}"
                );
                self.edge_state
                    .enqueue_rename(from_path, to_path, overwrite, base_remote_version)
                    .with_context(|| {
                        format!("failed to persist queued rename {from_path} -> {to_path}")
                    })?;
                tracing::info!(
                    from_path,
                    to_path,
                    overwrite,
                    "client-rights-edge: queued rename for retry"
                );
                Ok(())
            }
        }
    }

    fn delete_path(&self, path: &str, base_remote_version: Option<&str>) -> Result<()> {
        match self.sdk.delete_path_blocking(path) {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::warn!(
                    "client-rights-edge: remote delete {path} failed, queueing for retry: {error}"
                );
                self.edge_state
                    .enqueue_delete(path, base_remote_version, path.ends_with('/'))
                    .with_context(|| format!("failed to persist queued delete for {path}"))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_args() -> Args {
        Args {
            command: None,
            snapshot_file: None,
            server_base_url: Some("http://127.0.0.1:8080".to_string()),
            bootstrap_file: None,
            server_ca_pem_file: None,
            client_identity_file: None,
            client_edge_state_dir: None,
            offline_object_cache: CliOfflineObjectCacheMode::On,
            mountpoint: PathBuf::from("/tmp/mount"),
            fs_name: "ironmesh".to_string(),
            allow_other: false,
            prefix: None,
            depth: 64,
            remote_refresh_interval_ms: 3000,
            publish_gnome_status: false,
            gnome_status_file: None,
            remote_status_poll_interval_ms: default_remote_status_poll_interval_ms(),
        }
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ironmesh-adapter-linux-fuse-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn read_http_request(stream: &mut std::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            let bytes_read = stream.read(&mut buf).expect("request read should succeed");
            if bytes_read == 0 {
                break;
            }
            request.extend_from_slice(&buf[..bytes_read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        String::from_utf8(request).expect("request should be utf8")
    }

    fn assert_recorded_range_hydration_requests(
        remote_version: &str,
        expected_head_request: &str,
        expected_get_request: &str,
        expected_get_range_header: &str,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener bind should succeed");
        let server_addr = listener
            .local_addr()
            .expect("listener local addr should succeed");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_server = requests.clone();
        let server = thread::spawn(move || {
            for response in [
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Length: 22\r\n",
                    "x-ironmesh-object-size: 22\r\n",
                    "ETag: \"etag-v1\"\r\n",
                    "Accept-Ranges: bytes\r\n",
                    "Connection: close\r\n",
                    "\r\n",
                )
                .as_bytes()
                .to_vec(),
                [
                    concat!(
                        "HTTP/1.1 206 Partial Content\r\n",
                        "Content-Length: 22\r\n",
                        "Content-Range: bytes 0-21/22\r\n",
                        "x-ironmesh-object-size: 22\r\n",
                        "ETag: \"etag-v1\"\r\n",
                        "Accept-Ranges: bytes\r\n",
                        "Connection: close\r\n",
                        "\r\n",
                    )
                    .as_bytes(),
                    b"012345678abcdefghijklm".as_slice(),
                ]
                .concat(),
            ] {
                let (mut stream, _) = listener.accept().expect("accept should succeed");
                let request = read_http_request(&mut stream);
                requests_for_server
                    .lock()
                    .expect("request log lock should succeed")
                    .push(request);
                stream
                    .write_all(&response)
                    .expect("response write should succeed");
                stream.flush().expect("response flush should succeed");
            }
        });

        let state_dir = unique_temp_dir("versioned-range-read");
        let stage_dir = unique_temp_dir("versioned-range-stage");
        fs::create_dir_all(&stage_dir).expect("stage dir create should succeed");
        let edge_state = Arc::new(
            ClientRightsEdgeState::new(&state_dir, OfflineObjectCacheMode::On)
                .expect("edge state create should succeed"),
        );
        let io = ClientRightsEdgeIo::with_client(
            IronMeshClient::from_direct_base_url(format!("http://{server_addr}")),
            stage_dir.clone(),
            edge_state,
        );

        let payload = io
            .hydrate_range("docs/photo.jpg", remote_version, "hash-photo-v1", 9, 12)
            .expect("range hydration should succeed");
        assert_eq!(payload, b"abcdefghijkl");

        server.join().expect("server thread should succeed");

        let recorded_requests = requests.lock().expect("request log lock should succeed");
        assert_eq!(recorded_requests.len(), 2);
        assert!(recorded_requests[0].starts_with(expected_head_request));
        assert!(recorded_requests[1].starts_with(expected_get_request));
        let request_headers = recorded_requests[1].to_ascii_lowercase();
        assert!(request_headers.contains(expected_get_range_header));
        assert!(request_headers.contains("\r\nif-range: \"etag-v1\"\r\n"));

        let _ = fs::remove_dir_all(&state_dir);
        let _ = fs::remove_dir_all(&stage_dir);
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
                    remote_content_hash: "h1".to_string(),
                    remote_size: Some(12),
                },
                FuseAction::EnsurePlaceholder {
                    path: "notes/todo.txt".to_string(),
                    remote_version: "v3".to_string(),
                    remote_content_hash: "h3".to_string(),
                    remote_size: Some(8),
                },
            ],
        };

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/new.txt".to_string()],
            &std::collections::BTreeSet::new(),
        );

        assert_eq!(
            filtered.actions,
            vec![FuseAction::EnsurePlaceholder {
                path: "docs/new.txt".to_string(),
                remote_version: "v1".to_string(),
                remote_content_hash: "h1".to_string(),
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
                remote_content_hash: "h2".to_string(),
                remote_size: Some(14),
            }],
        };

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/new.txt".to_string(), "docs/old.txt".to_string()],
            &std::collections::BTreeSet::new(),
        );

        assert_eq!(
            filtered.actions,
            vec![
                FuseAction::EnsurePlaceholder {
                    path: "docs/new.txt".to_string(),
                    remote_version: "v2".to_string(),
                    remote_content_hash: "h2".to_string(),
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
                    remote_content_hash: "h2".to_string(),
                    remote_size: Some(14),
                },
            ],
        };

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/old.txt".to_string(), "docs/sub/new.txt".to_string()],
            &std::collections::BTreeSet::new(),
        );

        assert_eq!(
            filtered.actions,
            vec![
                FuseAction::EnsurePlaceholder {
                    path: "docs/sub/new.txt".to_string(),
                    remote_version: "v2".to_string(),
                    remote_content_hash: "h2".to_string(),
                    remote_size: Some(14),
                },
                FuseAction::RemovePath {
                    path: "docs/old.txt".to_string(),
                },
            ],
        );
    }

    #[test]
    fn filter_refresh_action_plan_suppresses_paths_with_pending_overlay_uploads() {
        let plan = FuseActionPlan {
            actions: vec![
                FuseAction::EnsurePlaceholder {
                    path: "docs/dirty.txt".to_string(),
                    remote_version: "v2".to_string(),
                    remote_content_hash: "h2".to_string(),
                    remote_size: Some(14),
                },
                FuseAction::RemovePath {
                    path: "docs".to_string(),
                },
            ],
        };
        let overlay_paths = std::collections::BTreeSet::from(["docs/dirty.txt".to_string()]);

        let filtered = filter_refresh_action_plan(
            plan,
            &["docs/dirty.txt".to_string(), "docs".to_string()],
            &overlay_paths,
        );

        assert!(filtered.actions.is_empty());
    }

    #[test]
    fn effective_client_edge_state_dir_derives_persistent_default() {
        let args = sample_args();
        let derived = effective_client_edge_state_dir(&args).unwrap();

        assert!(derived.ends_with("http___127.0.0.1_8080___tmp_mount"));
    }

    #[test]
    fn effective_client_edge_state_dir_uses_explicit_override() {
        let mut args = sample_args();
        args.client_edge_state_dir = Some(PathBuf::from("/tmp/custom-edge-state"));

        let derived = effective_client_edge_state_dir(&args).unwrap();
        assert_eq!(derived, PathBuf::from("/tmp/custom-edge-state"));
    }

    #[test]
    fn default_client_identity_path_uses_bootstrap_stem() {
        let path = default_client_identity_path(std::path::Path::new(
            "/tmp/ironmesh-client-bootstrap-cli-client.json",
        ));
        assert_eq!(
            path,
            PathBuf::from("/tmp/ironmesh-client-bootstrap-cli-client.client-identity.json")
        );
    }

    #[test]
    fn resolve_client_identity_uses_bootstrap_sibling_when_present() {
        let dir = unique_temp_dir("bootstrap-sibling-identity");
        fs::create_dir_all(&dir).expect("temp dir create should succeed");
        let bootstrap_path = dir.join("client.bootstrap.json");
        fs::write(&bootstrap_path, "{}").expect("bootstrap placeholder write should succeed");

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("linux-fuse-test".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let identity_path = default_client_identity_path(&bootstrap_path);
        identity
            .write_to_path(&identity_path)
            .expect("identity should persist");

        let mut args = sample_args();
        args.server_base_url = None;
        args.bootstrap_file = Some(bootstrap_path);

        let resolved = resolve_client_identity(&args)
            .expect("identity resolution should succeed")
            .expect("bootstrap sibling identity should be inferred");
        assert_eq!(resolved.device_id, identity.device_id);
        assert_eq!(resolved.cluster_id, identity.cluster_id);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn client_rights_edge_range_hydration_uses_placeholder_version_selector() {
        assert_recorded_range_hydration_requests(
            "v1:size=22",
            "HEAD /store/docs%2Fphoto.jpg?version=v1 HTTP/1.1",
            "GET /store/docs%2Fphoto.jpg?version=v1 HTTP/1.1",
            "\r\nrange: bytes=0-21\r\n",
        );
    }

    #[test]
    fn client_rights_edge_range_hydration_omits_server_head_placeholder_selector() {
        assert_recorded_range_hydration_requests(
            "server-head:size=22",
            "HEAD /store/docs%2Fphoto.jpg HTTP/1.1",
            "GET /store/docs%2Fphoto.jpg HTTP/1.1",
            "\r\nrange: bytes=0-21\r\n",
        );
    }

    #[test]
    fn client_rights_edge_range_hydration_reuses_in_memory_chunk_cache_when_disk_cache_is_off() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener bind should succeed");
        let server_addr = listener
            .local_addr()
            .expect("listener local addr should succeed");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_server = requests.clone();
        let server = thread::spawn(move || {
            for response in [
                concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Content-Length: 22\r\n",
                    "x-ironmesh-object-size: 22\r\n",
                    "ETag: \"etag-v1\"\r\n",
                    "Accept-Ranges: bytes\r\n",
                    "Connection: close\r\n",
                    "\r\n",
                )
                .as_bytes()
                .to_vec(),
                [
                    concat!(
                        "HTTP/1.1 206 Partial Content\r\n",
                        "Content-Length: 22\r\n",
                        "Content-Range: bytes 0-21/22\r\n",
                        "x-ironmesh-object-size: 22\r\n",
                        "ETag: \"etag-v1\"\r\n",
                        "Accept-Ranges: bytes\r\n",
                        "Connection: close\r\n",
                        "\r\n",
                    )
                    .as_bytes(),
                    b"012345678abcdefghijklm".as_slice(),
                ]
                .concat(),
            ] {
                let (mut stream, _) = listener.accept().expect("accept should succeed");
                let request = read_http_request(&mut stream);
                requests_for_server
                    .lock()
                    .expect("request log lock should succeed")
                    .push(request);
                stream
                    .write_all(&response)
                    .expect("response write should succeed");
                stream.flush().expect("response flush should succeed");
            }
        });

        let state_dir = unique_temp_dir("range-cache-off");
        let stage_dir = unique_temp_dir("range-cache-off-stage");
        fs::create_dir_all(&stage_dir).expect("stage dir create should succeed");
        let edge_state = Arc::new(
            ClientRightsEdgeState::new(&state_dir, OfflineObjectCacheMode::Off)
                .expect("edge state create should succeed"),
        );
        let io = ClientRightsEdgeIo::with_client(
            IronMeshClient::from_direct_base_url(format!("http://{server_addr}")),
            stage_dir.clone(),
            edge_state,
        );

        let first = io
            .hydrate_range("docs/photo.jpg", "server-head", "hash-photo-v1", 9, 4)
            .expect("first range hydration should succeed");
        let second = io
            .hydrate_range("docs/photo.jpg", "server-head", "hash-photo-v1", 13, 4)
            .expect("second range hydration should succeed");
        assert_eq!(first, b"abcd");
        assert_eq!(second, b"efgh");

        server.join().expect("server thread should succeed");

        let recorded_requests = requests.lock().expect("request log lock should succeed");
        assert_eq!(recorded_requests.len(), 2);
        assert!(recorded_requests[0].starts_with("HEAD /store/docs%2Fphoto.jpg HTTP/1.1"));
        assert!(recorded_requests[1].starts_with("GET /store/docs%2Fphoto.jpg HTTP/1.1"));

        let _ = fs::remove_dir_all(&state_dir);
        let _ = fs::remove_dir_all(&stage_dir);
    }
}
