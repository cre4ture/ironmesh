use anyhow::{Context, Result};
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope,
    RemoteSnapshotUpdate,
};
use client_sdk::remote_sync::RemoteSnapshotFetchProgress;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_core::{EntryKind, SyncSnapshot};

use crate::{
    FolderAgentUiState, LocalEntryKind, LocalEntryState, LocalTreeScanProgress, LocalTreeState,
    PathScope, RemoteTreeIndex, StartupStateStore, absolute_path, build_configured_client,
    cleanup_ironmesh_part_files, delete_remote_file, describe_connection_target, diff_local_trees,
    download_transfer_state_path, download_transfer_temp_path,
    load_local_baseline_hashes_with_retries, load_local_baseline_with_retries,
    local_entry_state_for_path, local_paths_to_preserve_on_startup,
    materialize_remote_conflict_copies, parent_directories, remote_file_hashes_by_local_path,
    remote_file_paths_by_local_path, remove_local_path, scan_local_tree,
    scan_local_tree_with_progress, spawn_ui_server, startup_add_delete_conflicts,
    startup_baseline_state_from_remote_index, startup_dual_modify_conflicts,
    startup_remote_delete_wins_paths, upload_local_file,
};

#[derive(Debug, Clone)]
pub struct FolderAgentRuntimeOptions {
    pub root_dir: PathBuf,
    pub state_root_dir: Option<PathBuf>,
    pub local_tree_uri: Option<String>,
    pub server_base_url: Option<String>,
    pub client_bootstrap_json: Option<String>,
    pub server_ca_pem: Option<String>,
    pub client_identity_json: Option<String>,
    pub prefix: Option<String>,
    pub depth: usize,
    pub remote_refresh_interval_ms: u64,
    pub local_scan_interval_ms: u64,
    pub no_watch_local: bool,
    pub run_once: bool,
    pub ui_bind: Option<String>,
}

pub fn run_folder_agent(options: &FolderAgentRuntimeOptions) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    run_folder_agent_with_control(options, running, true, None)
}

pub type FolderAgentStatusCallback = Arc<dyn Fn(FolderAgentRuntimeStatus) + Send + Sync + 'static>;

#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FolderAgentRuntimeMetrics {
    pub local_entry_count: u64,
    pub local_file_count: u64,
    pub local_directory_count: u64,
    pub remote_entry_count: u64,
    pub remote_file_count: u64,
    pub remote_directory_count: u64,
    pub changed_path_count: u64,
    pub uploaded_file_count: u64,
    pub downloaded_file_count: u64,
    pub deleted_remote_file_count: u64,
    pub removed_local_path_count: u64,
    pub ensured_directory_count: u64,
    pub preserved_local_file_count: u64,
    pub startup_conflict_count: u64,
}

impl FolderAgentRuntimeMetrics {
    pub fn from_states(
        local_state: Option<&LocalTreeState>,
        remote_index: Option<&RemoteTreeIndex>,
    ) -> Self {
        let mut metrics = Self::default();
        if let Some(local_state) = local_state {
            metrics.apply_local_state(local_state);
        }
        if let Some(remote_index) = remote_index {
            metrics.apply_remote_index(remote_index);
        }
        metrics
    }

    pub fn apply_local_state(&mut self, local_state: &LocalTreeState) {
        self.local_entry_count = usize_to_u64(local_state.len());
        self.local_file_count = usize_to_u64(
            local_state
                .values()
                .filter(|entry| entry.kind == LocalEntryKind::File)
                .count(),
        );
        self.local_directory_count = self.local_entry_count.saturating_sub(self.local_file_count);
    }

    pub fn apply_remote_index(&mut self, remote_index: &RemoteTreeIndex) {
        self.remote_directory_count = usize_to_u64(remote_index.directories.len());
        self.remote_file_count = usize_to_u64(remote_index.files.len());
        self.remote_entry_count = self
            .remote_directory_count
            .saturating_add(self.remote_file_count);
    }

    pub fn apply_snapshot(&mut self, snapshot: &SyncSnapshot, scope: &PathScope) {
        let mut remote_directory_count = 0usize;
        let mut remote_file_count = 0usize;

        for entry in &snapshot.remote {
            let remote_path = crate::normalize_relative_path(&entry.path);
            let Some(local_path) = scope.remote_to_local(&remote_path) else {
                continue;
            };
            if local_path.is_empty() {
                continue;
            }

            match entry.kind {
                EntryKind::Directory => remote_directory_count += 1,
                EntryKind::File => remote_file_count += 1,
            }
        }

        self.remote_directory_count = usize_to_u64(remote_directory_count);
        self.remote_file_count = usize_to_u64(remote_file_count);
        self.remote_entry_count = self
            .remote_directory_count
            .saturating_add(self.remote_file_count);
    }
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FolderAgentRuntimeStatus {
    pub state: String,
    pub message: String,
    pub updated_unix_ms: u64,
    pub phase: String,
    pub activity: String,
    pub scope_label: String,
    pub root_dir: String,
    pub local_tree_uri: Option<String>,
    pub connection_target: Option<String>,
    pub storage_mode: String,
    pub watch_mode: String,
    pub run_mode: String,
    pub last_success_unix_ms: Option<u64>,
    pub last_error: Option<String>,
    pub metrics: FolderAgentRuntimeMetrics,
}

impl FolderAgentRuntimeStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        options: &FolderAgentRuntimeOptions,
        connection_target: Option<&str>,
        storage_mode: &str,
        watch_mode: &str,
        state: impl Into<String>,
        phase: impl Into<String>,
        activity: impl Into<String>,
        message: impl Into<String>,
        metrics: FolderAgentRuntimeMetrics,
        last_success_unix_ms: Option<u64>,
        last_error: Option<String>,
    ) -> Self {
        Self {
            state: state.into(),
            message: message.into(),
            updated_unix_ms: now_unix_ms(),
            phase: phase.into(),
            activity: activity.into(),
            scope_label: options.prefix.as_deref().unwrap_or("<root>").to_string(),
            root_dir: options.root_dir.display().to_string(),
            local_tree_uri: options.local_tree_uri.clone(),
            connection_target: connection_target.map(ToOwned::to_owned),
            storage_mode: storage_mode.to_string(),
            watch_mode: watch_mode.to_string(),
            run_mode: if options.run_once {
                "once".to_string()
            } else {
                "continuous".to_string()
            },
            last_success_unix_ms,
            last_error,
            metrics,
        }
    }
}

pub fn run_folder_agent_with_control(
    options: &FolderAgentRuntimeOptions,
    running: Arc<AtomicBool>,
    install_signal_handler: bool,
    status_callback: Option<FolderAgentStatusCallback>,
) -> Result<()> {
    common::logging::init_compact_tracing_default("info");
    let prefix_label = options.prefix.as_deref().unwrap_or("<root>");
    emit_status(
        status_callback.as_ref(),
        options,
        None,
        "filesystem",
        watch_mode_label(options),
        "starting",
        "startup",
        "initializing",
        format!(
            "Starting folder sync runtime for prefix={prefix_label} root={}",
            options.root_dir.display()
        ),
        FolderAgentRuntimeMetrics::default(),
        None,
        None,
    );
    let result = run_folder_agent_inner(
        options,
        running,
        install_signal_handler,
        status_callback.clone(),
    );

    if let Err(error) = &result {
        emit_status(
            status_callback.as_ref(),
            options,
            None,
            "filesystem",
            watch_mode_label(options),
            "error",
            "error",
            "failed",
            format!("Folder sync runtime failed: {error:#}"),
            FolderAgentRuntimeMetrics::default(),
            None,
            Some(format!("{error:#}")),
        );
    }

    result
}

#[derive(Debug, Clone, Copy, Default)]
struct LocalSyncOutcome {
    changed_path_count: usize,
    ensured_directory_count: usize,
    uploaded_file_count: usize,
    deleted_remote_file_count: usize,
}

impl LocalSyncOutcome {
    fn is_empty(self) -> bool {
        self.ensured_directory_count == 0
            && self.uploaded_file_count == 0
            && self.deleted_remote_file_count == 0
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct RemoteApplyOutcome {
    changed_path_count: usize,
    ensured_directory_count: usize,
    downloaded_file_count: usize,
    removed_local_path_count: usize,
}

impl RemoteApplyOutcome {
    fn accumulate(&mut self, other: Self) {
        self.changed_path_count += other.changed_path_count;
        self.ensured_directory_count += other.ensured_directory_count;
        self.downloaded_file_count += other.downloaded_file_count;
        self.removed_local_path_count += other.removed_local_path_count;
    }
}

#[derive(Debug, Clone)]
struct BlockingStatusProgress {
    options: FolderAgentRuntimeOptions,
    connection_target: Option<String>,
    storage_mode: String,
    watch_mode: String,
    state: String,
    phase: String,
    activity: String,
    base_message: String,
    metrics: FolderAgentRuntimeMetrics,
    last_success_unix_ms: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct LocalScanStatusContext {
    options: FolderAgentRuntimeOptions,
    connection_target: String,
    watch_mode: String,
    state: String,
    phase: String,
    base_message: String,
    last_success_unix_ms: Option<u64>,
}

fn run_folder_agent_inner(
    options: &FolderAgentRuntimeOptions,
    running: Arc<AtomicBool>,
    install_signal_handler: bool,
    status_callback: Option<FolderAgentStatusCallback>,
) -> Result<()> {
    let scope = PathScope::new(options.prefix.clone());
    let watch_mode = watch_mode_label(options);
    let connection_target = describe_connection_target(
        options.server_base_url.as_deref(),
        options.client_bootstrap_json.as_deref(),
    )?;
    let mut last_success_unix_ms = None;
    let last_success_shared = Arc::new(AtomicU64::new(0));
    let state_store = match options.state_root_dir.as_deref() {
        Some(state_root_dir) => StartupStateStore::new_with_state_root(
            &options.root_dir,
            &scope,
            &connection_target,
            state_root_dir,
        ),
        None => StartupStateStore::new(&options.root_dir, &scope, &connection_target),
    };

    fs::create_dir_all(&options.root_dir).with_context(|| {
        format!(
            "failed to create root directory {}",
            options.root_dir.display()
        )
    })?;

    let _ui_handle = if let Some(bind_addr) = options.ui_bind.as_deref() {
        let listener = std::net::TcpListener::bind(bind_addr)
            .with_context(|| format!("ui: failed to bind to {bind_addr}"))?;
        listener
            .set_nonblocking(true)
            .context("ui: failed to set listener to nonblocking")?;
        let addr = listener
            .local_addr()
            .context("ui: failed to determine bound address")?;
        tracing::info!("ui: listening on http://{addr}");

        let ui_state = FolderAgentUiState::new(
            options.root_dir.clone(),
            connection_target.clone(),
            options.server_base_url.clone(),
            options.client_bootstrap_json.clone(),
            options.server_ca_pem.clone(),
            options.client_identity_json.clone(),
            scope.clone(),
            state_store.clone(),
        );
        Some(spawn_ui_server(listener, ui_state))
    } else {
        None
    };

    if let Err(error) = cleanup_ironmesh_part_files(&options.root_dir, false) {
        tracing::warn!("startup-state: failed to cleanup partial download artifacts: {error}");
    }

    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "starting",
        "startup",
        "scanning-local-tree",
        "Scanning local files before initial reconciliation",
        FolderAgentRuntimeMetrics::default(),
        last_success_unix_ms,
        None,
    );
    let local_state_before_remote_sync = scan_local_tree_with_status_progress(
        options,
        &connection_target,
        watch_mode,
        status_callback.as_ref(),
        "starting",
        "startup",
        "Scanning local files before initial reconciliation",
        &options.root_dir,
        None,
        last_success_unix_ms,
    )
    .context("failed to scan local state before initial remote sync")?;
    let local_scan_sample = sample_local_paths(&local_state_before_remote_sync, 5);
    let local_scan_metrics =
        FolderAgentRuntimeMetrics::from_states(Some(&local_state_before_remote_sync), None);
    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "starting",
        "startup",
        "scanning-local-tree",
        format!(
            "Initial local scan found {} path(s) under root={} sample=[{}]",
            local_state_before_remote_sync.len(),
            options.root_dir.display(),
            local_scan_sample
        ),
        local_scan_metrics.clone(),
        last_success_unix_ms,
        None,
    );

    let baseline_before_remote_sync =
        match load_local_baseline_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(state) => Some(state),
            Err(error) => {
                tracing::warn!("startup-state: failed to load sqlite baseline: {error}");
                state_store.quarantine_corrupt().ok();
                None
            }
        };
    let baseline_hashes_before_remote_sync = if baseline_before_remote_sync.is_some() {
        match load_local_baseline_hashes_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(hashes) => hashes,
            Err(error) => {
                tracing::warn!("startup-state: failed to load sqlite baseline hashes: {error}");
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };

    let client = configured_client(options)?;
    let snapshot_scope = RemoteSnapshotScope::new(
        scope.remote_prefix().map(ToString::to_string),
        options.depth,
        None,
    );

    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "starting",
        "startup",
        "fetching-remote-snapshot",
        "Fetching initial remote snapshot",
        local_scan_metrics.clone(),
        last_success_unix_ms,
        None,
    );
    let initial_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope.clone());
    let initial_snapshot = fetch_remote_snapshot_with_status_progress(
        options,
        &connection_target,
        "filesystem",
        watch_mode,
        status_callback.as_ref(),
        "starting",
        "startup",
        "fetching-remote-snapshot",
        "Fetching initial remote snapshot",
        &initial_fetcher,
        local_scan_metrics.clone(),
        last_success_unix_ms,
        None,
    )
    .context("failed to fetch initial remote snapshot")?;
    let remote_files_before_remote_sync =
        remote_file_paths_by_local_path(&initial_snapshot, &scope);
    let remote_hashes_before_remote_sync =
        remote_file_hashes_by_local_path(&initial_snapshot, &scope);
    let preserve_local_files = local_paths_to_preserve_on_startup(
        &options.root_dir,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &remote_hashes_before_remote_sync,
    );
    let remote_delete_wins_paths = startup_remote_delete_wins_paths(
        &options.root_dir,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &baseline_hashes_before_remote_sync,
        &remote_files_before_remote_sync,
        &preserve_local_files,
    );
    let mut startup_conflicts = startup_add_delete_conflicts(
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &remote_files_before_remote_sync,
        &preserve_local_files,
        &remote_delete_wins_paths,
    );
    startup_conflicts.extend(startup_dual_modify_conflicts(
        &options.root_dir,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &baseline_hashes_before_remote_sync,
        &remote_hashes_before_remote_sync,
        &preserve_local_files,
    ));
    if let Err(error) =
        materialize_remote_conflict_copies(&options.root_dir, &client, &scope, &startup_conflicts)
    {
        tracing::warn!("startup-state: failed to materialize conflict copies: {error}");
    }

    let mut startup_metrics =
        FolderAgentRuntimeMetrics::from_states(Some(&local_state_before_remote_sync), None);
    startup_metrics.apply_snapshot(&initial_snapshot, &scope);
    startup_metrics.preserved_local_file_count = usize_to_u64(preserve_local_files.len());
    startup_metrics.startup_conflict_count = usize_to_u64(startup_conflicts.len());
    startup_metrics.removed_local_path_count = usize_to_u64(remote_delete_wins_paths.len());
    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "starting",
        "startup",
        "reconciling-startup",
        format!(
            "Reconciling startup state: {} remote entrie(s), {} preserved local file(s), {} startup conflict(s), {} remote-delete winner(s)",
            startup_metrics.remote_entry_count,
            startup_metrics.preserved_local_file_count,
            startup_metrics.startup_conflict_count,
            startup_metrics.removed_local_path_count,
        ),
        startup_metrics,
        last_success_unix_ms,
        None,
    );

    let mut remote_index = RemoteTreeIndex::default();
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    let mut initial_remote_outcome = apply_remote_snapshot(
        &options.root_dir,
        &client,
        &initial_snapshot,
        None,
        Some(&preserve_local_files),
        Some(&state_store),
        &scope,
        &mut suppressed_uploads,
        &mut remote_index,
    )?;
    for path in &remote_delete_wins_paths {
        remove_local_path(&options.root_dir, path)?;
        suppressed_uploads.remove(path);
    }
    initial_remote_outcome.removed_local_path_count += remote_delete_wins_paths.len();

    let mut local_state = scan_local_tree_with_status_progress(
        options,
        &connection_target,
        watch_mode,
        status_callback.as_ref(),
        "syncing",
        "startup",
        "Rescanning local files after applying startup remote changes",
        &options.root_dir,
        Some(&remote_index),
        last_success_unix_ms,
    )
    .context("failed to scan local state after initial remote sync")?;
    local_state = startup_baseline_state_from_remote_index(
        &local_state,
        &remote_index,
        &preserve_local_files,
    );
    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after remote apply during startup")?;

    let mut initial_remote_metrics =
        FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index));
    initial_remote_metrics.changed_path_count =
        usize_to_u64(initial_remote_outcome.changed_path_count);
    initial_remote_metrics.downloaded_file_count =
        usize_to_u64(initial_remote_outcome.downloaded_file_count);
    initial_remote_metrics.ensured_directory_count =
        usize_to_u64(initial_remote_outcome.ensured_directory_count);
    initial_remote_metrics.removed_local_path_count =
        usize_to_u64(initial_remote_outcome.removed_local_path_count);
    initial_remote_metrics.preserved_local_file_count = usize_to_u64(preserve_local_files.len());
    initial_remote_metrics.startup_conflict_count = usize_to_u64(startup_conflicts.len());
    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "syncing",
        "startup",
        "applying-remote-snapshot",
        format!(
            "Applied startup remote snapshot: {}",
            format_remote_apply_summary(initial_remote_outcome)
        ),
        initial_remote_metrics,
        last_success_unix_ms,
        None,
    );

    let initial_local_sync_outcome = run_with_status_heartbeat(
        status_callback.clone(),
        BlockingStatusProgress {
            options: options.clone(),
            connection_target: Some(connection_target.clone()),
            storage_mode: "filesystem".to_string(),
            watch_mode: watch_mode.to_string(),
            state: "syncing".to_string(),
            phase: "startup".to_string(),
            activity: "scanning-local-tree".to_string(),
            base_message: "Scanning local files and reconciling startup local changes"
                .to_string(),
            metrics: FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index)),
            last_success_unix_ms,
            last_error: None,
        },
        || {
            sync_local_changes(
                &options.root_dir,
                &client,
                &mut local_state,
                Some(&state_store),
                &scope,
                &mut remote_index,
                &mut suppressed_uploads,
                status_callback.as_ref(),
                Some(&LocalScanStatusContext {
                    options: options.clone(),
                    connection_target: connection_target.clone(),
                    watch_mode: watch_mode.to_string(),
                    state: "syncing".to_string(),
                    phase: "startup".to_string(),
                    base_message:
                        "Scanning local files and reconciling startup local changes".to_string(),
                    last_success_unix_ms,
                }),
            )
        },
    )?;

    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after startup reconciliation")?;
    state_store
        .persist_startup_conflicts(&startup_conflicts)
        .context("failed to persist startup conflicts")?;

    last_success_unix_ms = Some(now_unix_ms());
    let mut initial_runtime_metrics =
        FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index));
    initial_runtime_metrics.changed_path_count = usize_to_u64(
        initial_remote_outcome.changed_path_count + initial_local_sync_outcome.changed_path_count,
    );
    initial_runtime_metrics.uploaded_file_count =
        usize_to_u64(initial_local_sync_outcome.uploaded_file_count);
    initial_runtime_metrics.downloaded_file_count =
        usize_to_u64(initial_remote_outcome.downloaded_file_count);
    initial_runtime_metrics.deleted_remote_file_count =
        usize_to_u64(initial_local_sync_outcome.deleted_remote_file_count);
    initial_runtime_metrics.removed_local_path_count =
        usize_to_u64(initial_remote_outcome.removed_local_path_count);
    initial_runtime_metrics.ensured_directory_count = usize_to_u64(
        initial_remote_outcome.ensured_directory_count
            + initial_local_sync_outcome.ensured_directory_count,
    );
    initial_runtime_metrics.preserved_local_file_count = usize_to_u64(preserve_local_files.len());
    initial_runtime_metrics.startup_conflict_count = usize_to_u64(startup_conflicts.len());
    let initial_sync_message = format!(
        "Initial sync complete: {} and {}",
        format_remote_apply_summary(initial_remote_outcome),
        format_local_sync_summary(initial_local_sync_outcome)
    );

    if options.run_once {
        emit_status(
            status_callback.as_ref(),
            options,
            Some(&connection_target),
            "filesystem",
            watch_mode,
            "stopped",
            "shutdown",
            "completed-one-shot",
            initial_sync_message,
            initial_runtime_metrics,
            last_success_unix_ms,
            None,
        );
        return Ok(());
    }

    if install_signal_handler {
        install_ctrlc_handler(running.clone())?;
    }
    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "running",
        "steady-state",
        "watching-for-changes",
        initial_sync_message,
        initial_runtime_metrics.clone(),
        last_success_unix_ms,
        None,
    );

    let refresh_interval = Duration::from_millis(options.remote_refresh_interval_ms.max(250));
    let local_scan_interval = Duration::from_millis(options.local_scan_interval_ms.max(250));

    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope);
    let latest_metrics = Arc::new(Mutex::new(initial_runtime_metrics.clone()));
    store_optional_unix_ms(&last_success_shared, last_success_unix_ms);

    let (remote_tx, remote_rx) = mpsc::channel::<RemoteSnapshotUpdate>();
    let remote_running = running.clone();
    let remote_stop_signal = running.clone();
    let remote_status_callback = status_callback.clone();
    let remote_options = options.clone();
    let remote_connection_target = connection_target.clone();
    let remote_watch_mode = watch_mode.to_string();
    let remote_latest_metrics = latest_metrics.clone();
    let remote_last_success = last_success_shared.clone();
    let remote_thread = refresh_poller.spawn_changed_paths_loop(
        remote_running,
        Some(initial_snapshot),
        move || {
            fetch_remote_snapshot_with_status_progress(
                &remote_options,
                &remote_connection_target,
                "filesystem",
                &remote_watch_mode,
                remote_status_callback.as_ref(),
                "running",
                "steady-state",
                "checking-remote-snapshot",
                "Checking remote snapshot for changes",
                &refresh_fetcher,
                latest_metrics_value(&remote_latest_metrics),
                load_optional_unix_ms(&remote_last_success),
                Some("Watching for changes; local and remote state are aligned"),
            )
        },
        move |update| {
            if remote_tx.send(update).is_err() {
                remote_stop_signal.store(false, Ordering::SeqCst);
            }
        },
    );

    let (local_event_tx, local_event_rx) = mpsc::channel::<()>();
    let _watcher = if options.no_watch_local {
        None
    } else {
        Some(start_local_watcher(
            options.root_dir.clone(),
            local_event_tx,
        )?)
    };

    let mut next_local_scan = Instant::now() + local_scan_interval;

    while running.load(Ordering::SeqCst) {
        let mut baseline_dirty = false;
        let mut remote_updates_applied = false;
        let mut combined_remote_outcome = RemoteApplyOutcome::default();
        while let Ok(update) = remote_rx.try_recv() {
            let mut remote_pending_metrics =
                FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index));
            remote_pending_metrics.changed_path_count = usize_to_u64(update.changed_paths.len());
            emit_status(
                status_callback.as_ref(),
                options,
                Some(&connection_target),
                "filesystem",
                watch_mode,
                "syncing",
                "steady-state",
                "applying-remote-snapshot",
                format!("Applying {} remote change(s)", update.changed_paths.len()),
                remote_pending_metrics,
                last_success_unix_ms,
                None,
            );
            combined_remote_outcome.accumulate(apply_remote_snapshot(
                &options.root_dir,
                &client,
                &update.snapshot,
                Some(&update.changed_paths),
                None,
                Some(&state_store),
                &scope,
                &mut suppressed_uploads,
                &mut remote_index,
            )?);
            remote_updates_applied = true;
        }

        if remote_updates_applied {
            local_state = scan_local_tree_with_status_progress(
                options,
                &connection_target,
                watch_mode,
                status_callback.as_ref(),
                "syncing",
                "steady-state",
                "Rescanning local files after applying remote changes",
                &options.root_dir,
                Some(&remote_index),
                last_success_unix_ms,
            )
            .context("failed to rescan local state after remote update")?;
            baseline_dirty = true;
            last_success_unix_ms = Some(now_unix_ms());
            store_optional_unix_ms(&last_success_shared, last_success_unix_ms);
            let mut remote_runtime_metrics =
                FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index));
            remote_runtime_metrics.changed_path_count =
                usize_to_u64(combined_remote_outcome.changed_path_count);
            remote_runtime_metrics.downloaded_file_count =
                usize_to_u64(combined_remote_outcome.downloaded_file_count);
            remote_runtime_metrics.ensured_directory_count =
                usize_to_u64(combined_remote_outcome.ensured_directory_count);
            remote_runtime_metrics.removed_local_path_count =
                usize_to_u64(combined_remote_outcome.removed_local_path_count);
            emit_status(
                status_callback.as_ref(),
                options,
                Some(&connection_target),
                "filesystem",
                watch_mode,
                "running",
                "steady-state",
                "watching-for-changes",
                format!(
                    "Applied remote changes: {}",
                    format_remote_apply_summary(combined_remote_outcome)
                ),
                remote_runtime_metrics.clone(),
                last_success_unix_ms,
                None,
            );
            set_latest_metrics(&latest_metrics, &remote_runtime_metrics);
        }

        let mut local_scan_requested = false;
        while local_event_rx.try_recv().is_ok() {
            local_scan_requested = true;
        }

        if local_scan_requested || Instant::now() >= next_local_scan {
            let previous_local_state = local_state.clone();
            let local_scan_state = if local_scan_requested {
                "syncing"
            } else {
                "running"
            };
            let local_scan_message = if local_scan_requested {
                "Local change detected; scanning local files"
            } else {
                "Checking local files for changes"
            };
            let local_scan_base_message = if local_scan_requested {
                "Scanning local files and reconciling event-driven local changes"
            } else {
                "Checking local files for changes"
            };
            emit_status(
                status_callback.as_ref(),
                options,
                Some(&connection_target),
                "filesystem",
                watch_mode,
                local_scan_state,
                "steady-state",
                "scanning-local-tree",
                local_scan_message,
                FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index)),
                last_success_unix_ms,
                None,
            );
            let local_sync_outcome = run_with_status_heartbeat(
                status_callback.clone(),
                BlockingStatusProgress {
                    options: options.clone(),
                    connection_target: Some(connection_target.clone()),
                    storage_mode: "filesystem".to_string(),
                    watch_mode: watch_mode.to_string(),
                    state: local_scan_state.to_string(),
                    phase: "steady-state".to_string(),
                    activity: "scanning-local-tree".to_string(),
                    base_message: local_scan_base_message.to_string(),
                    metrics: FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index)),
                    last_success_unix_ms,
                    last_error: None,
                },
                || {
                    sync_local_changes(
                        &options.root_dir,
                        &client,
                        &mut local_state,
                        Some(&state_store),
                        &scope,
                        &mut remote_index,
                        &mut suppressed_uploads,
                        status_callback.as_ref(),
                        Some(&LocalScanStatusContext {
                            options: options.clone(),
                            connection_target: connection_target.clone(),
                            watch_mode: watch_mode.to_string(),
                            state: local_scan_state.to_string(),
                            phase: "steady-state".to_string(),
                            base_message: local_scan_base_message.to_string(),
                            last_success_unix_ms,
                        }),
                    )
                },
            )?;
            if local_state != previous_local_state {
                baseline_dirty = true;
            }
            next_local_scan = Instant::now() + local_scan_interval;
            last_success_unix_ms = Some(now_unix_ms());
            store_optional_unix_ms(&last_success_shared, last_success_unix_ms);
            let mut local_runtime_metrics =
                FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index));
            local_runtime_metrics.changed_path_count =
                usize_to_u64(local_sync_outcome.changed_path_count);
            local_runtime_metrics.uploaded_file_count =
                usize_to_u64(local_sync_outcome.uploaded_file_count);
            local_runtime_metrics.deleted_remote_file_count =
                usize_to_u64(local_sync_outcome.deleted_remote_file_count);
            local_runtime_metrics.ensured_directory_count =
                usize_to_u64(local_sync_outcome.ensured_directory_count);
            emit_status(
                status_callback.as_ref(),
                options,
                Some(&connection_target),
                "filesystem",
                watch_mode,
                "running",
                "steady-state",
                "watching-for-changes",
                if local_sync_outcome.is_empty() {
                    "Watching for changes; local and remote state are aligned".to_string()
                } else {
                    format!(
                        "Watching for changes after local sync: {}",
                        format_local_sync_summary(local_sync_outcome)
                    )
                },
                local_runtime_metrics.clone(),
                last_success_unix_ms,
                None,
            );
            set_latest_metrics(&latest_metrics, &local_runtime_metrics);
        }

        if baseline_dirty {
            state_store
                .persist_local_baseline(&local_state)
                .context("failed to persist sqlite baseline during runtime")?;
        }

        thread::sleep(Duration::from_millis(250));
    }

    running.store(false, Ordering::SeqCst);
    let _ = remote_thread.join();
    set_latest_metrics(
        &latest_metrics,
        &FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index)),
    );
    emit_status(
        status_callback.as_ref(),
        options,
        Some(&connection_target),
        "filesystem",
        watch_mode,
        "stopped",
        "shutdown",
        "stopped",
        "Folder sync runtime stopped",
        FolderAgentRuntimeMetrics::from_states(Some(&local_state), Some(&remote_index)),
        last_success_unix_ms,
        None,
    );
    Ok(())
}

fn emit_status(
    callback: Option<&FolderAgentStatusCallback>,
    options: &FolderAgentRuntimeOptions,
    connection_target: Option<&str>,
    storage_mode: &str,
    watch_mode: &str,
    state: impl Into<String>,
    phase: impl Into<String>,
    activity: impl Into<String>,
    message: impl Into<String>,
    metrics: FolderAgentRuntimeMetrics,
    last_success_unix_ms: Option<u64>,
    last_error: Option<String>,
) {
    let Some(callback) = callback else {
        return;
    };
    callback(FolderAgentRuntimeStatus::new(
        options,
        connection_target,
        storage_mode,
        watch_mode,
        state,
        phase,
        activity,
        message,
        metrics,
        last_success_unix_ms,
        last_error,
    ));
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn sample_local_paths(local_state: &LocalTreeState, limit: usize) -> String {
    let mut sample = local_state
        .keys()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if sample.is_empty() {
        sample.push_str("<none>");
    }
    sample
}

fn configured_client(options: &FolderAgentRuntimeOptions) -> Result<IronMeshClient> {
    build_configured_client(
        options.server_base_url.as_deref(),
        options.client_bootstrap_json.as_deref(),
        options.server_ca_pem.as_deref(),
        options.client_identity_json.as_deref(),
    )
}

fn install_ctrlc_handler(running: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
    })
    .context("failed to install Ctrl+C handler")
}

fn start_local_watcher(
    root_dir: PathBuf,
    local_event_tx: mpsc::Sender<()>,
) -> Result<RecommendedWatcher> {
    let mut watcher =
        notify::recommended_watcher(move |result: notify::Result<notify::Event>| match result {
            Ok(event) => match event.kind {
                EventKind::Access(_) => {}
                _ => {
                    let _ = local_event_tx.send(());
                }
            },
            Err(error) => {
                tracing::warn!("local-watch: event error: {error}");
            }
        })
        .context("failed to create local filesystem watcher")?;

    watcher
        .watch(&root_dir, RecursiveMode::Recursive)
        .with_context(|| format!("failed to watch {}", root_dir.display()))?;

    Ok(watcher)
}

fn sync_local_changes(
    root_dir: &Path,
    client: &IronMeshClient,
    local_state: &mut LocalTreeState,
    state_store: Option<&StartupStateStore>,
    scope: &PathScope,
    remote_index: &mut RemoteTreeIndex,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    status_callback: Option<&FolderAgentStatusCallback>,
    local_scan_status: Option<&LocalScanStatusContext>,
) -> Result<LocalSyncOutcome> {
    let current = match local_scan_status {
        Some(progress) => scan_local_tree_with_status_progress(
            &progress.options,
            &progress.connection_target,
            &progress.watch_mode,
            status_callback,
            &progress.state,
            &progress.phase,
            &progress.base_message,
            root_dir,
            Some(remote_index),
            progress.last_success_unix_ms,
        )
        .context("failed to scan local root")?,
        None => scan_local_tree(root_dir).context("failed to scan local root")?,
    };
    let diff = diff_local_trees(local_state, &current);
    let mut outcome = LocalSyncOutcome {
        changed_path_count: diff.created_directories.len()
            + diff.created_or_modified_files.len()
            + diff.deleted_paths.len(),
        ..LocalSyncOutcome::default()
    };

    for path in &diff.created_directories {
        if remote_index.directories.contains(path) {
            continue;
        }

        ensure_remote_directory_marker(client, scope, path)?;
        outcome.ensured_directory_count += 1;
        remote_index.directories.insert(path.clone());
        if let Some(store) = state_store
            && let Some(entry_state) = current.get(path)
        {
            store
                .upsert_baseline_entry(path, entry_state)
                .with_context(|| {
                    format!("failed to persist baseline directory entry for {path}")
                })?;
        }
        tracing::info!("local-sync: uploaded directory marker {path}/");
    }

    for path in &diff.created_or_modified_files {
        let Some(entry_state) = current.get(path) else {
            continue;
        };

        if let Some(expected) = suppressed_uploads.get(path)
            && expected == entry_state
        {
            suppressed_uploads.remove(path);
            continue;
        }

        let content_hash =
            upload_local_file(root_dir, client, scope, path, entry_state.size_bytes)?;
        outcome.uploaded_file_count += 1;
        remote_index.files.insert(path.clone());
        for parent in parent_directories(path) {
            remote_index.directories.insert(parent);
        }
        if let Some(store) = state_store {
            store
                .upsert_baseline_entry_with_hash(path, entry_state, Some(content_hash.as_str()))
                .with_context(|| format!("failed to persist baseline file entry for {path}"))?;
        }
        tracing::info!("local-sync: uploaded file {path}");
    }

    if !diff.deleted_paths.is_empty() {
        let mut deleted_paths = diff.deleted_paths.clone();
        deleted_paths.sort_by(|left, right| {
            right
                .matches('/')
                .count()
                .cmp(&left.matches('/').count())
                .then_with(|| right.cmp(left))
        });

        for path in deleted_paths {
            let Some(previous) = local_state.get(&path) else {
                continue;
            };

            if previous.kind != LocalEntryKind::File {
                suppressed_uploads.remove(&path);
                continue;
            }
            let known_remote_file =
                remote_index.files.contains(&path) || suppressed_uploads.contains_key(&path);
            if !known_remote_file {
                suppressed_uploads.remove(&path);
                continue;
            }

            delete_remote_file(client, scope, &path)?;
            outcome.deleted_remote_file_count += 1;
            suppressed_uploads.remove(&path);
            remote_index.files.remove(&path);
            if let Some(store) = state_store {
                store
                    .remove_baseline_entry(&path)
                    .with_context(|| format!("failed to remove baseline entry for {path}"))?;
            }
            tracing::info!("local-sync: deleted remote file {path}");
        }
    }

    *local_state = current;
    Ok(outcome)
}

#[allow(clippy::too_many_arguments)]
fn apply_remote_snapshot(
    root_dir: &Path,
    client: &IronMeshClient,
    snapshot: &SyncSnapshot,
    changed_paths: Option<&[String]>,
    preserve_local_files: Option<&BTreeSet<String>>,
    state_store: Option<&StartupStateStore>,
    scope: &PathScope,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    remote_index: &mut RemoteTreeIndex,
) -> Result<RemoteApplyOutcome> {
    let mut outcome = RemoteApplyOutcome::default();
    let mut next_index = RemoteTreeIndex::default();
    let mut entry_kinds: BTreeMap<String, (EntryKind, String)> = BTreeMap::new();
    let mut entry_hashes: BTreeMap<String, String> = BTreeMap::new();

    for entry in &snapshot.remote {
        let remote_path = crate::normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }

        match entry.kind {
            EntryKind::Directory => {
                next_index.directories.insert(local_path.clone());
            }
            EntryKind::File => {
                next_index.files.insert(local_path.clone());
                if let Some(content_hash) = entry.content_hash.as_deref()
                    && !content_hash.trim().is_empty()
                {
                    entry_hashes.insert(local_path.clone(), content_hash.to_string());
                }
            }
        }
        entry_kinds.insert(local_path, (entry.kind, remote_path));
    }

    match changed_paths {
        Some(changed_paths) => {
            let mut changed_local_paths = BTreeSet::new();
            for changed in changed_paths {
                let Some(path) = scope.remote_to_local(changed) else {
                    continue;
                };
                if path.is_empty() {
                    continue;
                }
                changed_local_paths.insert(path);
            }

            for path in changed_local_paths {
                let path = path.as_str();

                match entry_kinds.get(path) {
                    Some((EntryKind::Directory, _)) => {
                        outcome.changed_path_count += 1;
                        outcome.ensured_directory_count += 1;
                        let directory = absolute_path(root_dir, path);
                        fs::create_dir_all(&directory).with_context(|| {
                            format!(
                                "failed to materialize remote directory {}",
                                directory.display()
                            )
                        })?;
                        if let Some(store) = state_store
                            && let Some(entry_state) = local_entry_state_for_path(root_dir, path)?
                        {
                            store
                                .upsert_baseline_entry(path, &entry_state)
                                .with_context(|| {
                                    format!("failed to persist baseline directory entry for {path}")
                                })?;
                        }
                    }
                    Some((EntryKind::File, remote_key)) => {
                        outcome.changed_path_count += 1;
                        outcome.downloaded_file_count += 1;
                        let content_hash = entry_hashes.get(path).map(|hash| hash.as_str());
                        download_remote_file(
                            root_dir,
                            client,
                            path,
                            remote_key,
                            content_hash,
                            state_store,
                        )?;
                        if let Some(entry_state) = local_entry_state_for_path(root_dir, path)? {
                            suppressed_uploads.insert(path.to_string(), entry_state);
                        }
                    }
                    None => {
                        outcome.changed_path_count += 1;
                        outcome.removed_local_path_count += 1;
                        remove_local_path(root_dir, path)?;
                        suppressed_uploads.remove(path);
                        if let Some(store) = state_store {
                            store.remove_baseline_entry(path).with_context(|| {
                                format!("failed to remove baseline entry for {path}")
                            })?;
                        }
                    }
                }
            }
            *remote_index = next_index;
        }
        None => {
            for directory in &next_index.directories {
                outcome.changed_path_count += 1;
                outcome.ensured_directory_count += 1;
                let absolute = absolute_path(root_dir, directory);
                fs::create_dir_all(&absolute).with_context(|| {
                    format!(
                        "failed to materialize remote directory {}",
                        absolute.display()
                    )
                })?;
                if let Some(store) = state_store
                    && let Some(entry_state) = local_entry_state_for_path(root_dir, directory)?
                {
                    store
                        .upsert_baseline_entry(directory, &entry_state)
                        .with_context(|| {
                            format!(
                                "failed to persist baseline directory entry for {}",
                                directory
                            )
                        })?;
                }
            }

            for file in &next_index.files {
                let Some((EntryKind::File, remote_key)) = entry_kinds.get(file) else {
                    continue;
                };
                if preserve_local_files.is_some_and(|set| set.contains(file))
                    && local_entry_state_for_path(root_dir, file)?
                        .is_some_and(|entry| entry.kind == LocalEntryKind::File)
                {
                    continue;
                }
                outcome.changed_path_count += 1;
                outcome.downloaded_file_count += 1;
                let content_hash = entry_hashes.get(file).map(|hash| hash.as_str());
                download_remote_file(
                    root_dir,
                    client,
                    file,
                    remote_key,
                    content_hash,
                    state_store,
                )?;
                if let Some(entry_state) = local_entry_state_for_path(root_dir, file)? {
                    suppressed_uploads.insert(file.clone(), entry_state);
                }
            }

            *remote_index = next_index;
        }
    }

    Ok(outcome)
}

fn usize_to_u64(value: usize) -> u64 {
    value.try_into().unwrap_or(u64::MAX)
}

fn watch_mode_label(options: &FolderAgentRuntimeOptions) -> &'static str {
    if options.run_once {
        "not-watching"
    } else if options.no_watch_local {
        "polling-only"
    } else {
        "fs-notify+polling"
    }
}

const BLOCKING_STATUS_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
const LOCAL_SCAN_PROGRESS_INTERVAL: Duration = Duration::from_millis(750);
const LOCAL_SCAN_PROGRESS_ENTRY_STRIDE: u64 = 256;
const REMOTE_FETCH_PROGRESS_INTERVAL: Duration = Duration::from_millis(750);
const REMOTE_FETCH_PROGRESS_ENTRY_STRIDE: u64 = 512;

fn run_with_status_heartbeat<T, F>(
    callback: Option<FolderAgentStatusCallback>,
    progress: BlockingStatusProgress,
    operation: F,
) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let progress_thread = callback.map(|callback| {
        let progress = progress.clone();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let handle = thread::Builder::new()
            .name("ironmesh-folder-status-heartbeat".to_string())
            .spawn(move || {
                let started = Instant::now();
                loop {
                    match done_rx.recv_timeout(BLOCKING_STATUS_HEARTBEAT_INTERVAL) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            callback(FolderAgentRuntimeStatus::new(
                                &progress.options,
                                progress.connection_target.as_deref(),
                                &progress.storage_mode,
                                &progress.watch_mode,
                                progress.state.clone(),
                                progress.phase.clone(),
                                progress.activity.clone(),
                                blocking_progress_message(
                                    &progress.base_message,
                                    started.elapsed(),
                                ),
                                progress.metrics.clone(),
                                progress.last_success_unix_ms,
                                progress.last_error.clone(),
                            ));
                        }
                    }
                }
            });
        (done_tx, handle)
    });

    let result = operation();

    if let Some((done_tx, progress_thread)) = progress_thread {
        let _ = done_tx.send(());
        if let Ok(handle) = progress_thread {
            let _ = handle.join();
        }
    }

    result
}

fn scan_local_tree_with_status_progress(
    options: &FolderAgentRuntimeOptions,
    connection_target: &str,
    watch_mode: &str,
    status_callback: Option<&FolderAgentStatusCallback>,
    state: &str,
    phase: &str,
    base_message: &str,
    root: &Path,
    remote_index: Option<&RemoteTreeIndex>,
    last_success_unix_ms: Option<u64>,
) -> Result<LocalTreeState> {
    let Some(callback) = status_callback.cloned() else {
        return scan_local_tree(root);
    };

    let last_reported_at = Arc::new(Mutex::new(Instant::now() - LOCAL_SCAN_PROGRESS_INTERVAL));
    let last_reported_entry_count = Arc::new(AtomicU64::new(0));

    scan_local_tree_with_progress(root, {
        let callback = callback.clone();
        let options = options.clone();
        let connection_target = connection_target.to_string();
        let watch_mode = watch_mode.to_string();
        let remote_metrics = FolderAgentRuntimeMetrics::from_states(None, remote_index);
        let last_reported_at = last_reported_at.clone();
        let last_reported_entry_count = last_reported_entry_count.clone();

        move |progress| {
            let should_report = {
                let previous_entry_count = last_reported_entry_count.load(Ordering::SeqCst);
                let enough_entries = progress.scanned_entry_count
                    >= previous_entry_count.saturating_add(LOCAL_SCAN_PROGRESS_ENTRY_STRIDE);
                let enough_time = last_reported_at
                    .lock()
                    .map(|instant| instant.elapsed() >= LOCAL_SCAN_PROGRESS_INTERVAL)
                    .unwrap_or(true);
                enough_entries || enough_time || progress.pending_directory_count == 0
            };

            if !should_report {
                return;
            }

            last_reported_entry_count.store(progress.scanned_entry_count, Ordering::SeqCst);
            if let Ok(mut instant) = last_reported_at.lock() {
                *instant = Instant::now();
            }

            let mut metrics = remote_metrics.clone();
            apply_local_scan_progress_metrics(&mut metrics, progress);
            callback(FolderAgentRuntimeStatus::new(
                &options,
                Some(&connection_target),
                "filesystem",
                &watch_mode,
                state.to_string(),
                phase.to_string(),
                "scanning-local-tree".to_string(),
                format_local_scan_progress_message(base_message, progress),
                metrics,
                last_success_unix_ms,
                None,
            ));
        }
    })
}

fn apply_local_scan_progress_metrics(
    metrics: &mut FolderAgentRuntimeMetrics,
    progress: &LocalTreeScanProgress,
) {
    metrics.local_entry_count = progress.scanned_entry_count;
    metrics.local_directory_count = progress.scanned_directory_count;
    metrics.local_file_count = progress
        .scanned_entry_count
        .saturating_sub(progress.scanned_directory_count);
}

fn format_local_scan_progress_message(
    base_message: &str,
    progress: &LocalTreeScanProgress,
) -> String {
    let current_path = progress.current_path.as_deref().unwrap_or("<complete>");
    format!(
        "{base_message}: {} entrie(s) examined, {} directorie(s) visited, {} directorie(s) pending, current={current_path}",
        progress.scanned_entry_count,
        progress.scanned_directory_count,
        progress.pending_directory_count,
    )
}

fn fetch_remote_snapshot_with_status_progress(
    options: &FolderAgentRuntimeOptions,
    connection_target: &str,
    storage_mode: &str,
    watch_mode: &str,
    status_callback: Option<&FolderAgentStatusCallback>,
    state: &str,
    phase: &str,
    activity: &str,
    base_message: &str,
    fetcher: &RemoteSnapshotFetcher,
    base_metrics: FolderAgentRuntimeMetrics,
    last_success_unix_ms: Option<u64>,
    restore_idle_message: Option<&str>,
) -> Result<SyncSnapshot> {
    let Some(callback) = status_callback.cloned() else {
        return fetcher.fetch_snapshot_blocking();
    };

    let mut last_reported_at = Instant::now() - REMOTE_FETCH_PROGRESS_INTERVAL;
    let mut last_reported_processed = 0u64;
    let detailed_progress = restore_idle_message.is_none();

    let snapshot = run_with_status_heartbeat(
        Some(callback.clone()),
        BlockingStatusProgress {
            options: options.clone(),
            connection_target: Some(connection_target.to_string()),
            storage_mode: storage_mode.to_string(),
            watch_mode: watch_mode.to_string(),
            state: state.to_string(),
            phase: phase.to_string(),
            activity: activity.to_string(),
            base_message: base_message.to_string(),
            metrics: base_metrics.clone(),
            last_success_unix_ms,
            last_error: None,
        },
        || {
            fetcher.fetch_snapshot_blocking_with_progress(|progress| {
                let should_report = progress.phase != "building-snapshot"
                    || progress.processed_entry_count == progress.entry_count
                    || progress.processed_entry_count
                        >= last_reported_processed
                            .saturating_add(REMOTE_FETCH_PROGRESS_ENTRY_STRIDE)
                    || last_reported_at.elapsed() >= REMOTE_FETCH_PROGRESS_INTERVAL;

                if !should_report {
                    return;
                }

                last_reported_at = Instant::now();
                last_reported_processed = progress.processed_entry_count;

                let mut metrics = base_metrics.clone();
                if detailed_progress {
                    apply_remote_fetch_progress_metrics(&mut metrics, &progress);
                }
                callback(FolderAgentRuntimeStatus::new(
                    options,
                    Some(connection_target),
                    storage_mode,
                    watch_mode,
                    state.to_string(),
                    phase.to_string(),
                    activity.to_string(),
                    format_remote_fetch_progress_message(base_message, &progress, detailed_progress),
                    metrics,
                    last_success_unix_ms,
                    None,
                ));
            })
        },
    )?;

    if let Some(idle_message) = restore_idle_message {
        callback(FolderAgentRuntimeStatus::new(
            options,
            Some(connection_target),
            storage_mode,
            watch_mode,
            "running",
            phase,
            "watching-for-changes",
            idle_message,
            base_metrics,
            last_success_unix_ms,
            None,
        ));
    }

    Ok(snapshot)
}

fn apply_remote_fetch_progress_metrics(
    metrics: &mut FolderAgentRuntimeMetrics,
    progress: &RemoteSnapshotFetchProgress,
) {
    metrics.remote_entry_count = progress.entry_count;
    metrics.remote_file_count = progress.file_count;
    metrics.remote_directory_count = progress.directory_count;
}

fn format_remote_fetch_progress_message(
    base_message: &str,
    progress: &RemoteSnapshotFetchProgress,
    detailed_progress: bool,
) -> String {
    if !detailed_progress {
        return match progress.phase.as_str() {
            "requesting-store-index" => base_message.to_string(),
            "received-store-index" => {
                format!("{base_message}: received remote snapshot header")
            }
            "building-snapshot" => {
                format!("{base_message}: rebuilding remote comparison view")
            }
            "completed" => format!("{base_message}: remote snapshot check complete"),
            _ => base_message.to_string(),
        };
    }

    match progress.phase.as_str() {
        "requesting-store-index" => format!("{base_message}: requesting store index from server"),
        "received-store-index" => format!(
            "{base_message}: received store index metadata for {} entrie(s)",
            progress.entry_count
        ),
        "building-snapshot" => format!(
            "{base_message}: normalized {} / {} entrie(s) ({} file(s), {} directorie(s)); current={}",
            progress.processed_entry_count,
            progress.entry_count,
            progress.file_count,
            progress.directory_count,
            progress.current_path.as_deref().unwrap_or("<none>"),
        ),
        "completed" => format!(
            "{base_message}: snapshot ready with {} entrie(s) ({} file(s), {} directorie(s))",
            progress.entry_count,
            progress.file_count,
            progress.directory_count,
        ),
        _ => base_message.to_string(),
    }
}

fn blocking_progress_message(base_message: &str, elapsed: Duration) -> String {
    format!(
        "{base_message} (still working, {} elapsed)",
        format_elapsed_duration(elapsed)
    )
}

fn format_elapsed_duration(elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        let minutes = seconds / 60;
        let remaining_seconds = seconds % 60;
        format!("{minutes}m {remaining_seconds}s")
    }
}

fn set_latest_metrics(
    latest_metrics: &Arc<Mutex<FolderAgentRuntimeMetrics>>,
    metrics: &FolderAgentRuntimeMetrics,
) {
    if let Ok(mut current) = latest_metrics.lock() {
        *current = metrics.clone();
    }
}

fn latest_metrics_value(
    latest_metrics: &Arc<Mutex<FolderAgentRuntimeMetrics>>,
) -> FolderAgentRuntimeMetrics {
    latest_metrics.lock().map(|metrics| metrics.clone()).unwrap_or_default()
}

fn store_optional_unix_ms(target: &AtomicU64, value: Option<u64>) {
    target.store(value.unwrap_or(0), Ordering::SeqCst);
}

fn load_optional_unix_ms(target: &AtomicU64) -> Option<u64> {
    match target.load(Ordering::SeqCst) {
        0 => None,
        value => Some(value),
    }
}

fn format_local_sync_summary(outcome: LocalSyncOutcome) -> String {
    let mut parts = Vec::new();
    if outcome.uploaded_file_count > 0 {
        parts.push(format!("{} upload(s)", outcome.uploaded_file_count));
    }
    if outcome.deleted_remote_file_count > 0 {
        parts.push(format!(
            "{} remote delete(s)",
            outcome.deleted_remote_file_count
        ));
    }
    if outcome.ensured_directory_count > 0 {
        parts.push(format!(
            "{} directory marker upload(s)",
            outcome.ensured_directory_count
        ));
    }

    if parts.is_empty() {
        "no local uploads or deletes were needed".to_string()
    } else {
        parts.join(", ")
    }
}

fn format_remote_apply_summary(outcome: RemoteApplyOutcome) -> String {
    let mut parts = Vec::new();
    if outcome.downloaded_file_count > 0 {
        parts.push(format!("{} download(s)", outcome.downloaded_file_count));
    }
    if outcome.ensured_directory_count > 0 {
        parts.push(format!(
            "{} directory materialization(s)",
            outcome.ensured_directory_count
        ));
    }
    if outcome.removed_local_path_count > 0 {
        parts.push(format!(
            "{} local removal(s)",
            outcome.removed_local_path_count
        ));
    }

    if parts.is_empty() {
        "no remote materialization was needed".to_string()
    } else {
        parts.join(", ")
    }
}

fn download_remote_file(
    root_dir: &Path,
    client: &IronMeshClient,
    local_relative_path: &str,
    remote_key: &str,
    remote_content_hash: Option<&str>,
    state_store: Option<&StartupStateStore>,
) -> Result<()> {
    let target = absolute_path(root_dir, local_relative_path);
    let temp_path = download_transfer_temp_path(root_dir, remote_key);
    let state_path = download_transfer_state_path(root_dir, remote_key);

    if target.is_dir() {
        fs::remove_dir_all(&target)
            .with_context(|| format!("failed to remove local directory {}", target.display()))?;
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }
    client
        .download_file_resumable(remote_key, None, None, &target, &temp_path, &state_path)
        .with_context(|| format!("failed to download remote file {remote_key}"))?;

    if let Some(store) = state_store {
        let metadata = fs::metadata(&target)
            .with_context(|| format!("failed to inspect downloaded file {}", target.display()))?;
        let entry_state = local_entry_state_from_metadata(&metadata);
        store
            .upsert_baseline_entry_with_hash(local_relative_path, &entry_state, remote_content_hash)
            .with_context(|| {
                format!("failed to persist baseline file entry for {local_relative_path}")
            })?;
    }

    Ok(())
}

fn ensure_remote_directory_marker(
    client: &IronMeshClient,
    scope: &PathScope,
    directory_path: &str,
) -> Result<()> {
    let Some(remote_directory) = scope.local_to_remote(directory_path) else {
        return Ok(());
    };

    let marker_key = format!("{}/", remote_directory);
    let mut empty = Cursor::new(Vec::<u8>::new());
    client
        .put_large_aware_reader(marker_key, &mut empty, 0)
        .with_context(|| format!("failed to upload directory marker for {remote_directory}"))?;

    Ok(())
}

fn local_entry_state_from_metadata(metadata: &fs::Metadata) -> LocalEntryState {
    let kind = if metadata.is_dir() {
        LocalEntryKind::Directory
    } else {
        LocalEntryKind::File
    };
    let modified_unix_ms = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis())
        .unwrap_or(0);

    LocalEntryState {
        kind,
        size_bytes: metadata.len(),
        modified_unix_ms,
    }
}
