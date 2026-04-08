use anyhow::{Context, Result};
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope,
    RemoteSnapshotUpdate,
};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_core::{EntryKind, SyncSnapshot};

use crate::{
    FolderAgentUiState, LocalEntryKind, LocalEntryState, LocalTreeState, PathScope,
    RemoteTreeIndex, StartupStateStore, absolute_path, build_configured_client,
    cleanup_ironmesh_part_files, delete_remote_file, describe_connection_target, diff_local_trees,
    download_transfer_state_path, download_transfer_temp_path,
    load_local_baseline_hashes_with_retries, load_local_baseline_with_retries,
    local_entry_state_for_path, local_paths_to_preserve_on_startup,
    materialize_remote_conflict_copies, parent_directories, remote_file_hashes_by_local_path,
    remote_file_paths_by_local_path, remove_local_path, scan_local_tree, spawn_ui_server,
    startup_add_delete_conflicts, startup_baseline_state_from_remote_index,
    startup_dual_modify_conflicts, startup_remote_delete_wins_paths, upload_local_file,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderAgentRuntimeStatus {
    pub state: String,
    pub message: String,
    pub updated_unix_ms: u64,
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
        "starting",
        format!(
            "Starting folder sync runtime for prefix={prefix_label} root={}",
            options.root_dir.display()
        ),
    );
    let result = run_folder_agent_inner(
        options,
        running,
        install_signal_handler,
        status_callback.clone(),
    );

    match &result {
        Ok(()) => emit_status(
            status_callback.as_ref(),
            "stopped",
            if options.run_once {
                "Folder sync run completed"
            } else {
                "Folder sync runtime stopped"
            },
        ),
        Err(error) => emit_status(
            status_callback.as_ref(),
            "error",
            format!("Folder sync runtime failed: {error:#}"),
        ),
    }

    result
}

fn run_folder_agent_inner(
    options: &FolderAgentRuntimeOptions,
    running: Arc<AtomicBool>,
    install_signal_handler: bool,
    status_callback: Option<FolderAgentStatusCallback>,
) -> Result<()> {
    let scope = PathScope::new(options.prefix.clone());
    let connection_target = describe_connection_target(
        options.server_base_url.as_deref(),
        options.client_bootstrap_json.as_deref(),
    )?;
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
        "starting",
        "Fetching initial remote snapshot",
    );
    let local_state_before_remote_sync = scan_local_tree(&options.root_dir)
        .context("failed to scan local state before initial remote sync")?;
    let local_scan_sample = sample_local_paths(&local_state_before_remote_sync, 5);
    emit_status(
        status_callback.as_ref(),
        "starting",
        format!(
            "Initial local scan found {} path(s) under root={} sample=[{}]",
            local_state_before_remote_sync.len(),
            options.root_dir.display(),
            local_scan_sample
        ),
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

    let initial_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope.clone());
    let initial_snapshot = initial_fetcher
        .fetch_snapshot_blocking()
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

    let mut remote_index = RemoteTreeIndex::default();
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    apply_remote_snapshot(
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

    let mut local_state = scan_local_tree(&options.root_dir)
        .context("failed to scan local state after initial remote sync")?;
    local_state = startup_baseline_state_from_remote_index(
        &local_state,
        &remote_index,
        &preserve_local_files,
    );
    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after remote apply during startup")?;

    sync_local_changes(
        &options.root_dir,
        &client,
        &mut local_state,
        Some(&state_store),
        &scope,
        &mut remote_index,
        &mut suppressed_uploads,
    )?;

    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after startup reconciliation")?;
    state_store
        .persist_startup_conflicts(&startup_conflicts)
        .context("failed to persist startup conflicts")?;

    if options.run_once {
        return Ok(());
    }

    if install_signal_handler {
        install_ctrlc_handler(running.clone())?;
    }
    emit_status(
        status_callback.as_ref(),
        "running",
        "Initial sync complete; watching for changes",
    );

    let refresh_interval = Duration::from_millis(options.remote_refresh_interval_ms.max(250));
    let local_scan_interval = Duration::from_millis(options.local_scan_interval_ms.max(250));

    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope);

    let (remote_tx, remote_rx) = mpsc::channel::<RemoteSnapshotUpdate>();
    let remote_running = running.clone();
    let remote_stop_signal = running.clone();
    let remote_thread = refresh_poller.spawn_fetcher_loop(
        remote_running,
        Some(initial_snapshot),
        refresh_fetcher,
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
        while let Ok(update) = remote_rx.try_recv() {
            emit_status(
                status_callback.as_ref(),
                "syncing",
                format!("Applying {} remote change(s)", update.changed_paths.len()),
            );
            apply_remote_snapshot(
                &options.root_dir,
                &client,
                &update.snapshot,
                Some(&update.changed_paths),
                None,
                Some(&state_store),
                &scope,
                &mut suppressed_uploads,
                &mut remote_index,
            )?;
            remote_updates_applied = true;
        }

        if remote_updates_applied {
            local_state = scan_local_tree(&options.root_dir)
                .context("failed to rescan local state after remote update")?;
            baseline_dirty = true;
        }

        let mut local_scan_requested = false;
        while local_event_rx.try_recv().is_ok() {
            local_scan_requested = true;
        }

        if local_scan_requested || Instant::now() >= next_local_scan {
            let previous_local_state = local_state.clone();
            emit_status(
                status_callback.as_ref(),
                "syncing",
                "Scanning local files for changes",
            );
            sync_local_changes(
                &options.root_dir,
                &client,
                &mut local_state,
                Some(&state_store),
                &scope,
                &mut remote_index,
                &mut suppressed_uploads,
            )?;
            if local_state != previous_local_state {
                baseline_dirty = true;
            }
            next_local_scan = Instant::now() + local_scan_interval;
            emit_status(status_callback.as_ref(), "running", "Watching for changes");
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
    Ok(())
}

fn emit_status(
    callback: Option<&FolderAgentStatusCallback>,
    state: impl Into<String>,
    message: impl Into<String>,
) {
    let Some(callback) = callback else {
        return;
    };
    callback(FolderAgentRuntimeStatus {
        state: state.into(),
        message: message.into(),
        updated_unix_ms: now_unix_ms(),
    });
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
) -> Result<()> {
    let current = scan_local_tree(root_dir).context("failed to scan local root")?;
    let diff = diff_local_trees(local_state, &current);

    for path in &diff.created_directories {
        if remote_index.directories.contains(path) {
            continue;
        }

        ensure_remote_directory_marker(client, scope, path)?;
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
    Ok(())
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
) -> Result<()> {
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

    Ok(())
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
