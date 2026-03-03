use anyhow::{Context, Result, bail};
use clap::Parser;
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotUpdate,
    normalize_server_base_url,
};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::{Connection, params};
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_agent_core::{
    LocalEntryKind, LocalEntryState, LocalTreeState, RemoteTreeIndex, absolute_path,
    diff_local_trees, local_entry_state_for_path, normalize_relative_path, scan_local_tree,
};
use sync_core::{EntryKind, SyncSnapshot};

#[derive(Debug, Parser)]
#[command(name = "ironmesh-folder-agent")]
#[command(about = "OS-independent folder synchronization agent for Ironmesh")]
struct Args {
    #[arg(long)]
    root_dir: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_base_url: String,
    #[arg(long)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64)]
    depth: usize,
    #[arg(long, default_value_t = 3000)]
    remote_refresh_interval_ms: u64,
    #[arg(long, default_value_t = 2000)]
    local_scan_interval_ms: u64,
    #[arg(long, default_value_t = false)]
    no_watch_local: bool,
    #[arg(long, default_value_t = false)]
    run_once: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let scope = PathScope::new(args.prefix.clone());
    let base_url = normalize_server_base_url(&args.server_base_url)?;
    let state_store = StartupStateStore::new(&args.root_dir, &scope, base_url.as_str());

    fs::create_dir_all(&args.root_dir).with_context(|| {
        format!(
            "failed to create root directory {}",
            args.root_dir.display()
        )
    })?;

    let local_state_before_remote_sync = scan_local_tree(&args.root_dir)
        .context("failed to scan local state before initial remote sync")?;

    let baseline_before_remote_sync = match state_store.load_local_baseline() {
        Ok(state) => Some(state),
        Err(error) => {
            eprintln!("startup-state: failed to load sqlite baseline: {error}");
            state_store.quarantine_corrupt().ok();
            None
        }
    };

    let preserve_local_files = local_paths_to_preserve_on_startup(
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
    );

    let client = IronMeshClient::new(base_url.as_str());

    let initial_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        scope.remote_prefix().map(ToString::to_string),
        args.depth,
        None,
    );
    let initial_snapshot = initial_fetcher
        .fetch_snapshot_blocking()
        .context("failed to fetch initial remote snapshot")?;

    let mut remote_index = RemoteTreeIndex::default();
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    apply_remote_snapshot(
        &args.root_dir,
        &client,
        &initial_snapshot,
        None,
        Some(&preserve_local_files),
        &scope,
        &mut suppressed_uploads,
        &mut remote_index,
    )?;

    let mut local_state = scan_local_tree(&args.root_dir)
        .context("failed to scan local state after initial remote sync")?;
    local_state = startup_baseline_state_from_remote_index(
        &local_state,
        &remote_index,
        &preserve_local_files,
    );

    sync_local_changes(
        &args.root_dir,
        &client,
        &mut local_state,
        &scope,
        &mut remote_index,
        &mut suppressed_uploads,
    )?;

    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after startup reconciliation")?;

    if args.run_once {
        return Ok(());
    }

    let running = Arc::new(AtomicBool::new(true));
    install_ctrlc_handler(running.clone())?;

    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let local_scan_interval = Duration::from_millis(args.local_scan_interval_ms.max(250));

    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        scope.remote_prefix().map(ToString::to_string),
        args.depth,
        None,
    );

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
    let _watcher = if args.no_watch_local {
        None
    } else {
        Some(start_local_watcher(args.root_dir.clone(), local_event_tx)?)
    };

    let mut next_local_scan = Instant::now() + local_scan_interval;

    while running.load(Ordering::SeqCst) {
        let mut baseline_dirty = false;
        let mut remote_updates_applied = false;
        while let Ok(update) = remote_rx.try_recv() {
            apply_remote_snapshot(
                &args.root_dir,
                &client,
                &update.snapshot,
                Some(&update.changed_paths),
                None,
                &scope,
                &mut suppressed_uploads,
                &mut remote_index,
            )?;
            remote_updates_applied = true;
        }

        if remote_updates_applied {
            local_state = scan_local_tree(&args.root_dir)
                .context("failed to rescan local state after remote update")?;
            baseline_dirty = true;
        }

        let mut local_scan_requested = false;
        while local_event_rx.try_recv().is_ok() {
            local_scan_requested = true;
        }

        if local_scan_requested || Instant::now() >= next_local_scan {
            let previous_local_state = local_state.clone();
            sync_local_changes(
                &args.root_dir,
                &client,
                &mut local_state,
                &scope,
                &mut remote_index,
                &mut suppressed_uploads,
            )?;
            if local_state != previous_local_state {
                baseline_dirty = true;
            }
            next_local_scan = Instant::now() + local_scan_interval;
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

fn install_ctrlc_handler(running: Arc<AtomicBool>) -> Result<()> {
    ctrlc::set_handler(move || {
        running.store(false, Ordering::SeqCst);
    })
    .context("failed to install Ctrl+C handler")
}

fn local_paths_to_preserve_on_startup(
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
) -> BTreeSet<String> {
    let mut preserve = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let unchanged = baseline
            .and_then(|state| state.get(path))
            .is_some_and(|previous| previous == entry_state);

        if !unchanged {
            preserve.insert(path.clone());
        }
    }

    preserve
}

fn startup_baseline_state_from_remote_index(
    local_state: &LocalTreeState,
    remote_index: &RemoteTreeIndex,
    excluded_paths: &BTreeSet<String>,
) -> LocalTreeState {
    let mut baseline = LocalTreeState::new();

    for path in &remote_index.directories {
        if excluded_paths.contains(path) {
            continue;
        }
        if let Some(entry_state) = local_state.get(path)
            && entry_state.kind == LocalEntryKind::Directory
        {
            baseline.insert(path.clone(), entry_state.clone());
        }
    }

    for path in &remote_index.files {
        if excluded_paths.contains(path) {
            continue;
        }
        if let Some(entry_state) = local_state.get(path)
            && entry_state.kind == LocalEntryKind::File
        {
            baseline.insert(path.clone(), entry_state.clone());
        }
    }

    baseline
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
                eprintln!("local-watch: event error: {error}");
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
        eprintln!("local-sync: uploaded directory marker {path}/");
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

        upload_local_file(root_dir, client, scope, path, entry_state.size_bytes)?;
        remote_index.files.insert(path.clone());
        for parent in parent_directories(path) {
            remote_index.directories.insert(parent);
        }
        eprintln!("local-sync: uploaded file {path}");
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
            eprintln!("local-sync: deleted remote file {path}");
        }
    }

    *local_state = current;
    Ok(())
}

fn apply_remote_snapshot(
    root_dir: &Path,
    client: &IronMeshClient,
    snapshot: &SyncSnapshot,
    changed_paths: Option<&[String]>,
    preserve_local_files: Option<&BTreeSet<String>>,
    scope: &PathScope,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    remote_index: &mut RemoteTreeIndex,
) -> Result<()> {
    let mut next_index = RemoteTreeIndex::default();
    let mut entry_kinds: BTreeMap<String, (EntryKind, String)> = BTreeMap::new();

    for entry in &snapshot.remote {
        let remote_path = normalize_relative_path(&entry.path);
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
                    }
                    Some((EntryKind::File, remote_key)) => {
                        download_remote_file(root_dir, client, path, remote_key)?;
                        if let Some(entry_state) = local_entry_state_for_path(root_dir, path)? {
                            suppressed_uploads.insert(path.to_string(), entry_state);
                        }
                    }
                    None => {
                        remove_local_path(root_dir, path)?;
                        suppressed_uploads.remove(path);
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
                download_remote_file(root_dir, client, file, remote_key)?;
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
) -> Result<()> {
    let target = absolute_path(root_dir, local_relative_path);

    if target.is_dir() {
        fs::remove_dir_all(&target)
            .with_context(|| format!("failed to remove local directory {}", target.display()))?;
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }

    let temp_name = format!(
        ".{}.ironmesh-part-{}",
        target
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "object".to_string()),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temp_path = target.with_file_name(temp_name);

    let mut file = File::create(&temp_path)
        .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
    client
        .get_with_selector_writer(remote_key, None, None, &mut file)
        .with_context(|| format!("failed to download remote file {remote_key}"))?;

    file.sync_all()
        .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;

    fs::rename(&temp_path, &target).with_context(|| {
        format!(
            "failed to place downloaded file {} into {}",
            temp_path.display(),
            target.display()
        )
    })?;

    Ok(())
}

fn upload_local_file(
    root_dir: &Path,
    client: &IronMeshClient,
    scope: &PathScope,
    relative_path: &str,
    size_bytes: u64,
) -> Result<()> {
    let absolute = absolute_path(root_dir, relative_path);
    let mut file = File::open(&absolute)
        .with_context(|| format!("failed to open local file {}", absolute.display()))?;

    let remote_key = scope.local_to_remote(relative_path).ok_or_else(|| {
        anyhow::anyhow!("refusing to upload local root without concrete scoped path")
    })?;

    client
        .put_large_aware_reader(remote_key.clone(), &mut file, size_bytes)
        .with_context(|| format!("failed to upload local file {relative_path} to {remote_key}"))?;

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

fn delete_remote_file(client: &IronMeshClient, scope: &PathScope, file_path: &str) -> Result<()> {
    let Some(remote_key) = scope.local_to_remote(file_path) else {
        return Ok(());
    };

    client
        .delete_path_blocking(&remote_key)
        .with_context(|| format!("failed to delete remote file {remote_key}"))?;

    Ok(())
}

fn remove_local_path(root_dir: &Path, relative_path: &str) -> Result<()> {
    let absolute = absolute_path(root_dir, relative_path);

    match fs::metadata(&absolute) {
        Ok(metadata) => {
            if metadata.is_dir() {
                fs::remove_dir_all(&absolute).with_context(|| {
                    format!("failed to remove local directory {}", absolute.display())
                })?;
            } else {
                fs::remove_file(&absolute).with_context(|| {
                    format!("failed to remove local file {}", absolute.display())
                })?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect local path {}", absolute.display()));
        }
    }

    Ok(())
}

fn parent_directories(path: &str) -> Vec<String> {
    let normalized = normalize_relative_path(path);
    if normalized.is_empty() {
        return Vec::new();
    }

    let segments: Vec<&str> = normalized.split('/').collect();
    let mut directories = Vec::new();
    if segments.len() < 2 {
        return directories;
    }

    for index in 1..segments.len() {
        directories.push(segments[..index].join("/"));
    }
    directories
}

#[derive(Debug, Clone)]
struct PathScope {
    prefix: Option<String>,
}

impl PathScope {
    fn new(prefix: Option<String>) -> Self {
        Self {
            prefix: prefix
                .map(|value| normalize_relative_path(&value))
                .filter(|value| !value.is_empty()),
        }
    }

    fn remote_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    fn remote_to_local(&self, remote_path: &str) -> Option<String> {
        let normalized = normalize_relative_path(remote_path);
        if normalized.is_empty() {
            return None;
        }

        match &self.prefix {
            None => Some(normalized),
            Some(prefix) => {
                if normalized == *prefix {
                    return Some(String::new());
                }

                let scoped_prefix = format!("{prefix}/");
                normalized
                    .strip_prefix(&scoped_prefix)
                    .map(ToString::to_string)
            }
        }
    }

    fn local_to_remote(&self, local_path: &str) -> Option<String> {
        let normalized = normalize_relative_path(local_path);
        if normalized.is_empty() {
            return None;
        }

        Some(match &self.prefix {
            None => normalized,
            Some(prefix) => format!("{prefix}/{normalized}"),
        })
    }
}

struct StartupStateStore {
    path: PathBuf,
}

impl StartupStateStore {
    fn new(root_dir: &Path, scope: &PathScope, server_base_url: &str) -> Self {
        let mut hasher = DefaultHasher::new();
        root_dir.to_string_lossy().hash(&mut hasher);
        scope.remote_prefix().unwrap_or_default().hash(&mut hasher);
        server_base_url.hash(&mut hasher);
        let fingerprint = hasher.finish();

        let mut path = std::env::temp_dir();
        path.push("ironmesh-folder-agent");
        path.push(format!("baseline-{fingerprint:016x}.sqlite"));
        Self { path }
    }

    fn load_local_baseline(&self) -> Result<LocalTreeState> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, kind, size_bytes, modified_unix_ms
                 FROM baseline_entries",
            )
            .context("failed to prepare sqlite baseline query")?;

        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .context("failed to read sqlite baseline rows")?;

        let mut state = LocalTreeState::new();
        for row in rows {
            let (path, kind_code, size_bytes_i64, modified_unix_ms_i64) =
                row.context("failed to decode sqlite baseline row")?;

            let kind = match kind_code {
                0 => LocalEntryKind::File,
                1 => LocalEntryKind::Directory,
                _ => bail!("invalid kind code in sqlite baseline for path={path}"),
            };

            let size_bytes = u64::try_from(size_bytes_i64)
                .with_context(|| format!("invalid size in sqlite baseline for path={path}"))?;
            let modified_unix_ms = u128::try_from(modified_unix_ms_i64)
                .with_context(|| format!("invalid mtime in sqlite baseline for path={path}"))?;

            state.insert(
                path,
                LocalEntryState {
                    kind,
                    size_bytes,
                    modified_unix_ms,
                },
            );
        }

        Ok(state)
    }

    fn persist_local_baseline(&self, state: &LocalTreeState) -> Result<()> {
        let mut connection = self.sqlite_connection()?;
        let tx = connection
            .transaction()
            .context("failed to start sqlite baseline transaction")?;

        tx.execute("DELETE FROM baseline_entries", [])
            .context("failed to clear sqlite baseline table")?;

        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms)
                     VALUES(?1, ?2, ?3, ?4)",
                )
                .context("failed to prepare sqlite baseline insert")?;

            for (path, entry_state) in state {
                let kind_code: i64 = match entry_state.kind {
                    LocalEntryKind::File => 0,
                    LocalEntryKind::Directory => 1,
                };
                let size_bytes = i64::try_from(entry_state.size_bytes)
                    .with_context(|| format!("size overflow while persisting baseline: {path}"))?;
                let modified_unix_ms = i64::try_from(entry_state.modified_unix_ms)
                    .with_context(|| format!("mtime overflow while persisting baseline: {path}"))?;

                insert
                    .execute(params![path, kind_code, size_bytes, modified_unix_ms])
                    .with_context(|| format!("failed to insert sqlite baseline row for {path}"))?;
            }
        }

        tx.commit()
            .context("failed to commit sqlite baseline transaction")?;

        Ok(())
    }

    fn quarantine_corrupt(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let quarantine = self
            .path
            .with_extension(format!("corrupt-{}", current_unix_ms()));
        fs::rename(&self.path, &quarantine).with_context(|| {
            format!(
                "failed to quarantine sqlite baseline {}",
                self.path.display()
            )
        })?;

        let wal = PathBuf::from(format!("{}-wal", self.path.display()));
        if wal.exists() {
            let _ = fs::remove_file(wal);
        }
        let shm = PathBuf::from(format!("{}-shm", self.path.display()));
        if shm.exists() {
            let _ = fs::remove_file(shm);
        }

        Ok(())
    }

    fn sqlite_connection(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sqlite baseline directory {}",
                    parent.display()
                )
            })?;
        }

        let connection = Connection::open(&self.path)
            .with_context(|| format!("failed to open sqlite baseline {}", self.path.display()))?;

        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("failed to set sqlite journal_mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("failed to set sqlite synchronous mode")?;

        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS baseline_meta (
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS baseline_entries (
                     path TEXT PRIMARY KEY,
                     kind INTEGER NOT NULL,
                     size_bytes INTEGER NOT NULL,
                     modified_unix_ms INTEGER NOT NULL
                 );",
            )
            .context("failed to initialize sqlite baseline schema")?;

        connection
            .execute(
                "INSERT OR IGNORE INTO baseline_meta(key, value) VALUES(?1, ?2)",
                params!["schema_version", "1"],
            )
            .context("failed to initialize sqlite baseline metadata")?;

        Ok(connection)
    }
}

fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::PathScope;

    #[test]
    fn path_scope_without_prefix_keeps_paths() {
        let scope = PathScope::new(None);
        assert_eq!(
            scope.remote_to_local("docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
        assert_eq!(
            scope.local_to_remote("docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
    }

    #[test]
    fn path_scope_with_prefix_maps_both_directions() {
        let scope = PathScope::new(Some("team/a".to_string()));
        assert_eq!(scope.remote_prefix(), Some("team/a"));
        assert_eq!(
            scope.remote_to_local("team/a/docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
        assert_eq!(scope.remote_to_local("other/docs/readme.txt"), None);
        assert_eq!(
            scope.local_to_remote("docs/readme.txt"),
            Some("team/a/docs/readme.txt".to_string())
        );
    }
}
