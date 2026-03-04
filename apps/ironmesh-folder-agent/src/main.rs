use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotUpdate,
    normalize_server_base_url,
};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Read, Write};
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
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long)]
    root_dir: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8080", global = true)]
    server_base_url: String,
    #[arg(long, global = true)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64, global = true)]
    depth: usize,
    #[arg(long, default_value_t = 3000, global = true)]
    remote_refresh_interval_ms: u64,
    #[arg(long, default_value_t = 2000, global = true)]
    local_scan_interval_ms: u64,
    #[arg(long, default_value_t = false, global = true)]
    no_watch_local: bool,
    #[arg(long, default_value_t = false, global = true)]
    run_once: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect or resolve startup conflicts persisted in the local SQLite state store.
    Conflicts {
        #[command(subcommand)]
        command: ConflictCommand,
    },
    /// Remove partial download artifacts (`.ironmesh-part-*`) left behind by crashes/power loss.
    Cleanup {
        /// Only print the number of files that would be removed.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ConflictCommand {
    /// Print all currently persisted startup conflicts.
    List {
        #[arg(long, value_enum, default_value_t = ConflictListFormat::Json)]
        format: ConflictListFormat,
    },
    /// Clear a single conflict row (optionally also deleting related local conflict-copy files).
    Resolve {
        /// Relative path within the agent root directory.
        path: String,
        #[arg(long, value_enum, default_value_t = ConflictResolutionStrategy::KeepLocal)]
        strategy: ConflictResolutionStrategy,
        #[arg(long, default_value_t = false)]
        delete_conflict_copies: bool,
    },
    /// Clear all persisted conflict rows.
    Clear {
        #[arg(long, default_value_t = false)]
        delete_conflict_copies: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConflictListFormat {
    Json,
    Table,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConflictResolutionStrategy {
    KeepLocal,
    KeepRemote,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(command) = args.command.as_ref() {
        return run_command(&args, command);
    }

    run_agent(&args)
}

fn run_command(args: &Args, command: &Command) -> Result<()> {
    match command {
        Command::Cleanup { dry_run } => {
            let removed = cleanup_ironmesh_part_files(&args.root_dir, *dry_run)?;
            if *dry_run {
                println!("cleanup: would remove {removed} partial download artifacts");
            } else {
                println!("cleanup: removed {removed} partial download artifacts");
            }
            Ok(())
        }
        Command::Conflicts { command } => run_conflict_command(args, command),
    }
}

fn run_conflict_command(args: &Args, command: &ConflictCommand) -> Result<()> {
    let scope = PathScope::new(args.prefix.clone());
    let base_url = normalize_server_base_url(&args.server_base_url)?;
    let state_store = StartupStateStore::new(&args.root_dir, &scope, base_url.as_str());

    match command {
        ConflictCommand::List { format } => {
            let conflicts = state_store.load_conflicts()?;
            match format {
                ConflictListFormat::Json => {
                    for conflict in conflicts {
                        let parsed_details = serde_json::from_str::<serde_json::Value>(
                            conflict.details_json.as_str(),
                        )
                        .unwrap_or_else(|_| serde_json::Value::String(conflict.details_json));
                        let line = json!({
                            "path": conflict.path,
                            "reason": conflict.reason,
                            "created_unix_ms": conflict.created_unix_ms,
                            "details": parsed_details,
                        });
                        println!("{}", line.to_string());
                    }
                }
                ConflictListFormat::Table => {
                    println!("{:<48}  {:<28}  {}", "path", "reason", "created_unix_ms");
                    for conflict in conflicts {
                        println!(
                            "{:<48}  {:<28}  {}",
                            conflict.path, conflict.reason, conflict.created_unix_ms
                        );
                    }
                }
            }

            Ok(())
        }
        ConflictCommand::Clear {
            delete_conflict_copies: delete_copies,
        } => {
            let conflicts = state_store.load_conflicts()?;
            let removed_rows = state_store.clear_conflicts()?;

            if *delete_copies {
                for conflict in &conflicts {
                    let _ = delete_conflict_copies(&args.root_dir, conflict.path.as_str());
                }
            }

            println!("conflicts: cleared {removed_rows} rows");
            Ok(())
        }
        ConflictCommand::Resolve {
            path,
            strategy,
            delete_conflict_copies: delete_copies,
        } => {
            match strategy {
                ConflictResolutionStrategy::KeepLocal => {
                    let removed_rows = state_store.remove_conflict(path.as_str())?;
                    if *delete_copies {
                        let removed_files =
                            delete_conflict_copies(&args.root_dir, path.as_str()).unwrap_or(0);
                        println!(
                            "conflicts: resolved {path} (keep-local), removed {removed_rows} rows, removed {removed_files} conflict copy files"
                        );
                    } else {
                        println!(
                            "conflicts: resolved {path} (keep-local), removed {removed_rows} rows"
                        );
                    }
                    Ok(())
                }
                ConflictResolutionStrategy::KeepRemote => {
                    let remote_copy = newest_remote_conflict_copy(&args.root_dir, path.as_str())?;

                    // Preserve the current local bytes before applying the remote copy.
                    let local_target = absolute_path(&args.root_dir, path.as_str());
                    if local_target.is_file() {
                        let timestamp = current_unix_ms();
                        let local_backup_dir =
                            conflict_copy_dir(&args.root_dir, "local", path.as_str());
                        fs::create_dir_all(&local_backup_dir).with_context(|| {
                            format!(
                                "failed to create conflict backup directory {}",
                                local_backup_dir.display()
                            )
                        })?;
                        let file_name = local_target
                            .file_name()
                            .map(|value| value.to_string_lossy().to_string())
                            .unwrap_or_else(|| "object".to_string());
                        let backup_target = local_backup_dir
                            .join(format!("{file_name}.local-conflict-{timestamp}"));

                        // Prefer atomic rename; fall back to copy if the file is locked.
                        if fs::rename(&local_target, &backup_target).is_err() {
                            fs::copy(&local_target, &backup_target).with_context(|| {
                                format!(
                                    "failed to copy local file {} to backup {}",
                                    local_target.display(),
                                    backup_target.display()
                                )
                            })?;
                        }
                    }

                    copy_file_atomically(&remote_copy, &local_target).with_context(|| {
                        format!(
                            "failed to apply remote conflict copy {} into {}",
                            remote_copy.display(),
                            local_target.display()
                        )
                    })?;

                    let client = IronMeshClient::new(base_url.as_str());
                    let metadata = fs::metadata(&local_target).with_context(|| {
                        format!(
                            "failed to inspect resolved local file {}",
                            local_target.display()
                        )
                    })?;
                    let content_hash = upload_local_file(
                        &args.root_dir,
                        &client,
                        &scope,
                        path.as_str(),
                        metadata.len(),
                    )?;

                    if let Some(entry_state) =
                        local_entry_state_for_path(&args.root_dir, path.as_str())?
                    {
                        state_store.upsert_baseline_entry_with_hash(
                            path.as_str(),
                            &entry_state,
                            Some(content_hash.as_str()),
                        )?;
                    }

                    let removed_rows = state_store.remove_conflict(path.as_str())?;
                    let removed_files = if *delete_copies {
                        delete_conflict_copies(&args.root_dir, path.as_str()).unwrap_or(0)
                    } else {
                        0
                    };

                    println!(
                        "conflicts: resolved {path} (keep-remote), removed {removed_rows} rows, removed {removed_files} conflict copy files"
                    );
                    Ok(())
                }
            }
        }
    }
}

fn run_agent(args: &Args) -> Result<()> {
    let scope = PathScope::new(args.prefix.clone());
    let base_url = normalize_server_base_url(&args.server_base_url)?;
    let state_store = StartupStateStore::new(&args.root_dir, &scope, base_url.as_str());

    fs::create_dir_all(&args.root_dir).with_context(|| {
        format!(
            "failed to create root directory {}",
            args.root_dir.display()
        )
    })?;

    if let Err(error) = cleanup_ironmesh_part_files(&args.root_dir, false) {
        eprintln!("startup-state: failed to cleanup partial download artifacts: {error}");
    }

    let local_state_before_remote_sync = scan_local_tree(&args.root_dir)
        .context("failed to scan local state before initial remote sync")?;

    let baseline_before_remote_sync =
        match load_local_baseline_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(state) => Some(state),
            Err(error) => {
                eprintln!("startup-state: failed to load sqlite baseline: {error}");
                state_store.quarantine_corrupt().ok();
                None
            }
        };
    let baseline_hashes_before_remote_sync = if baseline_before_remote_sync.is_some() {
        match load_local_baseline_hashes_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(hashes) => hashes,
            Err(error) => {
                eprintln!("startup-state: failed to load sqlite baseline hashes: {error}");
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };

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
    let remote_files_before_remote_sync =
        remote_file_paths_by_local_path(&initial_snapshot, &scope);
    let remote_hashes_before_remote_sync =
        remote_file_hashes_by_local_path(&initial_snapshot, &scope);
    let preserve_local_files = local_paths_to_preserve_on_startup(
        &args.root_dir,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &remote_hashes_before_remote_sync,
    );
    let remote_delete_wins_paths = startup_remote_delete_wins_paths(
        &args.root_dir,
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
        &args.root_dir,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &baseline_hashes_before_remote_sync,
        &remote_hashes_before_remote_sync,
        &preserve_local_files,
    ));
    if let Err(error) =
        materialize_remote_conflict_copies(&args.root_dir, &client, &scope, &startup_conflicts)
    {
        eprintln!("startup-state: failed to materialize conflict copies: {error}");
    }

    let mut remote_index = RemoteTreeIndex::default();
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    apply_remote_snapshot(
        &args.root_dir,
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
        remove_local_path(&args.root_dir, path)?;
        suppressed_uploads.remove(path);
    }

    let mut local_state = scan_local_tree(&args.root_dir)
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
        &args.root_dir,
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
                Some(&state_store),
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
                Some(&state_store),
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

fn load_local_baseline_with_retries(
    state_store: &StartupStateStore,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<LocalTreeState> {
    let attempts = max_attempts.max(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match state_store.load_local_baseline() {
            Ok(state) => return Ok(state),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    thread::sleep(retry_delay);
                }
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("failed to load sqlite baseline: no attempts executed"),
    }
}

fn load_local_baseline_hashes_with_retries(
    state_store: &StartupStateStore,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<BTreeMap<String, String>> {
    let attempts = max_attempts.max(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match state_store.load_local_baseline_hashes() {
            Ok(hashes) => return Ok(hashes),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    thread::sleep(retry_delay);
                }
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("failed to load sqlite baseline hashes: no attempts executed"),
    }
}

fn local_paths_to_preserve_on_startup(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    remote_hashes: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut preserve = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match local_file_content_hash(root_dir, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash local file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
            continue;
        };

        if previous != entry_state {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match local_file_content_hash(root_dir, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash local file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
        }
    }

    preserve
}

fn remote_file_hashes_by_local_path(
    snapshot: &SyncSnapshot,
    scope: &PathScope,
) -> BTreeMap<String, String> {
    let mut by_local_path = BTreeMap::new();

    for entry in &snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }
        let Some(content_hash) = entry.content_hash.as_deref() else {
            continue;
        };
        if content_hash.is_empty() {
            continue;
        }

        let remote_path = normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }
        by_local_path.insert(local_path, content_hash.to_string());
    }

    by_local_path
}

fn remote_file_paths_by_local_path(snapshot: &SyncSnapshot, scope: &PathScope) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();

    for entry in &snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }

        let remote_path = normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }
        paths.insert(local_path);
    }

    paths
}

fn startup_remote_delete_wins_paths(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_files: &BTreeSet<String>,
    preserve_local_files: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut delete_wins = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }
        if remote_files.contains(path) {
            continue;
        }
        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            continue;
        };

        if previous == entry_state {
            delete_wins.insert(path.clone());
            continue;
        }

        if preserve_local_files.contains(path) {
            let Some(expected_hash) = baseline_hashes.get(path) else {
                continue;
            };
            match local_file_content_hash(root_dir, path) {
                Ok(local_hash) if local_hash == *expected_hash => {
                    delete_wins.insert(path.clone());
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!(
                        "startup-state: failed to hash local file {path} for remote-delete check: {error}; preserving local bytes"
                    );
                }
            }
        }
    }

    delete_wins
}

#[derive(Debug, Clone)]
struct StartupConflict {
    path: String,
    reason: String,
    details_json: String,
    created_unix_ms: u128,
}

struct SleepAfterFirstWrite {
    inner: File,
    delay: Duration,
    slept: bool,
}

impl SleepAfterFirstWrite {
    fn new(inner: File, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            slept: false,
        }
    }

    fn sync_all(&self) -> std::io::Result<()> {
        self.inner.sync_all()
    }
}

impl Write for SleepAfterFirstWrite {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        if !self.slept && written > 0 {
            self.slept = true;
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
        }
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn materialize_remote_conflict_copies(
    root_dir: &Path,
    client: &IronMeshClient,
    scope: &PathScope,
    conflicts: &[StartupConflict],
) -> Result<()> {
    let timestamp = current_unix_ms();

    for conflict in conflicts {
        if conflict.reason != "dual_modify_conflict"
            && conflict.reason != "dual_modify_missing_baseline"
        {
            continue;
        }

        let Some(remote_key) = scope.local_to_remote(&conflict.path) else {
            continue;
        };

        let base_relative = format!(".ironmesh-conflicts/remote/{}", conflict.path);
        let base_target = absolute_path(root_dir, &base_relative);
        let file_name = base_target
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "object".to_string());
        let conflict_target =
            base_target.with_file_name(format!("{file_name}.remote-conflict-{timestamp}"));

        let Some(parent) = conflict_target.parent() else {
            continue;
        };

        if let Err(error) = fs::create_dir_all(parent)
            .with_context(|| format!("failed to create conflict directory {}", parent.display()))
        {
            eprintln!("startup-state: {error}");
            continue;
        }

        let temp_name = format!(
            ".{}.ironmesh-part-{}",
            conflict_target
                .file_name()
                .map(|value| value.to_string_lossy().to_string())
                .unwrap_or_else(|| "object".to_string()),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let temp_path = conflict_target.with_file_name(temp_name);

        let file = match File::create(&temp_path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!(
                    "startup-state: failed to create conflict temp file {}: {error}",
                    temp_path.display()
                );
                continue;
            }
        };

        if cfg!(debug_assertions) {
            if let Ok(raw) = std::env::var("IRONMESH_TEST_CONFLICT_COPY_SLEEP_AFTER_TEMP_CREATE_MS")
                && let Ok(delay_ms) = raw.parse::<u64>()
                && delay_ms > 0
            {
                thread::sleep(Duration::from_millis(delay_ms));
            }

            if std::env::var("IRONMESH_TEST_CRASH_AFTER_CONFLICT_COPY_TEMP_CREATE")
                .ok()
                .is_some_and(|value| value == "1")
            {
                // Test-only crash injection: simulates a power loss/crash with a temp file present.
                std::process::abort();
            }
        }

        let delay = if cfg!(debug_assertions) {
            std::env::var("IRONMESH_TEST_CONFLICT_COPY_WRITE_DELAY_MS")
                .ok()
                .and_then(|raw| raw.parse::<u64>().ok())
                .filter(|ms| *ms > 0)
                .map(Duration::from_millis)
                .unwrap_or(Duration::from_millis(0))
        } else {
            Duration::from_millis(0)
        };
        let mut writer = SleepAfterFirstWrite::new(file, delay);

        if let Err(error) = client.get_with_selector_writer(&remote_key, None, None, &mut writer) {
            eprintln!(
                "startup-state: failed to download remote conflict copy for {}: {error}",
                conflict.path
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        if let Err(error) = writer.sync_all() {
            eprintln!(
                "startup-state: failed to flush conflict temp file {}: {error}",
                temp_path.display()
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }

        if let Err(error) = fs::rename(&temp_path, &conflict_target) {
            eprintln!(
                "startup-state: failed to write conflict copy {}: {error}",
                conflict_target.display()
            );
            let _ = fs::remove_file(&temp_path);
            continue;
        }
    }

    Ok(())
}

fn startup_add_delete_conflicts(
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    remote_files: &BTreeSet<String>,
    preserve_local_files: &BTreeSet<String>,
    remote_delete_wins_paths: &BTreeSet<String>,
) -> Vec<StartupConflict> {
    let mut conflicts = Vec::new();

    for path in preserve_local_files {
        if remote_files.contains(path) || remote_delete_wins_paths.contains(path) {
            continue;
        }
        let Some(entry_state) = local_state.get(path) else {
            continue;
        };
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let (reason, details_json) = match baseline.and_then(|state| state.get(path)) {
            Some(previous) if previous != entry_state => (
                "modify_delete_conflict",
                json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "delete_seen",
                })
                .to_string(),
            ),
            None => (
                "add_delete_ambiguous_missing_baseline",
                json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "missing",
                })
                .to_string(),
            ),
            _ => continue,
        };
        conflicts.push(StartupConflict {
            path: path.clone(),
            reason: reason.to_string(),
            details_json,
            created_unix_ms: current_unix_ms(),
        });
    }

    conflicts
}

fn startup_dual_modify_conflicts(
    root_dir: &Path,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_hashes: &BTreeMap<String, String>,
    preserve_local_files: &BTreeSet<String>,
) -> Vec<StartupConflict> {
    let mut conflicts = Vec::new();

    for path in preserve_local_files {
        let Some(entry_state) = local_state.get(path) else {
            continue;
        };
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(remote_hash) = remote_hashes.get(path) else {
            continue;
        };

        let local_hash = match local_file_content_hash(root_dir, path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "startup-state: failed to hash local file {path} for dual-modify check: {error}; treating as conflict"
                );
                let stored_baseline = baseline.and_then(|state| state.get(path));
                let reason = match stored_baseline {
                    None => Some("dual_modify_missing_baseline"),
                    Some(_) => match baseline_hashes.get(path) {
                        Some(baseline_hash) if baseline_hash != remote_hash => {
                            Some("dual_modify_conflict")
                        }
                        _ => None,
                    },
                };

                if let Some(reason) = reason {
                    conflicts.push(StartupConflict {
                        path: path.clone(),
                        reason: reason.to_string(),
                        details_json: json!({
                            "policy": "keep_local_bytes",
                            "local_action": "upload_local",
                            "remote_action": "overwrite_possible",
                        })
                        .to_string(),
                        created_unix_ms: current_unix_ms(),
                    });
                }
                continue;
            }
        };

        let stored_baseline = baseline.and_then(|state| state.get(path));
        let reason = match stored_baseline {
            None => Some("dual_modify_missing_baseline"),
            Some(_) => match baseline_hashes.get(path) {
                Some(baseline_hash) if baseline_hash != remote_hash => Some("dual_modify_conflict"),
                _ => None,
            },
        };

        if local_hash != *remote_hash {
            if let Some(reason) = reason {
                conflicts.push(StartupConflict {
                    path: path.clone(),
                    reason: reason.to_string(),
                    details_json: json!({
                        "policy": "keep_local_bytes",
                        "local_action": "upload_local",
                        "remote_action": "overwrite_possible",
                    })
                    .to_string(),
                    created_unix_ms: current_unix_ms(),
                });
            }
        }
    }

    conflicts
}

fn local_file_content_hash(root_dir: &Path, relative_path: &str) -> Result<String> {
    let absolute = absolute_path(root_dir, relative_path);
    let mut file = File::open(&absolute).with_context(|| {
        format!(
            "failed to open local file for hashing {}",
            absolute.display()
        )
    })?;

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).with_context(|| {
            format!(
                "failed to read local file for hashing {}",
                absolute.display()
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn content_hash_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read > 0 {
            self.hasher.update(&buf[..read]);
        }
        Ok(read)
    }
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
            if let Some(store) = state_store {
                store
                    .remove_baseline_entry(&path)
                    .with_context(|| format!("failed to remove baseline entry for {path}"))?;
            }
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
    state_store: Option<&StartupStateStore>,
    scope: &PathScope,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    remote_index: &mut RemoteTreeIndex,
) -> Result<()> {
    let mut next_index = RemoteTreeIndex::default();
    let mut entry_kinds: BTreeMap<String, (EntryKind, String)> = BTreeMap::new();
    let mut entry_hashes: BTreeMap<String, String> = BTreeMap::new();

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

    if let Some(store) = state_store {
        let metadata = fs::metadata(&temp_path)
            .with_context(|| format!("failed to inspect temp file {}", temp_path.display()))?;
        let entry_state = local_entry_state_from_metadata(&metadata);
        store
            .upsert_baseline_entry_with_hash(local_relative_path, &entry_state, remote_content_hash)
            .with_context(|| {
                format!("failed to persist baseline file entry for {local_relative_path}")
            })?;
    }

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
) -> Result<String> {
    let absolute = absolute_path(root_dir, relative_path);
    let mut file = File::open(&absolute)
        .with_context(|| format!("failed to open local file {}", absolute.display()))?;

    let remote_key = scope.local_to_remote(relative_path).ok_or_else(|| {
        anyhow::anyhow!("refusing to upload local root without concrete scoped path")
    })?;

    let mut hashing_reader = HashingReader::new(&mut file);
    client
        .put_large_aware_reader(remote_key.clone(), &mut hashing_reader, size_bytes)
        .with_context(|| format!("failed to upload local file {relative_path} to {remote_key}"))?;

    Ok(hashing_reader.content_hash_hex())
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
    scope_fingerprint: String,
}

#[derive(Debug, Clone)]
struct StoredConflict {
    path: String,
    reason: String,
    details_json: String,
    created_unix_ms: i64,
}

const BASELINE_SCHEMA_VERSION_INITIAL: i64 = 1;
const BASELINE_SCHEMA_VERSION_CURRENT: i64 = 2;

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
        Self {
            path,
            scope_fingerprint: format!("{fingerprint:016x}"),
        }
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

    fn load_local_baseline_hashes(&self) -> Result<BTreeMap<String, String>> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, content_hash
                 FROM baseline_entries
                 WHERE kind = 0
                   AND content_hash IS NOT NULL
                   AND content_hash != ''",
            )
            .context("failed to prepare sqlite baseline hash query")?;

        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .context("failed to read sqlite baseline hash rows")?;

        let mut hashes = BTreeMap::new();
        for row in rows {
            let (path, hash) = row.context("failed to decode sqlite baseline hash row")?;
            hashes.insert(path, hash);
        }

        Ok(hashes)
    }

    fn persist_local_baseline(&self, state: &LocalTreeState) -> Result<()> {
        let mut connection = self.sqlite_connection()?;
        let existing_hashes = {
            let mut statement = connection
                .prepare(
                    "SELECT path, content_hash
                     FROM baseline_entries
                     WHERE kind = 0
                       AND content_hash IS NOT NULL
                       AND content_hash != ''",
                )
                .context("failed to prepare sqlite baseline hash preservation query")?;

            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .context("failed to read sqlite baseline hashes before rewrite")?;

            let mut hashes = BTreeMap::new();
            for row in rows {
                let (path, hash) =
                    row.context("failed to decode sqlite baseline hash preservation row")?;
                hashes.insert(path, hash);
            }
            hashes
        };

        let tx = connection
            .transaction()
            .context("failed to start sqlite baseline transaction")?;

        tx.execute("DELETE FROM baseline_entries", [])
            .context("failed to clear sqlite baseline table")?;

        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms, content_hash)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
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
                let content_hash = match entry_state.kind {
                    LocalEntryKind::File => existing_hashes.get(path).cloned(),
                    LocalEntryKind::Directory => None,
                };

                insert
                    .execute(params![
                        path,
                        kind_code,
                        size_bytes,
                        modified_unix_ms,
                        content_hash
                    ])
                    .with_context(|| format!("failed to insert sqlite baseline row for {path}"))?;
            }
        }

        tx.commit()
            .context("failed to commit sqlite baseline transaction")?;

        Ok(())
    }

    fn upsert_baseline_entry(&self, path: &str, entry_state: &LocalEntryState) -> Result<()> {
        self.upsert_baseline_entry_with_hash(path, entry_state, None)
    }

    fn upsert_baseline_entry_with_hash(
        &self,
        path: &str,
        entry_state: &LocalEntryState,
        content_hash: Option<&str>,
    ) -> Result<()> {
        let connection = self.sqlite_connection()?;
        let kind_code: i64 = match entry_state.kind {
            LocalEntryKind::File => 0,
            LocalEntryKind::Directory => 1,
        };
        let size_bytes = i64::try_from(entry_state.size_bytes)
            .with_context(|| format!("size overflow while persisting baseline: {path}"))?;
        let modified_unix_ms = i64::try_from(entry_state.modified_unix_ms)
            .with_context(|| format!("mtime overflow while persisting baseline: {path}"))?;
        let content_hash = match entry_state.kind {
            LocalEntryKind::File => content_hash
                .filter(|hash| !hash.trim().is_empty())
                .map(ToString::to_string),
            LocalEntryKind::Directory => None,
        };

        connection
            .execute(
                "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms, content_hash)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(path) DO UPDATE SET
                     kind = excluded.kind,
                     size_bytes = excluded.size_bytes,
                     modified_unix_ms = excluded.modified_unix_ms,
                     content_hash = CASE
                         WHEN excluded.kind != 0 THEN NULL
                         ELSE COALESCE(NULLIF(excluded.content_hash, ''), baseline_entries.content_hash)
                     END",
                params![path, kind_code, size_bytes, modified_unix_ms, content_hash],
            )
            .with_context(|| format!("failed to upsert sqlite baseline row for {path}"))?;

        Ok(())
    }

    fn remove_baseline_entry(&self, path: &str) -> Result<()> {
        let connection = self.sqlite_connection()?;
        connection
            .execute("DELETE FROM baseline_entries WHERE path = ?1", [path])
            .with_context(|| format!("failed to delete sqlite baseline row for {path}"))?;
        Ok(())
    }

    fn persist_startup_conflicts(&self, conflicts: &[StartupConflict]) -> Result<()> {
        let mut connection = self.sqlite_connection()?;
        let tx = connection
            .transaction()
            .context("failed to start sqlite conflicts transaction")?;
        tx.execute("DELETE FROM conflicts", [])
            .context("failed to clear sqlite conflicts table")?;

        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO conflicts(path, reason, details_json, created_unix_ms)
                     VALUES(?1, ?2, ?3, ?4)",
                )
                .context("failed to prepare sqlite conflict insert")?;
            for conflict in conflicts {
                let created_unix_ms = i64::try_from(conflict.created_unix_ms)
                    .with_context(|| format!("invalid conflict timestamp for {}", conflict.path))?;
                insert
                    .execute(params![
                        conflict.path,
                        conflict.reason,
                        conflict.details_json,
                        created_unix_ms
                    ])
                    .with_context(|| {
                        format!("failed to insert sqlite conflict row for {}", conflict.path)
                    })?;
            }
        }

        tx.commit()
            .context("failed to commit sqlite conflicts transaction")?;
        Ok(())
    }

    fn load_conflicts(&self) -> Result<Vec<StoredConflict>> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, reason, details_json, created_unix_ms
                 FROM conflicts
                 ORDER BY created_unix_ms ASC, path ASC",
            )
            .context("failed to prepare sqlite conflicts query")?;

        let rows = statement
            .query_map([], |row| {
                Ok(StoredConflict {
                    path: row.get::<_, String>(0)?,
                    reason: row.get::<_, String>(1)?,
                    details_json: row.get::<_, String>(2)?,
                    created_unix_ms: row.get::<_, i64>(3)?,
                })
            })
            .context("failed to read sqlite conflict rows")?;

        let mut values = Vec::new();
        for row in rows {
            values.push(row.context("failed to decode sqlite conflict row")?);
        }
        Ok(values)
    }

    fn clear_conflicts(&self) -> Result<usize> {
        let connection = self.sqlite_connection()?;
        let removed = connection
            .execute("DELETE FROM conflicts", [])
            .context("failed to clear sqlite conflicts table")?;
        Ok(removed)
    }

    fn remove_conflict(&self, path: &str) -> Result<usize> {
        let connection = self.sqlite_connection()?;
        let removed = connection
            .execute("DELETE FROM conflicts WHERE path = ?1", [path])
            .with_context(|| format!("failed to remove sqlite conflict row for {path}"))?;
        Ok(removed)
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

        let mut connection = Connection::open(&self.path)
            .with_context(|| format!("failed to open sqlite baseline {}", self.path.display()))?;

        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("failed to set sqlite journal_mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("failed to set sqlite synchronous mode")?;

        self.ensure_schema(&mut connection)?;
        self.ensure_scope_fingerprint(&connection)?;

        Ok(connection)
    }

    fn ensure_schema(&self, connection: &mut Connection) -> Result<()> {
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
                     modified_unix_ms INTEGER NOT NULL,
                     content_hash TEXT
                 );
                 CREATE TABLE IF NOT EXISTS conflicts (
                     path TEXT PRIMARY KEY,
                     reason TEXT NOT NULL,
                     details_json TEXT NOT NULL,
                     created_unix_ms INTEGER NOT NULL
                 );",
            )
            .context("failed to initialize sqlite baseline schema")?;

        let stored_version = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["schema_version"],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to read sqlite baseline schema version")?;

        let mut schema_version = match stored_version {
            Some(raw) => raw
                .parse::<i64>()
                .with_context(|| format!("invalid sqlite baseline schema version: {raw}"))?,
            None => BASELINE_SCHEMA_VERSION_INITIAL,
        };

        if schema_version < BASELINE_SCHEMA_VERSION_INITIAL {
            bail!(
                "unsupported sqlite baseline schema version: {schema_version} (minimum={})",
                BASELINE_SCHEMA_VERSION_INITIAL
            );
        }

        while schema_version < BASELINE_SCHEMA_VERSION_CURRENT {
            match schema_version {
                1 => {
                    self.migrate_schema_v1_to_v2(connection)?;
                    schema_version = 2;
                }
                _ => {
                    bail!("unsupported sqlite baseline schema version: {schema_version}");
                }
            }
        }

        if schema_version > BASELINE_SCHEMA_VERSION_CURRENT {
            bail!(
                "unsupported sqlite baseline schema version: {} (current={})",
                schema_version,
                BASELINE_SCHEMA_VERSION_CURRENT
            );
        }

        connection
            .execute(
                "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params!["schema_version", schema_version.to_string()],
            )
            .context("failed to persist sqlite baseline schema version")?;

        Ok(())
    }

    fn migrate_schema_v1_to_v2(&self, connection: &Connection) -> Result<()> {
        let mut statement = connection
            .prepare("PRAGMA table_info(baseline_entries)")
            .context("failed to inspect sqlite baseline_entries schema")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .context("failed to read sqlite baseline_entries columns")?;

        let mut has_content_hash = false;
        for column in columns {
            if column.context("failed to decode sqlite baseline_entries column")? == "content_hash"
            {
                has_content_hash = true;
                break;
            }
        }

        if !has_content_hash {
            connection
                .execute(
                    "ALTER TABLE baseline_entries ADD COLUMN content_hash TEXT",
                    [],
                )
                .context("failed to migrate sqlite baseline schema v1->v2")?;
        }

        Ok(())
    }

    fn ensure_scope_fingerprint(&self, connection: &Connection) -> Result<()> {
        connection
            .execute(
                "INSERT OR IGNORE INTO baseline_meta(key, value) VALUES(?1, ?2)",
                params!["scope_fingerprint", self.scope_fingerprint.as_str()],
            )
            .context("failed to initialize sqlite baseline scope metadata")?;

        let stored_fingerprint: String = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["scope_fingerprint"],
                |row| row.get(0),
            )
            .context("failed to read sqlite baseline scope fingerprint")?;
        if stored_fingerprint != self.scope_fingerprint {
            bail!(
                "sqlite baseline scope fingerprint mismatch (stored={}, expected={})",
                stored_fingerprint,
                self.scope_fingerprint
            );
        }

        Ok(())
    }
}

fn cleanup_ironmesh_part_files(root_dir: &Path, dry_run: bool) -> Result<usize> {
    if !root_dir.exists() {
        return Ok(0);
    }

    let mut removed = 0_usize;
    let mut stack = vec![root_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                eprintln!(
                    "cleanup: failed to read directory {}: {error}",
                    dir.display()
                );
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    eprintln!("cleanup: failed to read directory entry: {error}");
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    eprintln!("cleanup: failed to inspect {}: {error}", path.display());
                    continue;
                }
            };

            if file_type.is_dir() {
                // Skip symlinked directories to avoid loops.
                if file_type.is_symlink() {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };

            if !is_ironmesh_part_file_name(file_name) {
                continue;
            }

            if dry_run {
                removed += 1;
                continue;
            }

            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) => {
                    eprintln!("cleanup: failed to remove {}: {error}", path.display());
                }
            }
        }
    }

    Ok(removed)
}

fn is_ironmesh_part_file_name(file_name: &str) -> bool {
    if !file_name.starts_with('.') {
        return false;
    }

    let Some((_, suffix)) = file_name.rsplit_once(".ironmesh-part-") else {
        return false;
    };

    !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
}

fn conflict_copy_dir(root_dir: &Path, side: &str, relative_path: &str) -> PathBuf {
    let rel = Path::new(relative_path);
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    root_dir.join(".ironmesh-conflicts").join(side).join(parent)
}

fn newest_remote_conflict_copy(root_dir: &Path, relative_path: &str) -> Result<PathBuf> {
    let rel = Path::new(relative_path);
    let Some(file_name) = rel.file_name().and_then(|value| value.to_str()) else {
        bail!("conflicts: invalid path (expected file): {relative_path}");
    };

    let dir = conflict_copy_dir(root_dir, "remote", relative_path);
    if !dir.is_dir() {
        bail!(
            "conflicts: no remote conflict copies found for {relative_path} (missing directory {})",
            dir.display()
        );
    }

    let prefix = format!("{file_name}.remote-conflict-");
    let mut best: Option<(u128, PathBuf)> = None;

    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        let Some(rest) = name.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Ok(timestamp) = rest.parse::<u128>() else {
            continue;
        };

        match &best {
            None => best = Some((timestamp, path)),
            Some((best_ts, _)) if timestamp > *best_ts => best = Some((timestamp, path)),
            _ => {}
        }
    }

    best.map(|(_, path)| path).ok_or_else(|| {
        anyhow::anyhow!("conflicts: no remote conflict copies found for {relative_path}")
    })
}

fn delete_conflict_copies(root_dir: &Path, relative_path: &str) -> Result<usize> {
    let rel = Path::new(relative_path);
    let Some(file_name) = rel.file_name().and_then(|value| value.to_str()) else {
        return Ok(0);
    };

    let mut removed = 0_usize;
    for (side, prefix) in [
        ("remote", format!("{file_name}.remote-conflict-")),
        ("local", format!("{file_name}.local-conflict-")),
    ] {
        let dir = conflict_copy_dir(root_dir, side, relative_path);
        if !dir.is_dir() {
            continue;
        }

        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !name.starts_with(prefix.as_str()) {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }

    Ok(removed)
}

fn copy_file_atomically(source: &Path, target: &Path) -> Result<()> {
    if target.is_dir() {
        fs::remove_dir_all(target)
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

    let mut input = File::open(source)
        .with_context(|| format!("failed to open source file {}", source.display()))?;
    let mut output = File::create(&temp_path)
        .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
    std::io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "failed to copy {} into {}",
            source.display(),
            temp_path.display()
        )
    })?;
    output
        .sync_all()
        .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;

    fs::rename(&temp_path, target).with_context(|| {
        format!(
            "failed to place resolved file {} into {}",
            temp_path.display(),
            target.display()
        )
    })?;

    Ok(())
}

fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::{
        BASELINE_SCHEMA_VERSION_CURRENT, PathScope, StartupStateStore, local_entry_state_for_path,
        local_file_content_hash, local_paths_to_preserve_on_startup, startup_dual_modify_conflicts,
        startup_remote_delete_wins_paths,
    };
    use rusqlite::{Connection, params};
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};
    use sync_agent_core::{LocalEntryKind, LocalEntryState, LocalTreeState};

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

    #[test]
    fn startup_preserve_skips_missing_baseline_file_when_hash_matches_remote() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"hello");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert(
            "docs/readme.txt".to_string(),
            local_file_content_hash(&root, "docs/readme.txt").unwrap(),
        );

        let preserve = local_paths_to_preserve_on_startup(&root, &local, None, &remote_hashes);

        assert!(preserve.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_preserve_keeps_missing_baseline_file_when_hash_differs() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"hello");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert(
            "docs/readme.txt".to_string(),
            "not-the-local-hash".to_string(),
        );

        let preserve = local_paths_to_preserve_on_startup(&root, &local, None, &remote_hashes);

        assert_eq!(preserve.len(), 1);
        assert!(preserve.contains("docs/readme.txt"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_remote_delete_wins_only_for_unchanged_paths() {
        let root = test_root();
        let mut local = LocalTreeState::new();
        local.insert(
            "unchanged.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 100,
            },
        );
        local.insert(
            "changed.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 20,
                modified_unix_ms: 200,
            },
        );

        let mut baseline = LocalTreeState::new();
        baseline.insert(
            "unchanged.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 100,
            },
        );
        baseline.insert(
            "changed.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 21,
                modified_unix_ms: 201,
            },
        );

        let remote_files = std::collections::BTreeSet::new();
        let preserve = std::collections::BTreeSet::new();
        let baseline_hashes = BTreeMap::new();
        let delete_wins = startup_remote_delete_wins_paths(
            &root,
            &local,
            Some(&baseline),
            &baseline_hashes,
            &remote_files,
            &preserve,
        );

        assert!(delete_wins.contains("unchanged.txt"));
        assert!(!delete_wins.contains("changed.txt"));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_dual_modify_detects_missing_baseline_hash_mismatch() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"local-version");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert("docs/readme.txt".to_string(), "remote-hash".to_string());

        let preserve = std::iter::once("docs/readme.txt".to_string()).collect();
        let conflicts = startup_dual_modify_conflicts(
            &root,
            &local,
            None,
            &BTreeMap::new(),
            &remote_hashes,
            &preserve,
        );

        assert!(conflicts.iter().any(|conflict| {
            conflict.path == "docs/readme.txt" && conflict.reason == "dual_modify_missing_baseline"
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_dual_modify_detects_conflict_when_remote_hash_differs_from_baseline_hash() {
        let root = test_root();
        write_file(&root, "docs/readme.txt", b"local-version");

        let mut local = LocalTreeState::new();
        local.insert(
            "docs/readme.txt".to_string(),
            local_entry_state_for_path(&root, "docs/readme.txt")
                .unwrap()
                .unwrap(),
        );

        let mut baseline = LocalTreeState::new();
        baseline.insert(
            "docs/readme.txt".to_string(),
            LocalEntryState {
                kind: LocalEntryKind::File,
                size_bytes: 10,
                modified_unix_ms: 10,
            },
        );
        let mut baseline_hashes = BTreeMap::new();
        baseline_hashes.insert("docs/readme.txt".to_string(), "baseline-hash".to_string());

        let mut remote_hashes = BTreeMap::new();
        remote_hashes.insert("docs/readme.txt".to_string(), "remote-hash".to_string());

        let preserve = std::iter::once("docs/readme.txt".to_string()).collect();
        let conflicts = startup_dual_modify_conflicts(
            &root,
            &local,
            Some(&baseline),
            &baseline_hashes,
            &remote_hashes,
            &preserve,
        );

        assert!(conflicts.iter().any(|conflict| {
            conflict.path == "docs/readme.txt" && conflict.reason == "dual_modify_conflict"
        }));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_state_store_migrates_schema_v1_to_current() {
        let root = test_root();
        let scope = PathScope::new(None);
        let store = StartupStateStore::new(&root, &scope, "http://127.0.0.1:8080");
        remove_sqlite_sidecars(&store.path);

        {
            let connection = Connection::open(&store.path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE baseline_meta (
                         key TEXT PRIMARY KEY,
                         value TEXT NOT NULL
                     );
                     CREATE TABLE baseline_entries (
                         path TEXT PRIMARY KEY,
                         kind INTEGER NOT NULL,
                         size_bytes INTEGER NOT NULL,
                         modified_unix_ms INTEGER NOT NULL
                     );
                     CREATE TABLE conflicts (
                         path TEXT PRIMARY KEY,
                         reason TEXT NOT NULL,
                         details_json TEXT NOT NULL,
                         created_unix_ms INTEGER NOT NULL
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["schema_version", "1"],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["scope_fingerprint", store.scope_fingerprint.as_str()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms)
                     VALUES(?1, ?2, ?3, ?4)",
                    params!["docs/readme.txt", 0_i64, 5_i64, 11_i64],
                )
                .unwrap();
        }

        let loaded = store.load_local_baseline().unwrap();
        let state = loaded.get("docs/readme.txt").unwrap();
        assert_eq!(state.kind, LocalEntryKind::File);
        assert_eq!(state.size_bytes, 5);
        assert_eq!(state.modified_unix_ms, 11);

        let connection = Connection::open(&store.path).unwrap();
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["schema_version"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_version, BASELINE_SCHEMA_VERSION_CURRENT.to_string());

        let mut pragma = connection
            .prepare("PRAGMA table_info(baseline_entries)")
            .unwrap();
        let has_content_hash = pragma
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(Result::ok)
            .any(|column| column == "content_hash");
        assert!(has_content_hash);

        remove_sqlite_sidecars(&store.path);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_state_store_rejects_future_schema_version() {
        let root = test_root();
        let scope = PathScope::new(None);
        let store = StartupStateStore::new(&root, &scope, "http://127.0.0.1:8080");
        remove_sqlite_sidecars(&store.path);

        {
            let connection = Connection::open(&store.path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE baseline_meta (
                         key TEXT PRIMARY KEY,
                         value TEXT NOT NULL
                     );
                     CREATE TABLE baseline_entries (
                         path TEXT PRIMARY KEY,
                         kind INTEGER NOT NULL,
                         size_bytes INTEGER NOT NULL,
                         modified_unix_ms INTEGER NOT NULL,
                         content_hash TEXT
                     );
                     CREATE TABLE conflicts (
                         path TEXT PRIMARY KEY,
                         reason TEXT NOT NULL,
                         details_json TEXT NOT NULL,
                         created_unix_ms INTEGER NOT NULL
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["schema_version", "99"],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["scope_fingerprint", store.scope_fingerprint.as_str()],
                )
                .unwrap();
        }

        let error = store.load_local_baseline().unwrap_err().to_string();
        assert!(error.contains("unsupported sqlite baseline schema version"));

        remove_sqlite_sidecars(&store.path);
        fs::remove_dir_all(root).unwrap();
    }

    fn write_file(root: &Path, relative_path: &str, bytes: &[u8]) {
        let absolute = root.join(relative_path);
        if let Some(parent) = absolute.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(absolute, bytes).unwrap();
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!(
            "ironmesh-folder-agent-test-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn remove_sqlite_sidecars(path: &Path) {
        let _ = fs::remove_file(path);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(shm);
    }
}
