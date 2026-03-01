use anyhow::{Context, Result};
use clap::Parser;
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotUpdate,
    normalize_server_base_url,
};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_agent_core::{
    LocalEntryKind, LocalEntryState, LocalTreeState, RemoteTreeIndex, absolute_path,
    build_remote_index, diff_local_trees, local_entry_state_for_path, normalize_relative_path,
    remote_entry_kinds, scan_local_tree,
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
    fs::create_dir_all(&args.root_dir).with_context(|| {
        format!(
            "failed to create root directory {}",
            args.root_dir.display()
        )
    })?;

    let base_url = normalize_server_base_url(&args.server_base_url)?;
    let client = IronMeshClient::new(base_url.as_str());

    let initial_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        args.prefix.clone(),
        args.depth,
        None,
    );
    let initial_snapshot = initial_fetcher
        .fetch_snapshot_blocking()
        .context("failed to fetch initial remote snapshot")?;

    let mut remote_index = build_remote_index(&initial_snapshot);
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    apply_remote_snapshot(
        &args.root_dir,
        &client,
        &initial_snapshot,
        None,
        &mut suppressed_uploads,
        &mut remote_index,
    )?;

    let mut local_state = scan_local_tree(&args.root_dir)
        .context("failed to scan local state after initial remote sync")?;

    if args.run_once {
        sync_local_changes(
            &args.root_dir,
            &client,
            &mut local_state,
            &mut remote_index,
            &mut suppressed_uploads,
        )?;
        return Ok(());
    }

    let running = Arc::new(AtomicBool::new(true));
    install_ctrlc_handler(running.clone())?;

    let refresh_interval = Duration::from_millis(args.remote_refresh_interval_ms.max(250));
    let local_scan_interval = Duration::from_millis(args.local_scan_interval_ms.max(250));

    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::from_base_url(
        base_url.as_str(),
        args.prefix.clone(),
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
        let mut remote_updates_applied = false;
        while let Ok(update) = remote_rx.try_recv() {
            apply_remote_snapshot(
                &args.root_dir,
                &client,
                &update.snapshot,
                Some(&update.changed_paths),
                &mut suppressed_uploads,
                &mut remote_index,
            )?;
            remote_updates_applied = true;
        }

        if remote_updates_applied {
            local_state = scan_local_tree(&args.root_dir)
                .context("failed to rescan local state after remote update")?;
        }

        let mut local_scan_requested = false;
        while local_event_rx.try_recv().is_ok() {
            local_scan_requested = true;
        }

        if local_scan_requested || Instant::now() >= next_local_scan {
            sync_local_changes(
                &args.root_dir,
                &client,
                &mut local_state,
                &mut remote_index,
                &mut suppressed_uploads,
            )?;
            next_local_scan = Instant::now() + local_scan_interval;
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
    remote_index: &mut RemoteTreeIndex,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
) -> Result<()> {
    let current = scan_local_tree(root_dir).context("failed to scan local root")?;
    let diff = diff_local_trees(local_state, &current);

    for path in &diff.created_directories {
        if remote_index.directories.contains(path) {
            continue;
        }

        ensure_remote_directory_marker(client, path)?;
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

        upload_local_file(root_dir, client, path, entry_state.size_bytes)?;
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
            if !remote_index.files.contains(&path) {
                suppressed_uploads.remove(&path);
                continue;
            }

            delete_remote_file(client, &path)?;
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
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    remote_index: &mut RemoteTreeIndex,
) -> Result<()> {
    let next_index = build_remote_index(snapshot);
    let entry_kinds = remote_entry_kinds(snapshot);

    match changed_paths {
        Some(changed_paths) => {
            for changed in changed_paths {
                let path = normalize_relative_path(changed);
                if path.is_empty() {
                    continue;
                }

                match entry_kinds.get(&path) {
                    Some(EntryKind::Directory) => {
                        let directory = absolute_path(root_dir, &path);
                        fs::create_dir_all(&directory).with_context(|| {
                            format!(
                                "failed to materialize remote directory {}",
                                directory.display()
                            )
                        })?;
                    }
                    Some(EntryKind::File) => {
                        download_remote_file(root_dir, client, &path)?;
                        if let Some(entry_state) = local_entry_state_for_path(root_dir, &path)? {
                            suppressed_uploads.insert(path.clone(), entry_state);
                        }
                    }
                    None => {
                        remove_local_path(root_dir, &path)?;
                        suppressed_uploads.remove(&path);
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
                download_remote_file(root_dir, client, file)?;
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
    relative_path: &str,
) -> Result<()> {
    let target = absolute_path(root_dir, relative_path);

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
        .get_with_selector_writer(relative_path, None, None, &mut file)
        .with_context(|| format!("failed to download remote file {relative_path}"))?;

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
    relative_path: &str,
    size_bytes: u64,
) -> Result<()> {
    let absolute = absolute_path(root_dir, relative_path);
    let mut file = File::open(&absolute)
        .with_context(|| format!("failed to open local file {}", absolute.display()))?;

    client
        .put_large_aware_reader(relative_path.to_string(), &mut file, size_bytes)
        .with_context(|| format!("failed to upload local file {relative_path}"))?;

    Ok(())
}

fn ensure_remote_directory_marker(client: &IronMeshClient, directory_path: &str) -> Result<()> {
    let normalized = normalize_relative_path(directory_path);
    if normalized.is_empty() {
        return Ok(());
    }

    let marker_key = format!("{}/", normalized);
    let mut empty = Cursor::new(Vec::<u8>::new());
    client
        .put_large_aware_reader(marker_key, &mut empty, 0)
        .with_context(|| format!("failed to upload directory marker for {normalized}"))?;

    Ok(())
}

fn delete_remote_file(client: &IronMeshClient, file_path: &str) -> Result<()> {
    let normalized = normalize_relative_path(file_path);
    if normalized.is_empty() {
        return Ok(());
    }

    client
        .delete_path_blocking(&normalized)
        .with_context(|| format!("failed to delete remote file {normalized}"))?;

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
