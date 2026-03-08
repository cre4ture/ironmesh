use crate::ironmesh_client::IronMeshClient;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use sync_core::{EntryKind, SyncSnapshot};

#[derive(Debug, Clone, Copy)]
pub struct RemoteSyncStrategy {
    interval: Duration,
}

impl RemoteSyncStrategy {
    pub fn polling(interval: Duration) -> Self {
        Self {
            interval: interval.max(Duration::from_millis(250)),
        }
    }
}

impl Default for RemoteSyncStrategy {
    fn default() -> Self {
        Self::polling(Duration::from_secs(3))
    }
}

#[derive(Debug, Clone)]
pub struct RemoteSyncScheduler {
    strategy: RemoteSyncStrategy,
}

impl RemoteSyncScheduler {
    pub fn new(strategy: RemoteSyncStrategy) -> Self {
        Self { strategy }
    }

    pub fn wait_for_next_tick_blocking(&self, running: &AtomicBool) -> bool {
        sleep_until_or_stop(self.strategy.interval, running)
    }

    pub fn spawn_loop<F>(&self, running: Arc<AtomicBool>, mut on_tick: F) -> JoinHandle<()>
    where
        F: FnMut() + Send + 'static,
    {
        let strategy = self.strategy;
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                if !sleep_until_or_stop(strategy.interval, &running) {
                    break;
                }
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                on_tick();
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteSnapshotUpdate {
    pub snapshot: SyncSnapshot,
    pub changed_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RemoteSnapshotScope {
    pub prefix: Option<String>,
    pub depth: usize,
    pub snapshot: Option<String>,
}

impl RemoteSnapshotScope {
    pub fn new(prefix: Option<String>, depth: usize, snapshot: Option<String>) -> Self {
        Self {
            prefix,
            depth: depth.max(1),
            snapshot,
        }
    }
}

#[derive(Clone)]
pub struct RemoteSnapshotFetcher {
    client: IronMeshClient,
    scope: RemoteSnapshotScope,
}

impl RemoteSnapshotFetcher {
    pub fn new(client: IronMeshClient, scope: RemoteSnapshotScope) -> Self {
        Self { client, scope }
    }

    pub fn from_base_url(
        base_url: impl Into<String>,
        prefix: Option<String>,
        depth: usize,
        snapshot: Option<String>,
    ) -> Self {
        let client = IronMeshClient::new(base_url);
        let scope = RemoteSnapshotScope::new(prefix, depth, snapshot);
        Self::new(client, scope)
    }

    pub fn fetch_snapshot_blocking(&self) -> Result<SyncSnapshot> {
        let mut snapshot = self.client.load_snapshot_from_server_blocking(
            self.scope.prefix.as_deref(),
            self.scope.depth,
            self.scope.snapshot.as_deref(),
        )?;

        for entry in &mut snapshot.remote {
            if entry.kind != EntryKind::File {
                continue;
            }

            let size = self
                .client
                .get_object_size_blocking(&entry.path, None, None)
                .with_context(|| format!("failed to fetch remote size for {}", entry.path))?;

            let base_version = entry.version.as_deref().unwrap_or("server-head");
            entry.version = Some(format!("{base_version}:size={size}"));
        }

        Ok(snapshot)
    }
}

#[derive(Debug, Clone)]
pub struct RemoteSnapshotPoller {
    scheduler: RemoteSyncScheduler,
}

impl RemoteSnapshotPoller {
    pub fn polling(interval: Duration) -> Self {
        Self {
            scheduler: RemoteSyncScheduler::new(RemoteSyncStrategy::polling(interval)),
        }
    }

    pub fn spawn_fetcher_loop<C>(
        &self,
        running: Arc<AtomicBool>,
        initial_snapshot: Option<SyncSnapshot>,
        fetcher: RemoteSnapshotFetcher,
        on_change: C,
    ) -> JoinHandle<()>
    where
        C: FnMut(RemoteSnapshotUpdate) + Send + 'static,
    {
        self.spawn_changed_paths_loop(
            running,
            initial_snapshot,
            move || fetcher.fetch_snapshot_blocking(),
            on_change,
        )
    }

    pub fn spawn_changed_paths_loop<F, C>(
        &self,
        running: Arc<AtomicBool>,
        mut current_snapshot: Option<SyncSnapshot>,
        mut fetch_snapshot: F,
        mut on_change: C,
    ) -> JoinHandle<()>
    where
        F: FnMut() -> Result<SyncSnapshot> + Send + 'static,
        C: FnMut(RemoteSnapshotUpdate) + Send + 'static,
    {
        let scheduler = self.scheduler.clone();
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                if !scheduler.wait_for_next_tick_blocking(&running) {
                    break;
                }
                if !running.load(Ordering::SeqCst) {
                    break;
                }

                let next_snapshot = match fetch_snapshot() {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        eprintln!("remote-refresh: snapshot polling error: {error}");
                        continue;
                    }
                };

                if let Some(previous) = current_snapshot.as_ref() {
                    let changed_paths = changed_paths_between(previous, &next_snapshot);
                    if !changed_paths.is_empty() {
                        on_change(RemoteSnapshotUpdate {
                            snapshot: next_snapshot.clone(),
                            changed_paths,
                        });
                    }
                }

                current_snapshot = Some(next_snapshot);
            }
        })
    }
}

pub fn changed_paths_between(previous: &SyncSnapshot, current: &SyncSnapshot) -> Vec<String> {
    let previous_index = remote_snapshot_index(previous);
    let current_index = remote_snapshot_index(current);

    let mut all_paths: BTreeSet<String> = previous_index.keys().cloned().collect();
    all_paths.extend(current_index.keys().cloned());

    let mut changed_paths = Vec::new();
    for path in all_paths {
        if previous_index.get(&path) != current_index.get(&path) {
            changed_paths.push(path);
        }
    }
    changed_paths
}

type RemoteSnapshotIndex =
    BTreeMap<String, (EntryKind, Option<String>, Option<String>, Option<u64>)>;

fn remote_snapshot_index(snapshot: &SyncSnapshot) -> RemoteSnapshotIndex {
    let mut index = BTreeMap::new();
    for entry in &snapshot.remote {
        index.insert(
            entry.path.clone(),
            (
                entry.kind,
                entry.version.clone(),
                entry.content_hash.clone(),
                entry.size_bytes,
            ),
        );
    }
    index
}

fn sleep_until_or_stop(duration: Duration, running: &AtomicBool) -> bool {
    if duration.is_zero() {
        return running.load(Ordering::SeqCst);
    }

    let mut remaining = duration;
    let step = Duration::from_millis(100);
    while remaining > Duration::from_millis(0) {
        if !running.load(Ordering::SeqCst) {
            return false;
        }
        let nap = if remaining > step { step } else { remaining };
        thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
    }
    running.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::changed_paths_between;
    use sync_core::{NamespaceEntry, SyncSnapshot};

    #[test]
    fn changed_paths_between_detects_add_update_delete() {
        let previous = SyncSnapshot {
            local: Vec::new(),
            remote: vec![
                NamespaceEntry::directory("docs"),
                NamespaceEntry::file("docs/readme.md", "v1", "h1"),
                NamespaceEntry::file("docs/old.txt", "v1", "h-old"),
            ],
        };
        let current = SyncSnapshot {
            local: Vec::new(),
            remote: vec![
                NamespaceEntry::directory("docs"),
                NamespaceEntry::file("docs/readme.md", "v2", "h2"),
                NamespaceEntry::file("docs/new.txt", "v1", "h-new"),
            ],
        };

        let changed = changed_paths_between(&previous, &current);

        assert_eq!(
            changed,
            vec![
                "docs/new.txt".to_string(),
                "docs/old.txt".to_string(),
                "docs/readme.md".to_string(),
            ],
        );
    }

    #[test]
    fn changed_paths_between_detects_remote_size_only_changes() {
        let previous = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file_sized(
                "docs/readme.md",
                "v1",
                "h1",
                Some(12),
            )],
        };
        let current = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file_sized(
                "docs/readme.md",
                "v1",
                "h1",
                Some(24),
            )],
        };

        let changed = changed_paths_between(&previous, &current);

        assert_eq!(changed, vec!["docs/readme.md".to_string()]);
    }
}
