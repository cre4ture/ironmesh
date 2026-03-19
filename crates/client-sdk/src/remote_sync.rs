use crate::bootstrap::ConnectionBootstrap;
use crate::ironmesh_client::IronMeshClient;
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;
use sync_core::{EntryKind, SyncSnapshot};
use transport_sdk::ClientIdentityMaterial;

#[derive(Debug, Clone, Copy)]
pub struct RemoteSyncStrategy {
    mode: RemoteSyncMode,
}

#[derive(Debug, Clone, Copy)]
enum RemoteSyncMode {
    Polling {
        interval: Duration,
    },
    ServerNotifications {
        wait_timeout: Duration,
        retry_interval: Duration,
    },
}

impl RemoteSyncStrategy {
    pub fn polling(interval: Duration) -> Self {
        Self {
            mode: RemoteSyncMode::Polling {
                interval: interval.max(Duration::from_millis(250)),
            },
        }
    }

    pub fn server_notifications(wait_timeout: Duration, retry_interval: Duration) -> Self {
        Self {
            mode: RemoteSyncMode::ServerNotifications {
                wait_timeout: wait_timeout.max(Duration::from_millis(250)),
                retry_interval: retry_interval.max(Duration::from_millis(250)),
            },
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
        sleep_until_or_stop(self.fallback_interval(), running)
    }

    pub fn spawn_loop<F>(&self, running: Arc<AtomicBool>, mut on_tick: F) -> JoinHandle<()>
    where
        F: FnMut() + Send + 'static,
    {
        let interval = self.fallback_interval();
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                if !sleep_until_or_stop(interval, &running) {
                    break;
                }
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                on_tick();
            }
        })
    }

    fn fallback_interval(&self) -> Duration {
        match self.strategy.mode {
            RemoteSyncMode::Polling { interval } => interval,
            RemoteSyncMode::ServerNotifications { retry_interval, .. } => retry_interval,
        }
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

    pub fn from_bootstrap(
        bootstrap: &ConnectionBootstrap,
        identity: Option<&ClientIdentityMaterial>,
        prefix: Option<String>,
        depth: usize,
        snapshot: Option<String>,
    ) -> Result<Self> {
        let client = bootstrap.build_client_with_optional_identity(identity)?;
        let scope = RemoteSnapshotScope::new(prefix, depth, snapshot);
        Ok(Self::new(client, scope))
    }

    pub fn from_direct_base_url(
        base_url: impl Into<String>,
        prefix: Option<String>,
        depth: usize,
        snapshot: Option<String>,
    ) -> Self {
        let client = IronMeshClient::from_direct_base_url(base_url);
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

    pub fn server_notifications(wait_timeout: Duration, retry_interval: Duration) -> Self {
        Self {
            scheduler: RemoteSyncScheduler::new(RemoteSyncStrategy::server_notifications(
                wait_timeout,
                retry_interval,
            )),
        }
    }

    pub fn spawn_fetcher_loop<C>(
        &self,
        running: Arc<AtomicBool>,
        initial_snapshot: Option<SyncSnapshot>,
        fetcher: RemoteSnapshotFetcher,
        mut on_change: C,
    ) -> JoinHandle<()>
    where
        C: FnMut(RemoteSnapshotUpdate) + Send + 'static,
    {
        match self.scheduler.strategy.mode {
            RemoteSyncMode::Polling { .. } => self.spawn_changed_paths_loop(
                running,
                initial_snapshot,
                move || fetcher.fetch_snapshot_blocking(),
                on_change,
            ),
            RemoteSyncMode::ServerNotifications {
                wait_timeout,
                retry_interval: _,
            } => {
                let scheduler = self.scheduler.clone();
                thread::spawn(move || {
                    let mut current_snapshot = initial_snapshot;
                    let mut last_sequence = 0u64;
                    let mut notifications_available = true;

                    while running.load(Ordering::SeqCst) {
                        if notifications_available {
                            match fetcher.client.wait_for_store_index_change_blocking(
                                last_sequence,
                                wait_timeout.as_millis() as u64,
                            ) {
                                Ok(response) => {
                                    last_sequence = response.sequence;
                                    if !response.changed {
                                        continue;
                                    }
                                }
                                Err(error) => {
                                    eprintln!(
                                        "remote-refresh: server change wait unavailable, falling back to polling: {error}"
                                    );
                                    notifications_available = false;
                                }
                            }
                        }

                        if !notifications_available
                            && !scheduler.wait_for_next_tick_blocking(&running)
                        {
                            break;
                        }
                        if !running.load(Ordering::SeqCst) {
                            break;
                        }

                        let next_snapshot = match fetcher.fetch_snapshot_blocking() {
                            Ok(snapshot) => snapshot,
                            Err(error) => {
                                eprintln!("remote-refresh: snapshot refresh error: {error}");
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
    use super::*;
    use axum::{Json, Router, routing::get};
    use common::ClusterId;
    use std::sync::mpsc;
    use sync_core::{NamespaceEntry, SyncSnapshot};
    use transport_sdk::{BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, RelayMode};

    fn sample_bootstrap(base_url: &str) -> ConnectionBootstrap {
        ConnectionBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id: ClusterId::now_v7(),
            rendezvous_urls: vec![base_url.to_string()],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: base_url.to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: None,
            }],
            relay_mode: RelayMode::Disabled,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            pairing_token: None,
            device_label: None,
            device_id: None,
        }
    }

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

    #[test]
    fn remote_sync_strategy_polling_enforces_minimum_interval() {
        let strategy = RemoteSyncStrategy::polling(Duration::from_millis(10));

        match strategy.mode {
            RemoteSyncMode::Polling { interval } => {
                assert_eq!(interval, Duration::from_millis(250));
            }
            RemoteSyncMode::ServerNotifications { .. } => {
                panic!("polling strategy should stay in polling mode");
            }
        }

        let scheduler = RemoteSyncScheduler::new(strategy);
        assert_eq!(scheduler.fallback_interval(), Duration::from_millis(250));
    }

    #[test]
    fn remote_sync_strategy_server_notifications_enforces_minimum_intervals() {
        let strategy =
            RemoteSyncStrategy::server_notifications(Duration::from_millis(1), Duration::ZERO);

        match strategy.mode {
            RemoteSyncMode::Polling { .. } => {
                panic!("server notification strategy should not switch to polling mode");
            }
            RemoteSyncMode::ServerNotifications {
                wait_timeout,
                retry_interval,
            } => {
                assert_eq!(wait_timeout, Duration::from_millis(250));
                assert_eq!(retry_interval, Duration::from_millis(250));
            }
        }

        let scheduler = RemoteSyncScheduler::new(strategy);
        assert_eq!(scheduler.fallback_interval(), Duration::from_millis(250));
    }

    #[test]
    fn remote_sync_strategy_default_uses_three_second_polling() {
        match RemoteSyncStrategy::default().mode {
            RemoteSyncMode::Polling { interval } => {
                assert_eq!(interval, Duration::from_secs(3));
            }
            RemoteSyncMode::ServerNotifications { .. } => {
                panic!("default strategy should poll");
            }
        }
    }

    #[test]
    fn remote_snapshot_scope_and_direct_fetcher_normalize_defaults() {
        let fetcher = RemoteSnapshotFetcher::from_direct_base_url(
            "http://127.0.0.1:1",
            Some("docs".to_string()),
            0,
            Some("snap-1".to_string()),
        );

        assert_eq!(fetcher.scope.prefix.as_deref(), Some("docs"));
        assert_eq!(fetcher.scope.depth, 1);
        assert_eq!(fetcher.scope.snapshot.as_deref(), Some("snap-1"));
    }

    #[test]
    fn sleep_until_or_stop_respects_zero_duration_and_stopped_state() {
        let running = AtomicBool::new(true);
        assert!(sleep_until_or_stop(Duration::ZERO, &running));

        running.store(false, Ordering::SeqCst);
        assert!(!sleep_until_or_stop(Duration::from_millis(1), &running));
    }

    #[test]
    fn polling_loop_emits_changed_paths_updates() {
        let poller = RemoteSnapshotPoller::polling(Duration::from_millis(1));
        let running = Arc::new(AtomicBool::new(true));
        let initial_snapshot = SyncSnapshot {
            local: Vec::new(),
            remote: vec![NamespaceEntry::file("docs/readme.md", "v1", "h1")],
        };
        let next_snapshot = SyncSnapshot {
            local: Vec::new(),
            remote: vec![
                NamespaceEntry::file("docs/readme.md", "v2", "h2"),
                NamespaceEntry::file("docs/new.txt", "v1", "h-new"),
            ],
        };
        let (tx, rx) = mpsc::channel();
        let running_for_callback = Arc::clone(&running);

        let handle = poller.spawn_changed_paths_loop(
            Arc::clone(&running),
            Some(initial_snapshot),
            move || Ok(next_snapshot.clone()),
            move |update| {
                running_for_callback.store(false, Ordering::SeqCst);
                tx.send(update).expect("update should send");
            },
        );

        let update = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("changed snapshot should produce an update");
        handle.join().expect("polling loop should stop cleanly");

        assert_eq!(
            update.changed_paths,
            vec!["docs/new.txt".to_string(), "docs/readme.md".to_string(),],
        );
        assert_eq!(update.snapshot.remote.len(), 2);
    }

    #[test]
    fn remote_snapshot_fetcher_from_bootstrap_builds_transport_aware_client() {
        async fn health() -> Json<serde_json::Value> {
            Json(serde_json::json!({ "ok": true }))
        }

        async fn store_index() -> Json<crate::ironmesh_client::StoreIndexResponse> {
            Json(crate::ironmesh_client::StoreIndexResponse {
                prefix: String::new(),
                depth: 1,
                entry_count: 0,
                entries: Vec::new(),
            })
        }

        let router = Router::new()
            .route("/health", get(health))
            .route("/store/index", get(store_index));
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("listener should bind");
                let addr = listener.local_addr().expect("listener addr");
                addr_tx.send(addr).expect("listener addr should send");
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("test server should run");
            });
        });
        let addr = addr_rx.recv().expect("listener addr should arrive");

        let bootstrap = sample_bootstrap(&format!("http://{addr}"));
        let fetcher = RemoteSnapshotFetcher::from_bootstrap(&bootstrap, None, None, 1, None)
            .expect("bootstrap-backed fetcher should build");

        let snapshot = fetcher
            .fetch_snapshot_blocking()
            .expect("bootstrap-backed fetcher should load snapshot");

        assert!(snapshot.remote.is_empty());

        let _ = shutdown_tx.send(());
        let _ = server.join();
    }
}
