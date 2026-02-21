use super::{
    MetadataCommitMode, PeerHeartbeatConfig, RepairConfig, RepairExecutorState, ServerState,
    StartupRepairStatus, await_repair_busy_threshold, build_store_index_entries, cluster,
    constant_time_eq, expected_internal_token_for_node, internal_node_header_valid,
    internal_token_matches, jittered_backoff_secs, parse_internal_node_tokens,
    replication::build_internal_replication_put_url, run_startup_replication_repair_once,
    should_trigger_autonomous_post_write_replication,
};
use common::NodeId;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use super::storage::{PersistentStore, PutOptions, VersionConsistencyState};
use std::collections::HashMap;
use tokio::time::{Duration, Instant};

#[test]
fn jittered_backoff_is_deterministic_for_same_inputs() {
    let first = jittered_backoff_secs(30, "key@ver|node", 2);
    let second = jittered_backoff_secs(30, "key@ver|node", 2);
    assert_eq!(first, second);
}

#[test]
fn jittered_backoff_stays_within_expected_range() {
    let value = jittered_backoff_secs(40, "another-key|node", 3);
    assert!(value >= 40);
    assert!(value <= 60);
}

#[test]
fn constant_time_eq_compares_equal_and_non_equal_values() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(!constant_time_eq(b"secret", b"Secret"));
    assert!(!constant_time_eq(b"secret", b"secret-long"));
}

#[test]
fn internal_token_auth_requires_exact_match_when_configured() {
    assert!(!internal_token_matches("secret", None));
    assert!(!internal_token_matches("secret", Some("wrong")));
    assert!(internal_token_matches("secret", Some("secret")));
}

#[test]
fn internal_node_header_rules_match_token_mode() {
    assert!(!internal_node_header_valid(None));
    assert!(!internal_node_header_valid(Some("not-a-uuid")));
    assert!(internal_node_header_valid(Some(
        "00000000-0000-0000-0000-000000000001"
    )));
}

#[test]
fn parse_internal_node_tokens_parses_multiple_entries() {
    let parsed = parse_internal_node_tokens(
        "00000000-0000-0000-0000-000000000001=tok-a,00000000-0000-0000-0000-000000000002=tok-b",
    )
    .unwrap();

    assert_eq!(parsed.len(), 2);
}

#[test]
fn parse_internal_node_tokens_rejects_duplicate_node_ids() {
    let duplicate =
        "00000000-0000-0000-0000-000000000001=tok-a,00000000-0000-0000-0000-000000000001=tok-b";
    assert!(parse_internal_node_tokens(duplicate).is_err());
}

#[test]
fn expected_internal_token_returns_none_when_node_missing() {
    let node_tokens = HashMap::new();
    let expected = expected_internal_token_for_node(&node_tokens, NodeId::new_v4());
    assert_eq!(expected, None);
}

#[test]
fn expected_internal_token_returns_node_token() {
    let node = NodeId::new_v4();
    let mut node_tokens = HashMap::new();
    node_tokens.insert(node, "node-token".to_string());

    let expected = expected_internal_token_for_node(&node_tokens, node);
    assert_eq!(expected, Some("node-token"));
}

#[test]
fn store_index_depth_groups_prefixes() {
    let keys = vec![
        "docs/guide/intro.md".to_string(),
        "docs/guide/setup.md".to_string(),
        "docs/api/v1.json".to_string(),
    ];

    let entries = build_store_index_entries(&keys, "docs", 1);
    let paths = entries
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["docs/api/", "docs/guide/"]);
}

#[test]
fn store_index_prefix_returns_matching_keys() {
    let keys = vec![
        "images/cat.png".to_string(),
        "images/dogs/beagle.png".to_string(),
        "docs/readme.md".to_string(),
    ];

    let entries = build_store_index_entries(&keys, "images", 2);
    let mut key_paths = entries
        .into_iter()
        .filter(|entry| entry.entry_type == "key")
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    key_paths.sort();

    assert_eq!(key_paths, vec!["images/cat.png", "images/dogs/beagle.png"]);
}

#[test]
fn autonomous_post_write_replication_trigger_guard_blocks_internal_writes() {
    assert!(should_trigger_autonomous_post_write_replication(
        true, false
    ));
    assert!(!should_trigger_autonomous_post_write_replication(
        true, true
    ));
    assert!(!should_trigger_autonomous_post_write_replication(
        false, false
    ));
}

#[test]
fn internal_replication_put_url_sets_internal_flag() {
    let url = build_internal_replication_put_url(
        "http://127.0.0.1:18080",
        "hello",
        "confirmed",
        Some("ver-123"),
    );
    assert!(url.contains("/store/hello?"));
    assert!(url.contains("state=confirmed"));
    assert!(url.contains("version_id=ver-123"));
    assert!(url.contains("internal_replication=true"));
}

#[tokio::test]
async fn repair_busy_threshold_returns_immediately_when_disabled() {
    let mut state = build_test_state(1, false).await;
    state.repair_config.busy_throttle_enabled = false;
    state
        .inflight_requests
        .store(1_000, std::sync::atomic::Ordering::Relaxed);
    let start = Instant::now();

    await_repair_busy_threshold(&state).await;

    assert!(start.elapsed() < Duration::from_millis(10));
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn repair_busy_threshold_waits_until_load_drops() {
    let mut state = build_test_state(1, false).await;
    state.repair_config.busy_throttle_enabled = true;
    state.repair_config.busy_inflight_threshold = 1;
    state.repair_config.busy_wait_millis = 5;
    state
        .inflight_requests
        .store(5, std::sync::atomic::Ordering::Relaxed);

    let inflight_requests_for_release = Arc::clone(&state.inflight_requests);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        inflight_requests_for_release.store(0, std::sync::atomic::Ordering::Relaxed);
    });

    let start = Instant::now();
    await_repair_busy_threshold(&state).await;

    assert!(start.elapsed() >= Duration::from_millis(15));
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn startup_repair_noop_when_plan_is_empty() {
    let state = build_test_state(1, false).await;

    let result = run_startup_replication_repair_once(&state, 0).await;
    assert!(result.is_none());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn startup_repair_runs_when_gaps_exist() {
    let state = build_test_state(2, true).await;

    let result = run_startup_replication_repair_once(&state, 0).await;
    assert!(result.is_some());

    let (plan, report) = result.unwrap();
    assert!(!plan.items.is_empty());
    assert!(
        report.attempted_transfers > 0,
        "startup repair should attempt transfers when replication gaps exist"
    );

    cleanup_test_state(&state).await;
}

async fn build_test_state(replication_factor: usize, seed_gap: bool) -> ServerState {
    let root = fresh_test_dir("startup-repair-main");
    let local_node_id = NodeId::new_v4();

    let store = Arc::new(Mutex::new(
        PersistentStore::init(root.clone()).await.unwrap(),
    ));

    let mut service = cluster::ClusterService::new(
        local_node_id,
        cluster::ReplicationPolicy {
            replication_factor,
            ..cluster::ReplicationPolicy::default()
        },
        60,
    );

    service.register_node(cluster::NodeDescriptor {
        node_id: local_node_id,
        public_url: "http://127.0.0.1:39080".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 1_000_000,
        free_bytes: 900_000,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    if replication_factor > 1 {
        service.register_node(cluster::NodeDescriptor {
            node_id: NodeId::new_v4(),
            public_url: "http://127.0.0.1:9".to_string(),
            labels: HashMap::new(),
            capacity_bytes: 1_000_000,
            free_bytes: 800_000,
            last_heartbeat_unix: 0,
            status: cluster::NodeStatus::Online,
        });
    }

    let state = ServerState {
        node_id: local_node_id,
        store: store.clone(),
        cluster: Arc::new(Mutex::new(service)),
        metadata_commit_mode: MetadataCommitMode::Local,
        internal_node_tokens: Arc::new(Mutex::new(HashMap::new())),
        autonomous_replication_on_put_enabled: false,
        inflight_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        replication_audit_interval_secs: 3600,
        peer_heartbeat_config: PeerHeartbeatConfig {
            enabled: false,
            interval_secs: 15,
        },
        repair_config: RepairConfig {
            enabled: true,
            batch_size: 32,
            max_retries: 3,
            backoff_secs: 0,
            startup_repair_enabled: true,
            startup_repair_delay_secs: 0,
            busy_throttle_enabled: false,
            busy_inflight_threshold: 1,
            busy_wait_millis: 100,
        },
        log_buffer: Arc::new(super::LogBuffer::new(64)),
        startup_repair_status: Arc::new(Mutex::new(StartupRepairStatus::Scheduled)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
    };

    if seed_gap {
        let put = {
            let mut locked = store.lock().await;
            locked
                .put_object_versioned(
                    "startup-gap-key",
                    bytes::Bytes::from_static(b"payload"),
                    PutOptions {
                        parent_version_ids: Vec::new(),
                        state: VersionConsistencyState::Confirmed,
                        inherit_preferred_parent: true,
                        create_snapshot: true,
                        explicit_version_id: None,
                    },
                )
                .await
                .unwrap()
        };

        let mut cluster = state.cluster.lock().await;
        cluster.note_replica("startup-gap-key", local_node_id);
        cluster.note_replica(format!("startup-gap-key@{}", put.version_id), local_node_id);
    }

    state
}

async fn cleanup_test_state(state: &ServerState) {
    let root = {
        let store = state.store.lock().await;
        store.root_dir().to_path_buf()
    };
    let _ = tokio::fs::remove_dir_all(root).await;
}

fn fresh_test_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("ironmesh-{name}-{unique}"));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::create_dir_all(&path);
    path
}
