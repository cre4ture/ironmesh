use super::{
    AdminControl, MetadataCommitMode, PeerHeartbeatConfig, RepairConfig, RepairExecutorState,
    ServerState, StartupRepairStatus, await_repair_busy_threshold, build_store_index_entries,
    cluster, constant_time_eq, jittered_backoff_secs,
    replication::build_internal_replication_put_url, run_startup_replication_repair_once,
    should_trigger_autonomous_post_write_replication, token_matches,
};
use common::NodeId;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

use super::storage::{PersistentStore, PutOptions, VersionConsistencyState};
use axum::Router;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::{Json, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use std::collections::HashMap;
use tokio::time::{Duration, Instant};
use tower::ServiceExt;

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

fn sample_png_bytes() -> Vec<u8> {
    let image = image::DynamicImage::new_rgba8(4, 3);
    let mut cursor = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .unwrap();
    cursor.into_inner()
}

#[test]
fn token_matches_requires_exact_match() {
    assert!(!token_matches("secret", None));
    assert!(!token_matches("secret", Some("wrong")));
    assert!(token_matches("secret", Some("secret")));
}

#[tokio::test]
async fn admin_authorization_requires_token_when_configured() {
    let mut state = build_test_state(1, false).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let headers = HeaderMap::new();

    let result = super::authorize_admin_request(
        &state,
        &headers,
        "maintenance/tombstones/compact",
        true,
        true,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(result.err(), Some(axum::http::StatusCode::UNAUTHORIZED));

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn admin_authorization_requires_explicit_approval_for_destructive_action() {
    let mut state = build_test_state(1, false).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let result = super::authorize_admin_request(
        &state,
        &headers,
        "maintenance/tombstones/archive/purge",
        false,
        false,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        result.err(),
        Some(axum::http::StatusCode::PRECONDITION_FAILED)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn enroll_client_device_consumes_pairing_token_and_persists_device() {
    let state = build_test_state(1, false).await;
    let now = super::unix_ts();
    {
        let mut auth = state.client_auth.lock().await;
        auth.pairing_tokens.push(super::PairingTokenRecord {
            token_id: "pair-1".to_string(),
            token_hash: super::hash_token("pair-secret"),
            label: Some("Pixel".to_string()),
            created_at_unix: now,
            expires_at_unix: now + 300,
            used_at_unix: None,
            enrolled_device_id: None,
        });
    }

    let response = super::enroll_client_device(
        State(state.clone()),
        Json(super::ClientDeviceEnrollRequest {
            pairing_token: "pair-secret".to_string(),
            device_id: Some("device-a".to_string()),
            label: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let enrolled: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(enrolled["device_id"], "device-a");
    assert!(
        enrolled["device_token"]
            .as_str()
            .unwrap()
            .starts_with("im-dev-")
    );

    let auth = state.client_auth.lock().await;
    assert_eq!(auth.devices.len(), 1);
    assert_eq!(auth.devices[0].device_id, "device-a");
    assert!(auth.pairing_tokens[0].used_at_unix.is_some());
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn client_auth_middleware_requires_valid_bearer_when_enabled() {
    let mut state = build_test_state(1, false).await;
    state.client_auth_control.require_client_auth = true;
    {
        let mut auth = state.client_auth.lock().await;
        auth.devices.push(super::DeviceAuthRecord {
            device_id: "device-a".to_string(),
            label: Some("Pixel".to_string()),
            token_hash: super::hash_token("device-secret"),
            created_at_unix: super::unix_ts(),
            revoked_at_unix: None,
        });
    }

    let app = Router::new()
        .route("/store/index", get(|| async { StatusCode::OK }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::require_client_auth,
        ));

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/store/index")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/store/index")
                .header("Authorization", "Bearer device-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    cleanup_test_state(&state).await;
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

#[tokio::test]
async fn delete_object_handler_marks_tombstone_and_removes_current_key() {
    let state = build_test_state(1, false).await;

    // put an object into underlying store
    let key = "handler-delete-key".to_string();
    {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                &key,
                bytes::Bytes::from_static(b"payload"),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    // call handler directly
    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: None,
        internal_replication: false,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path(key.clone()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    // ensure underlying store current keys no longer include the key
    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(!keys.contains(&key));

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn list_store_index_includes_cached_media_metadata_for_images() {
    let state = build_test_state(1, false).await;
    let put = {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                "gallery/cat.png",
                bytes::Bytes::from(sample_png_bytes()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };
    {
        let locked = state.store.lock().await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index(
            axum::extract::State(state.clone()),
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("gallery".to_string()),
                depth: Some(2),
                snapshot: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = payload["entries"].as_array().unwrap();
    let media = &entries[0]["media"];

    assert_eq!(entries[0]["path"], "gallery/cat.png");
    assert_eq!(media["status"], "ready");
    assert_eq!(media["mime_type"], "image/png");
    assert_eq!(media["width"], 4);
    assert_eq!(media["height"], 3);
    assert!(
        media["thumbnail"]["url"]
            .as_str()
            .unwrap()
            .contains("/media/thumbnail?key=gallery%2Fcat.png")
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
        internal_url: "https://127.0.0.1:49080".to_string(),
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
            internal_url: "https://127.0.0.1:10009".to_string(),
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
        client_auth: Arc::new(Mutex::new(super::storage::ClientAuthState::default())),
        metadata_commit_mode: MetadataCommitMode::Local,
        internal_http: reqwest::Client::new(),
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
        admin_control: AdminControl::default(),
        client_auth_control: super::ClientAuthControl::default(),
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
