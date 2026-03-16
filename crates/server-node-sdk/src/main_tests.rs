use super::{
    AdminControl, LocalNodeHandle, MetadataCommitMode, PeerHeartbeatConfig, RepairConfig,
    RepairExecutorState, ServerNodeConfig, ServerState, StartupRepairStatus,
    await_repair_busy_threshold, build_rendezvous_presence_registration, build_store_index_entries,
    cluster, constant_time_eq, jittered_backoff_secs, node_descriptor_from_presence_entry,
    plan_peer_transport, replication::build_internal_replication_put_url, resolve_peer_base_url,
    run, run_startup_replication_repair_once, should_trigger_autonomous_post_write_replication,
    token_matches,
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
use axum::extract::{Json, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use tokio::time::{Duration, Instant};
use tower::ServiceExt;

#[derive(Clone, Copy)]
enum MainTestBackend {
    Sqlite,
    #[cfg(feature = "turso-metadata")]
    Turso,
}

impl MainTestBackend {
    fn kind(self) -> super::storage::MetadataBackendKind {
        match self {
            Self::Sqlite => super::storage::MetadataBackendKind::Sqlite,
            #[cfg(feature = "turso-metadata")]
            Self::Turso => super::storage::MetadataBackendKind::Turso,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            #[cfg(feature = "turso-metadata")]
            Self::Turso => "turso",
        }
    }
}

macro_rules! run_on_main_metadata_backends {
    ($body:ident, $sqlite_test:ident, $turso_test:ident) => {
        #[tokio::test]
        async fn $sqlite_test() {
            $body(MainTestBackend::Sqlite).await;
        }

        #[cfg(feature = "turso-metadata")]
        #[tokio::test]
        async fn $turso_test() {
            $body(MainTestBackend::Turso).await;
        }
    };
}

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
fn metadata_backend_parser_accepts_sqlite() {
    let backend = super::parse_metadata_backend("sqlite").unwrap();
    assert!(matches!(
        backend,
        super::storage::MetadataBackendKind::Sqlite
    ));
}

#[test]
fn metadata_backend_parser_handles_turso_feature_gate() {
    let result = super::parse_metadata_backend("turso");
    #[cfg(feature = "turso-metadata")]
    assert!(matches!(
        result.unwrap(),
        super::storage::MetadataBackendKind::Turso
    ));
    #[cfg(not(feature = "turso-metadata"))]
    assert!(result.unwrap_err().to_string().contains("turso-metadata"));
}

fn sample_png_bytes() -> Vec<u8> {
    let image = image::DynamicImage::new_rgba8(4, 3);
    let mut cursor = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .unwrap();
    cursor.into_inner()
}

fn free_bind_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

#[test]
fn token_matches_requires_exact_match() {
    assert!(!token_matches("secret", None));
    assert!(!token_matches("secret", Some("wrong")));
    assert!(token_matches("secret", Some("secret")));
}

async fn admin_authorization_requires_token_when_configured_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
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

run_on_main_metadata_backends!(
    admin_authorization_requires_token_when_configured_impl,
    admin_authorization_requires_token_when_configured,
    admin_authorization_requires_token_when_configured_turso
);

async fn admin_authorization_requires_explicit_approval_for_destructive_action_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
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

run_on_main_metadata_backends!(
    admin_authorization_requires_explicit_approval_for_destructive_action_impl,
    admin_authorization_requires_explicit_approval_for_destructive_action,
    admin_authorization_requires_explicit_approval_for_destructive_action_turso
);

async fn enroll_client_device_consumes_pairing_token_and_persists_device_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;
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
            cluster_id: state.cluster_id,
            pairing_token: "pair-secret".to_string(),
            device_id: Some("device-a".to_string()),
            label: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
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

run_on_main_metadata_backends!(
    enroll_client_device_consumes_pairing_token_and_persists_device_impl,
    enroll_client_device_consumes_pairing_token_and_persists_device,
    enroll_client_device_consumes_pairing_token_and_persists_device_turso
);

#[tokio::test]
async fn issue_bootstrap_bundle_includes_rendezvous_security_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_mtls_required = true;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_bundle(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let bootstrap: transport_sdk::ClientBootstrap = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        bootstrap.rendezvous_urls,
        vec!["https://rendezvous.example".to_string()]
    );
    assert!(bootstrap.rendezvous_mtls_required);
    assert_eq!(
        bootstrap.trust_roots.rendezvous_ca_pem.as_deref(),
        Some("rendezvous-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.public_api_ca_pem.as_deref(),
        Some("public-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.cluster_ca_pem.as_deref(),
        Some("cluster-ca")
    );
    assert_eq!(bootstrap.device_label.as_deref(), Some("tablet"));
    assert!(bootstrap.pairing_token.is_some());

    cleanup_test_state(&state).await;
}

async fn client_auth_middleware_requires_valid_signature_when_enabled_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
    state.client_auth_control.require_client_auth = true;
    let mut identity =
        transport_sdk::ClientIdentityMaterial::generate(state.cluster_id, None, None).unwrap();
    let credential_pem = super::generate_client_credential_pem(
        state.cluster_id,
        &identity.device_id.to_string(),
        &identity.public_key_pem,
        super::unix_ts(),
        None,
    );
    identity.credential_pem = Some(credential_pem.clone());
    {
        let mut auth = state.client_auth.lock().await;
        auth.devices.push(super::DeviceAuthRecord {
            device_id: identity.device_id.to_string(),
            label: Some("Pixel".to_string()),
            token_hash: super::hash_token("legacy-device-secret"),
            public_key_pem: Some(identity.public_key_pem.clone()),
            issued_credential_pem: Some(credential_pem),
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
    let signed_headers = transport_sdk::build_signed_request_headers(
        &identity,
        "GET",
        "/store/index",
        super::unix_ts(),
        Some("nonce-a".to_string()),
    )
    .unwrap();

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
                .header(
                    transport_sdk::HEADER_CLUSTER_ID,
                    signed_headers.cluster_id.to_string(),
                )
                .header(
                    transport_sdk::HEADER_DEVICE_ID,
                    signed_headers.device_id.as_str(),
                )
                .header(
                    transport_sdk::HEADER_CREDENTIAL_FINGERPRINT,
                    signed_headers.credential_fingerprint.as_str(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_TIMESTAMP,
                    signed_headers.timestamp_unix.to_string(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_NONCE,
                    signed_headers.nonce.as_str(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_SIGNATURE,
                    signed_headers.signature_base64.as_str(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    client_auth_middleware_requires_valid_signature_when_enabled_impl,
    client_auth_middleware_requires_valid_signature_when_enabled,
    client_auth_middleware_requires_valid_signature_when_enabled_turso
);

async fn client_auth_middleware_rejects_replayed_nonce_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.client_auth_control.require_client_auth = true;
    let mut identity =
        transport_sdk::ClientIdentityMaterial::generate(state.cluster_id, None, None).unwrap();
    let credential_pem = super::generate_client_credential_pem(
        state.cluster_id,
        &identity.device_id.to_string(),
        &identity.public_key_pem,
        super::unix_ts(),
        None,
    );
    identity.credential_pem = Some(credential_pem.clone());
    {
        let mut auth = state.client_auth.lock().await;
        auth.devices.push(super::DeviceAuthRecord {
            device_id: identity.device_id.to_string(),
            label: None,
            token_hash: super::hash_token("legacy-device-secret"),
            public_key_pem: Some(identity.public_key_pem.clone()),
            issued_credential_pem: Some(credential_pem),
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
    let signed_headers = transport_sdk::build_signed_request_headers(
        &identity,
        "GET",
        "/store/index",
        super::unix_ts(),
        Some("nonce-replay".to_string()),
    )
    .unwrap();

    let request = || {
        Request::builder()
            .uri("/store/index")
            .header(
                transport_sdk::HEADER_CLUSTER_ID,
                signed_headers.cluster_id.to_string(),
            )
            .header(
                transport_sdk::HEADER_DEVICE_ID,
                signed_headers.device_id.as_str(),
            )
            .header(
                transport_sdk::HEADER_CREDENTIAL_FINGERPRINT,
                signed_headers.credential_fingerprint.as_str(),
            )
            .header(
                transport_sdk::HEADER_AUTH_TIMESTAMP,
                signed_headers.timestamp_unix.to_string(),
            )
            .header(
                transport_sdk::HEADER_AUTH_NONCE,
                signed_headers.nonce.as_str(),
            )
            .header(
                transport_sdk::HEADER_AUTH_SIGNATURE,
                signed_headers.signature_base64.as_str(),
            )
            .body(Body::empty())
            .unwrap()
    };

    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let replayed = app.oneshot(request()).await.unwrap();
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    client_auth_middleware_rejects_replayed_nonce_impl,
    client_auth_middleware_rejects_replayed_nonce,
    client_auth_middleware_rejects_replayed_nonce_turso
);

async fn store_index_change_wait_unblocks_after_put_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let waiter_state = state.clone();
    let waiter = tokio::spawn(async move {
        let response = super::wait_for_store_index_change(
            State(waiter_state),
            Query(super::StoreIndexChangeWaitQuery {
                since: Some(0),
                timeout_ms: Some(2_000),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<super::StoreIndexChangeWaitResponse>(&body).unwrap()
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let response = super::put_object(
        State(state.clone()),
        axum::extract::Path("notify.txt".to_string()),
        Query(super::PutObjectQuery {
            state: None,
            parent: Vec::new(),
            version_id: None,
            internal_replication: false,
            recursive: false,
        }),
        Bytes::from_static(b"notify-payload"),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);

    let payload = waiter.await.unwrap();
    assert!(payload.changed);
    assert!(payload.sequence >= 1);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    store_index_change_wait_unblocks_after_put_impl,
    store_index_change_wait_unblocks_after_put,
    store_index_change_wait_unblocks_after_put_turso
);

async fn store_index_change_wait_times_out_without_mutation_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let response = super::wait_for_store_index_change(
        State(state.clone()),
        Query(super::StoreIndexChangeWaitQuery {
            since: Some(0),
            timeout_ms: Some(250),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload = serde_json::from_slice::<super::StoreIndexChangeWaitResponse>(&body).unwrap();
    assert!(!payload.changed);
    assert_eq!(payload.sequence, 0);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    store_index_change_wait_times_out_without_mutation_impl,
    store_index_change_wait_times_out_without_mutation,
    store_index_change_wait_times_out_without_mutation_turso
);

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

async fn repair_busy_threshold_returns_immediately_when_disabled_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.repair_config.busy_throttle_enabled = false;
    state
        .inflight_requests
        .store(1_000, std::sync::atomic::Ordering::Relaxed);
    let start = Instant::now();

    await_repair_busy_threshold(&state).await;

    assert!(start.elapsed() < Duration::from_millis(10));
    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    repair_busy_threshold_returns_immediately_when_disabled_impl,
    repair_busy_threshold_returns_immediately_when_disabled,
    repair_busy_threshold_returns_immediately_when_disabled_turso
);

async fn repair_busy_threshold_waits_until_load_drops_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
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

run_on_main_metadata_backends!(
    repair_busy_threshold_waits_until_load_drops_impl,
    repair_busy_threshold_waits_until_load_drops,
    repair_busy_threshold_waits_until_load_drops_turso
);

async fn startup_repair_noop_when_plan_is_empty_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let result = run_startup_replication_repair_once(&state, 0).await;
    assert!(result.is_none());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    startup_repair_noop_when_plan_is_empty_impl,
    startup_repair_noop_when_plan_is_empty,
    startup_repair_noop_when_plan_is_empty_turso
);

async fn startup_repair_runs_when_gaps_exist_impl(backend: MainTestBackend) {
    let state = build_test_state(2, true, backend).await;

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

run_on_main_metadata_backends!(
    startup_repair_runs_when_gaps_exist_impl,
    startup_repair_runs_when_gaps_exist,
    startup_repair_runs_when_gaps_exist_turso
);

async fn delete_object_handler_marks_tombstone_and_removes_current_key_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

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
        recursive: false,
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

run_on_main_metadata_backends!(
    delete_object_handler_marks_tombstone_and_removes_current_key_impl,
    delete_object_handler_marks_tombstone_and_removes_current_key,
    delete_object_handler_marks_tombstone_and_removes_current_key_turso
);

async fn delete_object_handler_recursively_tombstones_directory_subtree_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

    {
        let mut locked = state.store.lock().await;
        for (key, payload) in [
            ("docs/", bytes::Bytes::from_static(b"")),
            ("docs/a.txt", bytes::Bytes::from_static(b"a")),
            ("docs/nested/", bytes::Bytes::from_static(b"")),
            ("docs/nested/b.txt", bytes::Bytes::from_static(b"b")),
            ("other/keep.txt", bytes::Bytes::from_static(b"keep")),
        ] {
            locked
                .put_object_versioned(key, payload, PutOptions::default())
                .await
                .unwrap();
        }
    }

    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: None,
        internal_replication: false,
        recursive: true,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path("docs/".to_string()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(
        !keys
            .iter()
            .any(|key| key == "docs/" || key.starts_with("docs/"))
    );
    assert!(keys.contains(&"other/keep.txt".to_string()));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    delete_object_handler_recursively_tombstones_directory_subtree_impl,
    delete_object_handler_recursively_tombstones_directory_subtree,
    delete_object_handler_recursively_tombstones_directory_subtree_turso
);

async fn delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

    {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                "docs/",
                bytes::Bytes::from_static(b""),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: Some("repl-tomb-docs-marker".to_string()),
        internal_replication: true,
        recursive: false,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path("docs/".to_string()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(!keys.contains(&"docs/".to_string()));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_impl,
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker,
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_turso
);

async fn list_store_index_includes_cached_media_metadata_for_images_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;
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

run_on_main_metadata_backends!(
    list_store_index_includes_cached_media_metadata_for_images_impl,
    list_store_index_includes_cached_media_metadata_for_images,
    list_store_index_includes_cached_media_metadata_for_images_turso
);

async fn local_edge_mode_serves_health_without_internal_tls_impl(backend: MainTestBackend) {
    let bind_addr = free_bind_addr();
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-{}-{}-{}",
        backend.suffix(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut config = ServerNodeConfig::local_edge(&data_dir, bind_addr);
    config.public_url = Some(format!("http://{bind_addr}"));
    config.metadata_backend = backend.kind();

    let handle = tokio::spawn(async move { run(config).await });
    let client = reqwest::Client::new();
    let health_url = format!("http://{bind_addr}/health");

    let started = async {
        for _ in 0..50 {
            match client.get(&health_url).send().await {
                Ok(response) if response.status() == StatusCode::OK => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        anyhow::bail!("local-edge server did not become healthy at {health_url}");
    }
    .await;

    handle.abort();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(&data_dir);

    started.unwrap();
}

run_on_main_metadata_backends!(
    local_edge_mode_serves_health_without_internal_tls_impl,
    local_edge_mode_serves_health_without_internal_tls,
    local_edge_mode_serves_health_without_internal_tls_turso
);

async fn local_edge_persists_objects_across_restart_impl(
    backend: super::storage::MetadataBackendKind,
    label: &str,
    payload: &str,
) {
    let bind_addr = free_bind_addr();
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut config = ServerNodeConfig::local_edge(&data_dir, bind_addr);
    config.public_url = Some(format!("http://{bind_addr}"));
    config.metadata_backend = backend;

    let handle = tokio::spawn(async move { run(config).await });
    let client = reqwest::Client::new();
    let base_url = format!("http://{bind_addr}");
    let health_url = format!("{base_url}/health");

    wait_for_http_status(&client, &health_url, StatusCode::OK, Duration::from_secs(5)).await;

    let put = client
        .put(format!("{base_url}/store/persist.txt"))
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);

    handle.abort();
    let _ = handle.await;

    let restart_bind_addr = free_bind_addr();
    let mut restart_config = ServerNodeConfig::local_edge(&data_dir, restart_bind_addr);
    restart_config.public_url = Some(format!("http://{restart_bind_addr}"));
    restart_config.metadata_backend = backend;

    let restart_handle = tokio::spawn(async move { run(restart_config).await });
    let restart_base_url = format!("http://{restart_bind_addr}");
    wait_for_http_status(
        &client,
        &format!("{restart_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let get = client
        .get(format!("{restart_base_url}/store/persist.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let body = get.text().await.unwrap();
    assert_eq!(body, payload);

    restart_handle.abort();
    let _ = restart_handle.await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[tokio::test]
async fn local_edge_sqlite_persists_objects_across_restart() {
    local_edge_persists_objects_across_restart_impl(
        super::storage::MetadataBackendKind::Sqlite,
        "sqlite",
        "hello-sqlite",
    )
    .await;
}

#[cfg(feature = "turso-metadata")]
#[tokio::test]
async fn local_edge_turso_persists_objects_across_restart() {
    local_edge_persists_objects_across_restart_impl(
        super::storage::MetadataBackendKind::Turso,
        "turso",
        "hello-turso",
    )
    .await;
}

#[test]
fn local_node_handle_starts_and_reports_base_url() {
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-handle-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let handle = LocalNodeHandle::start_local_edge(&data_dir).unwrap();
    let response = reqwest::blocking::get(format!("{}/health", handle.base_url())).unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    drop(handle);
    let _ = std::fs::remove_dir_all(&data_dir);
}

async fn local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;
    let remote_key = "remote.txt";
    let remote_payload = "from-upstream";
    let response = http
        .put(format!("{upstream_base_url}/store/{remote_key}"))
        .body(remote_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    wait_for_condition(
        "edge sees remote replication gap",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/replication/plan"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(plan) = response.json::<cluster::ReplicationPlan>().await else {
                    return false;
                };
                plan.items.iter().any(|item| item.key == remote_key)
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition("edge pulls remote object", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let remote_key = remote_key.to_string();
        async move {
            match http
                .get(format!("{edge_base_url}/store/{remote_key}"))
                .send()
                .await
            {
                Ok(response) if response.status() == StatusCode::OK => {
                    match response.text().await {
                        Ok(body) => body == remote_payload,
                        Err(_) => false,
                    }
                }
                _ => false,
            }
        }
    })
    .await;

    let local_key = "local.txt";
    let local_payload = "from-edge";
    let response = http
        .put(format!("{edge_base_url}/store/{local_key}"))
        .body(local_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives pushed object",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let local_key = local_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{local_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == local_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_impl,
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes,
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_turso
);

async fn local_edge_pulls_upstream_delete_after_repair_impl(backend: MainTestBackend) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-delete-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let remote_key = "remote-delete.txt";
    let remote_payload = "delete-from-upstream";
    let response = http
        .put(format!("{upstream_base_url}/store/{remote_key}"))
        .body(remote_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-delete-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "edge pulls upstream object before delete",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                match http
                    .get(format!("{edge_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == remote_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    let response = http
        .delete(format!("{upstream_base_url}/store/{remote_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    wait_for_condition(
        "upstream removes deleted object from current state",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) => response.status() == StatusCode::NOT_FOUND,
                    Err(_) => false,
                }
            }
        },
    )
    .await;

    wait_for_condition(
        "edge removes upstream-deleted object after repair",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                let _ = http
                    .post(format!("{edge_base_url}/cluster/replication/repair"))
                    .send()
                    .await;
                match http
                    .get(format!("{edge_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) => response.status() == StatusCode::NOT_FOUND,
                    Err(_) => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_pulls_upstream_delete_after_repair_impl,
    local_edge_pulls_upstream_delete_after_repair,
    local_edge_pulls_upstream_delete_after_repair_turso
);

async fn local_edge_pulls_upstream_copy_after_repair_impl(backend: MainTestBackend) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-copy-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let source_key = "copy-source.txt";
    let copy_key = "copy-target.txt";
    let payload = "copy-upstream-payload";
    let response = http
        .put(format!("{upstream_base_url}/store/{source_key}"))
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-copy-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    http.post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    wait_for_condition(
        "edge pulls upstream source before copy",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let source_key = source_key.to_string();
            async move {
                match http
                    .get(format!("{edge_base_url}/store/{source_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => response
                        .text()
                        .await
                        .map(|body| body == payload)
                        .unwrap_or(false),
                    _ => false,
                }
            }
        },
    )
    .await;

    http.post(format!("{upstream_base_url}/store/copy"))
        .json(&serde_json::json!({
            "from_path": source_key,
            "to_path": copy_key,
            "overwrite": false,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    wait_for_condition(
        "edge pulls upstream copy after repair",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let source_key = source_key.to_string();
            let copy_key = copy_key.to_string();
            async move {
                let source = http
                    .get(format!("{edge_base_url}/store/{source_key}"))
                    .send()
                    .await;
                let copy = http
                    .get(format!("{edge_base_url}/store/{copy_key}"))
                    .send()
                    .await;

                match (source, copy) {
                    (Ok(source_response), Ok(copy_response))
                        if source_response.status() == StatusCode::OK
                            && copy_response.status() == StatusCode::OK =>
                    {
                        let source_body = source_response.text().await.ok();
                        let copy_body = copy_response.text().await.ok();
                        source_body.as_deref() == Some(payload)
                            && copy_body.as_deref() == Some(payload)
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_pulls_upstream_copy_after_repair_impl,
    local_edge_pulls_upstream_copy_after_repair,
    local_edge_pulls_upstream_copy_after_repair_turso
);

async fn local_edge_accepts_offline_write_and_syncs_after_upstream_restart_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-source-{}",
        backend.suffix()
    ));
    let upstream_bind_addr = free_bind_addr();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    let upstream_node_id = NodeId::new_v4();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.node_id = upstream_node_id;
    upstream_config.public_url = Some(upstream_base_url.clone());
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_restart_config = upstream_config.clone();
    let mut upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let edge_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-target-{}",
        backend.suffix()
    ));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    upstream_handle.abort();
    let _ = upstream_handle.await;

    let offline_key = "offline-after-restart.txt";
    let offline_payload = "queued-while-upstream-offline";
    let response = http
        .put(format!("{edge_base_url}/store/{offline_key}"))
        .body(offline_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    upstream_handle = tokio::spawn(async move { run(upstream_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        "edge refreshes upstream peer after restart",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let upstream_base_url = upstream_base_url.clone();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/nodes"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                    return false;
                };

                nodes.iter().any(|node| {
                    (node.public_url == upstream_base_url || node.internal_url == upstream_base_url)
                        && node.status == cluster::NodeStatus::Online
                })
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives offline object after repair",
        Duration::from_secs(10),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let offline_key = offline_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{offline_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == offline_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart_impl,
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart,
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart_turso
);

async fn local_edge_offline_write_survives_edge_restart_before_upstream_returns_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-after-edge-restart-source-{}",
        backend.suffix()
    ));
    let upstream_bind_addr = free_bind_addr();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    let upstream_node_id = NodeId::new_v4();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.node_id = upstream_node_id;
    upstream_config.public_url = Some(upstream_base_url.clone());
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_restart_config = upstream_config.clone();
    let mut upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let edge_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-after-edge-restart-target-{}",
        backend.suffix()
    ));
    let edge_bind_addr = free_bind_addr();
    let edge_node_id = NodeId::new_v4();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.node_id = edge_node_id;
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_restart_config = edge_config.clone();
    let mut edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    upstream_handle.abort();
    let _ = upstream_handle.await;

    let offline_key = "offline-edge-restart-durable.txt";
    let offline_payload = "persisted-across-edge-restart";
    let response = http
        .put(format!("{edge_base_url}/store/{offline_key}"))
        .body(offline_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    edge_handle.abort();
    let _ = edge_handle.await;

    edge_handle = tokio::spawn(async move { run(edge_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    upstream_handle = tokio::spawn(async move { run(upstream_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        "restarted edge refreshes upstream peer after restart",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let upstream_base_url = upstream_base_url.clone();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/nodes"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                    return false;
                };

                nodes.iter().any(|node| {
                    (node.public_url == upstream_base_url || node.internal_url == upstream_base_url)
                        && node.status == cluster::NodeStatus::Online
                })
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives durable offline object after edge restart",
        Duration::from_secs(10),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let offline_key = offline_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{offline_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == offline_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    let versions: serde_json::Value = http
        .get(format!("{upstream_base_url}/versions/{offline_key}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let version_count = versions
        .get("versions")
        .and_then(|value| value.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0);
    assert_eq!(
        version_count, 1,
        "expected exactly one synced version after repair"
    );

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_offline_write_survives_edge_restart_before_upstream_returns_impl,
    local_edge_offline_write_survives_edge_restart_before_upstream_returns,
    local_edge_offline_write_survives_edge_restart_before_upstream_returns_turso
);

async fn build_test_state(
    replication_factor: usize,
    seed_gap: bool,
    backend: MainTestBackend,
) -> ServerState {
    let root = fresh_test_dir(&format!("startup-repair-main-{}", backend.suffix()));
    let local_node_id = NodeId::new_v4();

    let store = Arc::new(Mutex::new(
        PersistentStore::init_with_metadata_backend(root.clone(), backend.kind())
            .await
            .unwrap(),
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

    let (namespace_change_tx, _) = tokio::sync::watch::channel(0);
    let state = ServerState {
        cluster_id: uuid::Uuid::now_v7(),
        node_id: local_node_id,
        store: store.clone(),
        cluster: Arc::new(Mutex::new(service)),
        client_auth: Arc::new(Mutex::new(super::storage::ClientAuthState::default())),
        public_ca_pem: None,
        cluster_ca_pem: None,
        rendezvous_ca_pem: None,
        rendezvous_urls: vec!["http://127.0.0.1:39080".to_string()],
        rendezvous_control: None,
        rendezvous_mtls_required: false,
        relay_mode: super::RelayMode::Fallback,
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
        namespace_change_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        namespace_change_tx,
        admin_control: AdminControl::default(),
        client_auth_control: super::ClientAuthControl::default(),
        client_auth_replay_cache: Arc::new(Mutex::new(super::ClientAuthReplayCache::default())),
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

#[tokio::test]
async fn rendezvous_presence_registration_includes_unique_direct_candidates() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;

    let registration = build_rendezvous_presence_registration(
        &state,
        Some("https://public.example/"),
        Some("https://public.example"),
        true,
        None,
    );

    assert_eq!(
        registration.identity,
        transport_sdk::PeerIdentity::Node(state.node_id)
    );
    assert_eq!(registration.direct_candidates.len(), 1);
    assert_eq!(
        registration.direct_candidates[0].kind,
        transport_sdk::CandidateKind::DirectHttps
    );
    assert_eq!(
        registration.direct_candidates[0].endpoint,
        "https://public.example"
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::DirectHttps)
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::RelayTunnel)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn rendezvous_presence_registration_omits_public_candidate_when_peer_api_disabled() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;

    let registration = build_rendezvous_presence_registration(
        &state,
        Some("https://public.example"),
        Some("https://internal.example"),
        false,
        None,
    );

    assert_eq!(registration.public_api_url, None);
    assert_eq!(
        registration.peer_api_url.as_deref(),
        Some("https://internal.example")
    );
    assert_eq!(registration.direct_candidates.len(), 1);
    assert_eq!(
        registration.direct_candidates[0].endpoint,
        "https://internal.example"
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::DirectHttps)
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::RelayTunnel)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn rendezvous_presence_entry_projects_into_node_descriptor() {
    let entry = transport_sdk::PresenceEntry {
        registration: transport_sdk::PresenceRegistration {
            cluster_id: uuid::Uuid::now_v7(),
            identity: transport_sdk::PeerIdentity::Node(NodeId::new_v4()),
            public_api_url: Some("https://public.example/".to_string()),
            peer_api_url: Some("https://internal.example/".to_string()),
            direct_candidates: vec![transport_sdk::ConnectionCandidate {
                kind: transport_sdk::CandidateKind::DirectHttps,
                endpoint: "https://internal.example/".to_string(),
                rtt_ms: None,
            }],
            labels: HashMap::from([("dc".to_string(), "edge-a".to_string())]),
            capacity_bytes: Some(100),
            free_bytes: Some(40),
            capabilities: vec![transport_sdk::TransportCapability::DirectHttps],
            relay_mode: transport_sdk::RelayMode::Fallback,
            connected_at_unix: 123,
        },
        updated_at_unix: 456,
    };

    let descriptor = node_descriptor_from_presence_entry(&entry)
        .expect("presence entry should project into a node descriptor");

    assert_eq!(
        descriptor.node_id,
        match entry.registration.identity {
            transport_sdk::PeerIdentity::Node(node_id) => node_id,
            _ => unreachable!("test uses node identity"),
        }
    );
    assert_eq!(descriptor.public_url, "https://public.example");
    assert_eq!(descriptor.internal_url, "https://internal.example");
    assert_eq!(
        descriptor.labels.get("dc").map(String::as_str),
        Some("edge-a")
    );
    assert_eq!(descriptor.capacity_bytes, 100);
    assert_eq!(descriptor.free_bytes, 40);
}

#[tokio::test]
async fn rendezvous_presence_entry_projects_relay_only_node_descriptor() {
    let node_id = NodeId::new_v4();
    let entry = transport_sdk::PresenceEntry {
        registration: transport_sdk::PresenceRegistration {
            cluster_id: uuid::Uuid::now_v7(),
            identity: transport_sdk::PeerIdentity::Node(node_id),
            public_api_url: None,
            peer_api_url: None,
            direct_candidates: Vec::new(),
            labels: HashMap::new(),
            capacity_bytes: None,
            free_bytes: None,
            capabilities: vec![transport_sdk::TransportCapability::RelayTunnel],
            relay_mode: transport_sdk::RelayMode::Fallback,
            connected_at_unix: 123,
        },
        updated_at_unix: 456,
    };

    let descriptor = node_descriptor_from_presence_entry(&entry)
        .expect("relay-only presence entry should still project into a node descriptor");

    assert_eq!(descriptor.node_id, node_id);
    assert!(descriptor.public_url.is_empty());
    assert!(descriptor.internal_url.is_empty());
}

#[tokio::test]
async fn resolve_peer_base_url_prefers_internal_url() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: "https://public.example".to_string(),
        internal_url: "https://internal.example".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let base_url =
        resolve_peer_base_url(&state, &node).expect("peer transport should resolve base URL");

    assert_eq!(base_url, "https://internal.example");
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn resolve_peer_base_url_rejects_missing_direct_candidates() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.relay_mode = super::RelayMode::Disabled;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: String::new(),
        internal_url: String::new(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let error = resolve_peer_base_url(&state, &node)
        .expect_err("peer transport should fail without direct candidates");

    assert!(
        error
            .to_string()
            .contains("does not expose any usable peer transport candidates")
    );
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn plan_peer_transport_falls_back_to_relay_when_direct_urls_are_missing() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: String::new(),
        internal_url: String::new(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let plan = plan_peer_transport(&state, &node)
        .expect("peer transport should synthesize a relay path when rendezvous is available");

    assert_eq!(
        plan.path_kind,
        transport_sdk::TransportPathKind::RelayTunnel
    );
    assert_eq!(
        plan.candidate.as_ref().map(|candidate| candidate.kind),
        Some(transport_sdk::CandidateKind::Relay)
    );
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn plan_peer_transport_uses_relay_when_required_even_with_direct_urls() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.relay_mode = super::RelayMode::Required;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: "https://public.example".to_string(),
        internal_url: "https://internal.example".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let plan =
        plan_peer_transport(&state, &node).expect("relay-required transport should still plan");

    assert_eq!(
        plan.path_kind,
        transport_sdk::TransportPathKind::RelayTunnel
    );
    assert_eq!(
        plan.candidate.as_ref().map(|candidate| candidate.kind),
        Some(transport_sdk::CandidateKind::Relay)
    );
    cleanup_test_state(&state).await;
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

async fn wait_for_condition<F, Fut>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;

    loop {
        if condition().await {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "{label} was not met within {:?}",
            timeout,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_http_status(
    http: &reqwest::Client,
    url: &str,
    expected_status: StatusCode,
    timeout: Duration,
) {
    wait_for_condition("http status", timeout, || {
        let http = http.clone();
        let url = url.to_string();
        async move {
            match http.get(url).send().await {
                Ok(response) => response.status() == expected_status,
                Err(_) => false,
            }
        }
    })
    .await;
}
