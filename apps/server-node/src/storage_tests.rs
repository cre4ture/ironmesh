use super::*;

fn test_store_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("ironmesh-{name}-{}", unix_ts_nanos()))
}

fn mk_record(
    version_id: &str,
    state: VersionConsistencyState,
    created_at_unix: u64,
) -> FileVersionRecord {
    FileVersionRecord {
        version_id: version_id.to_string(),
        key: "k".to_string(),
        manifest_hash: format!("m-{version_id}"),
        parent_version_ids: Vec::new(),
        state,
        created_at_unix,
    }
}

#[test]
fn preferred_head_prioritizes_confirmed_over_newer_provisional() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-old-confirmed".to_string(),
        mk_record("v-old-confirmed", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-new-provisional".to_string(),
        mk_record(
            "v-new-provisional",
            VersionConsistencyState::Provisional,
            100,
        ),
    );
    index.head_version_ids = vec![
        "v-old-confirmed".to_string(),
        "v-new-provisional".to_string(),
    ];

    let preferred = choose_preferred_head(&index);
    assert_eq!(preferred.as_deref(), Some("v-old-confirmed"));
}

#[test]
fn preferred_head_uses_latest_when_same_state() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v1".to_string(),
        mk_record("v1", VersionConsistencyState::Confirmed, 11),
    );
    index.versions.insert(
        "v2".to_string(),
        mk_record("v2", VersionConsistencyState::Confirmed, 22),
    );
    index.head_version_ids = vec!["v1".to_string(), "v2".to_string()];

    let preferred = choose_preferred_head(&index);
    assert_eq!(preferred.as_deref(), Some("v2"));
}

#[test]
fn preferred_head_none_for_empty_heads() {
    let index = empty_version_index("k");
    assert!(choose_preferred_head(&index).is_none());
}

#[test]
fn preferred_head_reason_is_confirmed_preferred() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-confirmed".to_string(),
        mk_record("v-confirmed", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-provisional".to_string(),
        mk_record("v-provisional", VersionConsistencyState::Provisional, 20),
    );
    index.head_version_ids = vec!["v-confirmed".to_string(), "v-provisional".to_string()];

    let preferred = choose_preferred_head_with_reason(&index);
    assert!(matches!(
        preferred,
        Some((_, PreferredHeadReason::ConfirmedPreferredOverProvisional))
    ));
}

#[test]
fn preferred_head_reason_uses_tiebreak_when_needed() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-aaa".to_string(),
        mk_record("v-aaa", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-bbb".to_string(),
        mk_record("v-bbb", VersionConsistencyState::Confirmed, 10),
    );
    index.head_version_ids = vec!["v-aaa".to_string(), "v-bbb".to_string()];

    let preferred = choose_preferred_head_with_reason(&index);
    assert!(matches!(
        preferred,
        Some((_, PreferredHeadReason::DeterministicTiebreakVersionId))
    ));
}

#[test]
fn preferred_head_reason_falls_back_to_provisional_when_no_confirmed() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-old".to_string(),
        mk_record("v-old", VersionConsistencyState::Provisional, 10),
    );
    index.versions.insert(
        "v-new".to_string(),
        mk_record("v-new", VersionConsistencyState::Provisional, 20),
    );
    index.head_version_ids = vec!["v-old".to_string(), "v-new".to_string()];

    let preferred = choose_preferred_head_with_reason(&index);
    assert!(matches!(
        preferred,
        Some((_, PreferredHeadReason::ProvisionalFallbackNoConfirmed))
    ));
}

#[test]
fn manifest_hash_preferred_uses_confirmed_when_provisional_is_newer() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-confirmed".to_string(),
        mk_record("v-confirmed", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-provisional".to_string(),
        mk_record("v-provisional", VersionConsistencyState::Provisional, 100),
    );
    index.head_version_ids = vec!["v-confirmed".to_string(), "v-provisional".to_string()];

    let selected = manifest_hash_for_read_mode(&index, ObjectReadMode::Preferred);
    assert_eq!(selected.as_deref(), Some("m-v-confirmed"));
}

#[test]
fn manifest_hash_confirmed_only_returns_none_without_confirmed_heads() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v1".to_string(),
        mk_record("v1", VersionConsistencyState::Provisional, 10),
    );
    index.versions.insert(
        "v2".to_string(),
        mk_record("v2", VersionConsistencyState::Provisional, 20),
    );
    index.head_version_ids = vec!["v1".to_string(), "v2".to_string()];

    let selected = manifest_hash_for_read_mode(&index, ObjectReadMode::ConfirmedOnly);
    assert!(selected.is_none());
}

#[test]
fn manifest_hash_confirmed_only_picks_latest_confirmed_head() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-confirmed-old".to_string(),
        mk_record("v-confirmed-old", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-confirmed-new".to_string(),
        mk_record("v-confirmed-new", VersionConsistencyState::Confirmed, 20),
    );
    index.versions.insert(
        "v-provisional".to_string(),
        mk_record("v-provisional", VersionConsistencyState::Provisional, 30),
    );
    index.head_version_ids = vec![
        "v-confirmed-old".to_string(),
        "v-confirmed-new".to_string(),
        "v-provisional".to_string(),
    ];

    let selected = manifest_hash_for_read_mode(&index, ObjectReadMode::ConfirmedOnly);
    assert_eq!(selected.as_deref(), Some("m-v-confirmed-new"));
}

#[test]
fn manifest_hash_provisional_allowed_picks_latest_head_regardless_of_state() {
    let mut index = empty_version_index("k");
    index.versions.insert(
        "v-confirmed".to_string(),
        mk_record("v-confirmed", VersionConsistencyState::Confirmed, 10),
    );
    index.versions.insert(
        "v-provisional".to_string(),
        mk_record("v-provisional", VersionConsistencyState::Provisional, 20),
    );
    index.head_version_ids = vec!["v-confirmed".to_string(), "v-provisional".to_string()];

    let selected = manifest_hash_for_read_mode(&index, ObjectReadMode::ProvisionalAllowed);
    assert_eq!(selected.as_deref(), Some("m-v-provisional"));
}

#[tokio::test]
async fn reconcile_marker_roundtrip_is_detected() {
    let root = test_store_dir("reconcile-marker");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    assert!(
        !store
            .has_reconcile_marker("node-a", "key-a", "source-v1")
            .await
            .unwrap()
    );

    store
        .mark_reconciled("node-a", "key-a", "source-v1", Some("local-v1"))
        .await
        .unwrap();

    assert!(
        store
            .has_reconcile_marker("node-a", "key-a", "source-v1")
            .await
            .unwrap()
    );

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn list_provisional_versions_filters_and_sorts_by_key_then_time() {
    let root = test_store_dir("provisional-list");
    let mut store = PersistentStore::init(root.clone()).await.unwrap();

    store
        .put_object_versioned(
            "z-key",
            Bytes::from_static(b"confirmed"),
            PutOptions {
                state: VersionConsistencyState::Confirmed,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    store
        .put_object_versioned(
            "b-key",
            Bytes::from_static(b"prov-b"),
            PutOptions {
                state: VersionConsistencyState::Provisional,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    store
        .put_object_versioned(
            "a-key",
            Bytes::from_static(b"prov-a"),
            PutOptions {
                state: VersionConsistencyState::Provisional,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let provisional = store.list_provisional_versions().await.unwrap();
    assert_eq!(provisional.len(), 2);
    assert_eq!(provisional[0].key, "a-key");
    assert_eq!(provisional[1].key, "b-key");
    assert!(
        provisional
            .iter()
            .all(|entry| entry.state == VersionConsistencyState::Provisional)
    );

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn cleanup_unreferenced_dry_run_reports_without_deleting() {
    let root = test_store_dir("cleanup-dry-run");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let orphan_chunk_payload = b"orphan-chunk";
    let orphan_chunk_hash = hash_hex(orphan_chunk_payload);
    let orphan_chunk_path = chunk_path_for_hash(&store.chunks_dir, &orphan_chunk_hash);
    fs::create_dir_all(orphan_chunk_path.parent().unwrap())
        .await
        .unwrap();
    fs::write(&orphan_chunk_path, orphan_chunk_payload)
        .await
        .unwrap();

    let orphan_manifest = ObjectManifest {
        key: "orphan-key".to_string(),
        total_size_bytes: orphan_chunk_payload.len(),
        created_at_unix: 0,
        chunks: vec![ChunkRef {
            hash: orphan_chunk_hash.clone(),
            size_bytes: orphan_chunk_payload.len(),
        }],
    };
    let orphan_manifest_bytes = serde_json::to_vec_pretty(&orphan_manifest).unwrap();
    let orphan_manifest_hash = hash_hex(&orphan_manifest_bytes);
    let orphan_manifest_path = store
        .manifests_dir
        .join(format!("{orphan_manifest_hash}.json"));
    fs::write(&orphan_manifest_path, orphan_manifest_bytes)
        .await
        .unwrap();

    let report = store.cleanup_unreferenced(0, true).await.unwrap();
    assert_eq!(report.deleted_manifests, 0);
    assert_eq!(report.deleted_chunks, 0);
    assert!(report.protected_manifests == 0);
    assert!(fs::try_exists(&orphan_manifest_path).await.unwrap());
    assert!(fs::try_exists(&orphan_chunk_path).await.unwrap());

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn cleanup_unreferenced_deletes_orphan_manifest_and_chunk() {
    let root = test_store_dir("cleanup-delete");
    let mut store = PersistentStore::init(root.clone()).await.unwrap();

    store
        .put_object_versioned(
            "live",
            Bytes::from_static(b"live-data"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let orphan_chunk_payload = b"orphan-chunk-delete";
    let orphan_chunk_hash = hash_hex(orphan_chunk_payload);
    let orphan_chunk_path = chunk_path_for_hash(&store.chunks_dir, &orphan_chunk_hash);
    fs::create_dir_all(orphan_chunk_path.parent().unwrap())
        .await
        .unwrap();
    fs::write(&orphan_chunk_path, orphan_chunk_payload)
        .await
        .unwrap();

    let orphan_manifest = ObjectManifest {
        key: "orphan-key-delete".to_string(),
        total_size_bytes: orphan_chunk_payload.len(),
        created_at_unix: 0,
        chunks: vec![ChunkRef {
            hash: orphan_chunk_hash.clone(),
            size_bytes: orphan_chunk_payload.len(),
        }],
    };
    let orphan_manifest_bytes = serde_json::to_vec_pretty(&orphan_manifest).unwrap();
    let orphan_manifest_hash = hash_hex(&orphan_manifest_bytes);
    let orphan_manifest_path = store
        .manifests_dir
        .join(format!("{orphan_manifest_hash}.json"));
    fs::write(&orphan_manifest_path, orphan_manifest_bytes)
        .await
        .unwrap();

    let report = store.cleanup_unreferenced(0, false).await.unwrap();
    assert!(report.deleted_manifests >= 1);
    assert!(report.deleted_chunks >= 1);
    assert!(!fs::try_exists(&orphan_manifest_path).await.unwrap());
    assert!(!fs::try_exists(&orphan_chunk_path).await.unwrap());

    let live = store
        .get_object("live", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(live.as_ref(), b"live-data");

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn load_repair_attempts_returns_empty_when_file_missing() {
    let root = test_store_dir("repair-attempts-empty");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let attempts = store.load_repair_attempts().await.unwrap();
    assert!(attempts.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn persist_and_load_repair_attempts_roundtrip() {
    let root = test_store_dir("repair-attempts-roundtrip");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let mut attempts = HashMap::new();
    attempts.insert(
        "subject@version|node".to_string(),
        RepairAttemptRecord {
            attempts: 2,
            last_failure_unix: 123,
        },
    );

    store.persist_repair_attempts(&attempts).await.unwrap();
    let loaded = store.load_repair_attempts().await.unwrap();

    let entry = loaded.get("subject@version|node").unwrap();
    assert_eq!(entry.attempts, 2);
    assert_eq!(entry.last_failure_unix, 123);

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn drop_replica_subject_removes_version() {
    let root = test_store_dir("drop-replica-subject");
    let mut store = PersistentStore::init(root.clone()).await.unwrap();

    let put = store
        .put_object_versioned(
            "drop-key",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let dropped = store
        .drop_replica_subject("drop-key", Some(&put.version_id))
        .await
        .unwrap();
    assert!(dropped);

    let versions = store.list_versions("drop-key").await.unwrap().unwrap();
    assert!(
        versions
            .versions
            .iter()
            .all(|entry| entry.version_id != put.version_id)
    );

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn list_replication_subjects_includes_all_heads_for_divergent_versions() {
    let root = test_store_dir("replication-subjects-divergent-heads");
    let mut store = PersistentStore::init(root.clone()).await.unwrap();

    let first = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-a"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let second = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-b"),
            PutOptions {
                parent_version_ids: Vec::new(),
                state: VersionConsistencyState::Provisional,
                inherit_preferred_parent: false,
                create_snapshot: true,
                explicit_version_id: None,
            },
        )
        .await
        .unwrap();

    assert_ne!(first.version_id, second.version_id);

    let versions = store.list_versions("hello").await.unwrap().unwrap();
    assert!(
        versions.head_version_ids.contains(&first.version_id),
        "first write should remain a head when second write is parentless"
    );
    assert!(
        versions.head_version_ids.contains(&second.version_id),
        "second write should be a concurrent head"
    );

    let subjects = store.list_replication_subjects().await.unwrap();

    assert!(subjects.contains(&"hello".to_string()));
    assert!(subjects.contains(&format!("hello@{}", first.version_id)));
    assert!(subjects.contains(&format!("hello@{}", second.version_id)));

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn load_cluster_replicas_returns_empty_when_file_missing() {
    let root = test_store_dir("cluster-replicas-empty");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let replicas = store.load_cluster_replicas().await.unwrap();
    assert!(replicas.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn explicit_version_id_is_idempotent_for_matching_manifest() {
    let root = test_store_dir("explicit-version-id-idempotent");
    let mut store = PersistentStore::init(root.clone()).await.unwrap();

    let first = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-a"),
            PutOptions {
                parent_version_ids: Vec::new(),
                state: VersionConsistencyState::Confirmed,
                inherit_preferred_parent: false,
                create_snapshot: false,
                explicit_version_id: Some("ver-fixed-1".to_string()),
            },
        )
        .await
        .unwrap();

    let second = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-a"),
            PutOptions {
                parent_version_ids: Vec::new(),
                state: VersionConsistencyState::Confirmed,
                inherit_preferred_parent: false,
                create_snapshot: false,
                explicit_version_id: Some("ver-fixed-1".to_string()),
            },
        )
        .await
        .unwrap();

    assert_eq!(first.version_id, "ver-fixed-1");
    assert_eq!(second.version_id, "ver-fixed-1");

    let versions = store.list_versions("hello").await.unwrap().unwrap();
    assert_eq!(versions.versions.len(), 1);
    assert_eq!(versions.versions[0].version_id, "ver-fixed-1");

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn persist_and_load_cluster_replicas_roundtrip() {
    let root = test_store_dir("cluster-replicas-roundtrip");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let mut replicas: HashMap<String, Vec<NodeId>> = HashMap::new();
    replicas.insert(
        "subject-a".to_string(),
        vec![NodeId::new_v4(), NodeId::new_v4()],
    );

    store.persist_cluster_replicas(&replicas).await.unwrap();
    let loaded = store.load_cluster_replicas().await.unwrap();

    assert_eq!(loaded.get("subject-a").map(Vec::len), Some(2));

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn load_internal_node_tokens_returns_empty_when_file_missing() {
    let root = test_store_dir("internal-node-tokens-empty");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let tokens = store.load_internal_node_tokens().await.unwrap();
    assert!(tokens.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

#[tokio::test]
async fn persist_and_load_internal_node_tokens_roundtrip() {
    let root = test_store_dir("internal-node-tokens-roundtrip");
    let store = PersistentStore::init(root.clone()).await.unwrap();

    let mut tokens = HashMap::new();
    let node_id = NodeId::new_v4();
    tokens.insert(node_id, "token-1".to_string());

    store.persist_internal_node_tokens(&tokens).await.unwrap();
    let loaded = store.load_internal_node_tokens().await.unwrap();

    assert_eq!(loaded.get(&node_id).map(String::as_str), Some("token-1"));

    let _ = fs::remove_dir_all(root).await;
}
