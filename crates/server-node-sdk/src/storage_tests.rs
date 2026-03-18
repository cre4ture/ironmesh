use super::*;
use std::path::Path;

fn test_store_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "ironmesh-{name}-{}-{}",
        std::process::id(),
        unix_ts_nanos()
    ))
}

fn mk_record(
    version_id: &str,
    state: VersionConsistencyState,
    created_at_unix: u64,
) -> FileVersionRecord {
    FileVersionRecord {
        version_id: version_id.to_string(),
        object_id: "obj-k".to_string(),
        manifest_hash: format!("m-{version_id}"),
        logical_path: None,
        parent_version_ids: Vec::new(),
        state,
        created_at_unix,
        copied_from_object_id: None,
        copied_from_version_id: None,
        copied_from_path: None,
    }
}

fn sample_png_bytes() -> Vec<u8> {
    let image = image::DynamicImage::new_rgba8(4, 3);
    let mut cursor = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .unwrap();
    cursor.into_inner()
}

#[derive(Clone, Copy)]
enum StorageTestBackend {
    Sqlite,
    #[cfg(feature = "turso-metadata")]
    Turso,
}

impl StorageTestBackend {
    fn suffix(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            #[cfg(feature = "turso-metadata")]
            Self::Turso => "turso",
        }
    }

    async fn init_store(self, name: &str) -> (PathBuf, PersistentStore) {
        let root = test_store_dir(&format!("{name}-{}", self.suffix()));
        let store = self.open_store(root.clone()).await;
        (root, store)
    }

    async fn open_store(self, root: PathBuf) -> PersistentStore {
        match self {
            Self::Sqlite => PersistentStore::init_with_sqlite_metadata(root.clone())
                .await
                .unwrap(),
            #[cfg(feature = "turso-metadata")]
            Self::Turso => PersistentStore::init_with_turso_metadata(root.clone())
                .await
                .unwrap(),
        }
    }
}

macro_rules! run_on_all_metadata_backends {
    ($body:ident, $sqlite_test:ident, $turso_test:ident) => {
        #[tokio::test]
        async fn $sqlite_test() {
            $body(StorageTestBackend::Sqlite).await;
        }

        #[cfg(feature = "turso-metadata")]
        #[tokio::test]
        async fn $turso_test() {
            $body(StorageTestBackend::Turso).await;
        }
    };
}

async fn load_admin_audit_event_from_metadata_db(
    backend: StorageTestBackend,
    metadata_db_path: &Path,
    event_id: &str,
) -> AdminAuditEvent {
    match backend {
        StorageTestBackend::Sqlite => {
            let db = rusqlite::Connection::open(metadata_db_path).unwrap();
            let payload: Vec<u8> = db
                .query_row(
                    "SELECT event_json FROM admin_audit_events WHERE event_id = ?1",
                    rusqlite::params![event_id],
                    |row| row.get(0),
                )
                .unwrap();
            serde_json::from_slice(&payload).unwrap()
        }
        #[cfg(feature = "turso-metadata")]
        StorageTestBackend::Turso => {
            let db = turso::Builder::new_local(&metadata_db_path.to_string_lossy())
                .build()
                .await
                .unwrap();
            let conn = db.connect().unwrap();
            let mut rows = conn
                .query(
                    "SELECT event_json FROM admin_audit_events WHERE event_id = ?1",
                    (event_id,),
                )
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("expected audit row");
            let payload = match row.get_value(0).unwrap() {
                turso::Value::Blob(value) => value,
                turso::Value::Text(value) => value.into_bytes(),
                other => panic!("unexpected audit payload type: {other:?}"),
            };
            serde_json::from_slice(&payload).unwrap()
        }
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

async fn reconcile_marker_roundtrip_is_detected_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("reconcile-marker").await;

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

run_on_all_metadata_backends!(
    reconcile_marker_roundtrip_is_detected_impl,
    reconcile_marker_roundtrip_is_detected,
    reconcile_marker_roundtrip_is_detected_turso
);

async fn list_provisional_versions_filters_and_sorts_by_key_then_time_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("provisional-list").await;

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

run_on_all_metadata_backends!(
    list_provisional_versions_filters_and_sorts_by_key_then_time_impl,
    list_provisional_versions_filters_and_sorts_by_key_then_time,
    list_provisional_versions_filters_and_sorts_by_key_then_time_turso
);

async fn cleanup_unreferenced_dry_run_reports_without_deleting_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("cleanup-dry-run").await;

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

run_on_all_metadata_backends!(
    cleanup_unreferenced_dry_run_reports_without_deleting_impl,
    cleanup_unreferenced_dry_run_reports_without_deleting,
    cleanup_unreferenced_dry_run_reports_without_deleting_turso
);

async fn cleanup_unreferenced_deletes_orphan_manifest_and_chunk_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("cleanup-delete").await;

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

run_on_all_metadata_backends!(
    cleanup_unreferenced_deletes_orphan_manifest_and_chunk_impl,
    cleanup_unreferenced_deletes_orphan_manifest_and_chunk,
    cleanup_unreferenced_deletes_orphan_manifest_and_chunk_turso
);

async fn compact_tombstone_indexes_dry_run_reports_without_deleting_index_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-compact-dry-run").await;

    store
        .put_object_versioned(
            "gone",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let before_delete = store.list_versions("gone").await.unwrap().unwrap();
    let object_id = before_delete.object_id.clone();

    store
        .tombstone_object("gone", PutOptions::default())
        .await
        .unwrap();

    let report = store.compact_tombstone_indexes(0, true).await.unwrap();
    assert!(report.scanned_indexes >= 1);
    assert!(report.tombstone_head_indexes >= 1);
    assert!(report.eligible_indexes >= 1);
    assert_eq!(report.archived_indexes, 0);
    assert_eq!(report.removed_indexes, 0);
    assert!(report.archive_path.is_none());
    assert!(store.has_version_index(&object_id).await.unwrap());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    compact_tombstone_indexes_dry_run_reports_without_deleting_index_impl,
    compact_tombstone_indexes_dry_run_reports_without_deleting_index,
    compact_tombstone_indexes_dry_run_reports_without_deleting_index_turso
);

async fn compact_tombstone_indexes_archives_and_removes_old_tombstoned_index_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-compact-delete").await;

    store
        .put_object_versioned(
            "gone",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let before_delete = store.list_versions("gone").await.unwrap().unwrap();
    let object_id = before_delete.object_id.clone();

    store
        .tombstone_object("gone", PutOptions::default())
        .await
        .unwrap();

    let report = store.compact_tombstone_indexes(0, false).await.unwrap();
    assert!(report.eligible_indexes >= 1);
    assert_eq!(report.archived_indexes, 1);
    assert_eq!(report.removed_indexes, 1);
    let archive_path = report.archive_path.expect("archive path should exist");
    assert!(fs::try_exists(&archive_path).await.unwrap());
    assert!(!store.has_version_index(&object_id).await.unwrap());

    let archive_bytes = fs::read(&archive_path).await.unwrap();
    assert!(!archive_bytes.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    compact_tombstone_indexes_archives_and_removes_old_tombstoned_index_impl,
    compact_tombstone_indexes_archives_and_removes_old_tombstoned_index,
    compact_tombstone_indexes_archives_and_removes_old_tombstoned_index_turso
);

async fn list_tombstone_archives_returns_metadata_for_compaction_artifacts_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-archive-list").await;

    store
        .put_object_versioned(
            "gone",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    store
        .tombstone_object("gone", PutOptions::default())
        .await
        .unwrap();
    let compact = store.compact_tombstone_indexes(0, false).await.unwrap();
    assert_eq!(compact.archived_indexes, 1);

    let archives = store.list_tombstone_archives().await.unwrap();
    assert_eq!(archives.len(), 1);
    assert!(archives[0].entries >= 1);
    assert!(archives[0].size_bytes > 0);
    assert!(archives[0].file_name.ends_with(".jsonl"));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    list_tombstone_archives_returns_metadata_for_compaction_artifacts_impl,
    list_tombstone_archives_returns_metadata_for_compaction_artifacts,
    list_tombstone_archives_returns_metadata_for_compaction_artifacts_turso
);

async fn restore_tombstone_index_from_archive_recreates_deleted_index_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-archive-restore").await;

    store
        .put_object_versioned(
            "gone",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let before_delete = store.list_versions("gone").await.unwrap().unwrap();
    let object_id = before_delete.object_id.clone();
    store
        .tombstone_object("gone", PutOptions::default())
        .await
        .unwrap();
    store.compact_tombstone_indexes(0, false).await.unwrap();
    assert!(!store.has_version_index(&object_id).await.unwrap());

    let dry_run = store
        .restore_tombstone_index_from_archive(&object_id, None, false, true)
        .await
        .unwrap();
    assert!(dry_run.found);
    assert!(dry_run.would_restore);
    assert!(!dry_run.restored);
    assert!(!store.has_version_index(&object_id).await.unwrap());

    let restored = store
        .restore_tombstone_index_from_archive(&object_id, None, false, false)
        .await
        .unwrap();
    assert!(restored.found);
    assert!(restored.restored);
    assert!(store.has_version_index(&object_id).await.unwrap());

    let skipped = store
        .restore_tombstone_index_from_archive(&object_id, None, false, false)
        .await
        .unwrap();
    assert!(skipped.skipped_existing);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    restore_tombstone_index_from_archive_recreates_deleted_index_impl,
    restore_tombstone_index_from_archive_recreates_deleted_index,
    restore_tombstone_index_from_archive_recreates_deleted_index_turso
);

async fn purge_tombstone_archives_dry_run_then_delete_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("tombstone-archive-purge").await;

    store
        .put_object_versioned(
            "gone",
            Bytes::from_static(b"payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    store
        .tombstone_object("gone", PutOptions::default())
        .await
        .unwrap();
    store.compact_tombstone_indexes(0, false).await.unwrap();
    assert_eq!(store.list_tombstone_archives().await.unwrap().len(), 1);

    let dry_run = store.purge_tombstone_archives(0, true).await.unwrap();
    assert!(dry_run.eligible_files >= 1);
    assert_eq!(dry_run.deleted_files, 0);
    assert_eq!(store.list_tombstone_archives().await.unwrap().len(), 1);

    let deleted = store.purge_tombstone_archives(0, false).await.unwrap();
    assert!(deleted.deleted_files >= 1);
    assert!(store.list_tombstone_archives().await.unwrap().is_empty());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    purge_tombstone_archives_dry_run_then_delete_impl,
    purge_tombstone_archives_dry_run_then_delete,
    purge_tombstone_archives_dry_run_then_delete_turso
);

async fn append_admin_audit_event_roundtrips_via_metadata_backend_impl(
    backend: StorageTestBackend,
) {
    let (root, store) = backend.init_store("admin-audit-log").await;

    let event = AdminAuditEvent {
        event_id: "evt-1".to_string(),
        action: "maintenance/tombstones/compact".to_string(),
        actor: Some("ci".to_string()),
        source_node: None,
        authorized: true,
        dry_run: true,
        approved: false,
        outcome: "success".to_string(),
        details_json: "{\"x\":1}".to_string(),
        created_at_unix: unix_ts(),
    };
    store.append_admin_audit_event(&event).await.unwrap();

    let parsed =
        load_admin_audit_event_from_metadata_db(backend, &store.metadata_db_path, "evt-1").await;
    assert_eq!(parsed.event_id, "evt-1");
    assert_eq!(parsed.action, "maintenance/tombstones/compact");
    assert_eq!(parsed.actor.as_deref(), Some("ci"));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    append_admin_audit_event_roundtrips_via_metadata_backend_impl,
    append_admin_audit_event_roundtrips_via_metadata_backend,
    append_admin_audit_event_roundtrips_via_metadata_backend_turso
);

async fn load_repair_attempts_returns_empty_when_file_missing_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("repair-attempts-empty").await;

    let attempts = store.load_repair_attempts().await.unwrap();
    assert!(attempts.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    load_repair_attempts_returns_empty_when_file_missing_impl,
    load_repair_attempts_returns_empty_when_file_missing,
    load_repair_attempts_returns_empty_when_file_missing_turso
);

async fn persist_and_load_repair_attempts_roundtrip_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("repair-attempts-roundtrip").await;

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

run_on_all_metadata_backends!(
    persist_and_load_repair_attempts_roundtrip_impl,
    persist_and_load_repair_attempts_roundtrip,
    persist_and_load_repair_attempts_roundtrip_turso
);

async fn drop_replica_subject_removes_version_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("drop-replica-subject").await;

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

    let versions = store.list_versions("drop-key").await.unwrap();
    assert!(versions.is_none());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    drop_replica_subject_removes_version_impl,
    drop_replica_subject_removes_version,
    drop_replica_subject_removes_version_turso
);

async fn list_replication_subjects_includes_all_heads_for_divergent_versions_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend
        .init_store("replication-subjects-divergent-heads")
        .await;

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

run_on_all_metadata_backends!(
    list_replication_subjects_includes_all_heads_for_divergent_versions_impl,
    list_replication_subjects_includes_all_heads_for_divergent_versions,
    list_replication_subjects_includes_all_heads_for_divergent_versions_turso
);

async fn tombstone_creates_tombstone_version_and_removes_current_key_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-storage").await;

    let _put = store
        .put_object_versioned(
            "will-delete",
            Bytes::from_static(b"to-be-deleted"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    // verify it's readable
    let read = store
        .get_object("will-delete", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(read.as_ref(), b"to-be-deleted");

    // tombstone
    let _tomb_id = store
        .tombstone_object("will-delete", PutOptions::default())
        .await
        .unwrap();

    // path is unbound after tombstone under stable-object-id semantics
    assert!(store.list_versions("will-delete").await.unwrap().is_none());

    // current keys should not include the key after tombstone
    let keys = store.current_keys();
    assert!(!keys.contains(&"will-delete".to_string()));

    // reading the object via store should return NotFound
    let read_after = store
        .get_object("will-delete", None, None, ObjectReadMode::Preferred)
        .await;
    match read_after {
        Err(super::StoreReadError::NotFound) => {}
        other => panic!("expected NotFound after tombstone, got: {:?}", other),
    }

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    tombstone_creates_tombstone_version_and_removes_current_key_impl,
    tombstone_creates_tombstone_version_and_removes_current_key,
    tombstone_creates_tombstone_version_and_removes_current_key_turso
);

async fn tombstone_replication_subjects_keep_deleted_head_version_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("tombstone-replication-subjects").await;

    store
        .put_object_versioned(
            "will-delete",
            Bytes::from_static(b"to-be-deleted"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let tombstone_version_id = store
        .tombstone_object("will-delete", PutOptions::default())
        .await
        .unwrap();

    let subjects = store.list_replication_subjects().await.unwrap();
    assert!(!subjects.contains(&"will-delete".to_string()));
    assert!(subjects.contains(&format!("will-delete@{tombstone_version_id}")));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    tombstone_replication_subjects_keep_deleted_head_version_impl,
    tombstone_replication_subjects_keep_deleted_head_version,
    tombstone_replication_subjects_keep_deleted_head_version_turso
);

async fn recursive_tombstone_removes_directory_marker_and_descendants_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("recursive-tombstone-subtree").await;

    for (key, payload) in [
        ("docs/", Bytes::from_static(b"")),
        ("docs/a.txt", Bytes::from_static(b"a")),
        ("docs/nested/", Bytes::from_static(b"")),
        ("docs/nested/b.txt", Bytes::from_static(b"b")),
        ("other/keep.txt", Bytes::from_static(b"keep")),
    ] {
        store
            .put_object_versioned(key, payload, PutOptions::default())
            .await
            .unwrap();
    }

    let deleted = store
        .tombstone_subtree("docs/", PutOptions::default())
        .await
        .unwrap();
    let deleted_paths = deleted
        .iter()
        .map(|entry| entry.path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        deleted_paths,
        std::collections::BTreeSet::from([
            "docs/",
            "docs/a.txt",
            "docs/nested/",
            "docs/nested/b.txt",
        ])
    );

    let current_keys = store.current_keys();
    assert!(
        !current_keys
            .iter()
            .any(|key| key == "docs/" || key.starts_with("docs/"))
    );
    assert!(current_keys.contains(&"other/keep.txt".to_string()));

    let subjects = store.list_replication_subjects().await.unwrap();
    assert!(
        subjects
            .iter()
            .any(|subject| subject.starts_with("docs/a.txt@")),
        "expected deleted file tombstone subject, subjects={subjects:?}"
    );
    assert!(
        subjects
            .iter()
            .any(|subject| subject.starts_with("docs/nested/b.txt@")),
        "expected nested deleted file tombstone subject, subjects={subjects:?}"
    );

    let kept = store
        .get_object("other/keep.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(kept.as_ref(), b"keep");

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    recursive_tombstone_removes_directory_marker_and_descendants_impl,
    recursive_tombstone_removes_directory_marker_and_descendants,
    recursive_tombstone_removes_directory_marker_and_descendants_turso
);

async fn export_replication_bundle_supports_tombstone_versions_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("tombstone-export-bundle").await;

    store
        .put_object_versioned(
            "will-delete",
            Bytes::from_static(b"to-be-deleted"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let tombstone_version_id = store
        .tombstone_object("will-delete", PutOptions::default())
        .await
        .unwrap();

    let bundle = store
        .export_replication_bundle(
            "will-delete",
            Some(&tombstone_version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("expected tombstone replication bundle");

    assert_eq!(bundle.key, "will-delete");
    assert_eq!(
        bundle.version_id.as_deref(),
        Some(tombstone_version_id.as_str())
    );
    assert_eq!(bundle.manifest_hash, TOMBSTONE_MANIFEST_HASH);
    assert!(bundle.manifest.chunks.is_empty());
    assert_eq!(bundle.manifest.total_size_bytes, 0);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    export_replication_bundle_supports_tombstone_versions_impl,
    export_replication_bundle_supports_tombstone_versions,
    export_replication_bundle_supports_tombstone_versions_turso
);

async fn rename_preserves_object_id_and_history_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("rename-preserves-object-id").await;

    let put = store
        .put_object_versioned(
            "docs/a.txt",
            Bytes::from_static(b"hello"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let before = store.list_versions("docs/a.txt").await.unwrap().unwrap();
    let before_object_id = before.object_id.clone();
    assert_eq!(before.versions.len(), 1);
    assert_eq!(before.versions[0].version_id, put.version_id);

    let mutation = store
        .rename_object_path("docs/a.txt", "docs/b.txt", false)
        .await
        .unwrap();
    assert_eq!(mutation, PathMutationResult::Applied);

    assert!(
        store
            .get_object("docs/a.txt", None, None, ObjectReadMode::Preferred)
            .await
            .is_err()
    );

    let after = store.list_versions("docs/b.txt").await.unwrap().unwrap();
    assert_eq!(after.object_id, before_object_id);
    assert!(
        after
            .versions
            .iter()
            .any(|v| v.version_id == put.version_id)
    );

    let read = store
        .get_object("docs/b.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(read.as_ref(), b"hello");

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    rename_preserves_object_id_and_history_impl,
    rename_preserves_object_id_and_history,
    rename_preserves_object_id_and_history_turso
);

async fn rename_replication_subjects_include_source_path_deletion_event_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend
        .init_store("rename-replication-subjects-source-delete")
        .await;

    store
        .put_object_versioned(
            "docs/a.txt",
            Bytes::from_static(b"hello"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let mutation = store
        .rename_object_path("docs/a.txt", "docs/b.txt", false)
        .await
        .unwrap();
    assert_eq!(mutation, PathMutationResult::Applied);

    let subjects = store.list_replication_subjects().await.unwrap();
    assert!(subjects.contains(&"docs/b.txt".to_string()));
    assert!(
        subjects
            .iter()
            .any(|subject| subject.starts_with("docs/a.txt@")),
        "expected rename to leave a versioned deletion subject for the old path, subjects={subjects:?}"
    );
    assert!(
        !subjects.contains(&"docs/a.txt".to_string()),
        "old path should only remain visible as a deletion/version subject, subjects={subjects:?}"
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    rename_replication_subjects_include_source_path_deletion_event_impl,
    rename_replication_subjects_include_source_path_deletion_event,
    rename_replication_subjects_include_source_path_deletion_event_turso
);

async fn copy_creates_new_object_id_with_provenance_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("copy-provenance-object-id").await;

    let _ = store
        .put_object_versioned(
            "docs/source.txt",
            Bytes::from_static(b"source-v1"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let source_before = store
        .list_versions("docs/source.txt")
        .await
        .unwrap()
        .unwrap();
    let source_object_id = source_before.object_id.clone();
    let source_head_version_id = source_before
        .preferred_head_version_id
        .clone()
        .expect("source should have a preferred head");

    let mutation = store
        .copy_object_path("docs/source.txt", "docs/copy.txt", false)
        .await
        .unwrap();
    assert_eq!(mutation, PathMutationResult::Applied);

    let copy_versions = store.list_versions("docs/copy.txt").await.unwrap().unwrap();
    assert_ne!(copy_versions.object_id, source_object_id);
    assert_eq!(copy_versions.versions.len(), 1);
    let copy_root = &copy_versions.versions[0];
    assert_eq!(
        copy_root.copied_from_object_id.as_deref(),
        Some(source_object_id.as_str())
    );
    assert_eq!(
        copy_root.copied_from_version_id.as_deref(),
        Some(source_head_version_id.as_str())
    );
    assert_eq!(
        copy_root.copied_from_path.as_deref(),
        Some("docs/source.txt")
    );

    let copied_payload = store
        .get_object("docs/copy.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(copied_payload.as_ref(), b"source-v1");

    let _ = store
        .put_object_versioned(
            "docs/copy.txt",
            Bytes::from_static(b"copy-v2"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let source_after = store
        .get_object("docs/source.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(source_after.as_ref(), b"source-v1");

    let copy_after = store
        .get_object("docs/copy.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(copy_after.as_ref(), b"copy-v2");

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    copy_creates_new_object_id_with_provenance_impl,
    copy_creates_new_object_id_with_provenance,
    copy_creates_new_object_id_with_provenance_turso
);

async fn load_cluster_replicas_returns_empty_when_file_missing_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("cluster-replicas-empty").await;

    let replicas = store.load_cluster_replicas().await.unwrap();
    assert!(replicas.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    load_cluster_replicas_returns_empty_when_file_missing_impl,
    load_cluster_replicas_returns_empty_when_file_missing,
    load_cluster_replicas_returns_empty_when_file_missing_turso
);

async fn explicit_version_id_is_idempotent_for_matching_manifest_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("explicit-version-id-idempotent").await;

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
    assert!(first.created_new_version);
    assert!(!second.created_new_version);

    let versions = store.list_versions("hello").await.unwrap().unwrap();
    assert_eq!(versions.versions.len(), 1);
    assert_eq!(versions.versions[0].version_id, "ver-fixed-1");

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    explicit_version_id_is_idempotent_for_matching_manifest_impl,
    explicit_version_id_is_idempotent_for_matching_manifest,
    explicit_version_id_is_idempotent_for_matching_manifest_turso
);

async fn unchanged_upload_reuses_preferred_head_version_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("unchanged-upload-reuses-version").await;

    let first = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-a"),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let second = store
        .put_object_versioned(
            "hello",
            Bytes::from_static(b"payload-a"),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(first.version_id, second.version_id);
    assert!(first.created_new_version);
    assert!(!second.created_new_version);

    let versions = store.list_versions("hello").await.unwrap().unwrap();
    assert_eq!(versions.versions.len(), 1);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    unchanged_upload_reuses_preferred_head_version_impl,
    unchanged_upload_reuses_preferred_head_version,
    unchanged_upload_reuses_preferred_head_version_turso
);

async fn persist_and_load_cluster_replicas_roundtrip_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("cluster-replicas-roundtrip").await;

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

run_on_all_metadata_backends!(
    persist_and_load_cluster_replicas_roundtrip_impl,
    persist_and_load_cluster_replicas_roundtrip,
    persist_and_load_cluster_replicas_roundtrip_turso
);

async fn client_credential_state_roundtrip_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("client-credential-roundtrip").await;

    let state = ClientCredentialState {
        pairing_authorizations: vec![PairingAuthorizationRecord {
            token_id: "tok-1".to_string(),
            pairing_secret_hash: "hash-1".to_string(),
            label: Some("laptop".to_string()),
            created_at_unix: 11,
            expires_at_unix: 22,
            used_at_unix: None,
            consumed_by_device_id: None,
        }],
        credentials: vec![ClientCredentialRecord {
            device_id: "dev-1".to_string(),
            label: Some("Pixel".to_string()),
            public_key_pem: None,
            public_key_fingerprint: None,
            issued_credential_pem: None,
            credential_fingerprint: None,
            created_at_unix: 33,
            revocation_reason: Some("retired".to_string()),
            revoked_by_actor: Some("qa-operator".to_string()),
            revoked_by_source_node: Some("node-admin".to_string()),
            revoked_at_unix: Some(44),
        }],
    };

    store.persist_client_credential_state(&state).await.unwrap();
    let loaded = store.load_client_credential_state().await.unwrap();

    assert_eq!(loaded.pairing_authorizations.len(), 1);
    assert_eq!(loaded.pairing_authorizations[0].token_id, "tok-1");
    assert_eq!(
        loaded.pairing_authorizations[0].label.as_deref(),
        Some("laptop")
    );
    assert_eq!(loaded.credentials.len(), 1);
    assert_eq!(loaded.credentials[0].device_id, "dev-1");
    assert_eq!(loaded.credentials[0].label.as_deref(), Some("Pixel"));
    assert_eq!(
        loaded.credentials[0].revocation_reason.as_deref(),
        Some("retired")
    );
    assert_eq!(
        loaded.credentials[0].revoked_by_actor.as_deref(),
        Some("qa-operator")
    );
    assert_eq!(
        loaded.credentials[0].revoked_by_source_node.as_deref(),
        Some("node-admin")
    );
    assert_eq!(loaded.credentials[0].revoked_at_unix, Some(44));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    client_credential_state_roundtrip_impl,
    client_credential_state_roundtrip,
    client_credential_state_roundtrip_turso
);

async fn ensure_media_cache_generates_thumbnail_and_dimensions_for_png_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("media-cache-png").await;

    let put = store
        .put_object_versioned(
            "photos/cat.png",
            Bytes::from(sample_png_bytes()),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let metadata = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.status, MediaCacheStatus::Ready);
    assert_eq!(metadata.media_type.as_deref(), Some("image"));
    assert_eq!(metadata.mime_type.as_deref(), Some("image/png"));
    assert_eq!(metadata.width, Some(4));
    assert_eq!(metadata.height, Some(3));
    assert!(metadata.thumbnail.is_some());

    let thumb = metadata.thumbnail.as_ref().unwrap();
    let thumb_path = store.media_thumbnail_path(&metadata.content_fingerprint, &thumb.profile);
    assert!(fs::try_exists(&thumb_path).await.unwrap());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    ensure_media_cache_generates_thumbnail_and_dimensions_for_png_impl,
    ensure_media_cache_generates_thumbnail_and_dimensions_for_png,
    ensure_media_cache_generates_thumbnail_and_dimensions_for_png_turso
);

async fn content_fingerprint_is_stable_across_distinct_keys_with_same_bytes_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("media-cache-fingerprint").await;
    let payload = sample_png_bytes();

    let first = store
        .put_object_versioned(
            "photos/a.png",
            Bytes::from(payload.clone()),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let second = store
        .put_object_versioned(
            "archive/b.png",
            Bytes::from(payload),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let first_lookup = store
        .lookup_media_cache(&first.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    let second_lookup = store
        .lookup_media_cache(&second.manifest_hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(
        first_lookup.content_fingerprint,
        second_lookup.content_fingerprint
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    content_fingerprint_is_stable_across_distinct_keys_with_same_bytes_impl,
    content_fingerprint_is_stable_across_distinct_keys_with_same_bytes,
    content_fingerprint_is_stable_across_distinct_keys_with_same_bytes_turso
);

async fn metadata_roundtrips_current_state_version_indexes_and_snapshots_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("metadata-roundtrip").await;

    store
        .put_object_versioned(
            "docs/hello.txt",
            Bytes::from_static(b"v1"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    store
        .put_object_versioned(
            "docs/hello.txt",
            Bytes::from_static(b"v2"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let snapshots_before = store.list_snapshots().await.unwrap();
    assert!(snapshots_before.len() >= 2);

    let before = store
        .list_versions("docs/hello.txt")
        .await
        .unwrap()
        .expect("expected version history");
    assert_eq!(before.versions.len(), 2);

    drop(store);

    let reopened = backend.open_store(root.clone()).await;
    assert_eq!(reopened.object_count(), 1);
    assert_eq!(reopened.current_keys(), vec!["docs/hello.txt".to_string()]);

    let payload = reopened
        .get_object("docs/hello.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(payload.as_ref(), b"v2");

    let after = reopened
        .list_versions("docs/hello.txt")
        .await
        .unwrap()
        .expect("expected version history after reopen");
    assert_eq!(after.object_id, before.object_id);
    assert_eq!(after.versions.len(), 2);
    assert_eq!(
        reopened.list_snapshots().await.unwrap().len(),
        snapshots_before.len()
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    metadata_roundtrips_current_state_version_indexes_and_snapshots_impl,
    metadata_roundtrips_current_state_version_indexes_and_snapshots,
    metadata_roundtrips_current_state_version_indexes_and_snapshots_turso
);

async fn metadata_roundtrips_media_cache_metadata_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("metadata-media-cache").await;

    let put = store
        .put_object_versioned(
            "photos/cat.png",
            Bytes::from(sample_png_bytes()),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let generated = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .expect("expected media metadata");
    assert_eq!(generated.status, MediaCacheStatus::Ready);

    drop(store);

    let reopened = backend.open_store(root.clone()).await;
    let lookup = reopened
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .expect("expected cached media lookup after reopen");

    assert_eq!(lookup.content_fingerprint, generated.content_fingerprint);
    let metadata = lookup.metadata.expect("expected metadata payload");
    assert_eq!(metadata.status, MediaCacheStatus::Ready);
    assert_eq!(metadata.width, Some(4));
    assert_eq!(metadata.height, Some(3));
    assert!(metadata.thumbnail.is_some());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    metadata_roundtrips_media_cache_metadata_impl,
    metadata_roundtrips_media_cache_metadata,
    metadata_roundtrips_media_cache_metadata_turso
);
