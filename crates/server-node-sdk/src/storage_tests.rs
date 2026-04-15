use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use time::{Date, Month, PrimitiveDateTime, Time, UtcOffset};

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

fn sample_oriented_jpeg_bytes(orientation: u16) -> Vec<u8> {
    let mut image = image::RgbImage::new(40, 30);
    for y in 0..30 {
        for x in 0..40 {
            let pixel = match (x < 20, y < 15) {
                (true, true) => image::Rgb([255, 0, 0]),
                (false, true) => image::Rgb([0, 255, 0]),
                (true, false) => image::Rgb([0, 0, 255]),
                (false, false) => image::Rgb([255, 255, 0]),
            };
            image.put_pixel(x, y, pixel);
        }
    }

    let mut jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 100);
    encoder
        .encode_image(&image::DynamicImage::ImageRgb8(image))
        .unwrap();
    jpeg_with_exif_orientation(jpeg, orientation)
}

fn sample_video_thumbnail_bytes() -> Vec<u8> {
    let mut image = image::RgbImage::new(256, 144);
    for y in 0..144 {
        for x in 0..256 {
            let pixel = if x < 128 {
                image::Rgb([28, 99, 193])
            } else {
                image::Rgb([244, 180, 0])
            };
            image.put_pixel(x, y, pixel);
        }
    }

    let mut jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 90);
    encoder
        .encode_image(&image::DynamicImage::ImageRgb8(image))
        .unwrap();
    jpeg
}

fn jpeg_with_exif_orientation(jpeg: Vec<u8>, orientation: u16) -> Vec<u8> {
    assert!(jpeg.starts_with(&[0xff, 0xd8]));
    let mut encoded = Vec::with_capacity(jpeg.len() + 36);
    encoded.extend_from_slice(&jpeg[..2]);
    encoded.extend_from_slice(&exif_orientation_app1_segment(orientation));
    encoded.extend_from_slice(&jpeg[2..]);
    encoded
}

fn exif_orientation_app1_segment(orientation: u16) -> Vec<u8> {
    assert!((1..=8).contains(&orientation));

    let mut segment = vec![0xff, 0xe1, 0x00, 0x22];
    segment.extend_from_slice(b"Exif\0\0");
    segment.extend_from_slice(&[
        0x4d, 0x4d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x01, 0x12, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x01,
    ]);
    segment.extend_from_slice(&orientation.to_be_bytes());
    segment.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    segment
}

fn assert_dominant_color(pixel: &image::Rgb<u8>, expected: [u8; 3]) {
    match expected {
        [255, 0, 0] => {
            assert!(pixel[0] > 180, "expected red pixel, got {pixel:?}");
            assert!(pixel[1] < 90, "expected low green channel, got {pixel:?}");
            assert!(pixel[2] < 90, "expected low blue channel, got {pixel:?}");
        }
        [0, 255, 0] => {
            assert!(pixel[1] > 180, "expected green pixel, got {pixel:?}");
            assert!(pixel[0] < 90, "expected low red channel, got {pixel:?}");
            assert!(pixel[2] < 90, "expected low blue channel, got {pixel:?}");
        }
        [0, 0, 255] => {
            assert!(pixel[2] > 180, "expected blue pixel, got {pixel:?}");
            assert!(pixel[0] < 90, "expected low red channel, got {pixel:?}");
            assert!(pixel[1] < 90, "expected low green channel, got {pixel:?}");
        }
        [255, 255, 0] => {
            assert!(pixel[0] > 180, "expected yellow pixel, got {pixel:?}");
            assert!(pixel[1] > 180, "expected yellow pixel, got {pixel:?}");
            assert!(pixel[2] < 90, "expected low blue channel, got {pixel:?}");
        }
        _ => panic!("unsupported expected color: {expected:?}"),
    }
}

fn sample_large_chunked_payload() -> Vec<u8> {
    let size = 2 * 1024 * 1024 + 1536;
    (0..size).map(|index| (index % 251) as u8).collect()
}

#[test]
fn parse_exif_taken_at_supports_offsets_and_utc_fallback() {
    let with_offset = parse_exif_taken_at(Some("2024:03:04 05:06:07"), Some("+02:30"));
    let expected_with_offset = PrimitiveDateTime::new(
        Date::from_calendar_date(2024, Month::March, 4).unwrap(),
        Time::from_hms(5, 6, 7).unwrap(),
    )
    .assume_offset(UtcOffset::from_hms(2, 30, 0).unwrap())
    .unix_timestamp() as u64;
    assert_eq!(with_offset, Some(expected_with_offset));

    let without_offset = parse_exif_taken_at(Some("2024:03:04 05:06:07"), None);
    let expected_without_offset = PrimitiveDateTime::new(
        Date::from_calendar_date(2024, Month::March, 4).unwrap(),
        Time::from_hms(5, 6, 7).unwrap(),
    )
    .assume_utc()
    .unix_timestamp() as u64;
    assert_eq!(without_offset, Some(expected_without_offset));

    assert_eq!(parse_exif_taken_at(Some("invalid"), Some("+02:00")), None);
}

#[cfg(unix)]
fn install_fake_video_tools(dir: &Path) -> (PathBuf, PathBuf, Vec<u8>) {
    std::fs::create_dir_all(dir).unwrap();
    let poster_path = dir.join("poster.jpg");
    let poster_bytes = sample_video_thumbnail_bytes();
    std::fs::write(&poster_path, &poster_bytes).unwrap();

    let ffprobe_path = dir.join("ffprobe");
    let ffprobe_script = r#"#!/bin/sh
set -eu
input=""
for arg in "$@"; do
  [ "$arg" != "-nostdin" ]
  input="$arg"
done
list="${input#concatf:}"
[ -f "$list" ]
line_count=$(wc -l < "$list" | tr -d ' ')
[ "$line_count" -ge 3 ]
grep -q '^file:' "$list"
printf '%s\n' '{"streams":[{"width":1920,"height":1080,"codec_name":"h264"}],"format":{"format_name":"mov,mp4,m4a,3gp,3g2,mj2","duration":"42.0"}}'
"#;
    std::fs::write(&ffprobe_path, ffprobe_script).unwrap();

    let ffmpeg_path = dir.join("ffmpeg");
    let ffmpeg_script = format!(
        r#"#!/bin/sh
set -eu
input=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-i" ]; then
    input="$arg"
    break
  fi
  prev="$arg"
done
list="${{input#concatf:}}"
[ -f "$list" ]
line_count=$(wc -l < "$list" | tr -d ' ')
[ "$line_count" -ge 3 ]
grep -q '^file:' "$list"
cat '{}'
"#,
        poster_path.display()
    );
    std::fs::write(&ffmpeg_path, ffmpeg_script).unwrap();

    for path in [&ffprobe_path, &ffmpeg_path] {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    (ffprobe_path, ffmpeg_path, poster_bytes)
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

async fn persist_raw_media_cache_record(
    backend: StorageTestBackend,
    metadata_db_path: &Path,
    content_fingerprint: &str,
    payload: &[u8],
) {
    match backend {
        StorageTestBackend::Sqlite => {
            let db = rusqlite::Connection::open(metadata_db_path).unwrap();
            db.execute(
                "INSERT INTO media_cache (content_fingerprint, metadata_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(content_fingerprint) DO UPDATE SET metadata_json = excluded.metadata_json",
                rusqlite::params![content_fingerprint, payload],
            )
            .unwrap();
        }
        #[cfg(feature = "turso-metadata")]
        StorageTestBackend::Turso => {
            let db = turso::Builder::new_local(&metadata_db_path.to_string_lossy())
                .build()
                .await
                .unwrap();
            let conn = db.connect().unwrap();
            conn.execute(
                "INSERT INTO media_cache (content_fingerprint, metadata_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(content_fingerprint) DO UPDATE SET metadata_json = excluded.metadata_json",
                (content_fingerprint, payload.to_vec()),
            )
            .await
            .unwrap();
        }
    }
}

async fn media_cache_record_exists(
    backend: StorageTestBackend,
    metadata_db_path: &Path,
    content_fingerprint: &str,
) -> bool {
    match backend {
        StorageTestBackend::Sqlite => {
            let db = rusqlite::Connection::open(metadata_db_path).unwrap();
            db.query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM media_cache WHERE content_fingerprint = ?1
                 )",
                rusqlite::params![content_fingerprint],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
                != 0
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
                    "SELECT COUNT(*) FROM media_cache WHERE content_fingerprint = ?1",
                    (content_fingerprint,),
                )
                .await
                .unwrap();
            let row = rows.next().await.unwrap().expect("expected count row");
            match row.get_value(0).unwrap() {
                turso::Value::Integer(value) => value != 0,
                other => panic!("unexpected count type: {other:?}"),
            }
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
fn exif_gps_coordinate_rejects_non_finite_rationals() {
    let value = exif::Value::Rational(vec![
        exif::Rational { num: 0, denom: 0 },
        exif::Rational { num: 1, denom: 1 },
        exif::Rational { num: 1, denom: 1 },
    ]);

    assert_eq!(exif_gps_coordinate(&value), None);
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

async fn rename_replication_subjects_use_each_heads_own_logical_path_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend
        .init_store("rename-replication-subjects-own-head-path")
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

    let renamed_object_id = store
        .current_state
        .object_ids
        .get("docs/b.txt")
        .cloned()
        .expect("renamed destination path should remain current");
    let renamed_index = store
        .load_version_index_by_object_id(&renamed_object_id)
        .await
        .unwrap()
        .expect("renamed destination should have a version index");
    let renamed_record = renamed_index
        .versions
        .values()
        .find(|record| record.version_id.starts_with("ren-"))
        .cloned()
        .expect("expected renamed head version record");

    let tombstone_subject = store
        .list_metadata_subjects()
        .await
        .unwrap()
        .into_iter()
        .find(|subject| subject.starts_with("docs/a.txt@rename-tomb-"))
        .expect("expected rename tombstone subject on source path");
    let (_, tombstone_version_id) = tombstone_subject
        .split_once('@')
        .expect("rename tombstone subject should include version id");
    let tombstone_object_id = store
        .resolve_object_id_for_key_version("docs/a.txt", tombstone_version_id)
        .await
        .unwrap()
        .expect("expected object id for rename tombstone");
    let mut tombstone_index = store
        .load_version_index_by_object_id(&tombstone_object_id)
        .await
        .unwrap()
        .expect("expected version index for rename tombstone");

    let mut divergent_renamed_record = renamed_record.clone();
    divergent_renamed_record.object_id = tombstone_object_id.clone();
    tombstone_index.versions.insert(
        divergent_renamed_record.version_id.clone(),
        divergent_renamed_record.clone(),
    );
    tombstone_index.head_version_ids = vec![
        tombstone_version_id.to_string(),
        divergent_renamed_record.version_id.clone(),
    ];
    tombstone_index.preferred_head_version_id = Some(tombstone_version_id.to_string());
    store
        .persist_version_index_by_object_id(&tombstone_object_id, &tombstone_index)
        .await
        .unwrap();

    let subjects = store.list_replication_subjects().await.unwrap();
    assert!(
        subjects.contains(&format!(
            "docs/b.txt@{}",
            divergent_renamed_record.version_id
        )),
        "renamed head should remain advertised on its destination path, subjects={subjects:?}"
    );
    assert!(
        !subjects.contains(&format!(
            "docs/a.txt@{}",
            divergent_renamed_record.version_id
        )),
        "renamed head must not be advertised under the old path, subjects={subjects:?}"
    );

    let wrong_export = store
        .export_replication_bundle(
            "docs/a.txt",
            Some(&divergent_renamed_record.version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap();
    assert!(
        wrong_export.is_none(),
        "source path should not resolve to renamed destination version"
    );

    let right_export = store
        .export_replication_bundle(
            "docs/b.txt",
            Some(&divergent_renamed_record.version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("destination path should resolve the renamed version");
    assert_eq!(right_export.key, "docs/b.txt");
    assert_eq!(right_export.manifest.key, "docs/b.txt");

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    rename_replication_subjects_use_each_heads_own_logical_path_impl,
    rename_replication_subjects_use_each_heads_own_logical_path,
    rename_replication_subjects_use_each_heads_own_logical_path_turso
);

async fn versioned_exports_preserve_historical_rename_tombstone_after_key_reuse_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend
        .init_store("versioned-export-historical-rename-tombstone")
        .await;

    store
        .put_object_versioned(
            "docs/a.txt",
            Bytes::from_static(b"before-rename"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let mutation = store
        .rename_object_path("docs/a.txt", "docs/b.txt", false)
        .await
        .unwrap();
    assert_eq!(mutation, PathMutationResult::Applied);

    let tombstone_subject = store
        .list_metadata_subjects()
        .await
        .unwrap()
        .into_iter()
        .find(|subject| subject.starts_with("docs/a.txt@rename-tomb-"))
        .expect("expected rename tombstone subject for original path");
    let (_, tombstone_version_id) = tombstone_subject
        .split_once('@')
        .expect("rename tombstone subject should include version id");
    let tombstone_version_id = tombstone_version_id.to_string();

    let tombstone_metadata_before_reuse = store
        .export_metadata_bundle(
            "docs/a.txt",
            Some(&tombstone_version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("expected metadata export bundle before key reuse");
    let tombstone_object_id = tombstone_metadata_before_reuse
        .object_id
        .clone()
        .expect("historical tombstone export should include object id");

    let tombstone_replication_before_reuse = store
        .export_replication_bundle(
            "docs/a.txt",
            Some(&tombstone_version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("expected replication export bundle before key reuse");
    assert_eq!(
        tombstone_replication_before_reuse.version_id.as_deref(),
        Some(tombstone_version_id.as_str())
    );
    assert_eq!(
        tombstone_replication_before_reuse.manifest_hash,
        TOMBSTONE_MANIFEST_HASH
    );

    store
        .put_object_versioned(
            "docs/a.txt",
            Bytes::from_static(b"after-recreate"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let current_versions = store
        .list_versions("docs/a.txt")
        .await
        .unwrap()
        .expect("recreated key should have versions");
    assert_ne!(current_versions.object_id, tombstone_object_id);

    let metadata_subjects = store.list_metadata_subjects().await.unwrap();
    assert!(
        metadata_subjects.contains(&tombstone_subject),
        "expected historical rename tombstone to stay advertised after key reuse, subjects={metadata_subjects:?}"
    );

    let tombstone_metadata_after_reuse = store
        .export_metadata_bundle(
            "docs/a.txt",
            Some(&tombstone_version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("expected metadata export bundle for advertised historical rename tombstone");
    assert_eq!(
        tombstone_metadata_after_reuse.object_id.as_deref(),
        Some(tombstone_object_id.as_str())
    );
    assert_eq!(tombstone_metadata_after_reuse.versions.len(), 1);
    assert_eq!(
        tombstone_metadata_after_reuse.versions[0].version_id,
        tombstone_version_id
    );

    let tombstone_replication_after_reuse = store
        .export_replication_bundle(
            "docs/a.txt",
            Some(&tombstone_version_id),
            ObjectReadMode::Preferred,
        )
        .await
        .unwrap()
        .expect("expected replication export bundle for advertised historical rename tombstone");
    assert_eq!(
        tombstone_replication_after_reuse.version_id.as_deref(),
        Some(tombstone_version_id.as_str())
    );
    assert_eq!(
        tombstone_replication_after_reuse.manifest_hash,
        TOMBSTONE_MANIFEST_HASH
    );
    assert!(tombstone_replication_after_reuse.manifest.chunks.is_empty());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    versioned_exports_preserve_historical_rename_tombstone_after_key_reuse_impl,
    versioned_exports_preserve_historical_rename_tombstone_after_key_reuse,
    versioned_exports_preserve_historical_rename_tombstone_after_key_reuse_turso
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

async fn restore_snapshot_same_path_creates_new_head_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("restore-snapshot-same-path").await;

    let first = store
        .put_object_versioned(
            "docs/readme.txt",
            Bytes::from_static(b"v1"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let _second = store
        .put_object_versioned(
            "docs/readme.txt",
            Bytes::from_static(b"v2"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let restored = store
        .restore_snapshot_path(
            &first.snapshot_id,
            "docs/readme.txt",
            "docs/readme.txt",
            false,
            false,
        )
        .await
        .unwrap();
    match restored {
        SnapshotRestoreMutationResult::Applied(report) => {
            assert_eq!(report.restored_count, 1);
            assert!(!report.recursive);
        }
        other => panic!("expected applied restore, got {other:?}"),
    }

    let payload = store
        .get_object("docs/readme.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(payload.as_ref(), b"v1");

    let versions = store
        .list_versions("docs/readme.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(versions.versions.len(), 3);
    let preferred_head_id = versions
        .preferred_head_version_id
        .clone()
        .expect("restored path should have a preferred head");
    let restored_head = versions
        .versions
        .iter()
        .find(|record| record.version_id == preferred_head_id)
        .expect("preferred head should exist in versions");
    assert_eq!(restored_head.parent_version_ids.len(), 1);
    assert_eq!(
        restored_head.copied_from_version_id.as_deref(),
        Some(first.version_id.as_str())
    );
    assert_eq!(
        restored_head.copied_from_path.as_deref(),
        Some("docs/readme.txt")
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    restore_snapshot_same_path_creates_new_head_impl,
    restore_snapshot_same_path_creates_new_head,
    restore_snapshot_same_path_creates_new_head_turso
);

async fn restore_snapshot_to_custom_target_uses_metadata_copy_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("restore-snapshot-custom-target").await;

    let first = store
        .put_object_versioned(
            "docs/source.txt",
            Bytes::from_static(b"source-v1"),
            PutOptions::default(),
        )
        .await
        .unwrap();
    let source_versions = store
        .list_versions("docs/source.txt")
        .await
        .unwrap()
        .unwrap();
    let source_object_id = source_versions.object_id.clone();

    let restored = store
        .restore_snapshot_path(
            &first.snapshot_id,
            "docs/source.txt",
            "restored/copy.txt",
            false,
            false,
        )
        .await
        .unwrap();
    match restored {
        SnapshotRestoreMutationResult::Applied(report) => {
            assert_eq!(report.restored_count, 1);
            assert_eq!(report.target_path, "restored/copy.txt");
        }
        other => panic!("expected applied restore, got {other:?}"),
    }

    let copied_payload = store
        .get_object("restored/copy.txt", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    assert_eq!(copied_payload.as_ref(), b"source-v1");

    let copy_versions = store
        .list_versions("restored/copy.txt")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(copy_versions.object_id, source_object_id);
    assert_eq!(copy_versions.versions.len(), 1);
    let copy_root = &copy_versions.versions[0];
    assert_eq!(
        copy_root.copied_from_object_id.as_deref(),
        Some(source_object_id.as_str())
    );
    assert_eq!(
        copy_root.copied_from_version_id.as_deref(),
        Some(first.version_id.as_str())
    );
    assert_eq!(
        copy_root.copied_from_path.as_deref(),
        Some("docs/source.txt")
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    restore_snapshot_to_custom_target_uses_metadata_copy_impl,
    restore_snapshot_to_custom_target_uses_metadata_copy,
    restore_snapshot_to_custom_target_uses_metadata_copy_turso
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

async fn ensure_media_cache_rotates_exif_oriented_jpeg_thumbnail_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-cache-oriented-jpeg").await;

    let put = store
        .put_object_versioned(
            "photos/portrait.jpg",
            Bytes::from(sample_oriented_jpeg_bytes(6)),
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
    assert_eq!(metadata.mime_type.as_deref(), Some("image/jpeg"));
    assert_eq!(metadata.width, Some(40));
    assert_eq!(metadata.height, Some(30));
    assert_eq!(metadata.orientation, Some(6));

    let thumb = metadata.thumbnail.as_ref().expect("expected thumbnail");
    assert_eq!((thumb.width, thumb.height), (192, 256));

    let thumb_path = store.media_thumbnail_path(&metadata.content_fingerprint, &thumb.profile);
    let rendered = image::load_from_memory(&fs::read(&thumb_path).await.unwrap())
        .unwrap()
        .to_rgb8();
    assert_eq!(rendered.dimensions(), (192, 256));
    assert_dominant_color(rendered.get_pixel(0, 0), [0, 0, 255]);
    assert_dominant_color(rendered.get_pixel(191, 0), [255, 0, 0]);
    assert_dominant_color(rendered.get_pixel(0, 255), [255, 255, 0]);
    assert_dominant_color(rendered.get_pixel(191, 255), [0, 255, 0]);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    ensure_media_cache_rotates_exif_oriented_jpeg_thumbnail_impl,
    ensure_media_cache_rotates_exif_oriented_jpeg_thumbnail,
    ensure_media_cache_rotates_exif_oriented_jpeg_thumbnail_turso
);

async fn ensure_media_metadata_persists_without_thumbnail_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-metadata-only").await;

    let put = store
        .put_object_versioned(
            "photos/portrait.jpg",
            Bytes::from(sample_oriented_jpeg_bytes(6)),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let metadata = store
        .ensure_media_metadata(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(metadata.status, MediaCacheStatus::Ready);
    assert_eq!(metadata.media_type.as_deref(), Some("image"));
    assert_eq!(metadata.orientation, Some(6));
    assert!(metadata.thumbnail.is_none());

    let lookup = store
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    let cached = lookup.metadata.expect("expected cached metadata");
    assert!(cached.thumbnail.is_none());

    let full = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(full.thumbnail.is_some());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    ensure_media_metadata_persists_without_thumbnail_impl,
    ensure_media_metadata_persists_without_thumbnail,
    ensure_media_metadata_persists_without_thumbnail_turso
);

#[cfg(unix)]
async fn ensure_media_cache_generates_thumbnail_for_mp4_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-cache-mp4").await;
    let tools_dir = root.join("test-video-tools");
    let (ffprobe_path, ffmpeg_path, poster_bytes) = install_fake_video_tools(&tools_dir);
    store.set_media_tool_paths_for_test(ffprobe_path, ffmpeg_path);

    let put = store
        .put_object_versioned(
            "movies/clip.mp4",
            Bytes::from(sample_large_chunked_payload()),
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
    assert_eq!(metadata.media_type.as_deref(), Some("video"));
    assert_eq!(metadata.mime_type.as_deref(), Some("video/mp4"));
    assert_eq!(metadata.width, Some(1920));
    assert_eq!(metadata.height, Some(1080));

    let thumb = metadata.thumbnail.as_ref().expect("expected thumbnail");
    assert_eq!((thumb.width, thumb.height), (256, 144));
    let thumb_path = store.media_thumbnail_path(&metadata.content_fingerprint, &thumb.profile);
    let written = fs::read(&thumb_path).await.unwrap();
    assert_eq!(written, poster_bytes);

    let _ = fs::remove_dir_all(root).await;
}

#[cfg(unix)]
run_on_all_metadata_backends!(
    ensure_media_cache_generates_thumbnail_for_mp4_impl,
    ensure_media_cache_generates_thumbnail_for_mp4,
    ensure_media_cache_generates_thumbnail_for_mp4_turso
);

#[cfg(unix)]
async fn ensure_video_metadata_survives_thumbnail_failures_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-metadata-video-preserve").await;
    let tools_dir = root.join("test-video-tools");
    let (ffprobe_path, _, _) = install_fake_video_tools(&tools_dir);
    store.set_media_tool_paths_for_test(ffprobe_path, root.join("missing-ffmpeg"));

    let put = store
        .put_object_versioned(
            "movies/clip.mp4",
            Bytes::from(sample_large_chunked_payload()),
            PutOptions {
                create_snapshot: false,
                ..PutOptions::default()
            },
        )
        .await
        .unwrap();

    let metadata = store
        .ensure_media_metadata(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(metadata.status, MediaCacheStatus::Ready);
    assert!(metadata.thumbnail.is_none());

    let full = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(full.status, MediaCacheStatus::Ready);
    assert_eq!(full.media_type.as_deref(), Some("video"));
    assert_eq!(full.width, Some(1920));
    assert_eq!(full.height, Some(1080));
    assert!(full.thumbnail.is_none());

    let _ = fs::remove_dir_all(root).await;
}

#[cfg(unix)]
run_on_all_metadata_backends!(
    ensure_video_metadata_survives_thumbnail_failures_impl,
    ensure_video_metadata_survives_thumbnail_failures,
    ensure_video_metadata_survives_thumbnail_failures_turso
);

async fn clear_media_cache_removes_metadata_and_thumbnails_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-cache-clear").await;

    let put = store
        .put_object_versioned(
            "photos/portrait.jpg",
            Bytes::from(sample_oriented_jpeg_bytes(6)),
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
    let thumb = metadata.thumbnail.as_ref().expect("expected thumbnail");
    let thumb_path = store.media_thumbnail_path(&metadata.content_fingerprint, &thumb.profile);
    assert!(fs::try_exists(&thumb_path).await.unwrap());

    let orphan_dir = root
        .join("state")
        .join("media_cache")
        .join("thumbnails")
        .join("orphan");
    fs::create_dir_all(&orphan_dir).await.unwrap();
    let orphan_path = orphan_dir.join("stale.jpg");
    fs::write(&orphan_path, sample_video_thumbnail_bytes())
        .await
        .unwrap();

    let report = store.clear_media_cache().await.unwrap();
    assert_eq!(report.deleted_metadata_records, 1);
    assert_eq!(report.deleted_thumbnail_files, 2);
    assert!(report.deleted_thumbnail_bytes > 0);

    let lookup = store
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(lookup.metadata.is_none());
    assert!(!fs::try_exists(&thumb_path).await.unwrap());
    assert!(!fs::try_exists(&orphan_path).await.unwrap());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    clear_media_cache_removes_metadata_and_thumbnails_impl,
    clear_media_cache_removes_metadata_and_thumbnails,
    clear_media_cache_removes_metadata_and_thumbnails_turso
);

async fn ensure_media_cache_rebuilds_stale_schema_records_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-cache-schema-refresh").await;

    let put = store
        .put_object_versioned(
            "photos/portrait.jpg",
            Bytes::from(sample_oriented_jpeg_bytes(6)),
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
    let mut stale = metadata.clone();
    stale.schema_version = MEDIA_CACHE_SCHEMA_VERSION.saturating_sub(1);
    let stale_thumb = stale.thumbnail.as_mut().expect("expected thumbnail");
    stale_thumb.width = 256;
    stale_thumb.height = 256;
    store.persist_media_cache_record(&stale).await.unwrap();

    let lookup = store
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(lookup.metadata.is_none());

    let rebuilt = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    let rebuilt_thumb = rebuilt.thumbnail.as_ref().expect("expected thumbnail");
    assert_eq!(rebuilt.schema_version, MEDIA_CACHE_SCHEMA_VERSION);
    assert_eq!((rebuilt_thumb.width, rebuilt_thumb.height), (192, 256));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    ensure_media_cache_rebuilds_stale_schema_records_impl,
    ensure_media_cache_rebuilds_stale_schema_records,
    ensure_media_cache_rebuilds_stale_schema_records_turso
);

async fn lookup_media_cache_deletes_invalid_metadata_records_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("media-cache-invalid-row-cleanup").await;

    let put = store
        .put_object_versioned(
            "photos/portrait.jpg",
            Bytes::from(sample_oriented_jpeg_bytes(6)),
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

    let invalid_payload = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": MEDIA_CACHE_SCHEMA_VERSION,
        "content_fingerprint": metadata.content_fingerprint,
        "source_manifest_hash": metadata.source_manifest_hash,
        "status": "ready",
        "media_type": "image",
        "mime_type": "image/jpeg",
        "width": metadata.width,
        "height": metadata.height,
        "orientation": metadata.orientation,
        "taken_at_unix": metadata.taken_at_unix,
        "gps": {
            "latitude": serde_json::Value::Null,
            "longitude": serde_json::Value::Null,
        },
        "thumbnail": serde_json::Value::Null,
        "source_size_bytes": metadata.source_size_bytes,
        "generated_at_unix": metadata.generated_at_unix,
        "error": metadata.error,
    }))
    .unwrap();
    persist_raw_media_cache_record(
        backend,
        &store.metadata_db_path,
        &metadata.content_fingerprint,
        &invalid_payload,
    )
    .await;

    let lookup = store
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(lookup.metadata.is_none());
    assert!(
        !media_cache_record_exists(
            backend,
            &store.metadata_db_path,
            &metadata.content_fingerprint,
        )
        .await
    );

    let rebuilt = store
        .ensure_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rebuilt.content_fingerprint, metadata.content_fingerprint);
    assert!(rebuilt.gps.is_none());

    let lookup = store
        .lookup_media_cache(&put.manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(lookup.metadata.is_some());

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    lookup_media_cache_deletes_invalid_metadata_records_impl,
    lookup_media_cache_deletes_invalid_metadata_records,
    lookup_media_cache_deletes_invalid_metadata_records_turso
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

async fn storage_stats_collect_and_persist_latest_snapshot_metrics_impl(
    backend: StorageTestBackend,
) {
    let (root, mut store) = backend.init_store("storage-stats").await;
    let payload = sample_png_bytes();

    let first_put = store
        .put_object_versioned(
            "photos/a.png",
            Bytes::from(payload.clone()),
            PutOptions::default(),
        )
        .await
        .unwrap();
    store
        .put_object_versioned(
            "photos/b.png",
            Bytes::from(payload.clone()),
            PutOptions::default(),
        )
        .await
        .unwrap();
    store
        .ensure_media_cache(&first_put.manifest_hash)
        .await
        .unwrap()
        .expect("expected media cache metadata");

    let sample = store.collect_storage_stats_sample().await.unwrap();
    assert!(sample.latest_snapshot_id.is_some());
    assert_eq!(sample.latest_snapshot_object_count, 2);
    assert_eq!(
        sample.latest_snapshot_logical_bytes,
        (payload.len() * 2) as u64
    );
    assert_eq!(
        sample.latest_snapshot_unique_chunk_bytes,
        payload.len() as u64
    );
    assert!(sample.chunk_store_bytes >= payload.len() as u64);
    assert!(sample.manifest_store_bytes > 0);
    assert!(sample.metadata_db_bytes > 0);
    assert!(sample.media_cache_bytes > 0);

    store.persist_storage_stats_sample(&sample).await.unwrap();

    let current = store
        .load_current_storage_stats()
        .await
        .unwrap()
        .expect("expected current storage stats");
    assert_eq!(current.latest_snapshot_id, sample.latest_snapshot_id);
    assert_eq!(
        current.latest_snapshot_unique_chunk_bytes,
        sample.latest_snapshot_unique_chunk_bytes
    );

    let history = store
        .list_storage_stats_history(Some(8), None)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].collected_at_unix, sample.collected_at_unix);
    assert_eq!(
        history[0].latest_snapshot_logical_bytes,
        sample.latest_snapshot_logical_bytes
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    storage_stats_collect_and_persist_latest_snapshot_metrics_impl,
    storage_stats_collect_and_persist_latest_snapshot_metrics,
    storage_stats_collect_and_persist_latest_snapshot_metrics_turso
);

async fn chunk_store_bytes_state_tracks_ingest_and_cleanup_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("chunk-store-state").await;
    let payload = Bytes::from_static(b"orphaned-chunk-payload");

    let (_, stored) = store.ingest_chunk_auto(&payload).await.unwrap();
    assert!(stored);
    assert_eq!(
        store.current_chunk_store_bytes(None).await.unwrap(),
        payload.len() as u64
    );

    let (_, stored_again) = store.ingest_chunk_auto(&payload).await.unwrap();
    assert!(!stored_again);
    assert_eq!(
        store.current_chunk_store_bytes(None).await.unwrap(),
        payload.len() as u64
    );

    let report = store.cleanup_unreferenced(0, false).await.unwrap();
    assert!(report.deleted_chunks >= 1);
    assert_eq!(store.current_chunk_store_bytes(None).await.unwrap(), 0);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    chunk_store_bytes_state_tracks_ingest_and_cleanup_impl,
    chunk_store_bytes_state_tracks_ingest_and_cleanup,
    chunk_store_bytes_state_tracks_ingest_and_cleanup_turso
);

async fn metadata_only_cached_chunks_are_evicted_by_cleanup_impl(backend: StorageTestBackend) {
    let (source_root, mut source) = backend
        .init_store("metadata-only-cached-chunks-source")
        .await;
    let (target_root, mut target) = backend
        .init_store("metadata-only-cached-chunks-target")
        .await;

    source
        .put_object_versioned(
            "docs/cached-range.bin",
            Bytes::from(sample_large_chunked_payload()),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let bundle = source
        .export_metadata_bundle("docs/cached-range.bin", None, ObjectReadMode::Preferred)
        .await
        .unwrap()
        .unwrap();
    target.import_metadata_bundle(&bundle).await.unwrap();

    let manifest =
        serde_json::from_slice::<ObjectManifest>(&bundle.manifests[0].manifest_bytes).unwrap();
    let first_chunk = manifest.chunks.first().cloned().unwrap();
    let first_chunk_payload = source
        .read_chunk_payload(&first_chunk.hash)
        .await
        .unwrap()
        .unwrap();
    target
        .ingest_chunk(&first_chunk.hash, first_chunk_payload.as_ref())
        .await
        .unwrap();
    target
        .note_cached_chunk_fetch(
            &first_chunk.hash,
            first_chunk.size_bytes,
            Some("source-node"),
        )
        .await
        .unwrap();

    assert_eq!(
        target
            .list_cached_chunk_records_for_test()
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        target
            .list_locally_owned_manifests_for_test()
            .await
            .unwrap()
            .is_empty()
    );

    let report = target.cleanup_unreferenced(0, false).await.unwrap();
    assert_eq!(report.deleted_cached_chunks, 1);
    assert!(report.deleted_cached_chunk_records >= 1);
    assert!(
        target
            .list_cached_chunk_records_for_test()
            .await
            .unwrap()
            .is_empty()
    );

    let first_chunk_path = chunk_path_for_hash(&target.chunks_dir, &first_chunk.hash);
    assert!(!fs::try_exists(&first_chunk_path).await.unwrap());

    let metadata_subjects = target.list_metadata_subjects().await.unwrap();
    assert!(metadata_subjects.contains(&"docs/cached-range.bin".to_string()));

    let replica_subjects = target.list_replication_subjects().await.unwrap();
    assert!(!replica_subjects.contains(&"docs/cached-range.bin".to_string()));

    let _ = fs::remove_dir_all(source_root).await;
    let _ = fs::remove_dir_all(target_root).await;
}

run_on_all_metadata_backends!(
    metadata_only_cached_chunks_are_evicted_by_cleanup_impl,
    metadata_only_cached_chunks_are_evicted_by_cleanup,
    metadata_only_cached_chunks_are_evicted_by_cleanup_turso
);

async fn importing_replica_manifest_marks_manifest_owned_and_clears_cached_records_impl(
    backend: StorageTestBackend,
) {
    let (source_root, mut source) = backend.init_store("replica-manifest-owned-source").await;
    let (target_root, mut target) = backend.init_store("replica-manifest-owned-target").await;

    source
        .put_object_versioned(
            "docs/owned.bin",
            Bytes::from_static(b"owned-manifest-payload"),
            PutOptions::default(),
        )
        .await
        .unwrap();

    let metadata_bundle = source
        .export_metadata_bundle("docs/owned.bin", None, ObjectReadMode::Preferred)
        .await
        .unwrap()
        .unwrap();
    target
        .import_metadata_bundle(&metadata_bundle)
        .await
        .unwrap();

    let replication_bundle = source
        .export_replication_bundle("docs/owned.bin", None, ObjectReadMode::Preferred)
        .await
        .unwrap()
        .unwrap();
    for chunk in &replication_bundle.manifest.chunks {
        let payload = source
            .read_chunk_payload(&chunk.hash)
            .await
            .unwrap()
            .unwrap();
        target
            .ingest_chunk(&chunk.hash, payload.as_ref())
            .await
            .unwrap();
        target
            .note_cached_chunk_fetch(&chunk.hash, chunk.size_bytes, Some("source-node"))
            .await
            .unwrap();
    }
    assert_eq!(
        target
            .list_cached_chunk_records_for_test()
            .await
            .unwrap()
            .len(),
        replication_bundle.manifest.chunks.len()
    );

    target
        .import_replica_manifest(
            &replication_bundle.key,
            replication_bundle.version_id.as_deref(),
            &replication_bundle.parent_version_ids,
            replication_bundle.state.clone(),
            &replication_bundle.manifest_hash,
            &replication_bundle.manifest_bytes,
        )
        .await
        .unwrap();

    let owned_manifests = target
        .list_locally_owned_manifests_for_test()
        .await
        .unwrap();
    assert!(owned_manifests.contains(&replication_bundle.manifest_hash));
    assert!(
        target
            .list_cached_chunk_records_for_test()
            .await
            .unwrap()
            .is_empty()
    );

    let _ = fs::remove_dir_all(source_root).await;
    let _ = fs::remove_dir_all(target_root).await;
}

run_on_all_metadata_backends!(
    importing_replica_manifest_marks_manifest_owned_and_clears_cached_records_impl,
    importing_replica_manifest_marks_manifest_owned_and_clears_cached_records,
    importing_replica_manifest_marks_manifest_owned_and_clears_cached_records_turso
);

async fn storage_stats_history_prune_drops_older_samples_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("storage-stats-prune").await;

    let older = StorageStatsSample {
        collected_at_unix: 1_000,
        latest_snapshot_id: Some("snap-old".to_string()),
        latest_snapshot_created_at_unix: Some(990),
        latest_snapshot_object_count: 1,
        chunk_store_bytes: 10,
        manifest_store_bytes: 20,
        metadata_db_bytes: 30,
        media_cache_bytes: 40,
        latest_snapshot_logical_bytes: 50,
        latest_snapshot_unique_chunk_bytes: 60,
    };
    let newer = StorageStatsSample {
        collected_at_unix: 2_000,
        latest_snapshot_id: Some("snap-new".to_string()),
        latest_snapshot_created_at_unix: Some(1_990),
        latest_snapshot_object_count: 2,
        chunk_store_bytes: 11,
        manifest_store_bytes: 21,
        metadata_db_bytes: 31,
        media_cache_bytes: 41,
        latest_snapshot_logical_bytes: 51,
        latest_snapshot_unique_chunk_bytes: 61,
    };

    store.persist_storage_stats_sample(&older).await.unwrap();
    store.persist_storage_stats_sample(&newer).await.unwrap();
    store
        .prune_storage_stats_history_before(1_500)
        .await
        .unwrap();

    let history = store
        .list_storage_stats_history(Some(8), None)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].collected_at_unix, newer.collected_at_unix);
    assert_eq!(
        history[0].latest_snapshot_unique_chunk_bytes,
        newer.latest_snapshot_unique_chunk_bytes
    );

    let current = store
        .load_current_storage_stats()
        .await
        .unwrap()
        .expect("expected current sample to remain available");
    assert_eq!(current.collected_at_unix, newer.collected_at_unix);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    storage_stats_history_prune_drops_older_samples_impl,
    storage_stats_history_prune_drops_older_samples,
    storage_stats_history_prune_drops_older_samples_turso
);

async fn storage_stats_history_since_filters_samples_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("storage-stats-since").await;

    let oldest = StorageStatsSample {
        collected_at_unix: 1_000,
        latest_snapshot_id: Some("snap-oldest".to_string()),
        latest_snapshot_created_at_unix: Some(990),
        latest_snapshot_object_count: 1,
        chunk_store_bytes: 10,
        manifest_store_bytes: 20,
        metadata_db_bytes: 30,
        media_cache_bytes: 40,
        latest_snapshot_logical_bytes: 50,
        latest_snapshot_unique_chunk_bytes: 60,
    };
    let middle = StorageStatsSample {
        collected_at_unix: 2_000,
        latest_snapshot_id: Some("snap-middle".to_string()),
        latest_snapshot_created_at_unix: Some(1_990),
        latest_snapshot_object_count: 2,
        chunk_store_bytes: 11,
        manifest_store_bytes: 21,
        metadata_db_bytes: 31,
        media_cache_bytes: 41,
        latest_snapshot_logical_bytes: 51,
        latest_snapshot_unique_chunk_bytes: 61,
    };
    let newest = StorageStatsSample {
        collected_at_unix: 3_000,
        latest_snapshot_id: Some("snap-newest".to_string()),
        latest_snapshot_created_at_unix: Some(2_990),
        latest_snapshot_object_count: 3,
        chunk_store_bytes: 12,
        manifest_store_bytes: 22,
        metadata_db_bytes: 32,
        media_cache_bytes: 42,
        latest_snapshot_logical_bytes: 52,
        latest_snapshot_unique_chunk_bytes: 62,
    };

    store.persist_storage_stats_sample(&oldest).await.unwrap();
    store.persist_storage_stats_sample(&middle).await.unwrap();
    store.persist_storage_stats_sample(&newest).await.unwrap();

    let history = store
        .list_storage_stats_history(None, Some(1_500))
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].collected_at_unix, newest.collected_at_unix);
    assert_eq!(history[1].collected_at_unix, middle.collected_at_unix);

    let limited_history = store
        .list_storage_stats_history(Some(1), Some(1_500))
        .await
        .unwrap();
    assert_eq!(limited_history.len(), 1);
    assert_eq!(
        limited_history[0].collected_at_unix,
        newest.collected_at_unix
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    storage_stats_history_since_filters_samples_impl,
    storage_stats_history_since_filters_samples,
    storage_stats_history_since_filters_samples_turso
);

async fn repair_run_history_roundtrip_and_prune_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("repair-run-history-roundtrip").await;

    let older = super::super::RepairRunRecord {
        run_id: "repair-run-older".to_string(),
        reporting_node_id: NodeId::nil(),
        scope: super::super::replication::ReplicationRepairScope::Local,
        trigger: super::super::RepairRunTrigger::ManualRequest,
        status: super::super::RepairRunStatus::Completed,
        started_at_unix: 900,
        finished_at_unix: 1_000,
        duration_ms: 100,
        plan_summary: super::super::RepairPlanSummary {
            generated_at_unix: 900,
            under_replicated: 1,
            over_replicated: 0,
            cleanup_deferred_items: 0,
            cleanup_deferred_extra_nodes: 0,
            item_count: 1,
        },
        summary: Some(super::super::RepairRunSummary {
            attempted_transfers: 1,
            successful_transfers: 1,
            failed_transfers: 0,
            skipped_items: 0,
            skipped_backoff: 0,
            skipped_max_retries: 0,
            skipped_detail_count: 0,
            last_error: None,
            nodes_contacted: None,
            failed_nodes: None,
        }),
        report: Some(serde_json::json!({ "status": "older" })),
    };
    let newer = super::super::RepairRunRecord {
        run_id: "repair-run-newer".to_string(),
        reporting_node_id: NodeId::nil(),
        scope: super::super::replication::ReplicationRepairScope::Cluster,
        trigger: super::super::RepairRunTrigger::BackgroundAudit,
        status: super::super::RepairRunStatus::Completed,
        started_at_unix: 1_900,
        finished_at_unix: 2_000,
        duration_ms: 200,
        plan_summary: super::super::RepairPlanSummary {
            generated_at_unix: 1_900,
            under_replicated: 2,
            over_replicated: 1,
            cleanup_deferred_items: 1,
            cleanup_deferred_extra_nodes: 2,
            item_count: 3,
        },
        summary: Some(super::super::RepairRunSummary {
            attempted_transfers: 3,
            successful_transfers: 2,
            failed_transfers: 1,
            skipped_items: 4,
            skipped_backoff: 1,
            skipped_max_retries: 1,
            skipped_detail_count: 4,
            last_error: Some("latest error".to_string()),
            nodes_contacted: Some(2),
            failed_nodes: Some(1),
        }),
        report: Some(serde_json::json!({ "status": "newer" })),
    };

    store
        .persist_repair_run_record_for_test(&older)
        .await
        .unwrap();
    store
        .persist_repair_run_record_for_test(&newer)
        .await
        .unwrap();

    let history = store.list_repair_run_history(Some(8), None).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].run_id, newer.run_id);
    assert_eq!(history[1].run_id, older.run_id);

    let filtered = store
        .list_repair_run_history(None, Some(1_500))
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].run_id, newer.run_id);

    store
        .prune_repair_run_history_before_for_test(1_500)
        .await
        .unwrap();

    let remaining = store.list_repair_run_history(Some(8), None).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].run_id, newer.run_id);
    assert_eq!(
        remaining[0]
            .summary
            .as_ref()
            .and_then(|summary| summary.failed_nodes),
        Some(1)
    );

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    repair_run_history_roundtrip_and_prune_impl,
    repair_run_history_roundtrip_and_prune,
    repair_run_history_roundtrip_and_prune_turso
);

async fn data_scrub_history_roundtrip_and_prune_impl(backend: StorageTestBackend) {
    let (root, store) = backend.init_store("data-scrub-history-roundtrip").await;

    let older = super::super::DataScrubRunRecord {
        run_id: "scrub-run-older".to_string(),
        reporting_node_id: NodeId::nil(),
        trigger: super::super::DataScrubRunTrigger::ManualRequest,
        status: super::super::DataScrubRunStatus::IssuesDetected,
        started_at_unix: 900,
        finished_at_unix: 1_000,
        duration_ms: 100,
        summary: super::DataScrubReport {
            current_keys_scanned: 1,
            version_indexes_scanned: 1,
            version_records_scanned: 1,
            manifests_scanned: 1,
            chunks_scanned: 2,
            bytes_scanned: 256,
            issue_count: 1,
            sampled_issue_count: 1,
            issue_sample_truncated: false,
            issues: vec![super::DataScrubIssue {
                kind: super::DataScrubIssueKind::ChunkMissing,
                key: Some("docs/a.bin".to_string()),
                object_id: Some("obj-a".to_string()),
                version_id: Some("ver-a".to_string()),
                manifest_hash: Some("manifest-a".to_string()),
                chunk_hash: Some("chunk-a".to_string()),
                detail: "chunk is missing".to_string(),
            }],
        },
        last_error: None,
    };
    let newer = super::super::DataScrubRunRecord {
        run_id: "scrub-run-newer".to_string(),
        reporting_node_id: NodeId::nil(),
        trigger: super::super::DataScrubRunTrigger::Scheduled,
        status: super::super::DataScrubRunStatus::Clean,
        started_at_unix: 1_900,
        finished_at_unix: 2_000,
        duration_ms: 200,
        summary: super::DataScrubReport {
            current_keys_scanned: 2,
            version_indexes_scanned: 2,
            version_records_scanned: 2,
            manifests_scanned: 2,
            chunks_scanned: 4,
            bytes_scanned: 4_096,
            issue_count: 0,
            sampled_issue_count: 0,
            issue_sample_truncated: false,
            issues: Vec::new(),
        },
        last_error: None,
    };

    store
        .persist_data_scrub_run_record_for_test(&older)
        .await
        .unwrap();
    store
        .persist_data_scrub_run_record_for_test(&newer)
        .await
        .unwrap();

    let history = store
        .list_data_scrub_run_history(Some(8), None)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].run_id, newer.run_id);
    assert_eq!(history[1].run_id, older.run_id);

    let filtered = store
        .list_data_scrub_run_history(None, Some(1_500))
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].run_id, newer.run_id);

    store
        .prune_data_scrub_run_history_before_for_test(1_500)
        .await
        .unwrap();

    let remaining = store
        .list_data_scrub_run_history(Some(8), None)
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].run_id, newer.run_id);
    assert_eq!(remaining[0].summary.issue_count, 0);

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    data_scrub_history_roundtrip_and_prune_impl,
    data_scrub_history_roundtrip_and_prune,
    data_scrub_history_roundtrip_and_prune_turso
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DataScrubCorruptionKind {
    ManifestMissing,
    ManifestUnreadable,
    ManifestInvalid,
    ManifestHashMismatch,
    ManifestKeyMismatch,
    ManifestSizeMismatch,
    ChunkMissing,
    ChunkUnreadable,
    ChunkSizeMismatch,
    ChunkHashMismatch,
}

impl DataScrubCorruptionKind {
    const ALL: [Self; 10] = [
        Self::ManifestMissing,
        Self::ManifestUnreadable,
        Self::ManifestInvalid,
        Self::ManifestHashMismatch,
        Self::ManifestKeyMismatch,
        Self::ManifestSizeMismatch,
        Self::ChunkMissing,
        Self::ChunkUnreadable,
        Self::ChunkSizeMismatch,
        Self::ChunkHashMismatch,
    ];

    fn slug(self) -> &'static str {
        match self {
            Self::ManifestMissing => "manifest-missing",
            Self::ManifestUnreadable => "manifest-unreadable",
            Self::ManifestInvalid => "manifest-invalid",
            Self::ManifestHashMismatch => "manifest-hash-mismatch",
            Self::ManifestKeyMismatch => "manifest-key-mismatch",
            Self::ManifestSizeMismatch => "manifest-size-mismatch",
            Self::ChunkMissing => "chunk-missing",
            Self::ChunkUnreadable => "chunk-unreadable",
            Self::ChunkSizeMismatch => "chunk-size-mismatch",
            Self::ChunkHashMismatch => "chunk-hash-mismatch",
        }
    }

    fn issue_kind(self) -> super::DataScrubIssueKind {
        match self {
            Self::ManifestMissing => super::DataScrubIssueKind::ManifestMissing,
            Self::ManifestUnreadable => super::DataScrubIssueKind::ManifestUnreadable,
            Self::ManifestInvalid => super::DataScrubIssueKind::ManifestInvalid,
            Self::ManifestHashMismatch => super::DataScrubIssueKind::ManifestHashMismatch,
            Self::ManifestKeyMismatch => super::DataScrubIssueKind::ManifestKeyMismatch,
            Self::ManifestSizeMismatch => super::DataScrubIssueKind::ManifestSizeMismatch,
            Self::ChunkMissing => super::DataScrubIssueKind::ChunkMissing,
            Self::ChunkUnreadable => super::DataScrubIssueKind::ChunkUnreadable,
            Self::ChunkSizeMismatch => super::DataScrubIssueKind::ChunkSizeMismatch,
            Self::ChunkHashMismatch => super::DataScrubIssueKind::ChunkHashMismatch,
        }
    }
}

async fn apply_data_scrub_corruption(
    store: &mut PersistentStore,
    key: &str,
    kind: DataScrubCorruptionKind,
) {
    let manifest_hash = store
        .resolve_manifest_hash_for_key(key, None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    let manifest = store
        .load_manifest_by_hash(&manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !manifest.chunks.is_empty(),
        "expected at least one chunk for scrub corruption test"
    );
    let first_chunk = manifest.chunks[0].clone();
    let manifest_path = store.manifest_path_for_test(&manifest_hash);
    let chunk_path = store.chunk_path_for_test(&first_chunk.hash);

    match kind {
        DataScrubCorruptionKind::ManifestMissing => {
            fs::remove_file(&manifest_path).await.unwrap();
        }
        DataScrubCorruptionKind::ManifestUnreadable => {
            fs::remove_file(&manifest_path).await.unwrap();
            fs::create_dir(&manifest_path).await.unwrap();
        }
        DataScrubCorruptionKind::ManifestInvalid => {
            store
                .replace_manifest_bytes_for_subject_for_test(key, None, br#"{not-valid-json"#)
                .await
                .unwrap();
        }
        DataScrubCorruptionKind::ManifestHashMismatch => {
            let mut payload = fs::read(&manifest_path).await.unwrap();
            payload.push(b'\n');
            fs::write(&manifest_path, payload).await.unwrap();
        }
        DataScrubCorruptionKind::ManifestKeyMismatch => {
            let mut mutated = manifest.clone();
            mutated.key = format!("mismatch/{key}");
            let payload = serde_json::to_vec(&mutated).unwrap();
            store
                .replace_manifest_bytes_for_subject_for_test(key, None, &payload)
                .await
                .unwrap();
        }
        DataScrubCorruptionKind::ManifestSizeMismatch => {
            let mut mutated = manifest.clone();
            mutated.total_size_bytes = mutated.total_size_bytes.saturating_add(7);
            let payload = serde_json::to_vec(&mutated).unwrap();
            store
                .replace_manifest_bytes_for_subject_for_test(key, None, &payload)
                .await
                .unwrap();
        }
        DataScrubCorruptionKind::ChunkMissing => {
            fs::remove_file(&chunk_path).await.unwrap();
        }
        DataScrubCorruptionKind::ChunkUnreadable => {
            fs::remove_file(&chunk_path).await.unwrap();
            fs::create_dir(&chunk_path).await.unwrap();
        }
        DataScrubCorruptionKind::ChunkSizeMismatch => {
            fs::write(
                &chunk_path,
                vec![0x5a; first_chunk.size_bytes.saturating_add(1)],
            )
            .await
            .unwrap();
        }
        DataScrubCorruptionKind::ChunkHashMismatch => {
            fs::write(&chunk_path, vec![0x5a; first_chunk.size_bytes])
                .await
                .unwrap();
        }
    }
}

async fn data_scrub_detects_each_corruption_kind_impl(backend: StorageTestBackend) {
    for kind in DataScrubCorruptionKind::ALL {
        let (root, mut store) = backend
            .init_store(&format!("data-scrub-detect-{}", kind.slug()))
            .await;
        let key = format!("docs/{}.bin", kind.slug());

        store
            .put_object_versioned(
                &key,
                Bytes::from(sample_large_chunked_payload()),
                PutOptions::default(),
            )
            .await
            .unwrap();

        apply_data_scrub_corruption(&mut store, &key, kind).await;

        let report = store.run_data_scrub().await.unwrap();
        assert!(
            report.issues.iter().any(|issue| issue.kind == kind.issue_kind()),
            "expected scrub to detect {:?}, issues={:?}",
            kind,
            report.issues
        );

        if matches!(
            kind,
            DataScrubCorruptionKind::ManifestInvalid
                | DataScrubCorruptionKind::ManifestKeyMismatch
                | DataScrubCorruptionKind::ManifestSizeMismatch
        ) {
            assert!(
                !report
                    .issues
                    .iter()
                    .any(|issue| issue.kind == super::DataScrubIssueKind::ManifestHashMismatch),
                "fixture for {:?} should not depend on manifest hash mismatch, issues={:?}",
                kind,
                report.issues
            );
        }

        let _ = fs::remove_dir_all(root).await;
    }
}

run_on_all_metadata_backends!(
    data_scrub_detects_each_corruption_kind_impl,
    data_scrub_detects_each_corruption_kind,
    data_scrub_detects_each_corruption_kind_turso
);

async fn data_scrub_detects_missing_and_corrupt_chunks_impl(backend: StorageTestBackend) {
    let (root, mut store) = backend.init_store("data-scrub-detects-issues").await;
    let payload = sample_large_chunked_payload();

    store
        .put_object_versioned("docs/demo.bin", Bytes::from(payload), PutOptions::default())
        .await
        .unwrap();

    let manifest_hash = store
        .resolve_manifest_hash_for_key("docs/demo.bin", None, None, ObjectReadMode::Preferred)
        .await
        .unwrap();
    let manifest = store
        .load_manifest_by_hash(&manifest_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(manifest.chunks.len() >= 3);

    let corrupt_chunk = &manifest.chunks[0];
    let missing_chunk = &manifest.chunks[1];
    let corrupt_path = chunk_path_for_hash(&store.chunks_dir, &corrupt_chunk.hash);
    let missing_path = chunk_path_for_hash(&store.chunks_dir, &missing_chunk.hash);

    fs::write(&corrupt_path, vec![0u8; corrupt_chunk.size_bytes])
        .await
        .unwrap();
    fs::remove_file(&missing_path).await.unwrap();

    let report = store.run_data_scrub().await.unwrap();
    assert_eq!(report.current_keys_scanned, 1);
    assert_eq!(report.manifests_scanned, 1);
    assert!(report.chunks_scanned >= 3);
    assert!(report.issue_count >= 2);
    assert!(report.issues.iter().any(|issue| {
        issue.kind == super::DataScrubIssueKind::ChunkHashMismatch
            && issue.chunk_hash.as_deref() == Some(corrupt_chunk.hash.as_str())
    }));
    assert!(report.issues.iter().any(|issue| {
        issue.kind == super::DataScrubIssueKind::ChunkMissing
            && issue.chunk_hash.as_deref() == Some(missing_chunk.hash.as_str())
    }));

    let _ = fs::remove_dir_all(root).await;
}

run_on_all_metadata_backends!(
    data_scrub_detects_missing_and_corrupt_chunks_impl,
    data_scrub_detects_missing_and_corrupt_chunks,
    data_scrub_detects_missing_and_corrupt_chunks_turso
);
