use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use common::NodeId;

use super::{
    AdminAuditEvent, CachedMediaMetadata, ClientCredentialState, CurrentState, FileVersionIndex,
    MetadataStore, ReconcileMarker, RepairAttemptRecord, SnapshotInfo, SnapshotManifest,
    StorageStatsSample,
};

pub(super) struct TursoMetadataStore {
    _database: turso::Database,
    connection: turso::Connection,
    metadata_path: PathBuf,
}

impl TursoMetadataStore {
    pub(super) async fn open(metadata_path: &Path) -> Result<Self> {
        let db = turso::Builder::new_local(&metadata_path.to_string_lossy())
            .build()
            .await
            .with_context(|| {
                format!(
                    "failed to open Turso metadata database at {}",
                    metadata_path.display()
                )
            })?;
        let conn = db.connect().with_context(|| {
            format!(
                "failed to connect to Turso metadata database at {}",
                metadata_path.display()
            )
        })?;
        init_metadata_db(&conn).await.with_context(|| {
            format!(
                "failed to initialize Turso metadata database at {}",
                metadata_path.display()
            )
        })?;

        Ok(Self {
            _database: db,
            connection: conn,
            metadata_path: metadata_path.to_path_buf(),
        })
    }

    async fn rollback(&self) {
        let _ = self.connection.execute_batch("ROLLBACK").await;
    }

    fn decode_json<T: serde::de::DeserializeOwned>(
        &self,
        payload: Vec<u8>,
        label: &str,
    ) -> Result<T> {
        serde_json::from_slice(&payload).with_context(|| {
            format!(
                "invalid {label} in Turso metadata database {}",
                self.metadata_path.display()
            )
        })
    }
}

#[async_trait]
impl MetadataStore for TursoMetadataStore {
    async fn load_current_state(&self) -> Result<CurrentState> {
        let mut rows = self
            .connection
            .query(
                "SELECT key, manifest_hash, object_id
                 FROM current_objects",
                (),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to load current state from {}",
                    self.metadata_path.display()
                )
            })?;

        let mut state = CurrentState::default();
        while let Some(row) = rows.next().await? {
            let key = row_string(&row, 0, "current_objects.key")?;
            let manifest_hash = row_string(&row, 1, "current_objects.manifest_hash")?;
            let object_id = row_string(&row, 2, "current_objects.object_id")?;
            state.objects.insert(key.clone(), manifest_hash);
            state.object_ids.insert(key, object_id);
        }

        Ok(state)
    }

    async fn load_repair_attempts(&self) -> Result<HashMap<String, RepairAttemptRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT subject, attempts, last_failure_unix
                 FROM repair_attempts",
                (),
            )
            .await?;
        let mut attempts = HashMap::new();
        while let Some(row) = rows.next().await? {
            let subject = row_string(&row, 0, "repair_attempts.subject")?;
            let attempts_count = u32::try_from(row_u64(&row, 1, "repair_attempts.attempts")?)
                .context("repair attempt count overflow")?;
            let last_failure_unix = row_u64(&row, 2, "repair_attempts.last_failure_unix")?;
            attempts.insert(
                subject,
                RepairAttemptRecord {
                    attempts: attempts_count,
                    last_failure_unix,
                },
            );
        }
        Ok(attempts)
    }

    async fn persist_repair_attempts(
        &self,
        attempts: &HashMap<String, RepairAttemptRecord>,
    ) -> Result<()> {
        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            self.connection
                .execute("DELETE FROM repair_attempts", ())
                .await?;
            for (subject, record) in attempts {
                self.connection
                    .execute(
                        "INSERT INTO repair_attempts (subject, attempts, last_failure_unix)
                         VALUES (?1, ?2, ?3)",
                        (
                            subject.as_str(),
                            i64::from(record.attempts),
                            i64::try_from(record.last_failure_unix)
                                .context("repair failure timestamp overflow")?,
                        ),
                    )
                    .await?;
            }
            self.connection.execute_batch("COMMIT").await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.rollback().await;
        }
        result
    }

    async fn load_cluster_replicas(&self) -> Result<HashMap<String, Vec<NodeId>>> {
        let mut rows = self
            .connection
            .query(
                "SELECT subject, node_id
                 FROM cluster_replicas
                 ORDER BY subject, node_id",
                (),
            )
            .await?;
        let mut replicas = HashMap::<String, Vec<NodeId>>::new();
        while let Some(row) = rows.next().await? {
            let subject = row_string(&row, 0, "cluster_replicas.subject")?;
            let node_id = row_string(&row, 1, "cluster_replicas.node_id")?
                .parse::<NodeId>()
                .with_context(|| format!("invalid node id in cluster replicas for {subject}"))?;
            replicas.entry(subject).or_default().push(node_id);
        }
        Ok(replicas)
    }

    async fn persist_cluster_replicas(
        &self,
        replicas: &HashMap<String, Vec<NodeId>>,
    ) -> Result<()> {
        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            self.connection
                .execute("DELETE FROM cluster_replicas", ())
                .await?;
            for (subject, nodes) in replicas {
                for node_id in nodes {
                    self.connection
                        .execute(
                            "INSERT INTO cluster_replicas (subject, node_id)
                             VALUES (?1, ?2)",
                            (subject.as_str(), node_id.to_string()),
                        )
                        .await?;
                }
            }
            self.connection.execute_batch("COMMIT").await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.rollback().await;
        }
        result
    }

    async fn load_client_credential_state(&self) -> Result<ClientCredentialState> {
        let mut rows = self
            .connection
            .query(
                "SELECT state_json FROM client_credential_state WHERE singleton = 1",
                (),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(ClientCredentialState::default());
        };
        let payload = row_blob(&row, 0, "client_credential_state.state_json")?;
        self.decode_json::<ClientCredentialState>(payload, "client credential state")
    }

    async fn persist_client_credential_state(&self, state: &ClientCredentialState) -> Result<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        self.connection
            .execute(
                "INSERT INTO client_credential_state (singleton, state_json)
                 VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET state_json = excluded.state_json",
                (payload,),
            )
            .await?;
        Ok(())
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        let mut rows = self
            .connection
            .query(
                "SELECT snapshot_json FROM snapshots WHERE snapshot_id = ?1",
                (snapshot_id,),
            )
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let payload = row_blob(&row, 0, "snapshots.snapshot_json")?;
        let snapshot = self.decode_json::<SnapshotManifest>(payload, "snapshot manifest")?;
        Ok(Some(snapshot))
    }

    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        let mut rows = self
            .connection
            .query(
                "SELECT metadata_json FROM media_cache WHERE content_fingerprint = ?1",
                (content_fingerprint,),
            )
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let payload = row_blob(&row, 0, "media_cache.metadata_json")?;
        let metadata = self.decode_json::<CachedMediaMetadata>(payload, "media metadata")?;
        Ok(Some(metadata))
    }

    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()> {
        let payload = serde_json::to_vec_pretty(metadata)?;
        self.connection
            .execute(
                "INSERT INTO media_cache (content_fingerprint, metadata_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(content_fingerprint) DO UPDATE SET metadata_json = excluded.metadata_json",
                (metadata.content_fingerprint.as_str(), payload),
            )
            .await?;
        Ok(())
    }

    async fn delete_media_cache_record(&self, content_fingerprint: &str) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM media_cache WHERE content_fingerprint = ?1",
                (content_fingerprint,),
            )
            .await?;
        Ok(())
    }

    async fn list_snapshot_infos(&self) -> Result<Vec<SnapshotInfo>> {
        let mut rows = self
            .connection
            .query(
                "SELECT snapshot_id, created_at_unix, object_count
                 FROM snapshots
                 ORDER BY created_at_unix DESC, snapshot_id DESC",
                (),
            )
            .await?;

        let mut snapshots = Vec::new();
        while let Some(row) = rows.next().await? {
            snapshots.push(SnapshotInfo {
                id: row_string(&row, 0, "snapshots.snapshot_id")?,
                created_at_unix: row_u64(&row, 1, "snapshots.created_at_unix")?,
                object_count: row_usize(&row, 2, "snapshots.object_count")?,
            });
        }
        Ok(snapshots)
    }

    async fn append_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        self.connection
            .execute(
                "INSERT INTO admin_audit_events (event_id, created_at_unix, event_json)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE
                 SET created_at_unix = excluded.created_at_unix,
                     event_json = excluded.event_json",
                (
                    event.event_id.as_str(),
                    i64::try_from(event.created_at_unix)
                        .context("audit event timestamp overflow")?,
                    payload,
                ),
            )
            .await?;
        Ok(())
    }

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        let mut rows = self
            .connection
            .query(
                "SELECT index_json FROM version_indexes WHERE object_id = ?1",
                (object_id,),
            )
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let payload = row_blob(&row, 0, "version_indexes.index_json")?;
        let index = self.decode_json::<FileVersionIndex>(payload, "version index")?;
        Ok(Some(index))
    }

    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(index)?;
        self.connection
            .execute(
                "INSERT INTO version_indexes (object_id, index_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(object_id) DO UPDATE SET index_json = excluded.index_json",
                (object_id, payload),
            )
            .await?;
        Ok(())
    }

    async fn persist_current_state(&self, current_state: &CurrentState) -> Result<()> {
        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            self.connection
                .execute("DELETE FROM current_objects", ())
                .await?;
            for (key, manifest_hash) in &current_state.objects {
                let object_id = current_state
                    .object_ids
                    .get(key)
                    .with_context(|| format!("missing object id for current key {key}"))?;
                self.connection
                    .execute(
                        "INSERT INTO current_objects (key, manifest_hash, object_id)
                         VALUES (?1, ?2, ?3)",
                        (key.as_str(), manifest_hash.as_str(), object_id.as_str()),
                    )
                    .await?;
            }
            self.connection.execute_batch("COMMIT").await?;
            Ok(())
        }
        .await;

        if result.is_err() {
            self.rollback().await;
        }
        result
    }

    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>> {
        let mut rows = self
            .connection
            .query(
                "SELECT index_json
                 FROM version_indexes
                 ORDER BY object_id",
                (),
            )
            .await?;

        let mut indexes = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "version_indexes.index_json")?;
            indexes.push(self.decode_json::<FileVersionIndex>(payload, "version index")?);
        }
        Ok(indexes)
    }

    async fn persist_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let payload = serde_json::to_vec_pretty(manifest)?;
        self.connection
            .execute(
                "INSERT INTO snapshots (snapshot_id, created_at_unix, object_count, snapshot_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(snapshot_id) DO NOTHING",
                (
                    manifest.id.as_str(),
                    i64::try_from(manifest.created_at_unix)
                        .context("snapshot timestamp overflow")?,
                    i64::try_from(manifest.objects.len())
                        .context("snapshot object count overflow")?,
                    payload,
                ),
            )
            .await?;
        Ok(())
    }

    async fn load_all_snapshots(&self) -> Result<Vec<SnapshotManifest>> {
        let mut rows = self
            .connection
            .query(
                "SELECT snapshot_json
                 FROM snapshots
                 ORDER BY created_at_unix DESC, snapshot_id DESC",
                (),
            )
            .await?;

        let mut snapshots = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "snapshots.snapshot_json")?;
            snapshots.push(self.decode_json::<SnapshotManifest>(payload, "snapshot manifest")?);
        }
        Ok(snapshots)
    }

    async fn load_current_storage_stats(&self) -> Result<Option<StorageStatsSample>> {
        let mut rows = self
            .connection
            .query(
                "SELECT sample_json
                 FROM storage_stats_current
                 WHERE singleton = 1",
                (),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let payload = row_blob(&row, 0, "storage_stats_current.sample_json")?;
        let sample = self.decode_json::<StorageStatsSample>(payload, "current storage stats")?;
        Ok(Some(sample))
    }

    async fn list_storage_stats_history(&self, limit: usize) -> Result<Vec<StorageStatsSample>> {
        let mut rows = self
            .connection
            .query(
                "SELECT sample_json
                 FROM storage_stats_history
                 ORDER BY collected_at_unix DESC, rowid DESC
                 LIMIT ?1",
                (i64::try_from(limit).context("storage stats history limit overflow")?,),
            )
            .await?;
        let mut samples = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "storage_stats_history.sample_json")?;
            samples.push(
                self.decode_json::<StorageStatsSample>(payload, "storage stats history sample")?,
            );
        }
        Ok(samples)
    }

    async fn persist_storage_stats_sample(&self, sample: &StorageStatsSample) -> Result<()> {
        let payload = serde_json::to_vec_pretty(sample)?;
        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            self.connection
                .execute(
                    "INSERT INTO storage_stats_current (singleton, sample_json)
                     VALUES (1, ?1)
                     ON CONFLICT(singleton) DO UPDATE SET sample_json = excluded.sample_json",
                    (payload.clone(),),
                )
                .await?;
            self.connection
                .execute(
                    "INSERT INTO storage_stats_history (collected_at_unix, sample_json)
                     VALUES (?1, ?2)",
                    (
                        i64::try_from(sample.collected_at_unix)
                            .context("storage stats collected timestamp overflow")?,
                        payload,
                    ),
                )
                .await?;
            self.connection.execute_batch("COMMIT").await?;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.rollback().await;
        }
        result
    }

    async fn has_version_index(&self, object_id: &str) -> Result<bool> {
        let mut rows = self
            .connection
            .query(
                "SELECT 1 FROM version_indexes WHERE object_id = ?1",
                (object_id,),
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    async fn delete_version_index_by_object_id(&self, object_id: &str) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM version_indexes WHERE object_id = ?1",
                (object_id,),
            )
            .await?;
        Ok(())
    }

    async fn list_media_cache_fingerprints(&self) -> Result<Vec<String>> {
        let mut rows = self
            .connection
            .query(
                "SELECT content_fingerprint
                 FROM media_cache
                 ORDER BY content_fingerprint",
                (),
            )
            .await?;

        let mut fingerprints = Vec::new();
        while let Some(row) = rows.next().await? {
            fingerprints.push(row_string(&row, 0, "media_cache.content_fingerprint")?);
        }
        Ok(fingerprints)
    }

    async fn has_reconcile_marker(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
    ) -> Result<bool> {
        let mut rows = self
            .connection
            .query(
                "SELECT 1
                 FROM reconcile_markers
                 WHERE source_node_id = ?1 AND key = ?2 AND source_version_id = ?3",
                (source_node_id, key, source_version_id),
            )
            .await?;
        Ok(rows.next().await?.is_some())
    }

    async fn mark_reconciled(&self, marker: &ReconcileMarker) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO reconcile_markers (
                     source_node_id,
                     key,
                     source_version_id,
                     local_version_id,
                     imported_at_unix
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(source_node_id, key, source_version_id) DO UPDATE
                 SET local_version_id = excluded.local_version_id,
                     imported_at_unix = excluded.imported_at_unix",
                (
                    marker.source_node_id.as_str(),
                    marker.key.as_str(),
                    marker.source_version_id.as_str(),
                    marker.local_version_id.as_deref(),
                    i64::try_from(marker.imported_at_unix)
                        .context("reconcile marker timestamp overflow")?,
                ),
            )
            .await?;
        Ok(())
    }
}

async fn init_metadata_db(connection: &turso::Connection) -> Result<()> {
    connection
        .execute_batch(
            "
            CREATE TABLE IF NOT EXISTS current_objects (
                key TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                object_id TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS version_indexes (
                object_id TEXT PRIMARY KEY,
                index_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                created_at_unix INTEGER NOT NULL,
                object_count INTEGER NOT NULL,
                snapshot_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS storage_stats_current (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                sample_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS storage_stats_history (
                collected_at_unix INTEGER NOT NULL,
                sample_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS repair_attempts (
                subject TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL,
                last_failure_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cluster_replicas (
                subject TEXT NOT NULL,
                node_id TEXT NOT NULL,
                PRIMARY KEY(subject, node_id)
            );

            CREATE TABLE IF NOT EXISTS client_credential_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                state_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_audit_events (
                event_id TEXT PRIMARY KEY,
                created_at_unix INTEGER NOT NULL,
                event_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS media_cache (
                content_fingerprint TEXT PRIMARY KEY,
                metadata_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS reconcile_markers (
                source_node_id TEXT NOT NULL,
                key TEXT NOT NULL,
                source_version_id TEXT NOT NULL,
                local_version_id TEXT,
                imported_at_unix INTEGER NOT NULL,
                PRIMARY KEY(source_node_id, key, source_version_id)
            );

            CREATE INDEX IF NOT EXISTS idx_current_objects_object_id
                ON current_objects(object_id);
            CREATE INDEX IF NOT EXISTS idx_snapshots_created
                ON snapshots(created_at_unix DESC, snapshot_id DESC);
            CREATE INDEX IF NOT EXISTS idx_storage_stats_history_collected
                ON storage_stats_history(collected_at_unix DESC);
            CREATE INDEX IF NOT EXISTS idx_admin_audit_created
                ON admin_audit_events(created_at_unix DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS idx_cluster_replicas_subject
                ON cluster_replicas(subject);
            ",
        )
        .await?;
    Ok(())
}

fn row_string(row: &turso::Row, idx: usize, label: &str) -> Result<String> {
    match row.get_value(idx)? {
        turso::Value::Text(value) => Ok(value),
        turso::Value::Blob(value) => {
            String::from_utf8(value).with_context(|| format!("invalid utf-8 in {label}"))
        }
        other => bail!("expected text value for {label}, got {other:?}"),
    }
}

fn row_blob(row: &turso::Row, idx: usize, label: &str) -> Result<Vec<u8>> {
    match row.get_value(idx)? {
        turso::Value::Blob(value) => Ok(value),
        turso::Value::Text(value) => Ok(value.into_bytes()),
        other => bail!("expected blob value for {label}, got {other:?}"),
    }
}

fn row_u64(row: &turso::Row, idx: usize, label: &str) -> Result<u64> {
    match row.get_value(idx)? {
        turso::Value::Integer(value) => {
            u64::try_from(value).with_context(|| format!("negative integer for {label}: {value}"))
        }
        other => bail!("expected integer value for {label}, got {other:?}"),
    }
}

fn row_usize(row: &turso::Row, idx: usize, label: &str) -> Result<usize> {
    let value = row_u64(row, idx, label)?;
    usize::try_from(value).with_context(|| format!("integer overflow for {label}: {value}"))
}
