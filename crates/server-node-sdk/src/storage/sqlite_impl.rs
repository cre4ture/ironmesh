use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;
use common::NodeId;
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    AdminAuditEvent, CachedMediaMetadata, ClientCredentialState, CurrentState, FileVersionIndex,
    MetadataStore, ReconcileMarker, RepairAttemptRecord, SnapshotInfo, SnapshotManifest,
};

pub(super) struct SqliteMetadataStore {
    metadata: Mutex<Connection>,
}

impl SqliteMetadataStore {
    pub(super) fn open(metadata_db_path: &Path) -> Result<Self> {
        let metadata = Connection::open(metadata_db_path)
            .with_context(|| format!("failed to open {}", metadata_db_path.display()))?;
        init_metadata_db(&metadata)
            .with_context(|| format!("failed to initialize {}", metadata_db_path.display()))?;
        Ok(Self {
            metadata: Mutex::new(metadata),
        })
    }

    fn metadata_conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.metadata
            .lock()
            .map_err(|_| anyhow::anyhow!("sqlite metadata mutex poisoned"))
    }

    fn in_metadata_tx<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let db = self.metadata_conn()?;
        db.execute_batch("BEGIN IMMEDIATE")?;
        match f(&db) {
            Ok(value) => {
                db.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(err) => {
                let _ = db.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }
}

#[async_trait]
impl MetadataStore for SqliteMetadataStore {
    async fn load_current_state(&self) -> Result<CurrentState> {
        let db = self.metadata_conn()?;
        load_current_state_from_db(&db)
    }

    async fn load_repair_attempts(
        &self,
    ) -> Result<std::collections::HashMap<String, RepairAttemptRecord>> {
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT subject, attempts, last_failure_unix
             FROM repair_attempts",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                RepairAttemptRecord {
                    attempts: row.get::<_, u32>(1)?,
                    last_failure_unix: row.get::<_, u64>(2)?,
                },
            ))
        })?;

        let mut attempts = std::collections::HashMap::new();
        for row in rows {
            let (subject, record) = row?;
            attempts.insert(subject, record);
        }
        Ok(attempts)
    }

    async fn persist_repair_attempts(
        &self,
        attempts: &std::collections::HashMap<String, RepairAttemptRecord>,
    ) -> Result<()> {
        self.in_metadata_tx(|db| {
            db.execute("DELETE FROM repair_attempts", [])?;
            let mut stmt = db.prepare(
                "INSERT INTO repair_attempts (subject, attempts, last_failure_unix)
                 VALUES (?1, ?2, ?3)",
            )?;
            for (subject, record) in attempts {
                stmt.execute(params![
                    subject,
                    record.attempts,
                    u64_to_i64(record.last_failure_unix)?
                ])?;
            }
            Ok(())
        })
    }

    async fn load_cluster_replicas(
        &self,
    ) -> Result<std::collections::HashMap<String, Vec<NodeId>>> {
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT subject, node_id
             FROM cluster_replicas
             ORDER BY subject, node_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut replicas: std::collections::HashMap<String, Vec<NodeId>> =
            std::collections::HashMap::new();
        for row in rows {
            let (subject, node_id) = row?;
            let node_id = node_id
                .parse::<NodeId>()
                .with_context(|| format!("invalid node id in cluster replicas: {node_id}"))?;
            replicas.entry(subject).or_default().push(node_id);
        }
        Ok(replicas)
    }

    async fn persist_cluster_replicas(
        &self,
        replicas: &std::collections::HashMap<String, Vec<NodeId>>,
    ) -> Result<()> {
        self.in_metadata_tx(|db| {
            db.execute("DELETE FROM cluster_replicas", [])?;
            let mut stmt = db.prepare(
                "INSERT INTO cluster_replicas (subject, node_id)
                 VALUES (?1, ?2)",
            )?;
            for (subject, nodes) in replicas {
                for node_id in nodes {
                    stmt.execute(params![subject, node_id.to_string()])?;
                }
            }
            Ok(())
        })
    }

    async fn load_client_credential_state(&self) -> Result<ClientCredentialState> {
        let db = self.metadata_conn()?;
        let payload = db
            .query_row(
                "SELECT state_json FROM client_credential_state WHERE singleton = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        match payload {
            Some(payload) => serde_json::from_slice::<ClientCredentialState>(&payload)
                .context("invalid client credential state in sqlite"),
            None => Ok(ClientCredentialState::default()),
        }
    }

    async fn persist_client_credential_state(&self, state: &ClientCredentialState) -> Result<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        let db = self.metadata_conn()?;
        db.execute(
            "INSERT INTO client_credential_state (singleton, state_json)
             VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET state_json = excluded.state_json",
            params![payload],
        )?;
        Ok(())
    }

    async fn load_snapshot_manifest(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
        let db = self.metadata_conn()?;
        let payload = db
            .query_row(
                "SELECT snapshot_json FROM snapshots WHERE snapshot_id = ?1",
                params![snapshot_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        match payload {
            Some(payload) => serde_json::from_slice::<SnapshotManifest>(&payload)
                .map(Some)
                .context("invalid snapshot manifest in sqlite"),
            None => Ok(None),
        }
    }

    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        let db = self.metadata_conn()?;
        let payload = db
            .query_row(
                "SELECT metadata_json FROM media_cache WHERE content_fingerprint = ?1",
                params![content_fingerprint],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        match payload {
            Some(payload) => serde_json::from_slice::<CachedMediaMetadata>(&payload)
                .map(Some)
                .context("invalid media metadata in sqlite"),
            None => Ok(None),
        }
    }

    async fn persist_media_cache_record(&self, metadata: &CachedMediaMetadata) -> Result<()> {
        let payload = serde_json::to_vec_pretty(metadata)?;
        let db = self.metadata_conn()?;
        db.execute(
            "INSERT INTO media_cache (content_fingerprint, metadata_json)
             VALUES (?1, ?2)
             ON CONFLICT(content_fingerprint) DO UPDATE SET metadata_json = excluded.metadata_json",
            params![metadata.content_fingerprint, payload],
        )?;
        Ok(())
    }

    async fn delete_media_cache_record(&self, content_fingerprint: &str) -> Result<()> {
        let db = self.metadata_conn()?;
        db.execute(
            "DELETE FROM media_cache WHERE content_fingerprint = ?1",
            params![content_fingerprint],
        )?;
        Ok(())
    }

    async fn list_snapshot_infos(&self) -> Result<Vec<SnapshotInfo>> {
        let mut snapshots = Vec::new();
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT snapshot_id, created_at_unix, object_count
             FROM snapshots
             ORDER BY created_at_unix DESC, snapshot_id DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SnapshotInfo {
                id: row.get(0)?,
                created_at_unix: row.get::<_, u64>(1)?,
                object_count: row.get::<_, i64>(2)? as usize,
            })
        })?;
        for row in rows {
            snapshots.push(row?);
        }
        Ok(snapshots)
    }

    async fn append_admin_audit_event(&self, event: &AdminAuditEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        let db = self.metadata_conn()?;
        db.execute(
            "INSERT INTO admin_audit_events (event_id, created_at_unix, event_json)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(event_id) DO UPDATE
             SET created_at_unix = excluded.created_at_unix,
                 event_json = excluded.event_json",
            params![event.event_id, u64_to_i64(event.created_at_unix)?, payload],
        )?;
        Ok(())
    }

    async fn load_version_index_by_object_id(
        &self,
        object_id: &str,
    ) -> Result<Option<FileVersionIndex>> {
        let db = self.metadata_conn()?;
        let payload = db
            .query_row(
                "SELECT index_json FROM version_indexes WHERE object_id = ?1",
                params![object_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;

        match payload {
            Some(payload) => serde_json::from_slice::<FileVersionIndex>(&payload)
                .map(Some)
                .context("invalid version index in sqlite"),
            None => Ok(None),
        }
    }

    async fn persist_version_index_by_object_id(
        &self,
        object_id: &str,
        index: &FileVersionIndex,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(index)?;
        let db = self.metadata_conn()?;
        db.execute(
            "INSERT INTO version_indexes (object_id, index_json)
             VALUES (?1, ?2)
             ON CONFLICT(object_id) DO UPDATE SET index_json = excluded.index_json",
            params![object_id, payload],
        )?;
        Ok(())
    }

    async fn persist_current_state(&self, current_state: &CurrentState) -> Result<()> {
        self.in_metadata_tx(|db| {
            db.execute("DELETE FROM current_objects", [])?;
            let mut stmt = db.prepare(
                "INSERT INTO current_objects (key, manifest_hash, object_id)
                 VALUES (?1, ?2, ?3)",
            )?;
            for (key, manifest_hash) in &current_state.objects {
                let object_id = current_state
                    .object_ids
                    .get(key)
                    .with_context(|| format!("missing object id for current key {key}"))?;
                stmt.execute(params![key, manifest_hash, object_id])?;
            }
            Ok(())
        })
    }

    async fn load_all_version_indexes(&self) -> Result<Vec<FileVersionIndex>> {
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT index_json
             FROM version_indexes
             ORDER BY object_id",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut indexes = Vec::new();
        for row in rows {
            let payload = row?;
            indexes.push(
                serde_json::from_slice::<FileVersionIndex>(&payload)
                    .context("invalid version index in sqlite")?,
            );
        }
        Ok(indexes)
    }

    async fn persist_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let payload = serde_json::to_vec_pretty(manifest)?;
        let db = self.metadata_conn()?;
        db.execute(
            "INSERT INTO snapshots (snapshot_id, created_at_unix, object_count, snapshot_json)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(snapshot_id) DO NOTHING",
            params![
                manifest.id,
                u64_to_i64(manifest.created_at_unix)?,
                i64::try_from(manifest.objects.len()).context("snapshot object count overflow")?,
                payload
            ],
        )?;
        Ok(())
    }

    async fn load_all_snapshots(&self) -> Result<Vec<SnapshotManifest>> {
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT snapshot_json
             FROM snapshots
             ORDER BY created_at_unix DESC, snapshot_id DESC",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut snapshots = Vec::new();
        for row in rows {
            let payload = row?;
            snapshots.push(
                serde_json::from_slice::<SnapshotManifest>(&payload)
                    .context("invalid snapshot manifest in sqlite")?,
            );
        }
        Ok(snapshots)
    }

    async fn has_version_index(&self, object_id: &str) -> Result<bool> {
        let db = self.metadata_conn()?;
        Ok(db
            .query_row(
                "SELECT 1 FROM version_indexes WHERE object_id = ?1",
                params![object_id],
                |_row| Ok(()),
            )
            .optional()?
            .is_some())
    }

    async fn delete_version_index_by_object_id(&self, object_id: &str) -> Result<()> {
        let db = self.metadata_conn()?;
        db.execute(
            "DELETE FROM version_indexes WHERE object_id = ?1",
            params![object_id],
        )?;
        Ok(())
    }

    async fn list_media_cache_fingerprints(&self) -> Result<Vec<String>> {
        let db = self.metadata_conn()?;
        let mut stmt = db.prepare(
            "SELECT content_fingerprint
             FROM media_cache
             ORDER BY content_fingerprint",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut fingerprints = Vec::new();
        for row in rows {
            fingerprints.push(row?);
        }
        Ok(fingerprints)
    }

    async fn has_reconcile_marker(
        &self,
        source_node_id: &str,
        key: &str,
        source_version_id: &str,
    ) -> Result<bool> {
        let db = self.metadata_conn()?;
        Ok(db
            .query_row(
                "SELECT 1
                 FROM reconcile_markers
                 WHERE source_node_id = ?1 AND key = ?2 AND source_version_id = ?3",
                params![source_node_id, key, source_version_id],
                |_row| Ok(()),
            )
            .optional()?
            .is_some())
    }

    async fn mark_reconciled(&self, marker: &ReconcileMarker) -> Result<()> {
        let db = self.metadata_conn()?;
        db.execute(
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
            params![
                marker.source_node_id,
                marker.key,
                marker.source_version_id,
                marker.local_version_id,
                u64_to_i64(marker.imported_at_unix)?
            ],
        )?;
        Ok(())
    }
}

fn init_metadata_db(db: &Connection) -> Result<()> {
    db.execute_batch(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA foreign_keys = ON;

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
        CREATE INDEX IF NOT EXISTS idx_admin_audit_created
            ON admin_audit_events(created_at_unix DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_cluster_replicas_subject
            ON cluster_replicas(subject);
        ",
    )?;
    Ok(())
}

fn load_current_state_from_db(db: &Connection) -> Result<CurrentState> {
    let mut stmt = db.prepare(
        "SELECT key, manifest_hash, object_id
         FROM current_objects",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;

    let mut state = CurrentState::default();
    for row in rows {
        let (key, manifest_hash, object_id) = row?;
        state.objects.insert(key.clone(), manifest_hash);
        state.object_ids.insert(key, object_id);
    }
    Ok(state)
}

fn u64_to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).context("integer overflow converting u64 to i64")
}
