use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use common::NodeId;
use tracing::warn;
use turso::params_from_iter;

use super::{
    ActiveSnapshotBatch, AdminAuditEvent, CachedChunkRecord, CachedMediaMetadata,
    ClientCredentialState, CurrentState, DataChangeEvent, DataChangeEventQuery, DataScrubRunRecord,
    FileVersionIndex, ManifestSummary, ManualRepairActionRunRecord, MetadataDbLogicalProgress,
    MetadataDbLogicalProgressCallback, MetadataDbTableLogicalBreakdown, MetadataStore,
    ObjectVersionMetadataRecord, ReconcileMarker, RepairAttemptRecord, RepairRunRecord,
    S3AccessKeyRecord, S3BucketRecord, S3BucketVersioningStatus, S3ControlPlaneState,
    S3ObjectVersionRecord, SnapshotInfo, SnapshotManifest, StorageStatsSample, StorageStatsState,
    compress_snapshot_json, decompress_snapshot_json, metadata_db_logical_summary_query,
    metadata_db_logical_table_specs,
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

    async fn list_repair_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<RepairRunRecord>> {
        let mut rows = match (finished_since_unix, limit) {
            (Some(finished_since_unix), Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM repair_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?2",
                        (
                            i64::try_from(finished_since_unix)
                                .context("repair run history timestamp overflow")?,
                            i64::try_from(limit).context("repair run history limit overflow")?,
                        ),
                    )
                    .await?
            }
            (Some(finished_since_unix), None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM repair_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (i64::try_from(finished_since_unix)
                            .context("repair run history timestamp overflow")?,),
                    )
                    .await?
            }
            (None, Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM repair_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?1",
                        (i64::try_from(limit).context("repair run history limit overflow")?,),
                    )
                    .await?
            }
            (None, None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM repair_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (),
                    )
                    .await?
            }
        };

        let mut records = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "repair_run_history.record_json")?;
            records.push(
                serde_json::from_slice::<RepairRunRecord>(&payload)
                    .context("invalid repair run history record in turso")?,
            );
        }

        Ok(records)
    }

    async fn persist_repair_run_record(&self, record: &RepairRunRecord) -> Result<()> {
        let payload = serde_json::to_vec_pretty(record)?;
        self.connection
            .execute(
                "INSERT INTO repair_run_history (run_id, finished_at_unix, record_json)\n                 VALUES (?1, ?2, ?3)\n                 ON CONFLICT(run_id) DO UPDATE SET\n                     finished_at_unix = excluded.finished_at_unix,\n                     record_json = excluded.record_json",
                (
                    record.run_id.as_str(),
                    i64::try_from(record.finished_at_unix)
                        .context("repair run history timestamp overflow")?,
                    payload,
                ),
            )
            .await?;
        Ok(())
    }

    async fn prune_repair_run_history_before(&self, finished_before_unix: u64) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM repair_run_history\n                 WHERE finished_at_unix < ?1",
                (i64::try_from(finished_before_unix)
                    .context("repair run history prune timestamp overflow")?,),
            )
            .await?;
        Ok(())
    }

    async fn list_manual_repair_action_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<ManualRepairActionRunRecord>> {
        let mut rows = match (finished_since_unix, limit) {
            (Some(finished_since_unix), Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM manual_repair_action_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?2",
                        (
                            i64::try_from(finished_since_unix)
                                .context("manual repair action history timestamp overflow")?,
                            i64::try_from(limit)
                                .context("manual repair action history limit overflow")?,
                        ),
                    )
                    .await?
            }
            (Some(finished_since_unix), None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM manual_repair_action_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (i64::try_from(finished_since_unix)
                            .context("manual repair action history timestamp overflow")?,),
                    )
                    .await?
            }
            (None, Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM manual_repair_action_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?1",
                        (i64::try_from(limit)
                            .context("manual repair action history limit overflow")?,),
                    )
                    .await?
            }
            (None, None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM manual_repair_action_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (),
                    )
                    .await?
            }
        };

        let mut records = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "manual_repair_action_run_history.record_json")?;
            records.push(
                serde_json::from_slice::<ManualRepairActionRunRecord>(&payload)
                    .context("invalid manual repair action history record in turso")?,
            );
        }

        Ok(records)
    }

    async fn persist_manual_repair_action_run_record(
        &self,
        record: &ManualRepairActionRunRecord,
    ) -> Result<()> {
        let payload = serde_json::to_vec_pretty(record)?;
        self.connection
            .execute(
                "INSERT INTO manual_repair_action_run_history (run_id, finished_at_unix, record_json)\n                 VALUES (?1, ?2, ?3)\n                 ON CONFLICT(run_id) DO UPDATE SET\n                     finished_at_unix = excluded.finished_at_unix,\n                     record_json = excluded.record_json",
                (
                    record.run_id.as_str(),
                    i64::try_from(record.finished_at_unix)
                        .context("manual repair action history timestamp overflow")?,
                    payload,
                ),
            )
            .await?;
        Ok(())
    }

    async fn prune_manual_repair_action_run_history_before(
        &self,
        finished_before_unix: u64,
    ) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM manual_repair_action_run_history\n                 WHERE finished_at_unix < ?1",
                (i64::try_from(finished_before_unix)
                    .context("manual repair action history prune timestamp overflow")?,),
            )
            .await?;
        Ok(())
    }

    async fn list_data_scrub_run_history(
        &self,
        limit: Option<usize>,
        finished_since_unix: Option<u64>,
    ) -> Result<Vec<DataScrubRunRecord>> {
        let mut rows = match (finished_since_unix, limit) {
            (Some(finished_since_unix), Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM data_scrub_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?2",
                        (
                            i64::try_from(finished_since_unix)
                                .context("data scrub run history timestamp overflow")?,
                            i64::try_from(limit)
                                .context("data scrub run history limit overflow")?,
                        ),
                    )
                    .await?
            }
            (Some(finished_since_unix), None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM data_scrub_run_history\n                         WHERE finished_at_unix >= ?1\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (i64::try_from(finished_since_unix)
                            .context("data scrub run history timestamp overflow")?,),
                    )
                    .await?
            }
            (None, Some(limit)) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM data_scrub_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC\n                         LIMIT ?1",
                        (i64::try_from(limit)
                            .context("data scrub run history limit overflow")?,),
                    )
                    .await?
            }
            (None, None) => {
                self.connection
                    .query(
                        "SELECT record_json\n                         FROM data_scrub_run_history\n                         ORDER BY finished_at_unix DESC, run_id DESC",
                        (),
                    )
                    .await?
            }
        };

        let mut records = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "data_scrub_run_history.record_json")?;
            records.push(
                serde_json::from_slice::<DataScrubRunRecord>(&payload)
                    .context("invalid data scrub run history record in turso")?,
            );
        }

        Ok(records)
    }

    async fn persist_data_scrub_run_record(&self, record: &DataScrubRunRecord) -> Result<()> {
        let payload = serde_json::to_vec_pretty(record)?;
        self.connection
            .execute(
                "INSERT INTO data_scrub_run_history (run_id, finished_at_unix, record_json)\n                 VALUES (?1, ?2, ?3)\n                 ON CONFLICT(run_id) DO UPDATE SET\n                     finished_at_unix = excluded.finished_at_unix,\n                     record_json = excluded.record_json",
                (
                    record.run_id.as_str(),
                    i64::try_from(record.finished_at_unix)
                        .context("data scrub run history timestamp overflow")?,
                    payload,
                ),
            )
            .await?;
        Ok(())
    }

    async fn prune_data_scrub_run_history_before(&self, finished_before_unix: u64) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM data_scrub_run_history\n                 WHERE finished_at_unix < ?1",
                (i64::try_from(finished_before_unix)
                    .context("data scrub run history prune timestamp overflow")?,),
            )
            .await?;
        Ok(())
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

    async fn load_s3_control_plane_state(&self) -> Result<S3ControlPlaneState> {
        let mut bucket_rows = self
            .connection
            .query(
                "SELECT bucket_name, root_prefix, versioning_status, read_only,
                        created_at_unix, updated_at_unix, created_by, deleted_at_unix
                 FROM s3_buckets
                 ORDER BY bucket_name",
                (),
            )
            .await?;
        let mut buckets = Vec::new();
        while let Some(row) = bucket_rows.next().await? {
            let versioning_status = row_string(&row, 2, "s3_buckets.versioning_status")?;
            buckets.push(S3BucketRecord {
                bucket_name: row_string(&row, 0, "s3_buckets.bucket_name")?,
                root_prefix: row_string(&row, 1, "s3_buckets.root_prefix")?,
                versioning_status: S3BucketVersioningStatus::parse(&versioning_status)
                    .with_context(|| {
                        format!(
                            "invalid s3 bucket versioning status in Turso metadata database {}: {versioning_status}",
                            self.metadata_path.display()
                        )
                    })?,
                read_only: row_bool(&row, 3, "s3_buckets.read_only")?,
                created_at_unix: row_u64(&row, 4, "s3_buckets.created_at_unix")?,
                updated_at_unix: row_u64(&row, 5, "s3_buckets.updated_at_unix")?,
                created_by: row_opt_string(&row, 6, "s3_buckets.created_by")?,
                deleted_at_unix: row_opt_u64(&row, 7, "s3_buckets.deleted_at_unix")?,
            });
        }

        let mut access_key_rows = self
            .connection
            .query(
                "SELECT access_key_id, secret_material, description, bucket_scope_json,
                        prefix_scope_json, allow_list, allow_read, allow_write,
                        allow_delete, created_at_unix, updated_at_unix,
                        last_used_at_unix, revoked_at_unix
                 FROM s3_access_keys
                 ORDER BY access_key_id",
                (),
            )
            .await?;
        let mut access_keys = Vec::new();
        while let Some(row) = access_key_rows.next().await? {
            let bucket_scope_json = row_blob(&row, 3, "s3_access_keys.bucket_scope_json")?;
            let prefix_scope_json = row_blob(&row, 4, "s3_access_keys.prefix_scope_json")?;
            access_keys.push(S3AccessKeyRecord {
                access_key_id: row_string(&row, 0, "s3_access_keys.access_key_id")?,
                secret_material: row_string(&row, 1, "s3_access_keys.secret_material")?,
                description: row_opt_string(&row, 2, "s3_access_keys.description")?,
                bucket_scope: self.decode_json(bucket_scope_json, "s3 access key bucket scope")?,
                prefix_scope: self.decode_json(prefix_scope_json, "s3 access key prefix scope")?,
                allow_list: row_bool(&row, 5, "s3_access_keys.allow_list")?,
                allow_read: row_bool(&row, 6, "s3_access_keys.allow_read")?,
                allow_write: row_bool(&row, 7, "s3_access_keys.allow_write")?,
                allow_delete: row_bool(&row, 8, "s3_access_keys.allow_delete")?,
                created_at_unix: row_u64(&row, 9, "s3_access_keys.created_at_unix")?,
                updated_at_unix: row_u64(&row, 10, "s3_access_keys.updated_at_unix")?,
                last_used_at_unix: row_opt_u64(&row, 11, "s3_access_keys.last_used_at_unix")?,
                revoked_at_unix: row_opt_u64(&row, 12, "s3_access_keys.revoked_at_unix")?,
            });
        }

        Ok(S3ControlPlaneState {
            buckets,
            access_keys,
        })
    }

    async fn persist_s3_control_plane_state(&self, state: &S3ControlPlaneState) -> Result<()> {
        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            self.connection
                .execute("DELETE FROM s3_buckets", ())
                .await?;
            self.connection
                .execute("DELETE FROM s3_access_keys", ())
                .await?;

            for bucket in &state.buckets {
                self.connection
                    .execute(
                        "INSERT INTO s3_buckets (
                             bucket_name,
                             root_prefix,
                             versioning_status,
                             read_only,
                             created_at_unix,
                             updated_at_unix,
                             created_by,
                             deleted_at_unix
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        (
                            bucket.bucket_name.as_str(),
                            bucket.root_prefix.as_str(),
                            bucket.versioning_status.as_str(),
                            if bucket.read_only { 1_i64 } else { 0_i64 },
                            i64::try_from(bucket.created_at_unix)
                                .context("s3 bucket created_at_unix overflow")?,
                            i64::try_from(bucket.updated_at_unix)
                                .context("s3 bucket updated_at_unix overflow")?,
                            bucket.created_by.clone(),
                            bucket
                                .deleted_at_unix
                                .map(i64::try_from)
                                .transpose()
                                .context("s3 bucket deleted_at_unix overflow")?,
                        ),
                    )
                    .await?;
            }

            for access_key in &state.access_keys {
                self.connection
                    .execute(
                        "INSERT INTO s3_access_keys (
                             access_key_id,
                             secret_material,
                             description,
                             bucket_scope_json,
                             prefix_scope_json,
                             allow_list,
                             allow_read,
                             allow_write,
                             allow_delete,
                             created_at_unix,
                             updated_at_unix,
                             last_used_at_unix,
                             revoked_at_unix
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                        (
                            access_key.access_key_id.as_str(),
                            access_key.secret_material.as_str(),
                            access_key.description.clone(),
                            serde_json::to_vec(&access_key.bucket_scope)?,
                            serde_json::to_vec(&access_key.prefix_scope)?,
                            if access_key.allow_list { 1_i64 } else { 0_i64 },
                            if access_key.allow_read { 1_i64 } else { 0_i64 },
                            if access_key.allow_write { 1_i64 } else { 0_i64 },
                            if access_key.allow_delete {
                                1_i64
                            } else {
                                0_i64
                            },
                            i64::try_from(access_key.created_at_unix)
                                .context("s3 access key created_at_unix overflow")?,
                            i64::try_from(access_key.updated_at_unix)
                                .context("s3 access key updated_at_unix overflow")?,
                            access_key
                                .last_used_at_unix
                                .map(i64::try_from)
                                .transpose()
                                .context("s3 access key last_used_at_unix overflow")?,
                            access_key
                                .revoked_at_unix
                                .map(i64::try_from)
                                .transpose()
                                .context("s3 access key revoked_at_unix overflow")?,
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
        let payload = decompress_snapshot_json(&payload)?;
        let snapshot = self.decode_json::<SnapshotManifest>(payload, "snapshot manifest")?;
        Ok(Some(snapshot))
    }

    async fn load_snapshot_batch_state(&self) -> Result<Option<ActiveSnapshotBatch>> {
        let mut rows = self
            .connection
            .query(
                "SELECT state_json
                 FROM snapshot_batch_state
                 WHERE singleton = 1",
                (),
            )
            .await?;

        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let payload = row_blob(&row, 0, "snapshot_batch_state.state_json")?;
        let state = self.decode_json::<ActiveSnapshotBatch>(payload, "snapshot batch state")?;
        Ok(Some(state))
    }

    async fn persist_snapshot_batch_state(
        &self,
        state: Option<&ActiveSnapshotBatch>,
    ) -> Result<()> {
        match state {
            Some(state) => {
                let payload = serde_json::to_vec_pretty(state)?;
                self.connection
                    .execute(
                        "INSERT INTO snapshot_batch_state (singleton, state_json)
                         VALUES (1, ?1)
                         ON CONFLICT(singleton) DO UPDATE SET state_json = excluded.state_json",
                        (payload,),
                    )
                    .await?;
            }
            None => {
                self.connection
                    .execute("DELETE FROM snapshot_batch_state WHERE singleton = 1", ())
                    .await?;
            }
        }
        Ok(())
    }

    async fn load_cached_media_metadata(
        &self,
        content_fingerprint: &str,
    ) -> Result<Option<CachedMediaMetadata>> {
        let payload = {
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

            row_blob(&row, 0, "media_cache.metadata_json")?
        };
        match self.decode_json::<CachedMediaMetadata>(payload, "media metadata") {
            Ok(metadata) => Ok(Some(metadata)),
            Err(err) => {
                self.connection
                    .execute(
                        "DELETE FROM media_cache WHERE content_fingerprint = ?1",
                        (content_fingerprint,),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to delete invalid media metadata row for {content_fingerprint}"
                        )
                    })?;
                warn!(
                    content_fingerprint = %content_fingerprint,
                    error = %err,
                    "deleted invalid cached media metadata row from Turso"
                );
                Ok(None)
            }
        }
    }

    async fn load_cached_media_metadata_many(
        &self,
        content_fingerprints: &[String],
    ) -> Result<HashMap<String, CachedMediaMetadata>> {
        const TURSO_MEDIA_CACHE_QUERY_BATCH_SIZE: usize = 500;

        let mut metadata_by_content_fingerprint =
            HashMap::with_capacity(content_fingerprints.len());

        for chunk in content_fingerprints.chunks(TURSO_MEDIA_CACHE_QUERY_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }

            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut rows = self
                .connection
                .query(
                    format!(
                        "SELECT content_fingerprint, metadata_json
                         FROM media_cache
                         WHERE content_fingerprint IN ({placeholders})"
                    ),
                    params_from_iter(chunk.iter().cloned()),
                )
                .await?;

            let mut invalid_rows = Vec::new();
            while let Some(row) = rows.next().await? {
                let content_fingerprint = row_string(&row, 0, "media_cache.content_fingerprint")?;
                let payload = row_blob(&row, 1, "media_cache.metadata_json")?;
                match self.decode_json::<CachedMediaMetadata>(payload, "media metadata") {
                    Ok(metadata) => {
                        metadata_by_content_fingerprint.insert(content_fingerprint, metadata);
                    }
                    Err(err) => invalid_rows.push((content_fingerprint, err.to_string())),
                }
            }

            for (content_fingerprint, error) in invalid_rows {
                self.connection
                    .execute(
                        "DELETE FROM media_cache WHERE content_fingerprint = ?1",
                        (content_fingerprint.as_str(),),
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "failed to delete invalid media metadata row for {content_fingerprint}"
                        )
                    })?;
                warn!(
                    content_fingerprint = %content_fingerprint,
                    error,
                    "deleted invalid cached media metadata row from Turso"
                );
            }
        }

        Ok(metadata_by_content_fingerprint)
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

    #[cfg(test)]
    async fn has_media_cache_record(&self, content_fingerprint: &str) -> Result<bool> {
        let mut rows = self
            .connection
            .query(
                "SELECT COUNT(*) FROM media_cache WHERE content_fingerprint = ?1",
                (content_fingerprint,),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(false);
        };
        match row.get_value(0)? {
            turso::Value::Integer(value) => Ok(value != 0),
            other => bail!("unexpected count type: {other:?}"),
        }
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

    async fn list_data_change_events(
        &self,
        query: &DataChangeEventQuery,
    ) -> Result<Vec<DataChangeEvent>> {
        let limit = match query.limit {
            Some(limit) => i64::try_from(limit).context("data change event limit overflow")?,
            None => i64::MAX,
        };
        let action_filter = query.action.map(|action| action.as_str().to_string());
        let path_filter = query
            .path_prefix
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("{value}%"));
        let actor_filter = query
            .actor_query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("%{value}%"));
        let before_created_at_unix = query
            .before
            .as_ref()
            .map(|cursor| i64::try_from(cursor.created_at_unix))
            .transpose()
            .context("data change event cursor timestamp overflow")?;
        let before_event_id = query.before.as_ref().map(|cursor| cursor.event_id.as_str());

        let mut rows = self
                    .connection
                    .query(
                        "SELECT event_json
                         FROM data_change_events
                         WHERE (?1 IS NULL OR action = ?1)
                           AND (?2 IS NULL OR path LIKE ?2 OR COALESCE(from_path, '') LIKE ?2 OR COALESCE(to_path, '') LIKE ?2)
                           AND (?3 IS NULL OR COALESCE(actor_id, '') LIKE ?3 OR COALESCE(actor_label, '') LIKE ?3 OR COALESCE(actor_credential_fingerprint, '') LIKE ?3)
                                                     AND (?4 IS NULL OR created_at_unix < ?4 OR (created_at_unix = ?4 AND event_id < ?5))
                                                 ORDER BY created_at_unix DESC, event_id DESC
                                                 LIMIT ?6",
                                                (action_filter, path_filter, actor_filter, before_created_at_unix, before_event_id, limit),
                    )
                    .await?;

        let mut events = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "data_change_events.event_json")?;
            events.push(
                serde_json::from_slice::<DataChangeEvent>(&payload)
                    .context("invalid data change event in turso")?,
            );
        }

        Ok(events)
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

    async fn append_data_change_event(&self, event: &DataChangeEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        self.connection
            .execute(
                "INSERT INTO data_change_events (
                     event_id,
                     created_at_unix,
                     action,
                     path,
                     from_path,
                     to_path,
                     actor_kind,
                     actor_id,
                     actor_label,
                     actor_credential_fingerprint,
                     event_json
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                 ON CONFLICT(event_id) DO UPDATE SET
                     created_at_unix = excluded.created_at_unix,
                     action = excluded.action,
                     path = excluded.path,
                     from_path = excluded.from_path,
                     to_path = excluded.to_path,
                     actor_kind = excluded.actor_kind,
                     actor_id = excluded.actor_id,
                     actor_label = excluded.actor_label,
                     actor_credential_fingerprint = excluded.actor_credential_fingerprint,
                     event_json = excluded.event_json",
                (
                    event.event_id.as_str(),
                    i64::try_from(event.created_at_unix)
                        .context("data change event timestamp overflow")?,
                    event.action.as_str(),
                    event.path.as_str(),
                    event.from_path.as_deref(),
                    event.to_path.as_deref(),
                    event.actor_kind.as_str(),
                    event.actor_id.as_deref(),
                    event.actor_label.as_deref(),
                    event.actor_credential_fingerprint.as_deref(),
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

    async fn load_manifest_summaries(
        &self,
        manifest_hashes: &[String],
    ) -> Result<HashMap<String, ManifestSummary>> {
        const TURSO_SUMMARY_QUERY_BATCH_SIZE: usize = 500;

        let mut summaries = HashMap::with_capacity(manifest_hashes.len());
        for chunk in manifest_hashes.chunks(TURSO_SUMMARY_QUERY_BATCH_SIZE) {
            if chunk.is_empty() {
                continue;
            }

            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut rows = self
                .connection
                .query(
                    format!(
                        "SELECT manifest_hash, total_size_bytes, content_fingerprint
                         FROM manifest_summaries
                         WHERE manifest_hash IN ({placeholders})"
                    ),
                    params_from_iter(chunk.iter().cloned()),
                )
                .await?;

            while let Some(row) = rows.next().await? {
                let manifest_hash = row_string(&row, 0, "manifest_summaries.manifest_hash")?;
                let total_size_bytes = row_u64(&row, 1, "manifest_summaries.total_size_bytes")?;
                let content_fingerprint =
                    row_string(&row, 2, "manifest_summaries.content_fingerprint")?;
                summaries.insert(
                    manifest_hash,
                    ManifestSummary {
                        total_size_bytes,
                        content_fingerprint,
                    },
                );
            }
        }

        Ok(summaries)
    }

    async fn load_object_version_metadata(
        &self,
        version_id: &str,
    ) -> Result<Option<ObjectVersionMetadataRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT content_type, content_encoding, content_language,
                        cache_control, content_disposition, user_metadata_json,
                        checksum_sha256, checksum_crc32c, updated_at_unix
                 FROM object_version_metadata
                 WHERE version_id = ?1",
                (version_id,),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        let user_metadata_json = row_blob(&row, 5, "object_version_metadata.user_metadata_json")?;
        Ok(Some(ObjectVersionMetadataRecord {
            version_id: version_id.to_string(),
            content_type: row_opt_string(&row, 0, "object_version_metadata.content_type")?,
            content_encoding: row_opt_string(&row, 1, "object_version_metadata.content_encoding")?,
            content_language: row_opt_string(&row, 2, "object_version_metadata.content_language")?,
            cache_control: row_opt_string(&row, 3, "object_version_metadata.cache_control")?,
            content_disposition: row_opt_string(
                &row,
                4,
                "object_version_metadata.content_disposition",
            )?,
            user_metadata: self.decode_json(user_metadata_json, "object version user metadata")?,
            checksum_sha256: row_opt_string(&row, 6, "object_version_metadata.checksum_sha256")?,
            checksum_crc32c: row_opt_string(&row, 7, "object_version_metadata.checksum_crc32c")?,
            updated_at_unix: row_u64(&row, 8, "object_version_metadata.updated_at_unix")?,
        }))
    }

    async fn persist_object_version_metadata(
        &self,
        metadata: &ObjectVersionMetadataRecord,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO object_version_metadata (
                     version_id,
                     content_type,
                     content_encoding,
                     content_language,
                     cache_control,
                     content_disposition,
                     user_metadata_json,
                     checksum_sha256,
                     checksum_crc32c,
                     updated_at_unix
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(version_id) DO UPDATE
                 SET content_type = excluded.content_type,
                     content_encoding = excluded.content_encoding,
                     content_language = excluded.content_language,
                     cache_control = excluded.cache_control,
                     content_disposition = excluded.content_disposition,
                     user_metadata_json = excluded.user_metadata_json,
                     checksum_sha256 = excluded.checksum_sha256,
                     checksum_crc32c = excluded.checksum_crc32c,
                     updated_at_unix = excluded.updated_at_unix",
                (
                    metadata.version_id.as_str(),
                    metadata.content_type.clone(),
                    metadata.content_encoding.clone(),
                    metadata.content_language.clone(),
                    metadata.cache_control.clone(),
                    metadata.content_disposition.clone(),
                    serde_json::to_vec(&metadata.user_metadata)?,
                    metadata.checksum_sha256.clone(),
                    metadata.checksum_crc32c.clone(),
                    i64::try_from(metadata.updated_at_unix)
                        .context("object version updated_at_unix overflow")?,
                ),
            )
            .await?;
        Ok(())
    }

    async fn delete_object_version_metadata(&self, version_id: &str) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM object_version_metadata WHERE version_id = ?1",
                (version_id,),
            )
            .await?;
        Ok(())
    }

    async fn load_s3_object_version(
        &self,
        bucket_name: &str,
        version_id: &str,
    ) -> Result<Option<S3ObjectVersionRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT ironmesh_key, etag, multipart_part_count, created_at_unix
                 FROM s3_object_versions
                 WHERE bucket_name = ?1 AND version_id = ?2",
                (bucket_name, version_id),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };

        Ok(Some(S3ObjectVersionRecord {
            bucket_name: bucket_name.to_string(),
            ironmesh_key: row_string(&row, 0, "s3_object_versions.ironmesh_key")?,
            version_id: version_id.to_string(),
            etag: row_string(&row, 1, "s3_object_versions.etag")?,
            multipart_part_count: row_opt_u32(&row, 2, "s3_object_versions.multipart_part_count")?,
            created_at_unix: row_u64(&row, 3, "s3_object_versions.created_at_unix")?,
        }))
    }

    async fn list_s3_object_versions_for_key(
        &self,
        bucket_name: &str,
        ironmesh_key: &str,
    ) -> Result<Vec<S3ObjectVersionRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT version_id, etag, multipart_part_count, created_at_unix
                 FROM s3_object_versions
                 WHERE bucket_name = ?1 AND ironmesh_key = ?2
                 ORDER BY created_at_unix DESC, version_id DESC",
                (bucket_name, ironmesh_key),
            )
            .await?;
        let mut records = Vec::new();
        while let Some(row) = rows.next().await? {
            records.push(S3ObjectVersionRecord {
                bucket_name: bucket_name.to_string(),
                ironmesh_key: ironmesh_key.to_string(),
                version_id: row_string(&row, 0, "s3_object_versions.version_id")?,
                etag: row_string(&row, 1, "s3_object_versions.etag")?,
                multipart_part_count: row_opt_u32(
                    &row,
                    2,
                    "s3_object_versions.multipart_part_count",
                )?,
                created_at_unix: row_u64(&row, 3, "s3_object_versions.created_at_unix")?,
            });
        }
        Ok(records)
    }

    async fn persist_s3_object_version(&self, record: &S3ObjectVersionRecord) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO s3_object_versions (
                     bucket_name,
                     ironmesh_key,
                     version_id,
                     etag,
                     multipart_part_count,
                     created_at_unix
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(bucket_name, version_id) DO UPDATE
                 SET ironmesh_key = excluded.ironmesh_key,
                     etag = excluded.etag,
                     multipart_part_count = excluded.multipart_part_count,
                     created_at_unix = excluded.created_at_unix",
                (
                    record.bucket_name.as_str(),
                    record.ironmesh_key.as_str(),
                    record.version_id.as_str(),
                    record.etag.as_str(),
                    record.multipart_part_count.map(i64::from),
                    i64::try_from(record.created_at_unix)
                        .context("s3 object version created_at_unix overflow")?,
                ),
            )
            .await?;
        Ok(())
    }

    async fn delete_s3_object_version(&self, bucket_name: &str, version_id: &str) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM s3_object_versions
                 WHERE bucket_name = ?1 AND version_id = ?2",
                (bucket_name, version_id),
            )
            .await?;
        Ok(())
    }

    async fn persist_manifest_summary(
        &self,
        manifest_hash: &str,
        summary: &ManifestSummary,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO manifest_summaries (manifest_hash, total_size_bytes, content_fingerprint)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(manifest_hash) DO UPDATE
                 SET total_size_bytes = excluded.total_size_bytes,
                     content_fingerprint = excluded.content_fingerprint",
                (
                    manifest_hash,
                    i64::try_from(summary.total_size_bytes)
                        .context("manifest summary size overflow")?,
                    summary.content_fingerprint.as_str(),
                ),
            )
            .await?;
        Ok(())
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

    async fn list_version_index_object_ids(&self) -> Result<Vec<String>> {
        let mut rows = self
            .connection
            .query(
                "SELECT object_id FROM version_indexes ORDER BY object_id",
                (),
            )
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            ids.push(row_string(&row, 0, "version_indexes.object_id")?);
        }
        Ok(ids)
    }

    async fn persist_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        let payload = compress_snapshot_json(&serde_json::to_vec_pretty(manifest)?)?;
        self.connection
            .execute(
                "INSERT INTO snapshots (snapshot_id, created_at_unix, object_count, snapshot_json)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(snapshot_id) DO UPDATE SET
                     created_at_unix = excluded.created_at_unix,
                     object_count = excluded.object_count,
                     snapshot_json = excluded.snapshot_json",
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
            let payload = decompress_snapshot_json(&payload)?;
            snapshots.push(self.decode_json::<SnapshotManifest>(payload, "snapshot manifest")?);
        }
        Ok(snapshots)
    }

    async fn load_snapshot_by_id(&self, snapshot_id: &str) -> Result<Option<SnapshotManifest>> {
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
        let payload = decompress_snapshot_json(&payload)?;
        let manifest = self.decode_json::<SnapshotManifest>(payload, "snapshot manifest")?;
        Ok(Some(manifest))
    }

    async fn list_uncompressed_snapshot_ids(&self) -> Result<Vec<String>> {
        const ZSTD_MAGIC: &[u8] = &[0x28, 0xB5, 0x2F, 0xFD];
        let mut rows = self
            .connection
            .query("SELECT snapshot_id, snapshot_json FROM snapshots", ())
            .await?;
        let mut ids = Vec::new();
        while let Some(row) = rows.next().await? {
            let id = row_string(&row, 0, "snapshots.snapshot_id")?;
            let payload = row_blob(&row, 1, "snapshots.snapshot_json")?;
            if !payload.starts_with(ZSTD_MAGIC) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    async fn delete_snapshots_by_id(&self, snapshot_ids: &[String]) -> Result<()> {
        const TURSO_SNAPSHOT_DELETE_BATCH_SIZE: usize = 500;

        if snapshot_ids.is_empty() {
            return Ok(());
        }

        self.connection.execute_batch("BEGIN IMMEDIATE").await?;
        let result: Result<()> = async {
            for chunk in snapshot_ids.chunks(TURSO_SNAPSHOT_DELETE_BATCH_SIZE) {
                let placeholders = std::iter::repeat_n("?", chunk.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                self.connection
                    .execute(
                        format!("DELETE FROM snapshots WHERE snapshot_id IN ({placeholders})"),
                        params_from_iter(chunk.iter().cloned()),
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

    async fn vacuum_metadata_store(&self) -> Result<bool> {
        match self.connection.execute("VACUUM", ()).await {
            Ok(_) => Ok(true),
            Err(err) => {
                let message = err.to_string();
                if message.contains("VACUUM is an experimental feature")
                    || message.contains("--experimental-vacuum")
                {
                    warn!(
                        metadata_db = %self.metadata_path.display(),
                        "skipping metadata VACUUM because this Turso build does not support it"
                    );
                    Ok(false)
                } else {
                    Err(err.into())
                }
            }
        }
    }

    async fn load_storage_stats_state(&self) -> Result<Option<StorageStatsState>> {
        let mut rows = self
            .connection
            .query(
                "SELECT state_json
                 FROM storage_stats_state
                 WHERE singleton = 1",
                (),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let payload = row_blob(&row, 0, "storage_stats_state.state_json")?;
        let state = self.decode_json::<StorageStatsState>(payload, "storage stats state")?;
        Ok(Some(state))
    }

    async fn persist_storage_stats_state(&self, state: &StorageStatsState) -> Result<()> {
        let payload = serde_json::to_vec_pretty(state)?;
        self.connection
            .execute(
                "INSERT INTO storage_stats_state (singleton, state_json)
                 VALUES (1, ?1)
                 ON CONFLICT(singleton) DO UPDATE SET state_json = excluded.state_json",
                (payload,),
            )
            .await?;
        Ok(())
    }

    async fn load_cached_chunk_record(&self, hash: &str) -> Result<Option<CachedChunkRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT record_json
                 FROM cached_chunks
                 WHERE hash = ?1",
                (hash,),
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let payload = row_blob(&row, 0, "cached_chunks.record_json")?;
        let record = self.decode_json::<CachedChunkRecord>(payload, "cached chunk record")?;
        Ok(Some(record))
    }

    async fn persist_cached_chunk_record(&self, record: &CachedChunkRecord) -> Result<()> {
        let payload = serde_json::to_vec_pretty(record)?;
        self.connection
            .execute(
                "INSERT INTO cached_chunks (hash, record_json)
                 VALUES (?1, ?2)
                 ON CONFLICT(hash) DO UPDATE SET record_json = excluded.record_json",
                (record.hash.as_str(), payload),
            )
            .await?;
        Ok(())
    }

    async fn delete_cached_chunk_record(&self, hash: &str) -> Result<()> {
        self.connection
            .execute("DELETE FROM cached_chunks WHERE hash = ?1", (hash,))
            .await?;
        Ok(())
    }

    async fn list_cached_chunk_records(&self) -> Result<Vec<CachedChunkRecord>> {
        let mut rows = self
            .connection
            .query(
                "SELECT record_json
                 FROM cached_chunks
                 ORDER BY hash ASC",
                (),
            )
            .await?;
        let mut records = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "cached_chunks.record_json")?;
            records.push(self.decode_json::<CachedChunkRecord>(payload, "cached chunk record")?);
        }
        Ok(records)
    }

    async fn mark_manifest_locally_owned(
        &self,
        manifest_hash: &str,
        owned_at_unix: u64,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO locally_owned_manifests (manifest_hash, owned_at_unix)
                 VALUES (?1, ?2)
                 ON CONFLICT(manifest_hash) DO UPDATE SET owned_at_unix = excluded.owned_at_unix",
                (
                    manifest_hash,
                    i64::try_from(owned_at_unix).context("owned manifest timestamp overflow")?,
                ),
            )
            .await?;
        Ok(())
    }

    async fn delete_locally_owned_manifest(&self, manifest_hash: &str) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM locally_owned_manifests WHERE manifest_hash = ?1",
                (manifest_hash,),
            )
            .await?;
        Ok(())
    }

    async fn list_locally_owned_manifests(&self) -> Result<Vec<String>> {
        let mut rows = self
            .connection
            .query(
                "SELECT manifest_hash
                 FROM locally_owned_manifests
                 ORDER BY manifest_hash ASC",
                (),
            )
            .await?;
        let mut manifests = Vec::new();
        while let Some(row) = rows.next().await? {
            manifests.push(row_string(
                &row,
                0,
                "locally_owned_manifests.manifest_hash",
            )?);
        }
        Ok(manifests)
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

    async fn list_storage_stats_history(
        &self,
        limit: Option<usize>,
        collected_since_unix: Option<u64>,
    ) -> Result<Vec<StorageStatsSample>> {
        let mut rows = match (collected_since_unix, limit) {
            (Some(collected_since_unix), Some(limit)) => {
                self.connection
                    .query(
                        "SELECT sample_json
                         FROM storage_stats_history
                         WHERE collected_at_unix >= ?1
                         ORDER BY collected_at_unix DESC, rowid DESC
                         LIMIT ?2",
                        (
                            i64::try_from(collected_since_unix)
                                .context("storage stats since timestamp overflow")?,
                            i64::try_from(limit).context("storage stats history limit overflow")?,
                        ),
                    )
                    .await?
            }
            (Some(collected_since_unix), None) => {
                self.connection
                    .query(
                        "SELECT sample_json
                         FROM storage_stats_history
                         WHERE collected_at_unix >= ?1
                         ORDER BY collected_at_unix DESC, rowid DESC",
                        (i64::try_from(collected_since_unix)
                            .context("storage stats since timestamp overflow")?,),
                    )
                    .await?
            }
            (None, Some(limit)) => {
                self.connection
                    .query(
                        "SELECT sample_json
                         FROM storage_stats_history
                         ORDER BY collected_at_unix DESC, rowid DESC
                         LIMIT ?1",
                        (i64::try_from(limit).context("storage stats history limit overflow")?,),
                    )
                    .await?
            }
            (None, None) => {
                self.connection
                    .query(
                        "SELECT sample_json
                         FROM storage_stats_history
                         ORDER BY collected_at_unix DESC, rowid DESC",
                        (),
                    )
                    .await?
            }
        };
        let mut samples = Vec::new();
        while let Some(row) = rows.next().await? {
            let payload = row_blob(&row, 0, "storage_stats_history.sample_json")?;
            samples.push(
                self.decode_json::<StorageStatsSample>(payload, "storage stats history sample")?,
            );
        }
        Ok(samples)
    }

    async fn load_metadata_db_logical_breakdown(
        &self,
        progress: Option<MetadataDbLogicalProgressCallback>,
    ) -> Result<Vec<MetadataDbTableLogicalBreakdown>> {
        let specs = metadata_db_logical_table_specs();
        let mut tables = Vec::with_capacity(specs.len());
        for (index, spec) in specs.iter().enumerate() {
            if let Some(progress) = progress.as_ref() {
                progress(MetadataDbLogicalProgress {
                    total_tables: specs.len(),
                    completed_tables: index,
                    current_table: Some(spec.table.to_string()),
                });
            }
            let mut rows = self
                .connection
                .query(&metadata_db_logical_summary_query(*spec), ())
                .await
                .with_context(|| {
                    format!(
                        "failed to load metadata db logical distribution for {} from {}",
                        spec.table,
                        self.metadata_path.display()
                    )
                })?;
            let Some(row) = rows.next().await? else {
                bail!(
                    "missing metadata db logical distribution row for {}",
                    spec.table
                );
            };
            let row_count = row_u64(&row, 0, "metadata_db_distribution.row_count")?;
            let tracked_value_bytes =
                row_u64(&row, 1, "metadata_db_distribution.tracked_value_bytes")?;
            tables.push(MetadataDbTableLogicalBreakdown {
                table: spec.table.to_string(),
                row_count,
                tracked_value_bytes,
                average_tracked_value_bytes: tracked_value_bytes.checked_div(row_count),
                tracked_columns: spec
                    .tracked_columns
                    .iter()
                    .map(|column| (*column).to_string())
                    .collect(),
            });
        }

        if let Some(progress) = progress.as_ref() {
            progress(MetadataDbLogicalProgress {
                total_tables: specs.len(),
                completed_tables: specs.len(),
                current_table: None,
            });
        }

        Ok(tables)
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

    async fn prune_storage_stats_history_before(&self, collected_before_unix: u64) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM storage_stats_history
                 WHERE collected_at_unix < ?1",
                (i64::try_from(collected_before_unix)
                    .context("storage stats prune timestamp overflow")?,),
            )
            .await?;
        Ok(())
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
            CREATE TABLE IF NOT EXISTS metadata_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

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

            CREATE TABLE IF NOT EXISTS snapshot_batch_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                state_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS storage_stats_current (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                sample_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS storage_stats_state (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                state_json BLOB NOT NULL
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

            CREATE TABLE IF NOT EXISTS repair_run_history (
                run_id TEXT PRIMARY KEY,
                finished_at_unix INTEGER NOT NULL,
                record_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS manual_repair_action_run_history (
                run_id TEXT PRIMARY KEY,
                finished_at_unix INTEGER NOT NULL,
                record_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_scrub_run_history (
                run_id TEXT PRIMARY KEY,
                finished_at_unix INTEGER NOT NULL,
                record_json BLOB NOT NULL
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

            CREATE TABLE IF NOT EXISTS s3_buckets (
                bucket_name TEXT PRIMARY KEY,
                root_prefix TEXT NOT NULL,
                versioning_status TEXT NOT NULL,
                read_only INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL,
                created_by TEXT,
                deleted_at_unix INTEGER
            );

            CREATE TABLE IF NOT EXISTS s3_access_keys (
                access_key_id TEXT PRIMARY KEY,
                secret_material TEXT NOT NULL,
                description TEXT,
                bucket_scope_json BLOB NOT NULL,
                prefix_scope_json BLOB NOT NULL,
                allow_list INTEGER NOT NULL,
                allow_read INTEGER NOT NULL,
                allow_write INTEGER NOT NULL,
                allow_delete INTEGER NOT NULL,
                created_at_unix INTEGER NOT NULL,
                updated_at_unix INTEGER NOT NULL,
                last_used_at_unix INTEGER,
                revoked_at_unix INTEGER
            );

            CREATE TABLE IF NOT EXISTS object_version_metadata (
                version_id TEXT PRIMARY KEY,
                content_type TEXT,
                content_encoding TEXT,
                content_language TEXT,
                cache_control TEXT,
                content_disposition TEXT,
                user_metadata_json BLOB NOT NULL,
                checksum_sha256 TEXT,
                checksum_crc32c TEXT,
                updated_at_unix INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS s3_object_versions (
                bucket_name TEXT NOT NULL,
                ironmesh_key TEXT NOT NULL,
                version_id TEXT NOT NULL,
                etag TEXT NOT NULL,
                multipart_part_count INTEGER,
                created_at_unix INTEGER NOT NULL,
                PRIMARY KEY(bucket_name, version_id)
            );

            CREATE TABLE IF NOT EXISTS admin_audit_events (
                event_id TEXT PRIMARY KEY,
                created_at_unix INTEGER NOT NULL,
                event_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS data_change_events (
                event_id TEXT PRIMARY KEY,
                created_at_unix INTEGER NOT NULL,
                action TEXT NOT NULL,
                path TEXT NOT NULL,
                from_path TEXT,
                to_path TEXT,
                actor_kind TEXT NOT NULL,
                actor_id TEXT,
                actor_label TEXT,
                actor_credential_fingerprint TEXT,
                event_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS media_cache (
                content_fingerprint TEXT PRIMARY KEY,
                metadata_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cached_chunks (
                hash TEXT PRIMARY KEY,
                record_json BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS manifest_summaries (
                manifest_hash TEXT PRIMARY KEY,
                total_size_bytes INTEGER NOT NULL,
                content_fingerprint TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS locally_owned_manifests (
                manifest_hash TEXT PRIMARY KEY,
                owned_at_unix INTEGER NOT NULL
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
            CREATE INDEX IF NOT EXISTS idx_repair_run_history_finished
                ON repair_run_history(finished_at_unix DESC, run_id DESC);
            CREATE INDEX IF NOT EXISTS idx_manual_repair_action_run_history_finished
                ON manual_repair_action_run_history(finished_at_unix DESC, run_id DESC);
            CREATE INDEX IF NOT EXISTS idx_data_scrub_run_history_finished
                ON data_scrub_run_history(finished_at_unix DESC, run_id DESC);
            CREATE INDEX IF NOT EXISTS idx_admin_audit_created
                ON admin_audit_events(created_at_unix DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS idx_data_change_events_created
                ON data_change_events(created_at_unix DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS idx_data_change_events_action
                ON data_change_events(action, created_at_unix DESC, event_id DESC);
            CREATE INDEX IF NOT EXISTS idx_data_change_events_path
                ON data_change_events(path);
            CREATE INDEX IF NOT EXISTS idx_data_change_events_actor_id
                ON data_change_events(actor_id);
            CREATE INDEX IF NOT EXISTS idx_cluster_replicas_subject
                ON cluster_replicas(subject);
            CREATE INDEX IF NOT EXISTS idx_s3_object_versions_key
                ON s3_object_versions(bucket_name, ironmesh_key, created_at_unix DESC, version_id DESC);
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

fn row_bool(row: &turso::Row, idx: usize, label: &str) -> Result<bool> {
    match row.get_value(idx)? {
        turso::Value::Integer(value) => Ok(value != 0),
        other => bail!("expected integer value for {label}, got {other:?}"),
    }
}

fn row_opt_string(row: &turso::Row, idx: usize, label: &str) -> Result<Option<String>> {
    match row.get_value(idx)? {
        turso::Value::Null => Ok(None),
        turso::Value::Text(value) => Ok(Some(value)),
        turso::Value::Blob(value) => Ok(Some(
            String::from_utf8(value).with_context(|| format!("invalid utf-8 in {label}"))?,
        )),
        other => bail!("expected optional text value for {label}, got {other:?}"),
    }
}

fn row_opt_u64(row: &turso::Row, idx: usize, label: &str) -> Result<Option<u64>> {
    match row.get_value(idx)? {
        turso::Value::Null => Ok(None),
        turso::Value::Integer(value) => {
            Ok(Some(u64::try_from(value).with_context(|| {
                format!("negative integer for {label}: {value}")
            })?))
        }
        other => bail!("expected optional integer value for {label}, got {other:?}"),
    }
}

fn row_opt_u32(row: &turso::Row, idx: usize, label: &str) -> Result<Option<u32>> {
    row_opt_u64(row, idx, label)?
        .map(|value| {
            u32::try_from(value).with_context(|| format!("integer overflow for {label}: {value}"))
        })
        .transpose()
}
