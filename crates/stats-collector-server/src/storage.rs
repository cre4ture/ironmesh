//! Append-only raw storage for ingested hardware-reliability payloads.
//!
//! Per `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 5.3, raw ingested
//! batches are stored separately from the public aggregate view: the public
//! `GET /v1/stats/summary` is computed via [`crate::aggregate`], while direct access to this raw
//! table is admin-token-guarded (the GDPR access/erasure endpoints in `lib.rs`).

use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// A single stored ingestion row, as inserted by [`IngestStorage::insert`].
///
/// `country_code` is whatever the configured [`crate::country::CountryResolver`] derived from the
/// request source IP at ingest time (doc Section 4.2). It is `None` with the default no-op
/// resolver; the raw source IP itself is never stored (see the struct docs below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub id: i64,
    pub received_at_unix: i64,
    pub telemetry_subject_id: String,
    pub schema_version: u32,
    pub country_code: Option<String>,
    pub raw_payload_json: String,
}

/// SQLite-backed append-only store for the `hardware_reliability_ingest` table.
///
/// Deliberately does *not* have a column for the request's source IP address: the project's
/// general "no IP addresses" data-minimization stance (Section 2.6) applies here too. The source
/// IP is only ever used transiently, in memory, for per-IP rate limiting (see `rate_limit.rs`) and
/// is never written to this table, logged, or otherwise persisted.
pub struct IngestStorage {
    connection: Mutex<Connection>,
}

impl IngestStorage {
    /// Opens (creating if necessary) the SQLite database at `path` and ensures the ingestion
    /// table exists.
    pub fn open(path: &str) -> Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open sqlite db at {path}"))?;
        Self::from_connection(connection)
    }

    /// Opens an in-memory database, primarily for tests.
    pub fn open_in_memory() -> Result<Self> {
        let connection =
            Connection::open_in_memory().context("failed to open in-memory sqlite db")?;
        Self::from_connection(connection)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS hardware_reliability_ingest (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    received_at_unix INTEGER NOT NULL,
                    telemetry_subject_id TEXT NOT NULL,
                    schema_version INTEGER NOT NULL,
                    country_code TEXT,
                    raw_payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_hardware_reliability_ingest_subject
                    ON hardware_reliability_ingest(telemetry_subject_id);
                ",
            )
            .context("failed to initialize hardware_reliability_ingest schema")?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Appends one raw ingestion record.
    ///
    /// `country_code` is the server-derived country (doc Section 4.2), or `None` when unknown / no
    /// resolver is configured. The request's raw source IP is deliberately never a parameter here.
    pub fn insert(
        &self,
        received_at_unix: i64,
        telemetry_subject_id: &str,
        schema_version: u32,
        country_code: Option<&str>,
        raw_payload_json: &str,
    ) -> Result<i64> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        connection
            .execute(
                "INSERT INTO hardware_reliability_ingest
                    (received_at_unix, telemetry_subject_id, schema_version, country_code, raw_payload_json)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    received_at_unix,
                    telemetry_subject_id,
                    schema_version,
                    country_code,
                    raw_payload_json
                ],
            )
            .context("failed to insert ingestion record")?;
        Ok(connection.last_insert_rowid())
    }

    /// Returns every stored row, most recent first. Used by the aggregation step (which dedupes to
    /// one current record per subject). Fine for the small fleet this service targets; a future
    /// large-scale deployment would replace this with a windowed/streamed aggregation query.
    pub fn all_records(&self) -> Result<Vec<StoredRecord>> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        let mut statement = connection.prepare(
            "SELECT id, received_at_unix, telemetry_subject_id, schema_version, country_code, raw_payload_json
             FROM hardware_reliability_ingest
             ORDER BY id DESC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(StoredRecord {
                    id: row.get(0)?,
                    received_at_unix: row.get(1)?,
                    telemetry_subject_id: row.get(2)?,
                    schema_version: row.get(3)?,
                    country_code: row.get(4)?,
                    raw_payload_json: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to read ingestion records")?;
        Ok(rows)
    }

    /// Deletes every row for a given `telemetry_subject_id` (GDPR erasure, doc Section 4.5).
    /// Returns the number of rows removed.
    pub fn delete_subject(&self, telemetry_subject_id: &str) -> Result<usize> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        let removed = connection
            .execute(
                "DELETE FROM hardware_reliability_ingest WHERE telemetry_subject_id = ?1",
                rusqlite::params![telemetry_subject_id],
            )
            .context("failed to delete records for subject")?;
        Ok(removed)
    }

    /// Deletes raw rows older than `cutoff_unix` (retention enforcement, doc Section 4.6). Returns
    /// the number of rows removed.
    pub fn delete_older_than(&self, cutoff_unix: i64) -> Result<usize> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        let removed = connection
            .execute(
                "DELETE FROM hardware_reliability_ingest WHERE received_at_unix < ?1",
                rusqlite::params![cutoff_unix],
            )
            .context("failed to prune expired records")?;
        Ok(removed)
    }

    /// Returns the total number of stored rows. Primarily useful for tests.
    pub fn count(&self) -> Result<i64> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        connection
            .query_row(
                "SELECT COUNT(*) FROM hardware_reliability_ingest",
                [],
                |row| row.get(0),
            )
            .context("failed to count ingestion records")
    }

    /// Fetches all rows for a given `telemetry_subject_id`, most recent first. Primarily useful
    /// for tests and for a future admin/erasure endpoint (Section 4.5).
    pub fn records_for_subject(&self, telemetry_subject_id: &str) -> Result<Vec<StoredRecord>> {
        let connection = self
            .connection
            .lock()
            .expect("ingest storage mutex should not be poisoned");
        let mut statement = connection.prepare(
            "SELECT id, received_at_unix, telemetry_subject_id, schema_version, country_code, raw_payload_json
             FROM hardware_reliability_ingest
             WHERE telemetry_subject_id = ?1
             ORDER BY id DESC",
        )?;
        let rows = statement
            .query_map(rusqlite::params![telemetry_subject_id], |row| {
                Ok(StoredRecord {
                    id: row.get(0)?,
                    received_at_unix: row.get(1)?,
                    telemetry_subject_id: row.get(2)?,
                    schema_version: row.get(3)?,
                    country_code: row.get(4)?,
                    raw_payload_json: row.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to read ingestion records")?;
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_count_round_trips() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        assert_eq!(storage.count().expect("count should succeed"), 0);

        storage
            .insert(
                1_752_912_000,
                "subject-a",
                1,
                None,
                "{\"schema_version\":1}",
            )
            .expect("insert should succeed");
        assert_eq!(storage.count().expect("count should succeed"), 1);

        let records = storage
            .records_for_subject("subject-a")
            .expect("query should succeed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].telemetry_subject_id, "subject-a");
        assert_eq!(records[0].schema_version, 1);
        assert_eq!(records[0].country_code, None);
    }

    #[test]
    fn insert_persists_resolved_country_code() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        storage
            .insert(1_752_912_000, "subject-de", 1, Some("DE"), "{}")
            .expect("insert should succeed");
        let records = storage
            .records_for_subject("subject-de")
            .expect("query should succeed");
        assert_eq!(records[0].country_code.as_deref(), Some("DE"));
    }

    #[test]
    fn delete_subject_removes_only_that_subject() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        storage.insert(1, "keep", 1, None, "{}").unwrap();
        storage.insert(2, "erase", 1, None, "{}").unwrap();
        storage.insert(3, "erase", 1, None, "{}").unwrap();

        let removed = storage
            .delete_subject("erase")
            .expect("delete should succeed");
        assert_eq!(removed, 2);
        assert_eq!(storage.count().unwrap(), 1);
        assert!(storage.records_for_subject("erase").unwrap().is_empty());
        assert_eq!(storage.records_for_subject("keep").unwrap().len(), 1);
    }

    #[test]
    fn delete_older_than_prunes_by_timestamp() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        storage.insert(100, "old", 1, None, "{}").unwrap();
        storage.insert(200, "new", 1, None, "{}").unwrap();

        let removed = storage
            .delete_older_than(150)
            .expect("prune should succeed");
        assert_eq!(removed, 1);
        assert_eq!(storage.count().unwrap(), 1);
        assert!(storage.records_for_subject("old").unwrap().is_empty());
    }
}
