//! Append-only raw storage for ingested hardware-reliability payloads.
//!
//! Per `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 5.3, raw ingested
//! batches are stored separately from any future aggregated/public view, and access to this raw
//! table is meant to be admin-only (not wired up in this slice, which only covers ingestion).

use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::Connection;

/// A single stored ingestion row, as inserted by [`IngestStorage::insert`].
///
/// `country_code` is an extension seam for future work (Section 4.2): it is always `None` in this
/// slice, since geo-IP-derived country lookup is not implemented yet.
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
    /// `country_code` is always inserted as `NULL` in this slice (see module docs and struct
    /// docs above) — the column exists now purely as a seam for a future geo-IP lookup step.
    pub fn insert(
        &self,
        received_at_unix: i64,
        telemetry_subject_id: &str,
        schema_version: u32,
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
                 VALUES (?1, ?2, ?3, NULL, ?4)",
                rusqlite::params![
                    received_at_unix,
                    telemetry_subject_id,
                    schema_version,
                    raw_payload_json
                ],
            )
            .context("failed to insert ingestion record")?;
        Ok(connection.last_insert_rowid())
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
            .insert(1_752_912_000, "subject-a", 1, "{\"schema_version\":1}")
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
}
