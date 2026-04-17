use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Row, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::folder_agent_state::{
    FOLDER_AGENT_MODIFICATION_LOG_FILE_NAME, FolderAgentProfilePaths,
    default_folder_agent_state_root, folder_agent_profile_paths,
};
use crate::{PathScope, StartupStateStore};

const MODIFICATION_LOG_SCHEMA_VERSION_CURRENT: i64 = 1;
const MODIFICATION_LOG_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MODIFICATION_LOG_MAX_RECORDS: usize = 25_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModificationOperation {
    Upload,
    Download,
    DeleteLocal,
    DeleteRemote,
}

impl ModificationOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::DeleteLocal => "delete-local",
            Self::DeleteRemote => "delete-remote",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModificationOutcome {
    Success,
    Error,
}

impl ModificationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModificationPhase {
    Startup,
    SteadyState,
    Manual,
}

impl ModificationPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::SteadyState => "steady-state",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ModificationTriggerSource {
    LocalScan,
    LocalWatch,
    RemoteRefresh,
    StartupReconcile,
    ConflictResolution,
}

impl ModificationTriggerSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalScan => "local-scan",
            Self::LocalWatch => "local-watch",
            Self::RemoteRefresh => "remote-refresh",
            Self::StartupReconcile => "startup-reconcile",
            Self::ConflictResolution => "conflict-resolution",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ModificationLogContext {
    pub phase: ModificationPhase,
    pub trigger_source: ModificationTriggerSource,
}

impl ModificationLogContext {
    pub const fn new(phase: ModificationPhase, trigger_source: ModificationTriggerSource) -> Self {
        Self {
            phase,
            trigger_source,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModificationLogEntry {
    pub operation: ModificationOperation,
    pub outcome: ModificationOutcome,
    pub phase: ModificationPhase,
    pub trigger_source: ModificationTriggerSource,
    pub local_relative_path: String,
    pub remote_key: String,
    pub size_bytes: Option<u64>,
    pub content_hash: Option<String>,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModificationLogRecord {
    pub id: i64,
    pub occurred_unix_ms: u64,
    pub operation: ModificationOperation,
    pub outcome: ModificationOutcome,
    pub phase: ModificationPhase,
    pub trigger_source: ModificationTriggerSource,
    pub local_relative_path: String,
    pub remote_key: String,
    pub size_bytes: Option<u64>,
    pub content_hash: Option<String>,
    pub scope_label: String,
    pub root_dir: String,
    pub connection_target: String,
    pub error_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModificationHistoryPage {
    pub records: Vec<ModificationLogRecord>,
    pub next_before_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ModificationLogStore {
    pub path: PathBuf,
    scope_fingerprint: String,
    scope_label: String,
    root_dir_label: String,
    connection_target: String,
}

impl ModificationLogStore {
    pub fn new(
        identity_root: &Path,
        root_dir_label: &Path,
        scope: &PathScope,
        connection_target: &str,
    ) -> Self {
        Self::new_with_state_root(
            identity_root,
            root_dir_label,
            scope,
            connection_target,
            &default_folder_agent_state_root(),
        )
    }

    pub fn new_with_state_root(
        identity_root: &Path,
        root_dir_label: &Path,
        scope: &PathScope,
        connection_target: &str,
        state_root_dir: &Path,
    ) -> Self {
        let profile_paths = folder_agent_profile_paths(
            identity_root,
            scope,
            connection_target,
            state_root_dir,
        );
        Self::from_profile_paths(profile_paths, root_dir_label, scope, connection_target)
    }

    pub fn from_state_store(
        state_store: &StartupStateStore,
        root_dir_label: &Path,
        scope: &PathScope,
        connection_target: &str,
    ) -> Self {
        let profile_dir = state_store
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let scope_fingerprint = profile_dir
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        Self {
            path: profile_dir.join(FOLDER_AGENT_MODIFICATION_LOG_FILE_NAME),
            scope_fingerprint,
            scope_label: scope.remote_prefix().unwrap_or("<root>").to_string(),
            root_dir_label: root_dir_label.display().to_string(),
            connection_target: connection_target.to_string(),
        }
    }

    fn from_profile_paths(
        profile_paths: FolderAgentProfilePaths,
        root_dir_label: &Path,
        scope: &PathScope,
        connection_target: &str,
    ) -> Self {
        Self {
            path: profile_paths.modification_log_path,
            scope_fingerprint: profile_paths.scope_fingerprint,
            scope_label: scope.remote_prefix().unwrap_or("<root>").to_string(),
            root_dir_label: root_dir_label.display().to_string(),
            connection_target: connection_target.to_string(),
        }
    }

    pub fn append(&self, entry: &ModificationLogEntry) -> Result<i64> {
        let connection = self.sqlite_connection()?;
        let occurred_unix_ms = i64::try_from(now_unix_ms())
            .context("modification log timestamp overflow")?;
        let size_bytes = entry
            .size_bytes
            .map(i64::try_from)
            .transpose()
            .context("modification log size overflow")?;

        connection
            .execute(
                "INSERT INTO modification_actions(
                     occurred_unix_ms,
                     operation,
                     outcome,
                     phase,
                     trigger_source,
                     local_relative_path,
                     remote_key,
                     size_bytes,
                     content_hash,
                     scope_label,
                     root_dir,
                     connection_target,
                     error_text
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    occurred_unix_ms,
                    entry.operation.as_str(),
                    entry.outcome.as_str(),
                    entry.phase.as_str(),
                    entry.trigger_source.as_str(),
                    entry.local_relative_path,
                    entry.remote_key,
                    size_bytes,
                    entry.content_hash,
                    self.scope_label,
                    self.root_dir_label,
                    self.connection_target,
                    entry.error_text,
                ],
            )
            .context("failed to append modification log row")?;

        self.prune_retained(&connection)?;
        Ok(connection.last_insert_rowid())
    }

    pub fn list(
        &self,
        limit: Option<usize>,
        before_id: Option<i64>,
        operation: Option<ModificationOperation>,
    ) -> Result<ModificationHistoryPage> {
        let connection = self.sqlite_connection()?;
        let resolved_limit = i64::try_from(limit.unwrap_or(50).clamp(1, 500))
            .context("modification log limit overflow")?;

        let mut records = match (before_id, operation) {
            (Some(before_id), Some(operation)) => query_records(
                &connection,
                "SELECT id, occurred_unix_ms, operation, outcome, phase, trigger_source,
                        local_relative_path, remote_key, size_bytes, content_hash,
                        scope_label, root_dir, connection_target, error_text
                 FROM modification_actions
                 WHERE id < ?1 AND operation = ?2
                 ORDER BY occurred_unix_ms DESC, id DESC
                 LIMIT ?3",
                params![before_id, operation.as_str(), resolved_limit],
            )?,
            (Some(before_id), None) => query_records(
                &connection,
                "SELECT id, occurred_unix_ms, operation, outcome, phase, trigger_source,
                        local_relative_path, remote_key, size_bytes, content_hash,
                        scope_label, root_dir, connection_target, error_text
                 FROM modification_actions
                 WHERE id < ?1
                 ORDER BY occurred_unix_ms DESC, id DESC
                 LIMIT ?2",
                params![before_id, resolved_limit],
            )?,
            (None, Some(operation)) => query_records(
                &connection,
                "SELECT id, occurred_unix_ms, operation, outcome, phase, trigger_source,
                        local_relative_path, remote_key, size_bytes, content_hash,
                        scope_label, root_dir, connection_target, error_text
                 FROM modification_actions
                 WHERE operation = ?1
                 ORDER BY occurred_unix_ms DESC, id DESC
                 LIMIT ?2",
                params![operation.as_str(), resolved_limit],
            )?,
            (None, None) => query_records(
                &connection,
                "SELECT id, occurred_unix_ms, operation, outcome, phase, trigger_source,
                        local_relative_path, remote_key, size_bytes, content_hash,
                        scope_label, root_dir, connection_target, error_text
                 FROM modification_actions
                 ORDER BY occurred_unix_ms DESC, id DESC
                 LIMIT ?1",
                params![resolved_limit],
            )?,
        };

        let next_before_id = if records.len() >= resolved_limit as usize {
            records.last().map(|record| record.id)
        } else {
            None
        };
        Ok(ModificationHistoryPage {
            next_before_id,
            records: std::mem::take(&mut records),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn sqlite_connection(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sqlite modification log directory {}",
                    parent.display()
                )
            })?;
        }

        let connection = Connection::open(&self.path)
            .with_context(|| format!("failed to open sqlite modification log {}", self.path.display()))?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("failed to set modification log journal_mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("failed to set modification log synchronous mode")?;

        self.ensure_schema(&connection)?;
        self.ensure_scope_fingerprint(&connection)?;

        Ok(connection)
    }

    fn ensure_schema(&self, connection: &Connection) -> Result<()> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS modification_meta (
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS modification_actions (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     occurred_unix_ms INTEGER NOT NULL,
                     operation TEXT NOT NULL,
                     outcome TEXT NOT NULL,
                     phase TEXT NOT NULL,
                     trigger_source TEXT NOT NULL,
                     local_relative_path TEXT NOT NULL,
                     remote_key TEXT NOT NULL,
                     size_bytes INTEGER,
                     content_hash TEXT,
                     scope_label TEXT NOT NULL,
                     root_dir TEXT NOT NULL,
                     connection_target TEXT NOT NULL,
                     error_text TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_modification_actions_time
                     ON modification_actions(occurred_unix_ms DESC, id DESC);
                 CREATE INDEX IF NOT EXISTS idx_modification_actions_operation
                     ON modification_actions(operation, occurred_unix_ms DESC, id DESC);",
            )
            .context("failed to initialize sqlite modification log schema")?;

        let stored_version = connection
            .query_row(
                "SELECT value FROM modification_meta WHERE key = ?1",
                ["schema_version"],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to read modification log schema version")?;

        let schema_version = match stored_version {
            Some(raw) => raw
                .parse::<i64>()
                .with_context(|| format!("invalid sqlite modification log schema version: {raw}"))?,
            None => MODIFICATION_LOG_SCHEMA_VERSION_CURRENT,
        };

        if schema_version != MODIFICATION_LOG_SCHEMA_VERSION_CURRENT {
            anyhow::bail!(
                "unsupported sqlite modification log schema version: {} (current={})",
                schema_version,
                MODIFICATION_LOG_SCHEMA_VERSION_CURRENT
            );
        }

        connection
            .execute(
                "INSERT INTO modification_meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![
                    "schema_version",
                    MODIFICATION_LOG_SCHEMA_VERSION_CURRENT.to_string(),
                ],
            )
            .context("failed to persist modification log schema version")?;

        Ok(())
    }

    fn ensure_scope_fingerprint(&self, connection: &Connection) -> Result<()> {
        connection
            .execute(
                "INSERT OR IGNORE INTO modification_meta(key, value) VALUES(?1, ?2)",
                params!["scope_fingerprint", self.scope_fingerprint.as_str()],
            )
            .context("failed to initialize modification log scope fingerprint")?;

        let stored_fingerprint: String = connection
            .query_row(
                "SELECT value FROM modification_meta WHERE key = ?1",
                ["scope_fingerprint"],
                |row| row.get(0),
            )
            .context("failed to read modification log scope fingerprint")?;
        if stored_fingerprint != self.scope_fingerprint {
            anyhow::bail!(
                "sqlite modification log scope fingerprint mismatch (stored={}, expected={})",
                stored_fingerprint,
                self.scope_fingerprint
            );
        }

        Ok(())
    }

    fn prune_retained(&self, connection: &Connection) -> Result<()> {
        let retention_cutoff = i64::try_from(now_unix_ms().saturating_sub(MODIFICATION_LOG_RETENTION_MS))
            .context("modification log retention cutoff overflow")?;
        connection
            .execute(
                "DELETE FROM modification_actions WHERE occurred_unix_ms < ?1",
                [retention_cutoff],
            )
            .context("failed to prune modification log by retention cutoff")?;

        connection
            .execute(
                "DELETE FROM modification_actions
                 WHERE id NOT IN (
                     SELECT id
                     FROM modification_actions
                     ORDER BY occurred_unix_ms DESC, id DESC
                     LIMIT ?1
                 )",
                [i64::try_from(MODIFICATION_LOG_MAX_RECORDS)
                    .context("modification log max record limit overflow")?],
            )
            .context("failed to prune modification log by row cap")?;
        Ok(())
    }
}

pub fn try_record_modification(
    store: Option<&ModificationLogStore>,
    context: Option<&ModificationLogContext>,
    operation: ModificationOperation,
    outcome: ModificationOutcome,
    local_relative_path: &str,
    remote_key: &str,
    size_bytes: Option<u64>,
    content_hash: Option<&str>,
    error_text: Option<&str>,
) {
    let (Some(store), Some(context)) = (store, context) else {
        return;
    };

    let entry = ModificationLogEntry {
        operation,
        outcome,
        phase: context.phase,
        trigger_source: context.trigger_source,
        local_relative_path: local_relative_path.to_string(),
        remote_key: remote_key.to_string(),
        size_bytes,
        content_hash: content_hash
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        error_text: error_text
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
    };

    if let Err(error) = store.append(&entry) {
        tracing::warn!(
            log_path = %store.path.display(),
            operation = operation.as_str(),
            outcome = outcome.as_str(),
            local_relative_path,
            remote_key,
            error = %error,
            "failed to append modification log row"
        );
    }
}

fn query_records<P>(connection: &Connection, query: &str, params: P) -> Result<Vec<ModificationLogRecord>>
where
    P: rusqlite::Params,
{
    let mut statement = connection
        .prepare(query)
        .context("failed to prepare modification log query")?;
    let rows = statement
        .query_map(params, decode_record)
        .context("failed to read modification log rows")?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row.context("failed to decode modification log row")?);
    }
    Ok(records)
}

fn decode_record(row: &Row<'_>) -> rusqlite::Result<ModificationLogRecord> {
    let occurred_unix_ms = row.get::<_, i64>(1)?;
    let size_bytes = row.get::<_, Option<i64>>(8)?;
    Ok(ModificationLogRecord {
        id: row.get(0)?,
        occurred_unix_ms: occurred_unix_ms.try_into().unwrap_or_default(),
        operation: decode_operation(&row.get::<_, String>(2)?)?,
        outcome: decode_outcome(&row.get::<_, String>(3)?)?,
        phase: decode_phase(&row.get::<_, String>(4)?)?,
        trigger_source: decode_trigger_source(&row.get::<_, String>(5)?)?,
        local_relative_path: row.get(6)?,
        remote_key: row.get(7)?,
        size_bytes: size_bytes.and_then(|value| value.try_into().ok()),
        content_hash: row.get(9)?,
        scope_label: row.get(10)?,
        root_dir: row.get(11)?,
        connection_target: row.get(12)?,
        error_text: row.get(13)?,
    })
}

fn decode_operation(value: &str) -> rusqlite::Result<ModificationOperation> {
    match value {
        "upload" => Ok(ModificationOperation::Upload),
        "download" => Ok(ModificationOperation::Download),
        "delete-local" => Ok(ModificationOperation::DeleteLocal),
        "delete-remote" => Ok(ModificationOperation::DeleteRemote),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid modification operation {value}"),
            )),
        )),
    }
}

fn decode_outcome(value: &str) -> rusqlite::Result<ModificationOutcome> {
    match value {
        "success" => Ok(ModificationOutcome::Success),
        "error" => Ok(ModificationOutcome::Error),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid modification outcome {value}"),
            )),
        )),
    }
}

fn decode_phase(value: &str) -> rusqlite::Result<ModificationPhase> {
    match value {
        "startup" => Ok(ModificationPhase::Startup),
        "steady-state" => Ok(ModificationPhase::SteadyState),
        "manual" => Ok(ModificationPhase::Manual),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            4,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid modification phase {value}"),
            )),
        )),
    }
}

fn decode_trigger_source(value: &str) -> rusqlite::Result<ModificationTriggerSource> {
    match value {
        "local-scan" => Ok(ModificationTriggerSource::LocalScan),
        "local-watch" => Ok(ModificationTriggerSource::LocalWatch),
        "remote-refresh" => Ok(ModificationTriggerSource::RemoteRefresh),
        "startup-reconcile" => Ok(ModificationTriggerSource::StartupReconcile),
        "conflict-resolution" => Ok(ModificationTriggerSource::ConflictResolution),
        _ => Err(rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid modification trigger source {value}"),
            )),
        )),
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn modification_log_store_appends_and_pages_records() {
        let root = test_root();
        let state_root = root.join("state-root");
        let identity_root = root.join("identity-root");
        let scope = PathScope::new(Some("photos/camera".to_string()));
        let store = ModificationLogStore::new_with_state_root(
            &identity_root,
            &root,
            &scope,
            "http://127.0.0.1:8080",
            &state_root,
        );

        store
            .append(&ModificationLogEntry {
                operation: ModificationOperation::Upload,
                outcome: ModificationOutcome::Success,
                phase: ModificationPhase::Startup,
                trigger_source: ModificationTriggerSource::StartupReconcile,
                local_relative_path: "docs/one.txt".to_string(),
                remote_key: "photos/camera/docs/one.txt".to_string(),
                size_bytes: Some(3),
                content_hash: Some("abc".to_string()),
                error_text: None,
            })
            .unwrap();
        store
            .append(&ModificationLogEntry {
                operation: ModificationOperation::DeleteRemote,
                outcome: ModificationOutcome::Success,
                phase: ModificationPhase::SteadyState,
                trigger_source: ModificationTriggerSource::LocalWatch,
                local_relative_path: "docs/two.txt".to_string(),
                remote_key: "photos/camera/docs/two.txt".to_string(),
                size_bytes: None,
                content_hash: None,
                error_text: None,
            })
            .unwrap();

        let first_page = store.list(Some(1), None, None).unwrap();
        assert_eq!(first_page.records.len(), 1);
        assert_eq!(first_page.records[0].operation, ModificationOperation::DeleteRemote);
        assert!(first_page.next_before_id.is_some());

        let second_page = store
            .list(Some(2), first_page.next_before_id, None)
            .unwrap();
        assert_eq!(second_page.records.len(), 1);
        assert_eq!(second_page.records[0].operation, ModificationOperation::Upload);

        let uploads = store
            .list(Some(8), None, Some(ModificationOperation::Upload))
            .unwrap();
        assert_eq!(uploads.records.len(), 1);
        assert_eq!(uploads.records[0].local_relative_path, "docs/one.txt");

        fs::remove_dir_all(root).unwrap();
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!(
            "ironmesh-modification-log-test-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }
}
