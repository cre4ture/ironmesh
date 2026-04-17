use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::folder_agent_startup::StartupConflict;
use crate::{LocalEntryKind, LocalEntryState, LocalTreeState, normalize_relative_path};

pub(crate) const FOLDER_AGENT_BASELINE_FILE_NAME: &str = "baseline.sqlite";
pub(crate) const FOLDER_AGENT_MODIFICATION_LOG_FILE_NAME: &str = "modification-log.sqlite";

#[derive(Debug, Clone)]
pub struct PathScope {
    prefix: Option<String>,
}

impl PathScope {
    pub fn new(prefix: Option<String>) -> Self {
        Self {
            prefix: prefix
                .map(|value| normalize_relative_path(&value))
                .filter(|value| !value.is_empty()),
        }
    }

    pub fn remote_prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }

    pub fn remote_to_local(&self, remote_path: &str) -> Option<String> {
        let normalized = normalize_relative_path(remote_path);
        if normalized.is_empty() {
            return None;
        }

        match &self.prefix {
            None => Some(normalized),
            Some(prefix) => {
                if normalized == *prefix {
                    return Some(String::new());
                }

                let scoped_prefix = format!("{prefix}/");
                normalized
                    .strip_prefix(&scoped_prefix)
                    .map(ToString::to_string)
            }
        }
    }

    pub fn local_to_remote(&self, local_path: &str) -> Option<String> {
        let normalized = normalize_relative_path(local_path);
        if normalized.is_empty() {
            return None;
        }

        Some(match &self.prefix {
            None => normalized,
            Some(prefix) => format!("{prefix}/{normalized}"),
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FolderAgentProfilePaths {
    pub scope_fingerprint: String,
    pub baseline_path: PathBuf,
    pub modification_log_path: PathBuf,
}

pub(crate) fn default_folder_agent_state_root() -> PathBuf {
    xdg_state_home().unwrap_or_else(std::env::temp_dir).join("ironmesh").join("folder-agent")
}

pub(crate) fn folder_agent_profile_paths(
    identity_root: &Path,
    scope: &PathScope,
    connection_target: &str,
    state_root_dir: &Path,
) -> FolderAgentProfilePaths {
    let mut hasher = DefaultHasher::new();
    identity_root.to_string_lossy().hash(&mut hasher);
    scope.remote_prefix().unwrap_or_default().hash(&mut hasher);
    connection_target.hash(&mut hasher);
    let scope_fingerprint = format!("{:016x}", hasher.finish());

    let profile_dir = state_root_dir.join("profiles").join(&scope_fingerprint);
    FolderAgentProfilePaths {
        scope_fingerprint,
        baseline_path: profile_dir.join(FOLDER_AGENT_BASELINE_FILE_NAME),
        modification_log_path: profile_dir.join(FOLDER_AGENT_MODIFICATION_LOG_FILE_NAME),
    }
}

fn xdg_state_home() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }

    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(".local").join("state"))
}

#[derive(Clone)]
pub struct StartupStateStore {
    pub path: PathBuf,
    scope_fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct StoredConflict {
    pub path: String,
    pub reason: String,
    pub details_json: String,
    pub created_unix_ms: i64,
}

const BASELINE_SCHEMA_VERSION_INITIAL: i64 = 1;
pub const BASELINE_SCHEMA_VERSION_CURRENT: i64 = 2;

impl StartupStateStore {
    pub fn new(root_dir: &Path, scope: &PathScope, server_base_url: &str) -> Self {
        Self::new_with_state_root(root_dir, scope, server_base_url, &default_folder_agent_state_root())
    }

    pub fn new_with_state_root(
        root_dir: &Path,
        scope: &PathScope,
        server_base_url: &str,
        state_root_dir: &Path,
    ) -> Self {
        let profile_paths = folder_agent_profile_paths(root_dir, scope, server_base_url, state_root_dir);
        Self {
            path: profile_paths.baseline_path,
            scope_fingerprint: profile_paths.scope_fingerprint,
        }
    }

    pub fn load_local_baseline(&self) -> Result<LocalTreeState> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, kind, size_bytes, modified_unix_ms
                 FROM baseline_entries",
            )
            .context("failed to prepare sqlite baseline query")?;

        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .context("failed to read sqlite baseline rows")?;

        let mut state = LocalTreeState::new();
        for row in rows {
            let (path, kind_code, size_bytes_i64, modified_unix_ms_i64) =
                row.context("failed to decode sqlite baseline row")?;

            let kind = match kind_code {
                0 => LocalEntryKind::File,
                1 => LocalEntryKind::Directory,
                _ => bail!("invalid kind code in sqlite baseline for path={path}"),
            };

            let size_bytes = u64::try_from(size_bytes_i64)
                .with_context(|| format!("invalid size in sqlite baseline for path={path}"))?;
            let modified_unix_ms = u128::try_from(modified_unix_ms_i64)
                .with_context(|| format!("invalid mtime in sqlite baseline for path={path}"))?;

            state.insert(
                path,
                LocalEntryState {
                    kind,
                    size_bytes,
                    modified_unix_ms,
                },
            );
        }

        Ok(state)
    }

    pub fn load_local_baseline_hashes(&self) -> Result<BTreeMap<String, String>> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, content_hash
                 FROM baseline_entries
                 WHERE kind = 0
                   AND content_hash IS NOT NULL
                   AND content_hash != ''",
            )
            .context("failed to prepare sqlite baseline hash query")?;

        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .context("failed to read sqlite baseline hash rows")?;

        let mut hashes = BTreeMap::new();
        for row in rows {
            let (path, hash) = row.context("failed to decode sqlite baseline hash row")?;
            hashes.insert(path, hash);
        }

        Ok(hashes)
    }

    pub fn persist_local_baseline(&self, state: &LocalTreeState) -> Result<()> {
        let mut connection = self.sqlite_connection()?;
        let existing_hashes = {
            let mut statement = connection
                .prepare(
                    "SELECT path, content_hash
                     FROM baseline_entries
                     WHERE kind = 0
                       AND content_hash IS NOT NULL
                       AND content_hash != ''",
                )
                .context("failed to prepare sqlite baseline hash preservation query")?;

            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .context("failed to read sqlite baseline hashes before rewrite")?;

            let mut hashes = BTreeMap::new();
            for row in rows {
                let (path, hash) =
                    row.context("failed to decode sqlite baseline hash preservation row")?;
                hashes.insert(path, hash);
            }
            hashes
        };

        let tx = connection
            .transaction()
            .context("failed to start sqlite baseline transaction")?;

        tx.execute("DELETE FROM baseline_entries", [])
            .context("failed to clear sqlite baseline table")?;

        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms, content_hash)
                     VALUES(?1, ?2, ?3, ?4, ?5)",
                )
                .context("failed to prepare sqlite baseline insert")?;

            for (path, entry_state) in state {
                let kind_code: i64 = match entry_state.kind {
                    LocalEntryKind::File => 0,
                    LocalEntryKind::Directory => 1,
                };
                let size_bytes = i64::try_from(entry_state.size_bytes)
                    .with_context(|| format!("size overflow while persisting baseline: {path}"))?;
                let modified_unix_ms = i64::try_from(entry_state.modified_unix_ms)
                    .with_context(|| format!("mtime overflow while persisting baseline: {path}"))?;
                let content_hash = match entry_state.kind {
                    LocalEntryKind::File => existing_hashes.get(path).cloned(),
                    LocalEntryKind::Directory => None,
                };

                insert
                    .execute(params![
                        path,
                        kind_code,
                        size_bytes,
                        modified_unix_ms,
                        content_hash
                    ])
                    .with_context(|| format!("failed to insert sqlite baseline row for {path}"))?;
            }
        }

        tx.commit()
            .context("failed to commit sqlite baseline transaction")?;

        Ok(())
    }

    pub fn upsert_baseline_entry(&self, path: &str, entry_state: &LocalEntryState) -> Result<()> {
        self.upsert_baseline_entry_with_hash(path, entry_state, None)
    }

    pub fn upsert_baseline_entry_with_hash(
        &self,
        path: &str,
        entry_state: &LocalEntryState,
        content_hash: Option<&str>,
    ) -> Result<()> {
        let connection = self.sqlite_connection()?;
        let kind_code: i64 = match entry_state.kind {
            LocalEntryKind::File => 0,
            LocalEntryKind::Directory => 1,
        };
        let size_bytes = i64::try_from(entry_state.size_bytes)
            .with_context(|| format!("size overflow while persisting baseline: {path}"))?;
        let modified_unix_ms = i64::try_from(entry_state.modified_unix_ms)
            .with_context(|| format!("mtime overflow while persisting baseline: {path}"))?;
        let content_hash = match entry_state.kind {
            LocalEntryKind::File => content_hash
                .filter(|hash| !hash.trim().is_empty())
                .map(ToString::to_string),
            LocalEntryKind::Directory => None,
        };

        connection
            .execute(
                "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms, content_hash)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(path) DO UPDATE SET
                     kind = excluded.kind,
                     size_bytes = excluded.size_bytes,
                     modified_unix_ms = excluded.modified_unix_ms,
                     content_hash = CASE
                         WHEN excluded.kind != 0 THEN NULL
                         ELSE COALESCE(NULLIF(excluded.content_hash, ''), baseline_entries.content_hash)
                     END",
                params![path, kind_code, size_bytes, modified_unix_ms, content_hash],
            )
            .with_context(|| format!("failed to upsert sqlite baseline row for {path}"))?;

        Ok(())
    }

    pub fn remove_baseline_entry(&self, path: &str) -> Result<()> {
        let connection = self.sqlite_connection()?;
        connection
            .execute("DELETE FROM baseline_entries WHERE path = ?1", [path])
            .with_context(|| format!("failed to delete sqlite baseline row for {path}"))?;
        Ok(())
    }

    pub fn persist_startup_conflicts(&self, conflicts: &[StartupConflict]) -> Result<()> {
        let mut connection = self.sqlite_connection()?;
        let tx = connection
            .transaction()
            .context("failed to start sqlite conflicts transaction")?;
        tx.execute("DELETE FROM conflicts", [])
            .context("failed to clear sqlite conflicts table")?;

        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO conflicts(path, reason, details_json, created_unix_ms)
                     VALUES(?1, ?2, ?3, ?4)",
                )
                .context("failed to prepare sqlite conflict insert")?;
            for conflict in conflicts {
                let created_unix_ms = i64::try_from(conflict.created_unix_ms)
                    .with_context(|| format!("invalid conflict timestamp for {}", conflict.path))?;
                insert
                    .execute(params![
                        conflict.path,
                        conflict.reason,
                        conflict.details_json,
                        created_unix_ms
                    ])
                    .with_context(|| {
                        format!("failed to insert sqlite conflict row for {}", conflict.path)
                    })?;
            }
        }

        tx.commit()
            .context("failed to commit sqlite conflicts transaction")?;
        Ok(())
    }

    pub fn load_conflicts(&self) -> Result<Vec<StoredConflict>> {
        let connection = self.sqlite_connection()?;
        let mut statement = connection
            .prepare(
                "SELECT path, reason, details_json, created_unix_ms
                 FROM conflicts
                 ORDER BY created_unix_ms ASC, path ASC",
            )
            .context("failed to prepare sqlite conflicts query")?;

        let rows = statement
            .query_map([], |row| {
                Ok(StoredConflict {
                    path: row.get::<_, String>(0)?,
                    reason: row.get::<_, String>(1)?,
                    details_json: row.get::<_, String>(2)?,
                    created_unix_ms: row.get::<_, i64>(3)?,
                })
            })
            .context("failed to read sqlite conflict rows")?;

        let mut values = Vec::new();
        for row in rows {
            values.push(row.context("failed to decode sqlite conflict row")?);
        }
        Ok(values)
    }

    pub fn load_conflict(&self, path: &str) -> Result<Option<StoredConflict>> {
        let connection = self.sqlite_connection()?;
        let conflict = connection
            .query_row(
                "SELECT path, reason, details_json, created_unix_ms
                 FROM conflicts
                 WHERE path = ?1",
                [path],
                |row| {
                    Ok(StoredConflict {
                        path: row.get::<_, String>(0)?,
                        reason: row.get::<_, String>(1)?,
                        details_json: row.get::<_, String>(2)?,
                        created_unix_ms: row.get::<_, i64>(3)?,
                    })
                },
            )
            .optional()
            .with_context(|| format!("failed to load sqlite conflict row for {path}"))?;
        Ok(conflict)
    }

    pub fn clear_conflicts(&self) -> Result<usize> {
        let connection = self.sqlite_connection()?;
        let removed = connection
            .execute("DELETE FROM conflicts", [])
            .context("failed to clear sqlite conflicts table")?;
        Ok(removed)
    }

    pub fn remove_conflict(&self, path: &str) -> Result<usize> {
        let connection = self.sqlite_connection()?;
        let removed = connection
            .execute("DELETE FROM conflicts WHERE path = ?1", [path])
            .with_context(|| format!("failed to remove sqlite conflict row for {path}"))?;
        Ok(removed)
    }

    pub fn quarantine_corrupt(&self) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }

        let quarantine = self
            .path
            .with_extension(format!("corrupt-{}", current_unix_ms()));
        fs::rename(&self.path, &quarantine).with_context(|| {
            format!(
                "failed to quarantine sqlite baseline {}",
                self.path.display()
            )
        })?;

        let wal = PathBuf::from(format!("{}-wal", self.path.display()));
        if wal.exists() {
            let _ = fs::remove_file(wal);
        }
        let shm = PathBuf::from(format!("{}-shm", self.path.display()));
        if shm.exists() {
            let _ = fs::remove_file(shm);
        }

        Ok(())
    }

    fn sqlite_connection(&self) -> Result<Connection> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create sqlite baseline directory {}",
                    parent.display()
                )
            })?;
        }

        let mut connection = Connection::open(&self.path)
            .with_context(|| format!("failed to open sqlite baseline {}", self.path.display()))?;

        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("failed to set sqlite journal_mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("failed to set sqlite synchronous mode")?;

        self.ensure_schema(&mut connection)?;
        self.ensure_scope_fingerprint(&connection)?;

        Ok(connection)
    }

    fn ensure_schema(&self, connection: &mut Connection) -> Result<()> {
        connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS baseline_meta (
                     key TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS baseline_entries (
                     path TEXT PRIMARY KEY,
                     kind INTEGER NOT NULL,
                     size_bytes INTEGER NOT NULL,
                     modified_unix_ms INTEGER NOT NULL,
                     content_hash TEXT
                 );
                 CREATE TABLE IF NOT EXISTS conflicts (
                     path TEXT PRIMARY KEY,
                     reason TEXT NOT NULL,
                     details_json TEXT NOT NULL,
                     created_unix_ms INTEGER NOT NULL
                 );",
            )
            .context("failed to initialize sqlite baseline schema")?;

        let stored_version = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["schema_version"],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .context("failed to read sqlite baseline schema version")?;

        let mut schema_version = match stored_version {
            Some(raw) => raw
                .parse::<i64>()
                .with_context(|| format!("invalid sqlite baseline schema version: {raw}"))?,
            None => BASELINE_SCHEMA_VERSION_INITIAL,
        };

        if schema_version < BASELINE_SCHEMA_VERSION_INITIAL {
            bail!(
                "unsupported sqlite baseline schema version: {schema_version} (minimum={})",
                BASELINE_SCHEMA_VERSION_INITIAL
            );
        }

        while schema_version < BASELINE_SCHEMA_VERSION_CURRENT {
            match schema_version {
                1 => {
                    self.migrate_schema_v1_to_v2(connection)?;
                    schema_version = 2;
                }
                _ => {
                    bail!("unsupported sqlite baseline schema version: {schema_version}");
                }
            }
        }

        if schema_version > BASELINE_SCHEMA_VERSION_CURRENT {
            bail!(
                "unsupported sqlite baseline schema version: {} (current={})",
                schema_version,
                BASELINE_SCHEMA_VERSION_CURRENT
            );
        }

        connection
            .execute(
                "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params!["schema_version", schema_version.to_string()],
            )
            .context("failed to persist sqlite baseline schema version")?;

        Ok(())
    }

    fn migrate_schema_v1_to_v2(&self, connection: &Connection) -> Result<()> {
        let mut statement = connection
            .prepare("PRAGMA table_info(baseline_entries)")
            .context("failed to inspect sqlite baseline_entries schema")?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))
            .context("failed to read sqlite baseline_entries columns")?;

        let mut has_content_hash = false;
        for column in columns {
            if column.context("failed to decode sqlite baseline_entries column")? == "content_hash"
            {
                has_content_hash = true;
                break;
            }
        }

        if !has_content_hash {
            connection
                .execute(
                    "ALTER TABLE baseline_entries ADD COLUMN content_hash TEXT",
                    [],
                )
                .context("failed to migrate sqlite baseline schema v1->v2")?;
        }

        Ok(())
    }

    fn ensure_scope_fingerprint(&self, connection: &Connection) -> Result<()> {
        connection
            .execute(
                "INSERT OR IGNORE INTO baseline_meta(key, value) VALUES(?1, ?2)",
                params!["scope_fingerprint", self.scope_fingerprint.as_str()],
            )
            .context("failed to initialize sqlite baseline scope metadata")?;

        let stored_fingerprint: String = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["scope_fingerprint"],
                |row| row.get(0),
            )
            .context("failed to read sqlite baseline scope fingerprint")?;
        if stored_fingerprint != self.scope_fingerprint {
            bail!(
                "sqlite baseline scope fingerprint mismatch (stored={}, expected={})",
                stored_fingerprint,
                self.scope_fingerprint
            );
        }

        Ok(())
    }
}

pub fn load_local_baseline_with_retries(
    state_store: &StartupStateStore,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<LocalTreeState> {
    let attempts = max_attempts.max(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match state_store.load_local_baseline() {
            Ok(state) => return Ok(state),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("failed to load sqlite baseline: no attempts executed"),
    }
}

pub fn load_local_baseline_hashes_with_retries(
    state_store: &StartupStateStore,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<BTreeMap<String, String>> {
    let attempts = max_attempts.max(1);
    let mut last_error = None;

    for attempt in 1..=attempts {
        match state_store.load_local_baseline_hashes() {
            Ok(hashes) => return Ok(hashes),
            Err(error) => {
                last_error = Some(error);
                if attempt < attempts {
                    std::thread::sleep(retry_delay);
                }
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => bail!("failed to load sqlite baseline hashes: no attempts executed"),
    }
}

pub fn cleanup_ironmesh_part_files(root_dir: &Path, dry_run: bool) -> Result<usize> {
    if !root_dir.exists() {
        return Ok(0);
    }

    let mut removed = 0_usize;
    let mut stack = vec![root_dir.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) => {
                tracing::warn!(
                    "cleanup: failed to read directory {}: {error}",
                    dir.display()
                );
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    tracing::warn!("cleanup: failed to read directory entry: {error}");
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    tracing::warn!("cleanup: failed to inspect {}: {error}", path.display());
                    continue;
                }
            };

            if file_type.is_dir() {
                if file_type.is_symlink() {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };

            if !is_ironmesh_part_file_name(file_name) {
                continue;
            }

            if dry_run {
                removed += 1;
                continue;
            }

            match fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) => {
                    tracing::warn!("cleanup: failed to remove {}: {error}", path.display());
                }
            }
        }
    }

    Ok(removed)
}

pub fn conflict_copy_dir(root_dir: &Path, side: &str, relative_path: &str) -> PathBuf {
    let rel = Path::new(relative_path);
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    root_dir.join(".ironmesh-conflicts").join(side).join(parent)
}

pub fn newest_remote_conflict_copy(root_dir: &Path, relative_path: &str) -> Result<PathBuf> {
    let rel = Path::new(relative_path);
    let Some(file_name) = rel.file_name().and_then(|value| value.to_str()) else {
        bail!("conflicts: invalid path (expected file): {relative_path}");
    };

    let dir = conflict_copy_dir(root_dir, "remote", relative_path);
    if !dir.is_dir() {
        bail!(
            "conflicts: no remote conflict copies found for {relative_path} (missing directory {})",
            dir.display()
        );
    }

    let prefix = format!("{file_name}.remote-conflict-");
    let mut best: Option<(u128, PathBuf)> = None;

    for entry in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };

        let Some(rest) = name.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Ok(timestamp) = rest.parse::<u128>() else {
            continue;
        };

        match &best {
            None => best = Some((timestamp, path)),
            Some((best_ts, _)) if timestamp > *best_ts => best = Some((timestamp, path)),
            _ => {}
        }
    }

    best.map(|(_, path)| path).ok_or_else(|| {
        anyhow::anyhow!("conflicts: no remote conflict copies found for {relative_path}")
    })
}

pub fn delete_conflict_copies(root_dir: &Path, relative_path: &str) -> Result<usize> {
    let rel = Path::new(relative_path);
    let Some(file_name) = rel.file_name().and_then(|value| value.to_str()) else {
        return Ok(0);
    };

    let mut removed = 0_usize;
    for (side, prefix) in [
        ("remote", format!("{file_name}.remote-conflict-")),
        ("local", format!("{file_name}.local-conflict-")),
    ] {
        let dir = conflict_copy_dir(root_dir, side, relative_path);
        if !dir.is_dir() {
            continue;
        }

        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if !name.starts_with(prefix.as_str()) {
                continue;
            }
            if fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }

    Ok(removed)
}

pub fn copy_file_atomically(source: &Path, target: &Path) -> Result<()> {
    if target.is_dir() {
        fs::remove_dir_all(target)
            .with_context(|| format!("failed to remove local directory {}", target.display()))?;
    }

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
    }

    let temp_name = format!(
        ".{}.ironmesh-part-{}",
        target
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_else(|| "object".to_string()),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temp_path = target.with_file_name(temp_name);

    let mut input = File::open(source)
        .with_context(|| format!("failed to open source file {}", source.display()))?;
    let mut output = File::create(&temp_path)
        .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
    std::io::copy(&mut input, &mut output).with_context(|| {
        format!(
            "failed to copy {} into {}",
            source.display(),
            temp_path.display()
        )
    })?;
    output
        .sync_all()
        .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;

    fs::rename(&temp_path, target).with_context(|| {
        format!(
            "failed to place resolved file {} into {}",
            temp_path.display(),
            target.display()
        )
    })?;

    Ok(())
}

pub fn current_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn is_ironmesh_part_file_name(file_name: &str) -> bool {
    if !file_name.starts_with('.') {
        return false;
    }

    let Some((_, suffix)) = file_name.rsplit_once(".ironmesh-part-") else {
        return false;
    };

    !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn path_scope_without_prefix_keeps_paths() {
        let scope = PathScope::new(None);
        assert_eq!(
            scope.remote_to_local("docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
        assert_eq!(
            scope.local_to_remote("docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
    }

    #[test]
    fn path_scope_with_prefix_maps_both_directions() {
        let scope = PathScope::new(Some("team/a".to_string()));
        assert_eq!(scope.remote_prefix(), Some("team/a"));
        assert_eq!(
            scope.remote_to_local("team/a/docs/readme.txt"),
            Some("docs/readme.txt".to_string())
        );
        assert_eq!(scope.remote_to_local("other/docs/readme.txt"), None);
        assert_eq!(
            scope.local_to_remote("docs/readme.txt"),
            Some("team/a/docs/readme.txt".to_string())
        );
    }

    #[test]
    fn startup_state_store_migrates_schema_v1_to_current() {
        let root = test_root();
        let scope = PathScope::new(None);
        let store = StartupStateStore::new(&root, &scope, "http://127.0.0.1:8080");
        remove_sqlite_sidecars(&store.path);
        ensure_parent_dir(&store.path);

        {
            let connection = Connection::open(&store.path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE baseline_meta (
                         key TEXT PRIMARY KEY,
                         value TEXT NOT NULL
                     );
                     CREATE TABLE baseline_entries (
                         path TEXT PRIMARY KEY,
                         kind INTEGER NOT NULL,
                         size_bytes INTEGER NOT NULL,
                         modified_unix_ms INTEGER NOT NULL
                     );
                     CREATE TABLE conflicts (
                         path TEXT PRIMARY KEY,
                         reason TEXT NOT NULL,
                         details_json TEXT NOT NULL,
                         created_unix_ms INTEGER NOT NULL
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["schema_version", "1"],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["scope_fingerprint", store.scope_fingerprint.as_str()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_entries(path, kind, size_bytes, modified_unix_ms)
                     VALUES(?1, ?2, ?3, ?4)",
                    params!["docs/readme.txt", 0_i64, 5_i64, 11_i64],
                )
                .unwrap();
        }

        let loaded = store.load_local_baseline().unwrap();
        let state = loaded.get("docs/readme.txt").unwrap();
        assert_eq!(state.kind, LocalEntryKind::File);
        assert_eq!(state.size_bytes, 5);
        assert_eq!(state.modified_unix_ms, 11);

        let connection = Connection::open(&store.path).unwrap();
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM baseline_meta WHERE key = ?1",
                ["schema_version"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(schema_version, BASELINE_SCHEMA_VERSION_CURRENT.to_string());

        remove_sqlite_sidecars(&store.path);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_state_store_rejects_future_schema_version() {
        let root = test_root();
        let scope = PathScope::new(None);
        let store = StartupStateStore::new(&root, &scope, "http://127.0.0.1:8080");
        remove_sqlite_sidecars(&store.path);
        ensure_parent_dir(&store.path);

        {
            let connection = Connection::open(&store.path).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE baseline_meta (
                         key TEXT PRIMARY KEY,
                         value TEXT NOT NULL
                     );
                     CREATE TABLE baseline_entries (
                         path TEXT PRIMARY KEY,
                         kind INTEGER NOT NULL,
                         size_bytes INTEGER NOT NULL,
                         modified_unix_ms INTEGER NOT NULL,
                         content_hash TEXT
                     );
                     CREATE TABLE conflicts (
                         path TEXT PRIMARY KEY,
                         reason TEXT NOT NULL,
                         details_json TEXT NOT NULL,
                         created_unix_ms INTEGER NOT NULL
                     );",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["schema_version", "99"],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO baseline_meta(key, value) VALUES(?1, ?2)",
                    params!["scope_fingerprint", store.scope_fingerprint.as_str()],
                )
                .unwrap();
        }

        let error = store.load_local_baseline().unwrap_err().to_string();
        assert!(error.contains("unsupported sqlite baseline schema version"));

        remove_sqlite_sidecars(&store.path);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn startup_state_store_uses_explicit_state_root() {
        let root = test_root();
        let state_root = root.join("state-root");
        let scope = PathScope::new(Some("photos/camera".to_string()));
        let store = StartupStateStore::new_with_state_root(
            &root,
            &scope,
            "http://127.0.0.1:8080",
            &state_root,
        );

        assert!(store.path.starts_with(&state_root));
        assert_eq!(
            store.path.parent().unwrap().file_name().unwrap(),
            store.scope_fingerprint.as_str()
        );
        assert_eq!(
            store
                .path
                .parent()
                .and_then(|value| value.parent())
                .and_then(|value| value.file_name())
                .unwrap(),
            "profiles"
        );
        assert_eq!(store.path.file_name().unwrap(), FOLDER_AGENT_BASELINE_FILE_NAME);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn newest_remote_conflict_copy_prefers_highest_timestamp() {
        let root = test_root();
        let remote_dir = conflict_copy_dir(&root, "remote", "docs/report.txt");
        fs::create_dir_all(&remote_dir).unwrap();
        let older = remote_dir.join("report.txt.remote-conflict-100");
        let newer = remote_dir.join("report.txt.remote-conflict-200");
        fs::write(&older, b"older").unwrap();
        fs::write(&newer, b"newer").unwrap();

        let selected = newest_remote_conflict_copy(&root, "docs/report.txt").unwrap();

        assert_eq!(selected, newer);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn delete_conflict_copies_removes_matching_local_and_remote_backups_only() {
        let root = test_root();
        let remote_dir = conflict_copy_dir(&root, "remote", "docs/report.txt");
        let local_dir = conflict_copy_dir(&root, "local", "docs/report.txt");
        fs::create_dir_all(&remote_dir).unwrap();
        fs::create_dir_all(&local_dir).unwrap();
        fs::write(remote_dir.join("report.txt.remote-conflict-100"), b"remote").unwrap();
        fs::write(local_dir.join("report.txt.local-conflict-200"), b"local").unwrap();
        fs::write(remote_dir.join("other.txt.remote-conflict-300"), b"keep").unwrap();

        let removed = delete_conflict_copies(&root, "docs/report.txt").unwrap();

        assert_eq!(removed, 2);
        assert!(!remote_dir.join("report.txt.remote-conflict-100").exists());
        assert!(!local_dir.join("report.txt.local-conflict-200").exists());
        assert!(remote_dir.join("other.txt.remote-conflict-300").exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn copy_file_atomically_replaces_directory_target_with_file_contents() {
        let root = test_root();
        let source = root.join("source.txt");
        let target = root.join("nested/target.txt");
        fs::create_dir_all(&target).unwrap();
        fs::write(&source, b"resolved").unwrap();

        copy_file_atomically(&source, &target).unwrap();

        assert!(target.is_file());
        assert_eq!(fs::read(&target).unwrap(), b"resolved");
        let leftovers = target
            .parent()
            .unwrap()
            .read_dir()
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".ironmesh-part-"))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty());

        fs::remove_dir_all(root).unwrap();
    }

    fn test_root() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut root = std::env::temp_dir();
        root.push(format!(
            "ironmesh-folder-agent-state-test-{}-{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn remove_sqlite_sidecars(path: &Path) {
        let _ = fs::remove_file(path);
        let wal = PathBuf::from(format!("{}-wal", path.display()));
        let shm = PathBuf::from(format!("{}-shm", path.display()));
        let _ = fs::remove_file(wal);
        let _ = fs::remove_file(shm);
    }

    fn ensure_parent_dir(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
    }
}
