use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use bytes::{Bytes, BytesMut};
use common::{CacheEntry, StorageObjectMeta};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::fs;
use uuid::Uuid;

use crate::ironmesh_client::{IronMeshClient, UploadResult};

const CACHE_CHUNK_SIZE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ContentAddressedClientCache {
    client: IronMeshClient,
    storage: Arc<CacheStorage>,
}

#[derive(Debug)]
struct CacheStorage {
    root_dir: PathBuf,
    chunks_dir: PathBuf,
    manifests_dir: PathBuf,
    db_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedManifest {
    total_size_bytes: usize,
    chunks: Vec<CachedChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedChunkRef {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Clone)]
struct ManifestRecord {
    hash: String,
    total_size_bytes: usize,
    chunks: Vec<CachedChunkRef>,
}

#[derive(Debug)]
struct KeyEntryRecord {
    manifest_hash: String,
    size_bytes: usize,
}

#[derive(Debug, Default)]
struct GarbageCollectionPlan {
    manifest_hashes: Vec<String>,
    chunk_hashes: Vec<String>,
}

impl ContentAddressedClientCache {
    pub fn new(
        server_base_url: impl Into<String>,
        storage_path: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::with_client(IronMeshClient::new(server_base_url), storage_path)
    }

    pub fn with_http_client(
        server_base_url: impl Into<String>,
        storage_path: impl Into<PathBuf>,
        http: reqwest::Client,
    ) -> Result<Self> {
        Self::with_client(
            IronMeshClient::with_http_client(server_base_url, http),
            storage_path,
        )
    }

    pub fn with_client(client: IronMeshClient, storage_path: impl Into<PathBuf>) -> Result<Self> {
        let storage = Arc::new(CacheStorage::init(storage_path.into())?);
        Ok(Self { client, storage })
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let meta = self.client.put(key.clone(), data.clone()).await?;
        self.cache_latest(&key, data).await?;
        Ok(meta)
    }

    pub async fn put_large_aware(
        &self,
        key: impl Into<String>,
        data: Bytes,
    ) -> Result<UploadResult> {
        let key = key.into();
        let report = self
            .client
            .put_large_aware(key.clone(), data.clone())
            .await?;
        self.cache_latest(&key, data).await?;
        Ok(report)
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        let key = key.as_ref();
        let payload = self.client.get(key).await?;
        self.cache_latest(key, payload.clone()).await?;
        Ok(payload)
    }

    pub async fn get_cached_or_fetch(&self, key: impl AsRef<str>) -> Result<Bytes> {
        let key = key.as_ref();
        match self.try_get_cached(key).await {
            Ok(Some(payload)) => Ok(payload),
            Ok(None) => self.get(key).await,
            Err(_) => self.get(key).await,
        }
    }

    pub async fn get_with_selector(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<Bytes> {
        let key = key.as_ref();
        let payload = self
            .client
            .get_with_selector(key, snapshot, version)
            .await?;

        if snapshot.is_none() && version.is_none() {
            self.cache_latest(key, payload.clone()).await?;
        }

        Ok(payload)
    }

    pub async fn rename_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        self.client
            .rename_path(from_path.clone(), to_path.clone(), overwrite)
            .await?;
        let gc_plan = self
            .storage
            .rename_key(from_path, to_path, overwrite)
            .await?;
        self.storage.apply_gc_plan(gc_plan).await?;
        Ok(())
    }

    pub async fn copy_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        self.client
            .copy_path(from_path.clone(), to_path.clone(), overwrite)
            .await?;
        let gc_plan = self
            .storage
            .copy_key(&from_path, to_path, overwrite)
            .await?;
        self.storage.apply_gc_plan(gc_plan).await?;
        Ok(())
    }

    pub async fn delete_path(&self, key: impl Into<String>) -> Result<()> {
        let key = key.into();
        self.client.delete_path(&key).await?;
        let gc_plan = self.storage.remove_key(&key).await?;
        self.storage.apply_gc_plan(gc_plan).await?;
        Ok(())
    }

    pub fn put_chunked_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
    ) -> Result<UploadResult> {
        let key = key.into();
        let report = self.client.put_chunked_reader(key.clone(), reader)?;
        let storage = Arc::clone(&self.storage);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for cache invalidation")?;
        runtime.block_on(async move {
            let gc_plan = storage.remove_key(&key).await?;
            storage.apply_gc_plan(gc_plan).await
        })?;
        Ok(report)
    }

    pub fn get_with_selector_writer(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn std::io::Write,
    ) -> Result<()> {
        self.client
            .get_with_selector_writer(key, snapshot, version, writer)
    }

    pub async fn cache_entries(&self) -> Result<Vec<CacheEntry>> {
        self.storage.list_entries().await
    }

    pub async fn remove_cached(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref();
        if self.storage.lookup_key(key).await?.is_none() {
            return Err(anyhow!("cache key not present: {key}"));
        }
        let gc_plan = self.storage.remove_key(key).await?;
        self.storage.apply_gc_plan(gc_plan).await?;
        Ok(())
    }

    async fn cache_latest(&self, key: &str, data: Bytes) -> Result<()> {
        let manifest = self.storage.persist_payload(&data).await?;
        let gc_plan = self.storage.upsert_key(key, manifest).await?;
        self.storage.apply_gc_plan(gc_plan).await
    }

    async fn try_get_cached(&self, key: &str) -> Result<Option<Bytes>> {
        let Some(entry) = self.storage.lookup_key(key).await? else {
            return Ok(None);
        };
        let manifest = self.storage.load_manifest(&entry.manifest_hash).await?;
        if manifest.total_size_bytes != entry.size_bytes {
            return Err(anyhow!(
                "cache metadata mismatch for key={key}: entry_size={} manifest_size={}",
                entry.size_bytes,
                manifest.total_size_bytes
            ));
        }
        let payload = self.storage.read_manifest_payload(&manifest).await?;
        Ok(Some(payload))
    }
}

impl CacheStorage {
    fn init(root_dir: PathBuf) -> Result<Self> {
        let chunks_dir = root_dir.join("chunks");
        let manifests_dir = root_dir.join("manifests");
        let state_dir = root_dir.join("state");
        let db_path = state_dir.join("cache.sqlite3");

        std::fs::create_dir_all(&chunks_dir)
            .with_context(|| format!("failed creating {}", chunks_dir.display()))?;
        std::fs::create_dir_all(&manifests_dir)
            .with_context(|| format!("failed creating {}", manifests_dir.display()))?;
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed creating {}", state_dir.display()))?;

        let connection = Connection::open(&db_path)
            .with_context(|| format!("failed opening {}", db_path.display()))?;
        configure_connection(&connection)?;
        init_schema(&connection)?;

        Ok(Self {
            root_dir,
            chunks_dir,
            manifests_dir,
            db_path,
        })
    }

    async fn persist_payload(&self, payload: &Bytes) -> Result<ManifestRecord> {
        let mut chunks = Vec::new();
        for chunk in payload.chunks(CACHE_CHUNK_SIZE_BYTES) {
            let hash = hash_hex(chunk);
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &hash);
            if !fs::try_exists(&chunk_path).await? {
                if let Some(parent) = chunk_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                write_atomic(&chunk_path, chunk).await?;
            }
            chunks.push(CachedChunkRef {
                hash,
                size_bytes: chunk.len(),
            });
        }

        let manifest = CachedManifest {
            total_size_bytes: payload.len(),
            chunks: chunks.clone(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_hash = hash_hex(&manifest_bytes);
        let manifest_path = manifest_path_for_hash(&self.manifests_dir, &manifest_hash);
        if !fs::try_exists(&manifest_path).await? {
            if let Some(parent) = manifest_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            write_atomic(&manifest_path, &manifest_bytes).await?;
        }

        Ok(ManifestRecord {
            hash: manifest_hash,
            total_size_bytes: payload.len(),
            chunks,
        })
    }

    async fn upsert_key(
        &self,
        key: &str,
        manifest: ManifestRecord,
    ) -> Result<GarbageCollectionPlan> {
        let db_path = self.db_path.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let mut connection = open_connection(&db_path)?;
            let tx = connection.transaction()?;

            let existing_manifest_hash = tx
                .query_row(
                    "SELECT manifest_hash FROM cache_entries WHERE key = ?1",
                    params![key],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;

            if existing_manifest_hash.as_deref() == Some(manifest.hash.as_str()) {
                tx.execute(
                    "UPDATE cache_entries
                     SET size_bytes = ?2, updated_at_unix = ?3
                     WHERE key = ?1",
                    params![key, manifest.total_size_bytes as i64, unix_ts() as i64],
                )?;
                tx.commit()?;
                return Ok(GarbageCollectionPlan::default());
            }

            let manifest_exists = tx
                .query_row(
                    "SELECT 1 FROM manifests WHERE manifest_hash = ?1",
                    params![manifest.hash],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();

            if manifest_exists {
                tx.execute(
                    "UPDATE manifests
                     SET ref_count = ref_count + 1
                     WHERE manifest_hash = ?1",
                    params![manifest.hash],
                )?;
            } else {
                tx.execute(
                    "INSERT INTO manifests (manifest_hash, total_size_bytes, ref_count, created_at_unix)
                     VALUES (?1, ?2, 1, ?3)",
                    params![
                        manifest.hash,
                        manifest.total_size_bytes as i64,
                        unix_ts() as i64
                    ],
                )?;
                for (index, chunk) in manifest.chunks.iter().enumerate() {
                    tx.execute(
                        "INSERT INTO manifest_chunks (manifest_hash, chunk_index, chunk_hash, size_bytes)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            manifest.hash,
                            index as i64,
                            chunk.hash,
                            chunk.size_bytes as i64
                        ],
                    )?;
                    tx.execute(
                        "INSERT INTO chunks (chunk_hash, size_bytes, ref_count, created_at_unix)
                         VALUES (?1, ?2, 1, ?3)
                         ON CONFLICT(chunk_hash) DO UPDATE SET ref_count = ref_count + 1",
                        params![chunk.hash, chunk.size_bytes as i64, unix_ts() as i64],
                    )?;
                }
            }

            tx.execute(
                "INSERT INTO cache_entries (key, manifest_hash, size_bytes, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key) DO UPDATE SET
                     manifest_hash = excluded.manifest_hash,
                     size_bytes = excluded.size_bytes,
                     updated_at_unix = excluded.updated_at_unix",
                params![
                    key,
                    manifest.hash,
                    manifest.total_size_bytes as i64,
                    unix_ts() as i64
                ],
            )?;

            let gc_plan = if let Some(existing_manifest_hash) = existing_manifest_hash {
                release_manifest_reference(&tx, &existing_manifest_hash)?
            } else {
                GarbageCollectionPlan::default()
            };

            tx.commit()?;
            Ok(gc_plan)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn lookup_key(&self, key: &str) -> Result<Option<KeyEntryRecord>> {
        let db_path = self.db_path.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = open_connection(&db_path)?;
            let row = connection
                .query_row(
                    "SELECT manifest_hash, size_bytes FROM cache_entries WHERE key = ?1",
                    params![key],
                    |row| {
                        Ok(KeyEntryRecord {
                            manifest_hash: row.get(0)?,
                            size_bytes: row.get::<_, i64>(1)? as usize,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn load_manifest(&self, manifest_hash: &str) -> Result<ManifestRecord> {
        let db_path = self.db_path.clone();
        let manifest_hash = manifest_hash.to_string();
        tokio::task::spawn_blocking(move || {
            let connection = open_connection(&db_path)?;
            let total_size_bytes = connection
                .query_row(
                    "SELECT total_size_bytes FROM manifests WHERE manifest_hash = ?1",
                    params![manifest_hash],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or_else(|| anyhow!("manifest not present in cache metadata"))?
                as usize;

            let mut stmt = connection.prepare(
                "SELECT chunk_hash, size_bytes
                 FROM manifest_chunks
                 WHERE manifest_hash = ?1
                 ORDER BY chunk_index ASC",
            )?;
            let rows = stmt.query_map(params![manifest_hash], |row| {
                Ok(CachedChunkRef {
                    hash: row.get(0)?,
                    size_bytes: row.get::<_, i64>(1)? as usize,
                })
            })?;

            let mut chunks = Vec::new();
            for row in rows {
                chunks.push(row?);
            }

            Ok(ManifestRecord {
                hash: manifest_hash,
                total_size_bytes,
                chunks,
            })
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn read_manifest_payload(&self, manifest: &ManifestRecord) -> Result<Bytes> {
        let mut assembled = BytesMut::with_capacity(manifest.total_size_bytes);
        for chunk in &manifest.chunks {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk.hash);
            let payload = fs::read(&chunk_path)
                .await
                .with_context(|| format!("failed reading cache chunk {}", chunk_path.display()))?;
            if payload.len() != chunk.size_bytes {
                return Err(anyhow!(
                    "cache chunk size mismatch hash={} expected={} actual={}",
                    chunk.hash,
                    chunk.size_bytes,
                    payload.len()
                ));
            }
            let actual_hash = hash_hex(&payload);
            if actual_hash != chunk.hash {
                return Err(anyhow!(
                    "cache chunk hash mismatch expected={} actual={}",
                    chunk.hash,
                    actual_hash
                ));
            }
            assembled.extend_from_slice(&payload);
        }

        if assembled.len() != manifest.total_size_bytes {
            return Err(anyhow!(
                "cache manifest size mismatch expected={} actual={}",
                manifest.total_size_bytes,
                assembled.len()
            ));
        }

        Ok(assembled.freeze())
    }

    async fn rename_key(
        &self,
        from_key: String,
        to_key: String,
        overwrite: bool,
    ) -> Result<GarbageCollectionPlan> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = open_connection(&db_path)?;
            let tx = connection.transaction()?;

            let source = tx
                .query_row(
                    "SELECT manifest_hash, size_bytes FROM cache_entries WHERE key = ?1",
                    params![from_key],
                    |row| {
                        Ok(KeyEntryRecord {
                            manifest_hash: row.get(0)?,
                            size_bytes: row.get::<_, i64>(1)? as usize,
                        })
                    },
                )
                .optional()?;

            let Some(source) = source else {
                tx.commit()?;
                return Ok(GarbageCollectionPlan::default());
            };

            let mut gc_plan = if overwrite {
                remove_key_inner(&tx, &to_key)?
            } else {
                GarbageCollectionPlan::default()
            };

            tx.execute(
                "DELETE FROM cache_entries WHERE key = ?1",
                params![from_key],
            )?;
            tx.execute(
                "INSERT INTO cache_entries (key, manifest_hash, size_bytes, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key) DO UPDATE SET
                     manifest_hash = excluded.manifest_hash,
                     size_bytes = excluded.size_bytes,
                     updated_at_unix = excluded.updated_at_unix",
                params![
                    to_key,
                    source.manifest_hash,
                    source.size_bytes as i64,
                    unix_ts() as i64
                ],
            )?;

            gc_plan.manifest_hashes.sort();
            gc_plan.manifest_hashes.dedup();
            gc_plan.chunk_hashes.sort();
            gc_plan.chunk_hashes.dedup();

            tx.commit()?;
            Ok(gc_plan)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn copy_key(
        &self,
        from_key: &str,
        to_key: String,
        overwrite: bool,
    ) -> Result<GarbageCollectionPlan> {
        let db_path = self.db_path.clone();
        let from_key = from_key.to_string();
        tokio::task::spawn_blocking(move || {
            let mut connection = open_connection(&db_path)?;
            let tx = connection.transaction()?;

            let source = tx
                .query_row(
                    "SELECT manifest_hash, size_bytes FROM cache_entries WHERE key = ?1",
                    params![from_key],
                    |row| {
                        Ok(KeyEntryRecord {
                            manifest_hash: row.get(0)?,
                            size_bytes: row.get::<_, i64>(1)? as usize,
                        })
                    },
                )
                .optional()?;

            let Some(source) = source else {
                tx.commit()?;
                return Ok(GarbageCollectionPlan::default());
            };

            let mut gc_plan = if overwrite {
                remove_key_inner(&tx, &to_key)?
            } else {
                GarbageCollectionPlan::default()
            };

            tx.execute(
                "UPDATE manifests
                 SET ref_count = ref_count + 1
                 WHERE manifest_hash = ?1",
                params![source.manifest_hash],
            )?;
            tx.execute(
                "INSERT INTO cache_entries (key, manifest_hash, size_bytes, updated_at_unix)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(key) DO UPDATE SET
                     manifest_hash = excluded.manifest_hash,
                     size_bytes = excluded.size_bytes,
                     updated_at_unix = excluded.updated_at_unix",
                params![
                    to_key,
                    source.manifest_hash,
                    source.size_bytes as i64,
                    unix_ts() as i64
                ],
            )?;

            gc_plan.manifest_hashes.sort();
            gc_plan.manifest_hashes.dedup();
            gc_plan.chunk_hashes.sort();
            gc_plan.chunk_hashes.dedup();

            tx.commit()?;
            Ok(gc_plan)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn remove_key(&self, key: &str) -> Result<GarbageCollectionPlan> {
        let db_path = self.db_path.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let mut connection = open_connection(&db_path)?;
            let tx = connection.transaction()?;
            let gc_plan = remove_key_inner(&tx, &key)?;
            tx.commit()?;
            Ok(gc_plan)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn list_entries(&self) -> Result<Vec<CacheEntry>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || {
            let connection = open_connection(&db_path)?;
            let mut stmt = connection.prepare(
                "SELECT key, size_bytes
                 FROM cache_entries
                 ORDER BY key ASC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(CacheEntry {
                    key: row.get(0)?,
                    size_bytes: row.get::<_, i64>(1)? as usize,
                })
            })?;

            let mut entries = Vec::new();
            for row in rows {
                entries.push(row?);
            }
            Ok(entries)
        })
        .await
        .context("cache metadata task join failed")?
    }

    async fn apply_gc_plan(&self, gc_plan: GarbageCollectionPlan) -> Result<()> {
        for manifest_hash in gc_plan.manifest_hashes {
            let manifest_path = manifest_path_for_hash(&self.manifests_dir, &manifest_hash);
            if fs::try_exists(&manifest_path).await? {
                fs::remove_file(&manifest_path).await?;
            }
        }

        for chunk_hash in gc_plan.chunk_hashes {
            let chunk_path = chunk_path_for_hash(&self.chunks_dir, &chunk_hash);
            if fs::try_exists(&chunk_path).await? {
                fs::remove_file(&chunk_path).await?;
            }
            prune_empty_chunk_dirs(&self.root_dir, &chunk_path).await?;
        }

        Ok(())
    }
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;",
    )?;
    Ok(())
}

fn init_schema(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS cache_entries (
             key TEXT PRIMARY KEY,
             manifest_hash TEXT NOT NULL,
             size_bytes INTEGER NOT NULL,
             updated_at_unix INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS manifests (
             manifest_hash TEXT PRIMARY KEY,
             total_size_bytes INTEGER NOT NULL,
             ref_count INTEGER NOT NULL,
             created_at_unix INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS manifest_chunks (
             manifest_hash TEXT NOT NULL,
             chunk_index INTEGER NOT NULL,
             chunk_hash TEXT NOT NULL,
             size_bytes INTEGER NOT NULL,
             PRIMARY KEY (manifest_hash, chunk_index)
         );
         CREATE TABLE IF NOT EXISTS chunks (
             chunk_hash TEXT PRIMARY KEY,
             size_bytes INTEGER NOT NULL,
             ref_count INTEGER NOT NULL,
             created_at_unix INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_manifest_chunks_chunk_hash
             ON manifest_chunks(chunk_hash);",
    )?;
    Ok(())
}

fn open_connection(db_path: &Path) -> Result<Connection> {
    let connection = Connection::open(db_path)
        .with_context(|| format!("failed opening {}", db_path.display()))?;
    configure_connection(&connection)?;
    Ok(connection)
}

fn remove_key_inner(tx: &rusqlite::Transaction<'_>, key: &str) -> Result<GarbageCollectionPlan> {
    let manifest_hash = tx
        .query_row(
            "SELECT manifest_hash FROM cache_entries WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    let Some(manifest_hash) = manifest_hash else {
        return Ok(GarbageCollectionPlan::default());
    };

    tx.execute("DELETE FROM cache_entries WHERE key = ?1", params![key])?;
    release_manifest_reference(tx, &manifest_hash)
}

fn release_manifest_reference(
    tx: &rusqlite::Transaction<'_>,
    manifest_hash: &str,
) -> Result<GarbageCollectionPlan> {
    let ref_count = tx
        .query_row(
            "SELECT ref_count FROM manifests WHERE manifest_hash = ?1",
            params![manifest_hash],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;

    let Some(ref_count) = ref_count else {
        return Ok(GarbageCollectionPlan::default());
    };

    if ref_count > 1 {
        tx.execute(
            "UPDATE manifests SET ref_count = ref_count - 1 WHERE manifest_hash = ?1",
            params![manifest_hash],
        )?;
        return Ok(GarbageCollectionPlan::default());
    }

    let mut stmt = tx.prepare(
        "SELECT chunk_hash FROM manifest_chunks
         WHERE manifest_hash = ?1
         ORDER BY chunk_index ASC",
    )?;
    let rows = stmt.query_map(params![manifest_hash], |row| row.get::<_, String>(0))?;

    let mut chunk_hashes = Vec::new();
    for row in rows {
        chunk_hashes.push(row?);
    }
    drop(stmt);

    tx.execute(
        "DELETE FROM manifest_chunks WHERE manifest_hash = ?1",
        params![manifest_hash],
    )?;
    tx.execute(
        "DELETE FROM manifests WHERE manifest_hash = ?1",
        params![manifest_hash],
    )?;

    let mut gc_plan = GarbageCollectionPlan {
        manifest_hashes: vec![manifest_hash.to_string()],
        chunk_hashes: Vec::new(),
    };

    for chunk_hash in chunk_hashes {
        let ref_count = tx
            .query_row(
                "SELECT ref_count FROM chunks WHERE chunk_hash = ?1",
                params![chunk_hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;

        let Some(ref_count) = ref_count else {
            continue;
        };

        if ref_count > 1 {
            tx.execute(
                "UPDATE chunks SET ref_count = ref_count - 1 WHERE chunk_hash = ?1",
                params![chunk_hash],
            )?;
        } else {
            tx.execute(
                "DELETE FROM chunks WHERE chunk_hash = ?1",
                params![chunk_hash],
            )?;
            gc_plan.chunk_hashes.push(chunk_hash);
        }
    }

    Ok(gc_plan)
}

fn hash_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn chunk_path_for_hash(chunks_dir: &Path, hash: &str) -> PathBuf {
    chunks_dir.join(&hash[..2]).join(&hash[2..4]).join(hash)
}

fn manifest_path_for_hash(manifests_dir: &Path, hash: &str) -> PathBuf {
    manifests_dir.join(format!("{hash}.json"))
}

async fn write_atomic(path: &Path, payload: &[u8]) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("path has no parent: {}", path.display()));
    };
    fs::create_dir_all(parent).await?;

    let temp_path = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    fs::write(&temp_path, payload).await?;
    fs::rename(&temp_path, path).await?;
    Ok(())
}

async fn prune_empty_chunk_dirs(root_dir: &Path, chunk_path: &Path) -> Result<()> {
    let mut current = chunk_path.parent().map(Path::to_path_buf);
    while let Some(path) = current {
        if path == root_dir {
            break;
        }
        match fs::remove_dir(&path).await {
            Ok(()) => current = path.parent().map(Path::to_path_buf),
            Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                current = path.parent().map(Path::to_path_buf)
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
