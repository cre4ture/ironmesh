use anyhow::{Context, Result, anyhow};
use client_sdk::{IronMeshClient, RequestedRange, ironmesh_client::DownloadRangeRequest};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use sqlite_vfs::{DatabaseHandle, LockKind, OpenAccess, OpenKind, OpenOptions, Vfs};
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::info;

use crate::LoadedSplitLogicalFileManifest;

const SQLITE_RANGE_CACHE_CHUNK_BYTES: u64 = 1024 * 1024;
const SQLITE_RANGE_CACHE_MAX_CHUNKS: usize = 1024;

static NEXT_VFS_ID: AtomicU64 = AtomicU64::new(1);

std::thread_local! {
    static ACTIVE_TILE_LOOKUP_PERF_STATS: RefCell<Option<Rc<RefCell<MbtilesTileLookupPerfStats>>>> =
        const { RefCell::new(None) };
    static ACTIVE_TILE_LOOKUP_CANCELLATION: RefCell<Option<Arc<AtomicBool>>> =
        const { RefCell::new(None) };
}

#[derive(Clone, Debug, Default)]
struct MbtilesTileLookupPerfStats {
    vfs_reads: u64,
    vfs_bytes: u64,
    vfs_read_elapsed_ms: u64,
    chunk_cache_hits: u64,
    chunk_cache_misses: u64,
    logical_range_requests: u64,
    logical_range_bytes: u64,
    logical_range_elapsed_ms: u64,
    segment_downloads: u64,
    segment_bytes: u64,
    segment_download_elapsed_ms: u64,
}

struct ActiveTileLookupPerfGuard {
    previous: Option<Rc<RefCell<MbtilesTileLookupPerfStats>>>,
}

impl ActiveTileLookupPerfGuard {
    fn install(
        current: Option<Rc<RefCell<MbtilesTileLookupPerfStats>>>,
    ) -> ActiveTileLookupPerfGuard {
        let previous = ACTIVE_TILE_LOOKUP_PERF_STATS.with(|slot| {
            let mut slot = slot.borrow_mut();
            let previous = slot.take();
            *slot = current;
            previous
        });
        ActiveTileLookupPerfGuard { previous }
    }
}

impl Drop for ActiveTileLookupPerfGuard {
    fn drop(&mut self) {
        ACTIVE_TILE_LOOKUP_PERF_STATS.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

struct ActiveTileLookupCancellationGuard {
    previous: Option<Arc<AtomicBool>>,
}

impl ActiveTileLookupCancellationGuard {
    fn install(current: Option<Arc<AtomicBool>>) -> ActiveTileLookupCancellationGuard {
        let previous = ACTIVE_TILE_LOOKUP_CANCELLATION.with(|slot| {
            let mut slot = slot.borrow_mut();
            let previous = slot.take();
            *slot = current;
            previous
        });
        ActiveTileLookupCancellationGuard { previous }
    }
}

impl Drop for ActiveTileLookupCancellationGuard {
    fn drop(&mut self) {
        ACTIVE_TILE_LOOKUP_CANCELLATION.with(|slot| {
            *slot.borrow_mut() = self.previous.take();
        });
    }
}

fn record_active_tile_lookup_perf_stats(update: impl FnOnce(&mut MbtilesTileLookupPerfStats)) {
    ACTIVE_TILE_LOOKUP_PERF_STATS.with(|slot| {
        let stats = slot.borrow().as_ref().cloned();
        if let Some(stats) = stats {
            update(&mut stats.borrow_mut());
        }
    });
}

fn active_tile_lookup_is_cancelled() -> bool {
    ACTIVE_TILE_LOOKUP_CANCELLATION.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|cancelled| cancelled.load(Ordering::Relaxed))
            .unwrap_or(false)
    })
}

fn ensure_active_tile_lookup_not_cancelled() -> Result<(), Error> {
    if active_tile_lookup_is_cancelled() {
        return Err(Error::new(
            ErrorKind::Interrupted,
            "logical MBTiles tile lookup canceled",
        ));
    }
    Ok(())
}

fn canceled_anyhow(message: &'static str) -> anyhow::Error {
    anyhow::Error::new(Error::new(ErrorKind::Interrupted, message))
}

#[derive(Clone, Debug)]
pub(crate) struct MbtilesMetadata {
    pub(crate) attribution: Option<String>,
    pub(crate) center: Option<[f64; 3]>,
    pub(crate) format: Option<String>,
    pub(crate) id: Option<String>,
    pub(crate) minzoom: Option<u8>,
    pub(crate) maxzoom: Option<u8>,
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
}

#[derive(Clone)]
pub(crate) struct LogicalMbtilesSource {
    manifest_key: String,
    perf_logging_enabled: bool,
    vfs_name: String,
    metadata: MbtilesMetadata,
}

impl LogicalMbtilesSource {
    pub(crate) fn new(
        manifest_key: String,
        sdk: IronMeshClient,
        loaded_manifest: LoadedSplitLogicalFileManifest,
        perf_logging_enabled: bool,
    ) -> Result<Self> {
        let shared = Arc::new(LogicalFileSharedState {
            manifest_key: manifest_key.clone(),
            perf_logging_enabled,
            sdk,
            loaded_manifest,
            chunk_size_bytes: SQLITE_RANGE_CACHE_CHUNK_BYTES,
            cache: Mutex::new(LogicalFileChunkCache::default()),
        });
        let vfs_name = format!(
            "ironmesh-mbtiles-{}",
            NEXT_VFS_ID.fetch_add(1, Ordering::Relaxed)
        );
        sqlite_vfs::register(
            &vfs_name,
            LogicalFileVfs {
                manifest_key: manifest_key.clone(),
                shared: Arc::clone(&shared),
            },
            false,
        )
        .with_context(|| format!("failed registering SQLite VFS {vfs_name}"))?;

        let source = Self {
            manifest_key,
            perf_logging_enabled,
            vfs_name,
            metadata: MbtilesMetadata {
                attribution: None,
                center: None,
                format: None,
                id: None,
                minzoom: None,
                maxzoom: None,
                name: None,
                version: None,
            },
        };

        let metadata = source.load_metadata()?;
        Ok(Self { metadata, ..source })
    }

    pub(crate) fn metadata(&self) -> &MbtilesMetadata {
        &self.metadata
    }

    pub(crate) fn lookup_tile_with_cancellation(
        &self,
        zoom: u32,
        x: u32,
        y_xyz: u32,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<TilePayload>> {
        self.lookup_tile_with_optional_cancellation(zoom, x, y_xyz, Some(cancelled))
    }

    fn lookup_tile_with_optional_cancellation(
        &self,
        zoom: u32,
        x: u32,
        y_xyz: u32,
        cancelled: Option<Arc<AtomicBool>>,
    ) -> Result<Option<TilePayload>> {
        Ok(self
            .lookup_tile_bytes(zoom, x, y_xyz, cancelled)?
            .map(|bytes| TilePayload {
                content_type: infer_tile_mime_type(&bytes, self.metadata.format.as_deref()),
                content_encoding: None,
                bytes,
            }))
    }

    pub(crate) fn lookup_vector_tile_with_cancellation(
        &self,
        zoom: u32,
        x: u32,
        y_xyz: u32,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Option<TilePayload>> {
        self.lookup_vector_tile_with_optional_cancellation(zoom, x, y_xyz, Some(cancelled))
    }

    fn lookup_vector_tile_with_optional_cancellation(
        &self,
        zoom: u32,
        x: u32,
        y_xyz: u32,
        cancelled: Option<Arc<AtomicBool>>,
    ) -> Result<Option<TilePayload>> {
        Ok(self
            .lookup_tile_bytes(zoom, x, y_xyz, cancelled)?
            .map(|bytes| TilePayload {
                content_type: "application/vnd.mapbox-vector-tile",
                content_encoding: infer_vector_tile_content_encoding(&bytes),
                bytes,
            }))
    }

    fn load_metadata(&self) -> Result<MbtilesMetadata> {
        let started = Instant::now();
        let connection = self.open_connection()?;
        let mut statement = connection
            .prepare("select name, value from metadata")
            .context("failed preparing MBTiles metadata query")?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .context("failed executing MBTiles metadata query")?;

        let mut raw = HashMap::new();
        for row in rows {
            let (name, value) = row.context("failed reading MBTiles metadata row")?;
            raw.insert(name, value);
        }

        let metadata = MbtilesMetadata {
            attribution: raw.get("attribution").cloned(),
            center: raw.get("center").and_then(|value| parse_center(value)),
            format: raw.get("format").cloned(),
            id: raw.get("id").cloned(),
            minzoom: raw
                .get("minzoom")
                .and_then(|value| value.parse::<u8>().ok()),
            maxzoom: raw
                .get("maxzoom")
                .and_then(|value| value.parse::<u8>().ok()),
            name: raw.get("name").cloned(),
            version: raw.get("version").cloned(),
        };
        if self.perf_logging_enabled {
            info!(
                manifest_key = %self.manifest_key,
                elapsed_ms = started.elapsed().as_millis() as u64,
                metadata_rows = raw.len(),
                "map perf: loaded MBTiles metadata table"
            );
        }
        Ok(metadata)
    }

    fn lookup_tile_bytes(
        &self,
        zoom: u32,
        x: u32,
        y_xyz: u32,
        cancelled: Option<Arc<AtomicBool>>,
    ) -> Result<Option<Vec<u8>>> {
        let total_started = Instant::now();
        let tms_y = xyz_row_to_tms(zoom, y_xyz)?;
        let perf_stats = self
            .perf_logging_enabled
            .then(|| Rc::new(RefCell::new(MbtilesTileLookupPerfStats::default())));
        let _perf_guard = ActiveTileLookupPerfGuard::install(perf_stats.clone());
        let _cancellation_guard = ActiveTileLookupCancellationGuard::install(cancelled);

        let open_started = Instant::now();
        let connection = match self.open_connection() {
            Ok(connection) => connection,
            Err(error) => {
                if self.perf_logging_enabled {
                    let perf_stats = perf_stats
                        .as_ref()
                        .map(|stats| stats.borrow().clone())
                        .unwrap_or_default();
                    info!(
                        manifest_key = %self.manifest_key,
                        z = zoom,
                        x,
                        y = y_xyz,
                        error = %error,
                        elapsed_ms = total_started.elapsed().as_millis() as u64,
                        sqlite_open_ms = open_started.elapsed().as_millis() as u64,
                        sqlite_query_ms = 0_u64,
                        vfs_reads = perf_stats.vfs_reads,
                        vfs_bytes = perf_stats.vfs_bytes,
                        vfs_read_elapsed_ms = perf_stats.vfs_read_elapsed_ms,
                        chunk_cache_hits = perf_stats.chunk_cache_hits,
                        chunk_cache_misses = perf_stats.chunk_cache_misses,
                        logical_range_requests = perf_stats.logical_range_requests,
                        logical_range_bytes = perf_stats.logical_range_bytes,
                        logical_range_elapsed_ms = perf_stats.logical_range_elapsed_ms,
                        segment_downloads = perf_stats.segment_downloads,
                        segment_bytes = perf_stats.segment_bytes,
                        segment_download_elapsed_ms = perf_stats.segment_download_elapsed_ms,
                        "map perf: MBTiles tile lookup failed"
                    );
                }
                return Err(error);
            }
        };
        let sqlite_open_ms = open_started.elapsed().as_millis() as u64;
        let query_started = Instant::now();
        let result = connection
            .query_row(
                "select tile_data from tiles where zoom_level = ?1 and tile_column = ?2 and tile_row = ?3 limit 1",
                params![i64::from(zoom), i64::from(x), i64::from(tms_y)],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .context("failed querying MBTiles tile");
        let sqlite_query_ms = query_started.elapsed().as_millis() as u64;
        if self.perf_logging_enabled {
            let perf_stats = perf_stats
                .as_ref()
                .map(|stats| stats.borrow().clone())
                .unwrap_or_default();
            match &result {
                Ok(Some(bytes)) => info!(
                    manifest_key = %self.manifest_key,
                    z = zoom,
                    x,
                    y = y_xyz,
                    bytes = bytes.len(),
                    elapsed_ms = total_started.elapsed().as_millis() as u64,
                    sqlite_open_ms,
                    sqlite_query_ms,
                    vfs_reads = perf_stats.vfs_reads,
                    vfs_bytes = perf_stats.vfs_bytes,
                    vfs_read_elapsed_ms = perf_stats.vfs_read_elapsed_ms,
                    chunk_cache_hits = perf_stats.chunk_cache_hits,
                    chunk_cache_misses = perf_stats.chunk_cache_misses,
                    logical_range_requests = perf_stats.logical_range_requests,
                    logical_range_bytes = perf_stats.logical_range_bytes,
                    logical_range_elapsed_ms = perf_stats.logical_range_elapsed_ms,
                    segment_downloads = perf_stats.segment_downloads,
                    segment_bytes = perf_stats.segment_bytes,
                    segment_download_elapsed_ms = perf_stats.segment_download_elapsed_ms,
                    "map perf: looked up MBTiles tile"
                ),
                Ok(None) => info!(
                    manifest_key = %self.manifest_key,
                    z = zoom,
                    x,
                    y = y_xyz,
                    elapsed_ms = total_started.elapsed().as_millis() as u64,
                    sqlite_open_ms,
                    sqlite_query_ms,
                    vfs_reads = perf_stats.vfs_reads,
                    vfs_bytes = perf_stats.vfs_bytes,
                    vfs_read_elapsed_ms = perf_stats.vfs_read_elapsed_ms,
                    chunk_cache_hits = perf_stats.chunk_cache_hits,
                    chunk_cache_misses = perf_stats.chunk_cache_misses,
                    logical_range_requests = perf_stats.logical_range_requests,
                    logical_range_bytes = perf_stats.logical_range_bytes,
                    logical_range_elapsed_ms = perf_stats.logical_range_elapsed_ms,
                    segment_downloads = perf_stats.segment_downloads,
                    segment_bytes = perf_stats.segment_bytes,
                    segment_download_elapsed_ms = perf_stats.segment_download_elapsed_ms,
                    "map perf: MBTiles tile lookup missed"
                ),
                Err(error) => info!(
                    manifest_key = %self.manifest_key,
                    z = zoom,
                    x,
                    y = y_xyz,
                    error = %error,
                    elapsed_ms = total_started.elapsed().as_millis() as u64,
                    sqlite_open_ms,
                    sqlite_query_ms,
                    vfs_reads = perf_stats.vfs_reads,
                    vfs_bytes = perf_stats.vfs_bytes,
                    vfs_read_elapsed_ms = perf_stats.vfs_read_elapsed_ms,
                    chunk_cache_hits = perf_stats.chunk_cache_hits,
                    chunk_cache_misses = perf_stats.chunk_cache_misses,
                    logical_range_requests = perf_stats.logical_range_requests,
                    logical_range_bytes = perf_stats.logical_range_bytes,
                    logical_range_elapsed_ms = perf_stats.logical_range_elapsed_ms,
                    segment_downloads = perf_stats.segment_downloads,
                    segment_bytes = perf_stats.segment_bytes,
                    segment_download_elapsed_ms = perf_stats.segment_download_elapsed_ms,
                    "map perf: MBTiles tile lookup failed"
                ),
            }
        }
        result
    }

    fn open_connection(&self) -> Result<Connection> {
        Connection::open_with_flags_and_vfs(
            &self.manifest_key,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            &self.vfs_name,
        )
        .with_context(|| {
            format!(
                "failed opening MBTiles connection via VFS {} for {}",
                self.vfs_name, self.manifest_key
            )
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct TilePayload {
    pub(crate) content_encoding: Option<&'static str>,
    pub(crate) content_type: &'static str,
    pub(crate) bytes: Vec<u8>,
}

struct LogicalFileSharedState {
    manifest_key: String,
    perf_logging_enabled: bool,
    sdk: IronMeshClient,
    loaded_manifest: LoadedSplitLogicalFileManifest,
    chunk_size_bytes: u64,
    cache: Mutex<LogicalFileChunkCache>,
}

impl LogicalFileSharedState {
    fn file_size_bytes(&self) -> u64 {
        self.loaded_manifest.manifest.logical_size_bytes
    }

    fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> Result<(), Error> {
        ensure_active_tile_lookup_not_cancelled()?;
        let started = Instant::now();
        let read_end = offset.checked_add(buffer.len() as u64).ok_or_else(|| {
            Error::new(
                ErrorKind::UnexpectedEof,
                "requested logical-file read overflowed",
            )
        })?;
        if read_end > self.file_size_bytes() {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }

        let mut copied = 0usize;
        let mut cache_hits = 0usize;
        let mut cache_misses = 0usize;
        while copied < buffer.len() {
            ensure_active_tile_lookup_not_cancelled()?;
            let absolute_offset = offset + copied as u64;
            let chunk_index = absolute_offset / self.chunk_size_bytes;
            let (chunk, cache_hit) = self.cached_chunk(chunk_index)?;
            if cache_hit {
                cache_hits += 1;
            } else {
                cache_misses += 1;
            }
            let chunk_offset = (absolute_offset % self.chunk_size_bytes) as usize;
            if chunk_offset >= chunk.len() {
                return Err(Error::from(ErrorKind::UnexpectedEof));
            }
            let available = chunk.len() - chunk_offset;
            let remaining = buffer.len() - copied;
            let to_copy = available.min(remaining);
            buffer[copied..copied + to_copy]
                .copy_from_slice(&chunk[chunk_offset..chunk_offset + to_copy]);
            copied += to_copy;
        }

        let elapsed_ms = started.elapsed().as_millis() as u64;
        record_active_tile_lookup_perf_stats(|stats| {
            stats.vfs_reads += 1;
            stats.vfs_bytes += buffer.len() as u64;
            stats.vfs_read_elapsed_ms += elapsed_ms;
            stats.chunk_cache_hits += cache_hits as u64;
            stats.chunk_cache_misses += cache_misses as u64;
        });

        if self.perf_logging_enabled {
            info!(
                manifest_key = %self.manifest_key,
                offset,
                bytes = buffer.len(),
                cache_hits,
                cache_misses,
                elapsed_ms,
                "map perf: SQLite VFS logical read"
            );
        }

        Ok(())
    }

    fn cached_chunk(&self, chunk_index: u64) -> Result<(Arc<Vec<u8>>, bool), Error> {
        ensure_active_tile_lookup_not_cancelled()?;
        {
            let mut cache = self
                .cache
                .lock()
                .map_err(|_| Error::other("logical-file chunk cache lock poisoned"))?;
            if let Some(bytes) = cache.chunks.get(&chunk_index).cloned() {
                cache.touch(chunk_index);
                return Ok((bytes, true));
            }
        }

        let chunk_start = chunk_index
            .checked_mul(self.chunk_size_bytes)
            .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "chunk offset overflowed"))?;
        let chunk_len = self
            .chunk_size_bytes
            .min(self.file_size_bytes().saturating_sub(chunk_start));
        let started = Instant::now();
        let bytes = download_logical_range_blocking(
            &self.sdk,
            &self.loaded_manifest,
            &self.manifest_key,
            chunk_start,
            chunk_len,
            self.perf_logging_enabled,
        )
        .map_err(other_io_error)?;
        let bytes = Arc::new(bytes);
        let elapsed_ms = started.elapsed().as_millis() as u64;
        record_active_tile_lookup_perf_stats(|stats| {
            stats.logical_range_requests += 1;
            stats.logical_range_bytes += bytes.len() as u64;
            stats.logical_range_elapsed_ms += elapsed_ms;
        });

        let mut cache = self
            .cache
            .lock()
            .map_err(|_| Error::other("logical-file chunk cache lock poisoned"))?;
        cache.insert(chunk_index, Arc::clone(&bytes));
        if self.perf_logging_enabled {
            info!(
                manifest_key = %self.manifest_key,
                chunk_index,
                chunk_start,
                chunk_len = bytes.len(),
                cache_entries = cache.chunks.len(),
                elapsed_ms,
                "map perf: logical-file chunk cache miss"
            );
        }
        Ok((bytes, false))
    }
}

#[derive(Default)]
struct LogicalFileChunkCache {
    chunks: HashMap<u64, Arc<Vec<u8>>>,
    access_order: VecDeque<u64>,
}

impl LogicalFileChunkCache {
    fn insert(&mut self, chunk_index: u64, bytes: Arc<Vec<u8>>) {
        self.chunks.insert(chunk_index, bytes);
        self.touch(chunk_index);

        while self.chunks.len() > SQLITE_RANGE_CACHE_MAX_CHUNKS {
            let Some(oldest) = self.access_order.pop_front() else {
                break;
            };
            if self.chunks.remove(&oldest).is_some() {
                break;
            }
        }
    }

    fn touch(&mut self, chunk_index: u64) {
        self.access_order.push_back(chunk_index);
    }
}

struct LogicalFileVfs {
    manifest_key: String,
    shared: Arc<LogicalFileSharedState>,
}

impl Vfs for LogicalFileVfs {
    type Handle = LogicalFileHandle;

    fn open(&self, db: &str, opts: OpenOptions) -> Result<Self::Handle, Error> {
        if db != self.manifest_key {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("unknown logical MBTiles database {db}"),
            ));
        }
        if opts.kind != OpenKind::MainDb {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                format!("unsupported logical MBTiles open kind {:?}", opts.kind),
            ));
        }
        if opts.access != OpenAccess::Read {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                "logical MBTiles VFS is read-only",
            ));
        }

        Ok(LogicalFileHandle {
            shared: Arc::clone(&self.shared),
            current_lock: LockKind::None,
        })
    }

    fn delete(&self, _db: &str) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "logical MBTiles VFS is read-only",
        ))
    }

    fn exists(&self, db: &str) -> Result<bool, Error> {
        Ok(db == self.manifest_key)
    }

    fn temporary_name(&self) -> String {
        format!("{}-temp", self.manifest_key)
    }

    fn random(&self, buffer: &mut [i8]) {
        for (index, value) in buffer.iter_mut().enumerate() {
            *value = ((index as i32 * 31) & 0x7f) as i8;
        }
    }

    fn sleep(&self, duration: Duration) -> Duration {
        std::thread::sleep(duration);
        duration
    }

    fn access(&self, db: &str, write: bool) -> Result<bool, Error> {
        Ok(db == self.manifest_key && !write)
    }

    fn full_pathname<'a>(&self, db: &'a str) -> Result<Cow<'a, str>, Error> {
        Ok(Cow::Borrowed(db))
    }
}

struct LogicalFileHandle {
    shared: Arc<LogicalFileSharedState>,
    current_lock: LockKind,
}

impl DatabaseHandle for LogicalFileHandle {
    type WalIndex = DisabledWalIndex;

    fn size(&self) -> Result<u64, Error> {
        Ok(self.shared.file_size_bytes())
    }

    fn read_exact_at(&mut self, buf: &mut [u8], offset: u64) -> Result<(), Error> {
        self.shared.read_exact_at(buf, offset)
    }

    fn write_all_at(&mut self, _buf: &[u8], _offset: u64) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "logical MBTiles VFS is read-only",
        ))
    }

    fn sync(&mut self, _data_only: bool) -> Result<(), Error> {
        Ok(())
    }

    fn set_len(&mut self, _size: u64) -> Result<(), Error> {
        Err(Error::new(
            ErrorKind::PermissionDenied,
            "logical MBTiles VFS is read-only",
        ))
    }

    fn lock(&mut self, lock: LockKind) -> Result<bool, Error> {
        match lock {
            LockKind::None => {
                self.current_lock = LockKind::None;
                Ok(true)
            }
            LockKind::Shared => {
                self.current_lock = LockKind::Shared;
                Ok(true)
            }
            LockKind::Reserved | LockKind::Pending | LockKind::Exclusive => Ok(false),
        }
    }

    fn reserved(&mut self) -> Result<bool, Error> {
        Ok(false)
    }

    fn current_lock(&self) -> Result<LockKind, Error> {
        Ok(self.current_lock)
    }

    fn wal_index(&self, _readonly: bool) -> Result<Self::WalIndex, Error> {
        Ok(DisabledWalIndex)
    }
}

struct DisabledWalIndex;

impl sqlite_vfs::wip::WalIndex for DisabledWalIndex {
    fn enabled() -> bool {
        false
    }

    fn map(&mut self, _region: u32) -> Result<[u8; 32768], Error> {
        Err(Error::new(
            ErrorKind::Unsupported,
            "logical MBTiles VFS does not support WAL",
        ))
    }

    fn lock(
        &mut self,
        _locks: std::ops::Range<u8>,
        _lock: sqlite_vfs::wip::WalIndexLock,
    ) -> Result<bool, Error> {
        Ok(false)
    }

    fn delete(self) -> Result<(), Error> {
        Ok(())
    }
}

fn download_logical_range_blocking(
    sdk: &IronMeshClient,
    loaded_manifest: &LoadedSplitLogicalFileManifest,
    manifest_key: &str,
    start: u64,
    length: u64,
    perf_logging_enabled: bool,
) -> Result<Vec<u8>> {
    if active_tile_lookup_is_cancelled() {
        return Err(canceled_anyhow("logical MBTiles range download canceled"));
    }
    let started = Instant::now();
    let end_exclusive = start
        .checked_add(length)
        .ok_or_else(|| anyhow!("logical MBTiles range overflow"))?;
    let mut body = Vec::with_capacity(length.min(1024 * 1024) as usize);
    let mut segments = 0usize;

    for part in &loaded_manifest.manifest.parts {
        if active_tile_lookup_is_cancelled() {
            return Err(canceled_anyhow("logical MBTiles range download canceled"));
        }
        let part_start = part.offset_bytes;
        let part_end_exclusive = part
            .offset_bytes
            .checked_add(part.size_bytes)
            .ok_or_else(|| anyhow!("manifest part end overflow for {}", part.part_id))?;
        if part_end_exclusive <= start || part_start >= end_exclusive {
            continue;
        }

        let segment_start = start.max(part_start);
        let segment_end_exclusive = end_exclusive.min(part_end_exclusive);
        let local_start = segment_start - part_start;
        let segment_length = segment_end_exclusive - segment_start;
        if segment_length == 0 {
            continue;
        }

        segments += 1;
        let segment_started = Instant::now();
        let mut on_progress = |_progress: client_sdk::ironmesh_client::DownloadProgress| {};
        let should_cancel = || active_tile_lookup_is_cancelled();
        sdk.download_range_to_writer_with_progress_blocking(
            DownloadRangeRequest {
                key: part.key.as_str(),
                snapshot: None,
                version: None,
                range: RequestedRange {
                    offset: local_start,
                    length: segment_length,
                },
            },
            &mut body,
            &mut on_progress,
            &should_cancel,
        )
        .with_context(|| {
            format!(
                "failed downloading logical MBTiles segment key={} start={} length={}",
                part.key, local_start, segment_length
            )
        })?;
        let segment_elapsed_ms = segment_started.elapsed().as_millis() as u64;
        record_active_tile_lookup_perf_stats(|stats| {
            stats.segment_downloads += 1;
            stats.segment_bytes += segment_length;
            stats.segment_download_elapsed_ms += segment_elapsed_ms;
        });
        if perf_logging_enabled {
            info!(
                manifest_key = %manifest_key,
                part_id = %part.part_id,
                part_key = %part.key,
                local_start,
                segment_length,
                elapsed_ms = segment_elapsed_ms,
                "map perf: downloaded logical MBTiles segment"
            );
        }
    }

    if body.len() as u64 != length {
        return Err(anyhow!(
            "logical MBTiles segment reconstruction produced {} bytes, expected {}",
            body.len(),
            length
        ));
    }

    if perf_logging_enabled {
        info!(
            manifest_key = %manifest_key,
            start,
            length,
            segments,
            elapsed_ms = started.elapsed().as_millis() as u64,
            "map perf: downloaded logical MBTiles range"
        );
    }

    Ok(body)
}

fn xyz_row_to_tms(zoom: u32, y_xyz: u32) -> Result<u32> {
    let row_count = 1_u32
        .checked_shl(zoom)
        .ok_or_else(|| anyhow!("zoom level {zoom} is too large for MBTiles lookup"))?;
    if y_xyz >= row_count {
        return Err(anyhow!(
            "y tile coordinate {} is out of range for zoom {}",
            y_xyz,
            zoom
        ));
    }
    Ok(row_count - 1 - y_xyz)
}

fn parse_center(value: &str) -> Option<[f64; 3]> {
    let parts = value
        .split(',')
        .map(|part| part.trim().parse::<f64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if parts.len() < 2 {
        return None;
    }
    Some([parts[0], parts[1], parts.get(2).copied().unwrap_or(0.0)])
}

fn infer_tile_mime_type(bytes: &[u8], declared_format: Option<&str>) -> &'static str {
    match declared_format.map(|value| value.trim().to_ascii_lowercase()) {
        Some(format) if format == "jpg" || format == "jpeg" => return "image/jpeg",
        Some(format) if format == "png" => return "image/png",
        Some(format) if format == "webp" => return "image/webp",
        _ => {}
    }

    if bytes.len() >= 8
        && bytes[0] == 0x89
        && bytes[1] == 0x50
        && bytes[2] == 0x4e
        && bytes[3] == 0x47
        && bytes[4] == 0x0d
        && bytes[5] == 0x0a
        && bytes[6] == 0x1a
        && bytes[7] == 0x0a
    {
        return "image/png";
    }

    if bytes.len() >= 3 && bytes[0] == 0xff && bytes[1] == 0xd8 && bytes[2] == 0xff {
        return "image/jpeg";
    }

    if bytes.len() >= 12
        && bytes[0] == 0x52
        && bytes[1] == 0x49
        && bytes[2] == 0x46
        && bytes[3] == 0x46
        && bytes[8] == 0x57
        && bytes[9] == 0x45
        && bytes[10] == 0x42
        && bytes[11] == 0x50
    {
        return "image/webp";
    }

    "application/octet-stream"
}

fn infer_vector_tile_content_encoding(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return Some("gzip");
    }
    None
}

fn other_io_error(error: anyhow::Error) -> Error {
    match error.downcast::<Error>() {
        Ok(error) => error,
        Err(error) => Error::other(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlite_vfs::wip::WalIndex;

    #[test]
    fn active_tile_lookup_perf_guard_records_and_restores_previous_state() {
        let outer_stats = Rc::new(RefCell::new(MbtilesTileLookupPerfStats::default()));
        let inner_stats = Rc::new(RefCell::new(MbtilesTileLookupPerfStats::default()));

        {
            let _outer_guard = ActiveTileLookupPerfGuard::install(Some(Rc::clone(&outer_stats)));
            record_active_tile_lookup_perf_stats(|stats| stats.vfs_reads += 1);
            assert_eq!(outer_stats.borrow().vfs_reads, 1);

            {
                let _inner_guard =
                    ActiveTileLookupPerfGuard::install(Some(Rc::clone(&inner_stats)));
                record_active_tile_lookup_perf_stats(|stats| stats.segment_downloads += 2);
                assert_eq!(inner_stats.borrow().segment_downloads, 2);
                assert_eq!(outer_stats.borrow().segment_downloads, 0);
            }

            record_active_tile_lookup_perf_stats(|stats| stats.vfs_reads += 3);
            assert_eq!(outer_stats.borrow().vfs_reads, 4);
        }
    }

    #[test]
    fn active_tile_lookup_cancellation_guard_tracks_and_restores_state() {
        let outer = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(AtomicBool::new(true));

        assert!(!active_tile_lookup_is_cancelled());

        {
            let _outer_guard = ActiveTileLookupCancellationGuard::install(Some(Arc::clone(&outer)));
            assert!(!active_tile_lookup_is_cancelled());
            assert!(ensure_active_tile_lookup_not_cancelled().is_ok());

            {
                let _inner_guard =
                    ActiveTileLookupCancellationGuard::install(Some(Arc::clone(&inner)));
                assert!(active_tile_lookup_is_cancelled());
                let error = ensure_active_tile_lookup_not_cancelled().unwrap_err();
                assert_eq!(error.kind(), ErrorKind::Interrupted);
            }

            assert!(!active_tile_lookup_is_cancelled());
        }

        assert!(!active_tile_lookup_is_cancelled());
    }

    #[test]
    fn logical_file_chunk_cache_evicts_oldest_entry_once_capacity_is_exceeded() {
        let mut cache = LogicalFileChunkCache::default();

        for chunk_index in 0..=SQLITE_RANGE_CACHE_MAX_CHUNKS as u64 {
            cache.insert(chunk_index, Arc::new(vec![chunk_index as u8]));
        }

        assert_eq!(cache.chunks.len(), SQLITE_RANGE_CACHE_MAX_CHUNKS);
        assert!(!cache.chunks.contains_key(&0));
        assert!(
            cache
                .chunks
                .contains_key(&(SQLITE_RANGE_CACHE_MAX_CHUNKS as u64))
        );
    }

    #[test]
    fn xyz_row_to_tms_converts_rows_and_rejects_invalid_coordinates() {
        assert_eq!(xyz_row_to_tms(0, 0).unwrap(), 0);
        assert_eq!(xyz_row_to_tms(3, 0).unwrap(), 7);
        assert_eq!(xyz_row_to_tms(3, 7).unwrap(), 0);

        let error = xyz_row_to_tms(2, 4).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("y tile coordinate 4 is out of range for zoom 2")
        );
    }

    #[test]
    fn parse_center_accepts_two_or_three_coordinates() {
        assert_eq!(parse_center("7.5, 46.8"), Some([7.5, 46.8, 0.0]));
        assert_eq!(parse_center("7.5,46.8,12"), Some([7.5, 46.8, 12.0]));
        assert_eq!(parse_center("7.5"), None);
        assert_eq!(parse_center("7.5,nope,12"), None);
    }

    #[test]
    fn infer_tile_mime_type_prefers_declared_format_and_falls_back_to_magic_bytes() {
        assert_eq!(infer_tile_mime_type(&[], Some("JPEG")), "image/jpeg");
        assert_eq!(
            infer_tile_mime_type(&[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], None),
            "image/png"
        );
        assert_eq!(
            infer_tile_mime_type(&[0xff, 0xd8, 0xff, 0xdb], None),
            "image/jpeg"
        );
        assert_eq!(
            infer_tile_mime_type(
                &[0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50],
                None,
            ),
            "image/webp"
        );
        assert_eq!(
            infer_tile_mime_type(b"plain-bytes", None),
            "application/octet-stream"
        );
    }

    #[test]
    fn infer_vector_tile_content_encoding_detects_gzip_payloads() {
        assert_eq!(
            infer_vector_tile_content_encoding(&[0x1f, 0x8b, 0x08, 0x00]),
            Some("gzip")
        );
        assert_eq!(infer_vector_tile_content_encoding(b"plain"), None);
    }

    #[test]
    fn io_error_helpers_preserve_io_errors_and_wrap_other_failures() {
        let canceled = canceled_anyhow("stop");
        let canceled = canceled.downcast::<Error>().unwrap();
        assert_eq!(canceled.kind(), ErrorKind::Interrupted);
        assert_eq!(canceled.to_string(), "stop");

        let permission_denied = Error::new(ErrorKind::PermissionDenied, "denied");
        let preserved = other_io_error(anyhow::Error::new(permission_denied));
        assert_eq!(preserved.kind(), ErrorKind::PermissionDenied);
        assert_eq!(preserved.to_string(), "denied");

        let wrapped = other_io_error(anyhow!("boom"));
        assert_eq!(wrapped.kind(), ErrorKind::Other);
        assert!(wrapped.to_string().contains("boom"));
    }

    #[test]
    fn disabled_wal_index_rejects_mapping_and_locking() {
        assert!(!<DisabledWalIndex as sqlite_vfs::wip::WalIndex>::enabled());

        let mut wal = DisabledWalIndex;
        let error = wal.map(0).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Unsupported);
        assert!(error.to_string().contains("does not support WAL"));
        assert!(
            !wal.lock(0..1, sqlite_vfs::wip::WalIndexLock::Shared)
                .unwrap()
        );
        wal.delete().unwrap();
    }
}
