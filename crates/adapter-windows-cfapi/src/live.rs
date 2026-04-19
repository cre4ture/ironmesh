use crate::content_fingerprint::FingerprintingReader;
use crate::runtime::{
    HydrationProgress, HydrationRequest, HydrationResult, Hydrator, UploadReceipt, Uploader,
};
use anyhow::{Context, Result, anyhow};
use client_sdk::ironmesh_client::{DownloadProgress, DownloadRangeRequest};
use client_sdk::{
    ClientIdentityMaterial, IronMeshClient, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use common::range_chunk_cache::{RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES, RangeChunkCache};
use reqwest::Url;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RangeChunkCacheKey {
    path: String,
    remote_version: String,
    chunk_index: u64,
}

impl RangeChunkCacheKey {
    fn new(path: &str, remote_version: &str, chunk_index: u64) -> Self {
        Self {
            path: path.to_string(),
            remote_version: remote_version.to_string(),
            chunk_index,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedRangeChunk {
    object_size_bytes: u64,
    payload: Vec<u8>,
}

#[derive(Clone)]
pub struct ServerNodeHydrator {
    sdk: IronMeshClient,
    download_stage_root: PathBuf,
    range_chunk_cache: Arc<Mutex<RangeChunkCache<RangeChunkCacheKey, CachedRangeChunk>>>,
}

impl ServerNodeHydrator {
    pub fn with_client(sdk: IronMeshClient, download_stage_root: PathBuf) -> Self {
        Self {
            sdk,
            download_stage_root,
            range_chunk_cache: Arc::new(Mutex::new(RangeChunkCache::default())),
        }
    }

    pub fn new(
        base_url: Url,
        client_identity: Option<ClientIdentityMaterial>,
        server_ca_pem: Option<&str>,
    ) -> Result<Self> {
        let sdk = match client_identity.as_ref() {
            Some(identity) => build_http_client_with_identity_from_pem(
                server_ca_pem,
                base_url.as_str(),
                identity,
            )?,
            None => build_http_client_from_pem(server_ca_pem, base_url.as_str())?,
        };
        Ok(Self::with_client(
            sdk,
            windows_download_stage_root(base_url.as_str())?,
        ))
    }

    fn read_cached_range_chunk(
        &self,
        path: &str,
        remote_version: &str,
        chunk_index: u64,
    ) -> Result<Option<Arc<CachedRangeChunk>>> {
        let key = RangeChunkCacheKey::new(path, remote_version, chunk_index);
        let mut cache = self
            .range_chunk_cache
            .lock()
            .map_err(|_| anyhow!("range chunk cache lock poisoned"))?;
        Ok(cache.get(&key))
    }

    fn cache_range_chunk(
        &self,
        path: &str,
        remote_version: &str,
        chunk_index: u64,
        chunk: CachedRangeChunk,
    ) -> Result<Arc<CachedRangeChunk>> {
        if chunk.payload.is_empty() {
            return Ok(Arc::new(chunk));
        }

        let key = RangeChunkCacheKey::new(path, remote_version, chunk_index);
        let mut cache = self
            .range_chunk_cache
            .lock()
            .map_err(|_| anyhow!("range chunk cache lock poisoned"))?;
        Ok(cache.insert(key, chunk))
    }

    fn download_range_chunk(
        &self,
        path: &str,
        chunk_start: u64,
        chunk_length: u64,
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<CachedRangeChunk> {
        let mut downloaded = Vec::new();
        let mut on_progress = |_progress: DownloadProgress| {};
        let result = self
            .sdk
            .download_range_to_writer_with_progress_blocking(
                DownloadRangeRequest {
                    key: path,
                    snapshot: None,
                    version: None,
                    range: client_sdk::RequestedRange {
                        offset: chunk_start,
                        length: chunk_length,
                    },
                },
                &mut downloaded,
                &mut on_progress,
                should_cancel,
            )
            .with_context(|| {
                format!(
                    "failed to fetch ranged object chunk for path {path} chunk_offset={chunk_start}"
                )
            })?;

        Ok(CachedRangeChunk {
            object_size_bytes: result.object_size_bytes,
            payload: downloaded,
        })
    }
}

impl Hydrator for ServerNodeHydrator {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        tracing::info!("hydrating path {path} from server");
        let mut bytes = Vec::new();
        self.sdk
            .download_to_writer_resumable_staged(
                path,
                None,
                None,
                &mut bytes,
                &self.download_stage_root,
            )
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        Ok(bytes)
    }

    fn hydrate_range_to_writer(
        &self,
        request: HydrationRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(HydrationProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<HydrationResult> {
        tracing::info!(
            "hydrating range path {path} from server required_range={} transfer_range={}",
            request.required_range,
            request.transfer_range,
            path = request.path,
        );
        if request.transfer_range.length == 0 {
            return Ok(HydrationResult {
                object_size_bytes: 0,
                range: request.transfer_range,
                bytes_transferred: 0,
            });
        }

        let chunk_size = RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES as u64;
        let range_end_exclusive = request
            .transfer_range
            .offset
            .saturating_add(request.transfer_range.length);
        let first_chunk_index = request.transfer_range.offset / chunk_size;
        let last_chunk_index = range_end_exclusive.saturating_sub(1) / chunk_size;
        let mut bytes_transferred = 0_u64;
        let mut object_size_bytes = 0_u64;

        for chunk_index in first_chunk_index..=last_chunk_index {
            if should_cancel() {
                return Err(anyhow!("hydration canceled for {}", request.path));
            }

            let chunk_start = chunk_index.saturating_mul(chunk_size);
            let chunk = if let Some(chunk) =
                self.read_cached_range_chunk(request.path, request.remote_version, chunk_index)?
            {
                chunk
            } else {
                let downloaded = self.download_range_chunk(
                    request.path,
                    chunk_start,
                    chunk_size,
                    should_cancel,
                )?;
                self.cache_range_chunk(
                    request.path,
                    request.remote_version,
                    chunk_index,
                    downloaded,
                )?
            };

            object_size_bytes = object_size_bytes.max(chunk.object_size_bytes);
            let slice_start = request.transfer_range.offset.saturating_sub(chunk_start) as usize;
            let slice_end = range_end_exclusive
                .min(chunk_start.saturating_add(chunk.payload.len() as u64))
                .saturating_sub(chunk_start) as usize;
            if slice_start < slice_end {
                writer
                    .write_all(&chunk.payload[slice_start..slice_end])
                    .map_err(|err| {
                        anyhow!("failed to write hydrated bytes for {}: {err}", request.path)
                    })?;
                bytes_transferred =
                    bytes_transferred.saturating_add(slice_end.saturating_sub(slice_start) as u64);
                on_progress(HydrationProgress {
                    object_size_bytes,
                    range: request.transfer_range,
                    bytes_transferred,
                });
            }

            if chunk.payload.len() < RANGE_CHUNK_CACHE_CHUNK_SIZE_BYTES {
                break;
            }
        }

        writer
            .flush()
            .map_err(|err| anyhow!("failed to flush hydrated bytes for {}: {err}", request.path))?;

        if object_size_bytes == 0 {
            object_size_bytes = request
                .transfer_range
                .offset
                .saturating_add(bytes_transferred);
        }

        Ok(HydrationResult {
            object_size_bytes,
            range: request.transfer_range,
            bytes_transferred,
        })
    }
}

impl Uploader for ServerNodeHydrator {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadReceipt> {
        let mut fingerprinting_reader = FingerprintingReader::new(reader, length);
        self.sdk
            .put_large_aware_reader(path.to_string(), &mut fingerprinting_reader, length)
            .with_context(|| format!("failed to upload object for path {path}"))?;
        let in_sync_content_fingerprint = fingerprinting_reader
            .finish()
            .with_context(|| format!("failed to finalize content fingerprint for {path}"))?;

        Ok(UploadReceipt {
            remote_version: Some(format!("server-head:size={length}")),
            in_sync_content_fingerprint: Some(in_sync_content_fingerprint),
        })
    }

    fn delete_path(&self, path: &str) -> Result<()> {
        self.sdk
            .delete_path_blocking(path)
            .with_context(|| format!("failed to delete remote object for path {path}"))?;
        Ok(())
    }

    fn rename_path(&self, from_path: &str, to_path: &str) -> Result<bool> {
        self.sdk
            .rename_path_blocking(from_path, to_path, false)
            .with_context(|| format!("failed to rename remote object {from_path} -> {to_path}"))?;
        Ok(true)
    }
}

pub fn normalize_base_url(input: &str) -> Result<Url> {
    normalize_server_base_url(input)
}

const WINDOWS_LOCAL_STATE_ROOT_DIR: &str = "Ironmesh";
const WINDOWS_DOWNLOAD_STAGE_SUBDIR: &str = "cfapi-downloads";

pub fn windows_download_stage_root(scope: &str) -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = windows_download_stage_base_root(base).join(download_scope_label(scope));
    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create download stage root {}", path.display()))?;
    Ok(path)
}

pub fn windows_download_stage_root_for_sync_root(sync_root: &Path) -> Result<PathBuf> {
    windows_download_stage_root(&sync_root.to_string_lossy())
}

fn download_scope_label(scope: &str) -> String {
    blake3::hash(scope.as_bytes()).to_hex().to_string()
}

fn windows_download_stage_base_root(base: PathBuf) -> PathBuf {
    base.join(WINDOWS_LOCAL_STATE_ROOT_DIR)
        .join(WINDOWS_DOWNLOAD_STAGE_SUBDIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_normalization_adds_scheme_and_trailing_slash() {
        let url = normalize_base_url("127.0.0.1:18080").expect("url should be valid");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/");
    }

    #[test]
    fn windows_download_stage_root_uses_ironmesh_localappdata_root() {
        let base = PathBuf::from("C:/Users/Example/AppData/Local");
        assert_eq!(
            windows_download_stage_base_root(base.clone()),
            base.join("Ironmesh").join("cfapi-downloads")
        );
    }
}
