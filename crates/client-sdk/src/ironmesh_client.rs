use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use common::StorageObjectMeta;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use sync_core::{NamespaceEntry, SyncSnapshot};

const LARGE_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;
const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct IronMeshClient {
    http: HttpClient,
    server_base_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadMode {
    Direct,
    Chunked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub meta: StorageObjectMeta,
    pub upload_mode: UploadMode,
    pub chunk_size_bytes: Option<usize>,
    pub chunk_count: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct StoreChunkUploadResponse {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexEntry {
    pub path: String,
    pub entry_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexResponse {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub depth: usize,
    #[serde(default)]
    pub entry_count: usize,
    #[serde(default)]
    pub entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Serialize)]
struct CompleteStoreUploadRequest {
    total_size_bytes: usize,
    chunks: Vec<CompleteStoreUploadChunkRef>,
}

#[derive(Debug, Serialize)]
struct CompleteStoreUploadChunkRef {
    hash: String,
    size_bytes: usize,
}

impl IronMeshClient {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            http: HttpClient::new(),
            server_base_url: server_base_url.into().trim_end_matches('/').to_string(),
        }
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let url = self.store_key_url(&key)?;

        self.http
            .put(url)
            .body(data.clone())
            .send()
            .await
            .with_context(|| format!("failed to PUT object key={key}"))?
            .error_for_status()
            .with_context(|| format!("server rejected PUT for key={key}"))?;

        Ok(StorageObjectMeta {
            key,
            size_bytes: data.len(),
        })
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        self.get_with_selector(key, None, None).await
    }

    pub async fn get_with_selector(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<Bytes> {
        let key = key.as_ref();
        let url = self.store_key_url(key)?;

        let mut request = self.http.get(url);
        if let Some(snapshot) = snapshot {
            request = request.query(&[("snapshot", snapshot)]);
        }
        if let Some(version) = version {
            request = request.query(&[("version", version)]);
        }

        request
            .send()
            .await
            .with_context(|| format!("failed to GET object key={key}"))?
            .error_for_status()
            .with_context(|| format!("object not found or inaccessible key={key}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read payload for key={key}"))
    }

    pub async fn store_index(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        let url = self.store_index_url()?;

        let mut request = self
            .http
            .get(url)
            .query(&[("depth", depth.max(1).to_string())]);
        if let Some(prefix) = prefix {
            request = request.query(&[("prefix", prefix)]);
        }
        if let Some(snapshot) = snapshot {
            request = request.query(&[("snapshot", snapshot)]);
        }

        request
            .send()
            .await
            .context("failed to request /store/index")?
            .error_for_status()
            .context("/store/index returned non-success status")?
            .json::<StoreIndexResponse>()
            .await
            .context("failed to parse /store/index response")
    }

    pub fn store_index_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for store index request")?;
        runtime.block_on(self.store_index(prefix, depth, snapshot))
    }

    pub async fn load_snapshot_from_server(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let response = self.store_index(prefix, depth, snapshot).await?;
        Ok(snapshot_from_store_index_entries(response.entries))
    }

    pub fn load_snapshot_from_server_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for snapshot load")?;
        runtime.block_on(self.load_snapshot_from_server(prefix, depth, snapshot))
    }

    pub async fn put_large_aware(
        &self,
        key: impl Into<String>,
        data: Bytes,
    ) -> Result<UploadResult> {
        let key = key.into();

        if data.len() > LARGE_UPLOAD_THRESHOLD_BYTES {
            let chunk_upload_url = self.store_chunk_upload_url()?;
            let complete_url = self.store_complete_url(&key)?;

            let mut chunk_refs = Vec::new();
            for chunk in data.chunks(CHUNK_UPLOAD_SIZE_BYTES) {
                let response = self
                    .http
                    .post(&chunk_upload_url)
                    .body(chunk.to_vec())
                    .send()
                    .await
                    .with_context(|| format!("failed to upload chunk for key={key}"))?
                    .error_for_status()
                    .with_context(|| format!("chunk upload rejected for key={key}"))?;

                let uploaded = response
                    .json::<StoreChunkUploadResponse>()
                    .await
                    .with_context(|| format!("failed to parse chunk upload response for {key}"))?;

                chunk_refs.push(CompleteStoreUploadChunkRef {
                    hash: uploaded.hash,
                    size_bytes: uploaded.size_bytes,
                });
            }

            let complete_payload = CompleteStoreUploadRequest {
                total_size_bytes: data.len(),
                chunks: chunk_refs,
            };

            self.http
                .post(complete_url)
                .json(&complete_payload)
                .send()
                .await
                .with_context(|| format!("failed to finalize chunked upload for key={key}"))?
                .error_for_status()
                .with_context(|| format!("chunked finalize rejected for key={key}"))?;

            Ok(UploadResult {
                meta: StorageObjectMeta {
                    key,
                    size_bytes: data.len(),
                },
                upload_mode: UploadMode::Chunked,
                chunk_size_bytes: Some(CHUNK_UPLOAD_SIZE_BYTES),
                chunk_count: Some(complete_payload.chunks.len()),
            })
        } else {
            let meta = self.put(key, data).await?;
            Ok(UploadResult {
                meta,
                upload_mode: UploadMode::Direct,
                chunk_size_bytes: None,
                chunk_count: None,
            })
        }
    }

    pub fn put_large_aware_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadResult> {
        let key = key.into();

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            let mut buf = Vec::with_capacity(std::cmp::min(length as usize, 8192));
            let mut limited = reader.take(length);
            std::io::Read::read_to_end(&mut limited, &mut buf)
                .with_context(|| format!("failed reading payload for key={key}"))?;

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to create runtime for upload")?;
            return runtime.block_on(self.put_large_aware(key, Bytes::from(buf)));
        }

        self.put_chunked_reader(key, reader)
    }

    pub fn put_chunked_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
    ) -> Result<UploadResult> {
        let key = key.into();
        let chunk_upload_url = self.store_chunk_upload_url()?;
        let complete_url = self.store_complete_url(&key)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for upload")?;

        let mut uploaded_total: usize = 0;
        let mut chunk_refs = Vec::new();
        let mut chunk = vec![0u8; CHUNK_UPLOAD_SIZE_BYTES];

        loop {
            let read_bytes = reader
                .read(&mut chunk)
                .with_context(|| format!("failed reading chunk for key={key}"))?;
            if read_bytes == 0 {
                break;
            }

            uploaded_total = uploaded_total
                .checked_add(read_bytes)
                .context("uploaded byte count overflow")?;

            let response = runtime
                .block_on(
                    self.http
                        .post(&chunk_upload_url)
                        .body(chunk[..read_bytes].to_vec())
                        .send(),
                )
                .with_context(|| format!("failed to upload chunk for key={key}"))?
                .error_for_status()
                .with_context(|| format!("chunk upload rejected for key={key}"))?;

            let uploaded = runtime
                .block_on(response.json::<StoreChunkUploadResponse>())
                .with_context(|| format!("failed to parse chunk upload response for {key}"))?;

            chunk_refs.push(CompleteStoreUploadChunkRef {
                hash: uploaded.hash,
                size_bytes: uploaded.size_bytes,
            });
        }

        if chunk_refs.is_empty() {
            let meta = runtime.block_on(self.put(key, Bytes::new()))?;
            return Ok(UploadResult {
                meta,
                upload_mode: UploadMode::Direct,
                chunk_size_bytes: None,
                chunk_count: None,
            });
        }

        let complete_payload = CompleteStoreUploadRequest {
            total_size_bytes: uploaded_total,
            chunks: chunk_refs,
        };

        runtime
            .block_on(self.http.post(complete_url).json(&complete_payload).send())
            .with_context(|| format!("failed to finalize chunked upload for key={key}"))?
            .error_for_status()
            .with_context(|| format!("chunked finalize rejected for key={key}"))?;

        Ok(UploadResult {
            meta: StorageObjectMeta {
                key,
                size_bytes: complete_payload.total_size_bytes,
            },
            upload_mode: UploadMode::Chunked,
            chunk_size_bytes: Some(CHUNK_UPLOAD_SIZE_BYTES),
            chunk_count: Some(complete_payload.chunks.len()),
        })
    }

    pub fn get_with_selector_writer(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let key = key.as_ref();
        let url = self.store_key_url(key)?;

        let mut request = self.http.get(url);
        if let Some(snapshot) = snapshot {
            request = request.query(&[("snapshot", snapshot)]);
        }
        if let Some(version) = version {
            request = request.query(&[("version", version)]);
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for download")?;

        let mut response = runtime
            .block_on(request.send())
            .with_context(|| format!("failed to GET object key={key}"))?
            .error_for_status()
            .with_context(|| format!("object not found or inaccessible key={key}"))?;

        loop {
            let chunk = runtime
                .block_on(response.chunk())
                .with_context(|| format!("failed to read payload chunk for key={key}"))?;

            match chunk {
                Some(chunk) => writer
                    .write_all(chunk.as_ref())
                    .with_context(|| format!("failed to write payload chunk for key={key}"))?,
                None => break,
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(())
    }

    fn store_key_url(&self, key: &str) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.server_base_url)
            .with_context(|| format!("invalid server URL: {}", self.server_base_url))?;

        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("server URL cannot be a base"))?;
        segments.push("store");
        segments.push(key);
        drop(segments);

        Ok(url.to_string())
    }

    fn store_index_url(&self) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.server_base_url)
            .with_context(|| format!("invalid server URL: {}", self.server_base_url))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("index");
        }

        Ok(url.to_string())
    }

    fn store_chunk_upload_url(&self) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.server_base_url)
            .with_context(|| format!("invalid server URL: {}", self.server_base_url))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store-chunks");
            segments.push("upload");
        }

        Ok(url.to_string())
    }

    fn store_complete_url(&self, key: &str) -> Result<String> {
        let mut url = reqwest::Url::parse(&self.server_base_url)
            .with_context(|| format!("invalid server URL: {}", self.server_base_url))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push(key);
        }
        url.query_pairs_mut().append_pair("complete", "");

        Ok(url.to_string())
    }
}

pub fn snapshot_from_store_index_entries(entries: Vec<StoreIndexEntry>) -> SyncSnapshot {
    let mut remote = Vec::with_capacity(entries.len());

    for entry in entries {
        if entry.entry_type == "prefix" {
            let directory_path = entry.path.trim_end_matches('/').to_string();
            if !directory_path.is_empty() {
                remote.push(NamespaceEntry::directory(directory_path));
            }
            continue;
        }

        remote.push(NamespaceEntry::file(
            entry.path.clone(),
            "server-head",
            format!("server-head:{}", entry.path),
        ));
    }

    SyncSnapshot {
        local: Vec::new(),
        remote,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_url_builder_escapes_segments() {
        let client = IronMeshClient::new("http://127.0.0.1:18080/");
        let url = client
            .store_key_url("read me.txt")
            .expect("object url should build");
        assert_eq!(url, "http://127.0.0.1:18080/store/read%20me.txt");
    }

    #[test]
    fn snapshot_conversion_maps_prefix_and_keys() {
        let snapshot = snapshot_from_store_index_entries(vec![
            StoreIndexEntry {
                path: "docs/".to_string(),
                entry_type: "prefix".to_string(),
            },
            StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
            },
        ]);

        assert_eq!(snapshot.local.len(), 0);
        assert_eq!(snapshot.remote.len(), 2);
        assert_eq!(snapshot.remote[0], NamespaceEntry::directory("docs"));
        assert_eq!(
            snapshot.remote[1],
            NamespaceEntry::file(
                "docs/readme.txt",
                "server-head",
                "server-head:docs/readme.txt"
            )
        );
    }
}
