use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use common::StorageObjectMeta;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};

const LARGE_UPLOAD_THRESHOLD_BYTES: usize = 1 * 1024 * 1024;
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
        let key = key.as_ref();
        let url = self.store_key_url(key)?;

        self.http
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed to GET object key={key}"))?
            .error_for_status()
            .with_context(|| format!("object not found or inaccessible key={key}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read payload for key={key}"))
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
