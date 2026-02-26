use crate::runtime::{Hydrator, Uploader};
use anyhow::{Context, Result};
use reqwest::Url;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use sync_core::{NamespaceEntry, SyncSnapshot};

const CHUNK_UPLOAD_THRESHOLD_BYTES: u64 = 1 * 1024 * 1024;
const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ServerNodeHydrator {
    client: Client,
    base_url: Url,
}

impl ServerNodeHydrator {
    pub fn new(client: Client, base_url: Url) -> Self {
        Self { client, base_url }
    }
}

impl Hydrator for ServerNodeHydrator {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        let object_url = build_store_object_url(&self.base_url, path)?;
        let response = self
            .client
            .get(object_url)
            .send()
            .with_context(|| format!("failed to fetch object for path {path}"))?
            .error_for_status()
            .with_context(|| format!("server returned error for path {path}"))?;

        let bytes = response.bytes().context("failed reading object bytes")?;
        Ok(bytes.to_vec())
    }
}

impl Uploader for ServerNodeHydrator {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>> {
        use std::io::Read;

        if length <= CHUNK_UPLOAD_THRESHOLD_BYTES {
            let object_url = build_store_object_url(&self.base_url, path)?;
            let mut buf = Vec::with_capacity(std::cmp::min(length as usize, 8192));
            let mut limited = reader.take(length);
            limited
                .read_to_end(&mut buf)
                .with_context(|| format!("failed reading payload for upload {path}"))?;

            self.client
                .put(object_url)
                .body(buf)
                .send()
                .with_context(|| format!("failed to upload object for path {path}"))?
                .error_for_status()
                .with_context(|| format!("server returned error while uploading path {path}"))?;

            return Ok(Some("server-head".to_string()));
        }

        let chunks_url = build_store_chunks_url(&self.base_url)?;
        let complete_url = build_store_complete_upload_url(&self.base_url, path)?;

        let mut limited = reader.take(length);
        let mut uploaded_chunks = Vec::<UploadChunkRef>::new();
        let mut uploaded_total = 0u64;

        loop {
            let mut chunk = vec![0u8; CHUNK_UPLOAD_SIZE_BYTES];
            let read_bytes = limited
                .read(&mut chunk)
                .with_context(|| format!("failed reading chunk for upload {path}"))?;
            if read_bytes == 0 {
                break;
            }

            chunk.truncate(read_bytes);
            uploaded_total = uploaded_total
                .checked_add(read_bytes as u64)
                .context("uploaded byte count overflow")?;

            let chunk_response = self
                .client
                .post(chunks_url.clone())
                .body(chunk)
                .send()
                .with_context(|| format!("failed to upload chunk for path {path}"))?
                .error_for_status()
                .with_context(|| format!("server rejected chunk upload for path {path}"))?
                .json::<StoreChunkUploadResponse>()
                .with_context(|| format!("failed parsing chunk upload response for path {path}"))?;

            uploaded_chunks.push(UploadChunkRef {
                hash: chunk_response.hash,
                size_bytes: chunk_response.size_bytes,
            });
        }

        if uploaded_total != length {
            anyhow::bail!(
                "short read while uploading {path}: expected={length} actual={uploaded_total}"
            );
        }

        let total_size_bytes = usize::try_from(length)
            .with_context(|| format!("payload too large to represent for path {path}"))?;
        let complete_payload = CompleteStoreUploadRequest {
            total_size_bytes,
            chunks: uploaded_chunks,
        };

        self.client
            .post(complete_url)
            .json(&complete_payload)
            .send()
            .with_context(|| format!("failed to finalize chunked upload for path {path}"))?
            .error_for_status()
            .with_context(|| format!("server rejected chunked upload finalize for path {path}"))?;

        Ok(Some("server-head".to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct StoreIndexResponse {
    entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct StoreIndexEntry {
    path: String,
    entry_type: String,
}

#[derive(Debug, Deserialize)]
struct StoreChunkUploadResponse {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Serialize)]
struct CompleteStoreUploadRequest {
    total_size_bytes: usize,
    chunks: Vec<UploadChunkRef>,
}

#[derive(Debug, Serialize)]
struct UploadChunkRef {
    hash: String,
    size_bytes: usize,
}

pub fn normalize_base_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };
    let url = if with_scheme.ends_with('/') {
        with_scheme
    } else {
        format!("{with_scheme}/")
    };
    Url::parse(&url).with_context(|| format!("invalid server base url: {input}"))
}

pub fn load_snapshot_from_server(
    client: &Client,
    base_url: &Url,
    prefix: Option<&str>,
    depth: usize,
) -> Result<SyncSnapshot> {
    let endpoint = base_url
        .join("store/index")
        .context("failed to compose store/index url")?;

    let response = client
        .get(endpoint)
        .query(&[("depth", depth.max(1).to_string())])
        .query(&[("prefix", prefix.unwrap_or_default().to_string())])
        .send()
        .context("failed calling /store/index")?
        .error_for_status()
        .context("/store/index returned non-success status")?;

    let payload: StoreIndexResponse = response
        .json()
        .context("failed parsing /store/index response")?;

    Ok(snapshot_from_index_entries(payload.entries))
}

fn snapshot_from_index_entries(entries: Vec<StoreIndexEntry>) -> SyncSnapshot {
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

pub fn build_store_object_url(base_url: &Url, key: &str) -> Result<Url> {
    let mut url = base_url
        .join("store")
        .context("failed to compose object base url")?;

    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow::anyhow!("base url cannot be used for path segments"))?;
        for segment in key.split('/').filter(|segment| !segment.is_empty()) {
            segments.push(segment);
        }
    }

    Ok(url)
}

pub fn build_store_chunks_url(base_url: &Url) -> Result<Url> {
    base_url
        .join("store-chunks/upload")
        .context("failed to compose chunk upload url")
}

pub fn build_store_complete_upload_url(base_url: &Url, key: &str) -> Result<Url> {
    let mut url = build_store_object_url(base_url, key)?;
    url.query_pairs_mut().append_pair("complete", "");
    Ok(url)
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
    fn object_url_builder_escapes_segments() {
        let base = normalize_base_url("http://127.0.0.1:18080/").expect("valid base");
        let url = build_store_object_url(&base, "docs/read me.txt").expect("object url");
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:18080/store/docs/read%20me.txt"
        );
    }

    #[test]
    fn complete_upload_url_builder_escapes_segments() {
        let base = normalize_base_url("http://127.0.0.1:18080/").expect("valid base");
        let url =
            build_store_complete_upload_url(&base, "docs/read me.txt").expect("complete url");
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:18080/store/docs/read%20me.txt?complete="
        );
    }
}
