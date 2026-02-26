use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use common::StorageObjectMeta;
use reqwest::Client as HttpClient;

#[derive(Clone)]
pub struct IronMeshClient {
    http: HttpClient,
    server_base_url: String,
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
}
