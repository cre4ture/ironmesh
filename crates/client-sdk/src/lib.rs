use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use common::{CacheEntry, StorageObjectMeta};
use reqwest::Client;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ClientNode {
    http: Client,
    server_base_url: String,
    cache: Arc<RwLock<HashMap<String, Bytes>>>,
}

impl ClientNode {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            http: Client::new(),
            server_base_url: server_base_url.into().trim_end_matches('/').to_string(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let url = format!("{}/store/{}", self.server_base_url, key);

        self.http
            .put(url)
            .body(data.clone())
            .send()
            .await
            .with_context(|| format!("failed to PUT object key={key}"))?
            .error_for_status()
            .with_context(|| format!("server rejected PUT for key={key}"))?;

        self.cache.write().await.insert(key.clone(), data.clone());

        Ok(StorageObjectMeta {
            key,
            size_bytes: data.len(),
        })
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        let key = key.as_ref();
        let url = format!("{}/store/{}", self.server_base_url, key);

        let payload = self
            .http
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed to GET object key={key}"))?
            .error_for_status()
            .with_context(|| format!("object not found or inaccessible key={key}"))?
            .bytes()
            .await
            .with_context(|| format!("failed to read payload for key={key}"))?;

        self.cache
            .write()
            .await
            .insert(key.to_string(), payload.clone());

        Ok(payload)
    }

    pub async fn get_cached_or_fetch(&self, key: impl AsRef<str>) -> Result<Bytes> {
        let key = key.as_ref();

        if let Some(entry) = self.cache.read().await.get(key).cloned() {
            return Ok(entry);
        }

        self.get(key).await
    }

    pub async fn cache_entries(&self) -> Vec<CacheEntry> {
        self.cache
            .read()
            .await
            .iter()
            .map(|(key, value)| CacheEntry {
                key: key.clone(),
                size_bytes: value.len(),
            })
            .collect()
    }

    pub async fn remove_cached(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref();
        let removed = self.cache.write().await.remove(key);

        if removed.is_none() {
            return Err(anyhow!("cache key not present: {key}"));
        }

        Ok(())
    }
}
