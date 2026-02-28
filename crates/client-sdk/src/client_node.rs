use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use bytes::Bytes;
use common::{CacheEntry, StorageObjectMeta};
use tokio::sync::RwLock;

use crate::ironmesh_client::{IronMeshClient, UploadResult};

#[derive(Clone)]
pub struct ClientNode {
    client: IronMeshClient,
    cache: Arc<RwLock<HashMap<String, Bytes>>>,
}

impl ClientNode {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            client: IronMeshClient::new(server_base_url),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let meta = self.client.put(key.clone(), data.clone()).await?;

        self.cache.write().await.insert(key.clone(), data.clone());
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
        self.cache.write().await.insert(key, data);
        Ok(report)
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        let key = key.as_ref();
        let payload = self.client.get(key).await?;

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
            self.cache
                .write()
                .await
                .insert(key.to_string(), payload.clone());
        }

        Ok(payload)
    }

    pub fn put_chunked_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
    ) -> Result<UploadResult> {
        let key = key.into();
        let report = self.client.put_chunked_reader(key.clone(), reader)?;
        self.cache.blocking_write().remove(&key);
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
