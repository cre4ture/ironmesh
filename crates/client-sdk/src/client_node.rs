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
    pub fn from_direct_base_url(server_base_url: impl Into<String>) -> Self {
        Self::with_client(IronMeshClient::from_direct_base_url(server_base_url))
    }

    pub fn from_direct_http_client(
        server_base_url: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self::with_client(IronMeshClient::from_direct_http_client(
            server_base_url,
            http,
        ))
    }

    pub fn with_client(client: IronMeshClient) -> Self {
        Self {
            client,
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

        let mut cache = self.cache.write().await;
        if let Some(payload) = cache.remove(&from_path) {
            cache.insert(to_path, payload);
        }
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

        if let Some(payload) = self.cache.read().await.get(&from_path).cloned() {
            self.cache.write().await.insert(to_path, payload);
        }
        Ok(())
    }

    pub async fn delete_path(&self, key: impl Into<String>) -> Result<()> {
        let key = key.into();
        self.client.delete_path(&key).await?;
        self.cache.write().await.remove(&key);
        Ok(())
    }

    pub fn put_large_aware_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadResult> {
        let key = key.into();
        let report = self
            .client
            .put_large_aware_reader(key.clone(), reader, length)?;
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

    pub fn download_to_writer_resumable_staged(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn std::io::Write,
        staging_root: impl AsRef<std::path::Path>,
    ) -> Result<()> {
        self.client.download_to_writer_resumable_staged(
            key,
            snapshot,
            version,
            writer,
            staging_root,
        )
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
