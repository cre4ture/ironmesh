use anyhow::Result;
use bytes::Bytes;
use client_sdk::ClientNode;

pub struct IosStorageApp {
    client: ClientNode,
}

impl IosStorageApp {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self {
            client: ClientNode::new(server_base_url),
        }
    }

    pub async fn store(&self, key: impl Into<String>, data: Vec<u8>) -> Result<()> {
        self.client.put(key, Bytes::from(data)).await?;
        Ok(())
    }

    pub async fn fetch(&self, key: impl AsRef<str>) -> Result<Vec<u8>> {
        let bytes = self.client.get_cached_or_fetch(key).await?;
        Ok(bytes.to_vec())
    }

    pub fn web_gui_html(&self) -> String {
        web_ui::app_html()
    }
}
