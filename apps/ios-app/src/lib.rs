use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, build_http_client_from_pem,
    build_http_client_with_identity_from_pem,
};

pub struct IosStorageApp {
    client: ClientNode,
}

impl IosStorageApp {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self::with_client(ClientNode::new(server_base_url))
    }

    pub fn configured(
        server_base_url: impl Into<String>,
        server_ca_pem: Option<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        let server_base_url = server_base_url.into();
        let server_ca_pem = normalize_optional_string(server_ca_pem);
        let client_identity_json = normalize_optional_string(client_identity_json);
        let client = match client_identity_json.as_deref() {
            Some(raw) => build_http_client_with_identity_from_pem(
                server_ca_pem.as_deref(),
                &server_base_url,
                &ClientIdentityMaterial::from_json_str(raw)
                    .context("failed to parse iOS client identity JSON")?,
            )?,
            None => build_http_client_from_pem(server_ca_pem.as_deref(), &server_base_url, &None)?,
        };
        Ok(Self::with_client(ClientNode::with_client(client)))
    }

    pub fn with_client(client: ClientNode) -> Self {
        Self { client }
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
        web_ui_backend::assets::app_html()
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
