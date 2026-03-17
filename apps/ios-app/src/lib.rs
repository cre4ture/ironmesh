use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, normalize_server_base_url,
};

pub struct IosStorageApp {
    client: ClientNode,
}

impl IosStorageApp {
    pub fn new(connection_input: impl Into<String>) -> Result<Self> {
        Self::configured(connection_input, None, None)
    }

    pub fn configured(
        connection_input: impl Into<String>,
        server_ca_pem: Option<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        let connection_input = normalized_connection_input_string(connection_input)?;
        let server_ca_pem = normalize_optional_string(server_ca_pem);
        let client_identity_json = normalize_optional_string(client_identity_json);
        let client_identity = client_identity_json
            .as_deref()
            .map(ClientIdentityMaterial::from_json_str)
            .transpose()
            .context("failed to parse iOS client identity JSON")?;

        let client = if connection_input.starts_with('{') {
            let mut bootstrap = ConnectionBootstrap::from_json_str(&connection_input)
                .context("failed to parse iOS connection bootstrap JSON")?;
            if let Some(server_ca_pem) = server_ca_pem.as_ref() {
                bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
            }
            match client_identity.as_ref() {
                Some(identity) => bootstrap.build_client_with_identity(identity)?,
                None => bootstrap.build_client()?,
            }
        } else {
            match client_identity.as_ref() {
                Some(identity) => client_sdk::build_http_client_with_identity_from_pem(
                    server_ca_pem.as_deref(),
                    &connection_input,
                    identity,
                )?,
                None => client_sdk::build_http_client_from_pem(
                    server_ca_pem.as_deref(),
                    &connection_input,
                    &None,
                )?,
            }
        };

        Ok(Self::with_client(ClientNode::with_client(client)))
    }

    pub fn configured_from_bootstrap(
        bootstrap_json: impl Into<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        Self::configured(bootstrap_json, None, client_identity_json)
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

fn normalized_connection_input_string(connection_input: impl Into<String>) -> Result<String> {
    let connection_input = connection_input.into();
    let trimmed = connection_input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("iOS client requires a non-empty connection input");
    }

    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }

    Ok(normalize_server_base_url(trimmed)?.to_string())
}
