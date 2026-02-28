use crate::runtime::{Hydrator, Uploader};
use anyhow::{Context, Result};
use client_sdk::IronMeshClient;
use reqwest::Url;
use reqwest::blocking::Client;
use sync_core::SyncSnapshot;

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
        let sdk = IronMeshClient::new(self.base_url.as_str());
        sdk.put_large_aware_reader(path.to_string(), reader, length)
            .with_context(|| format!("failed to upload object for path {path}"))?;

        Ok(Some("server-head".to_string()))
    }
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
    base_url: &Url,
    prefix: Option<&str>,
    depth: usize,
) -> Result<SyncSnapshot> {
    let sdk = IronMeshClient::new(base_url.as_str());
    sdk.load_snapshot_from_server_blocking(prefix, depth, None)
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
}
