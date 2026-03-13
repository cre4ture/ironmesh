use crate::runtime::{Hydrator, Uploader};
use anyhow::{Context, Result};
use client_sdk::{IronMeshClient, build_http_client, normalize_server_base_url};
use reqwest::Url;
use std::path::Path;

#[derive(Clone)]
pub struct ServerNodeHydrator {
    sdk: IronMeshClient,
}

impl ServerNodeHydrator {
    pub fn new(
        base_url: Url,
        bearer_token: Option<String>,
        server_ca_cert: Option<&Path>,
    ) -> Result<Self> {
        let sdk = build_http_client(server_ca_cert, base_url.as_str(), &bearer_token)?;
        Ok(Self { sdk })
    }
}

impl Hydrator for ServerNodeHydrator {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        eprintln!("hydrating path {path} from server");
        let mut bytes = Vec::new();
        self.sdk
            .get_with_selector_writer(path, None, None, &mut bytes)
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        Ok(bytes)
    }
}

impl Uploader for ServerNodeHydrator {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>> {
        self.sdk
            .put_large_aware_reader(path.to_string(), reader, length)
            .with_context(|| format!("failed to upload object for path {path}"))?;

        Ok(Some(format!("server-head:size={length}")))
    }

    fn delete_path(&self, path: &str) -> Result<()> {
        self.sdk
            .delete_path_blocking(path)
            .with_context(|| format!("failed to delete remote object for path {path}"))?;
        Ok(())
    }
}

pub fn normalize_base_url(input: &str) -> Result<Url> {
    normalize_server_base_url(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_normalization_adds_scheme_and_trailing_slash() {
        let url = normalize_base_url("127.0.0.1:18080").expect("url should be valid");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/");
    }
}
