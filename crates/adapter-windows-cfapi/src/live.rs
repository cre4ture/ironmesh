use crate::runtime::{Hydrator, Uploader};
use anyhow::{Context, Result};
use client_sdk::{
    ClientIdentityMaterial, IronMeshClient, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use reqwest::Url;

#[derive(Clone)]
pub struct ServerNodeHydrator {
    sdk: IronMeshClient,
}

impl ServerNodeHydrator {
    pub fn with_client(sdk: IronMeshClient) -> Self {
        Self { sdk }
    }

    pub fn new(
        base_url: Url,
        client_identity: Option<ClientIdentityMaterial>,
        server_ca_pem: Option<&str>,
    ) -> Result<Self> {
        let sdk = match client_identity.as_ref() {
            Some(identity) => build_http_client_with_identity_from_pem(
                server_ca_pem,
                base_url.as_str(),
                identity,
            )?,
            None => build_http_client_from_pem(server_ca_pem, base_url.as_str())?,
        };
        Ok(Self::with_client(sdk))
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
