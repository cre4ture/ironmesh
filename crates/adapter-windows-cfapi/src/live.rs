use crate::runtime::{Hydrator, Uploader};
use anyhow::{Context, Result};
use client_sdk::{IronMeshClient, normalize_server_base_url};
use reqwest::Url;
use sync_core::{EntryKind, SyncSnapshot};

#[derive(Clone)]
pub struct ServerNodeHydrator {
    sdk: IronMeshClient,
}

impl ServerNodeHydrator {
    pub fn new(base_url: Url) -> Self {
        Self {
            sdk: IronMeshClient::new(base_url.as_str()),
        }
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
}

pub fn normalize_base_url(input: &str) -> Result<Url> {
    normalize_server_base_url(input)
}

pub fn load_snapshot_from_server(
    base_url: &Url,
    prefix: Option<&str>,
    depth: usize,
) -> Result<SyncSnapshot> {
    let sdk = IronMeshClient::new(base_url.as_str());
    let mut snapshot = sdk.load_snapshot_from_server_blocking(prefix, depth, None)?;

    for entry in &mut snapshot.remote {
        if entry.kind != EntryKind::File {
            continue;
        }

        let size = sdk
            .get_object_size_blocking(&entry.path, None, None)
            .with_context(|| format!("failed to fetch remote size for {}", entry.path))?;

        let base_version = entry.version.as_deref().unwrap_or("server-head");
        entry.version = Some(format!("{base_version}:size={size}"));
    }

    Ok(snapshot)
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
