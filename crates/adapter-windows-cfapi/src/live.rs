#![cfg(feature = "cfapi-runtime")]

use crate::runtime::Hydrator;
use anyhow::{Context, Result};
use reqwest::Url;
use reqwest::blocking::Client;
use serde::Deserialize;
use sync_core::{NamespaceEntry, SyncSnapshot};

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

#[derive(Debug, Deserialize)]
struct StoreIndexResponse {
    entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Deserialize)]
struct StoreIndexEntry {
    path: String,
    entry_type: String,
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
    client: &Client,
    base_url: &Url,
    prefix: Option<&str>,
    depth: usize,
) -> Result<SyncSnapshot> {
    let endpoint = base_url
        .join("store/index")
        .context("failed to compose store/index url")?;

    let response = client
        .get(endpoint)
        .query(&[("depth", depth.max(1).to_string())])
        .query(&[("prefix", prefix.unwrap_or_default().to_string())])
        .send()
        .context("failed calling /store/index")?
        .error_for_status()
        .context("/store/index returned non-success status")?;

    let payload: StoreIndexResponse = response
        .json()
        .context("failed parsing /store/index response")?;

    Ok(snapshot_from_index_entries(payload.entries))
}

fn snapshot_from_index_entries(entries: Vec<StoreIndexEntry>) -> SyncSnapshot {
    let mut remote = Vec::with_capacity(entries.len());

    for entry in entries {
        if entry.entry_type == "prefix" {
            let directory_path = entry.path.trim_end_matches('/').to_string();
            if !directory_path.is_empty() {
                remote.push(NamespaceEntry::directory(directory_path));
            }
            continue;
        }

        remote.push(NamespaceEntry::file(
            entry.path.clone(),
            "server-head",
            format!("server-head:{}", entry.path),
        ));
    }

    SyncSnapshot {
        local: Vec::new(),
        remote,
    }
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
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/store/docs/read%20me.txt");
    }
}
