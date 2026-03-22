use crate::runtime::{HydrationProgress, HydrationRequest, HydrationResult, Hydrator, Uploader};
use anyhow::{Context, Result};
use client_sdk::ironmesh_client::{DownloadProgress, DownloadRangeRequest};
use client_sdk::{
    ClientIdentityMaterial, IronMeshClient, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, normalize_server_base_url,
};
use reqwest::Url;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct ServerNodeHydrator {
    sdk: IronMeshClient,
    download_stage_root: PathBuf,
}

impl ServerNodeHydrator {
    pub fn with_client(sdk: IronMeshClient, download_stage_root: PathBuf) -> Self {
        Self {
            sdk,
            download_stage_root,
        }
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
        Ok(Self::with_client(
            sdk,
            windows_download_stage_root(base_url.as_str())?,
        ))
    }
}

impl Hydrator for ServerNodeHydrator {
    fn hydrate(&self, path: &str, _remote_version: &str) -> Result<Vec<u8>> {
        eprintln!("hydrating path {path} from server");
        let mut bytes = Vec::new();
        self.sdk
            .download_to_writer_resumable_staged(
                path,
                None,
                None,
                &mut bytes,
                &self.download_stage_root,
            )
            .with_context(|| format!("failed to fetch object for path {path}"))?;
        Ok(bytes)
    }

    fn hydrate_range_to_writer(
        &self,
        request: HydrationRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(HydrationProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<HydrationResult> {
        eprintln!(
            "hydrating range path {path} from server offset={} length={}",
            request.offset,
            request.length,
            path = request.path,
        );
        let result = self
            .sdk
            .download_range_to_writer_with_progress_blocking(
                DownloadRangeRequest {
                    key: request.path,
                    snapshot: None,
                    version: None,
                    start: request.offset,
                    length: request.length,
                },
                writer,
                &mut |progress: DownloadProgress| {
                    on_progress(HydrationProgress {
                        object_size_bytes: progress.object_size_bytes,
                        range_start: progress.range_start,
                        range_length: progress.range_length,
                        bytes_transferred: progress.bytes_downloaded,
                    });
                },
                should_cancel,
            )
            .with_context(|| format!("failed to fetch ranged object for path {}", request.path))?;

        Ok(HydrationResult {
            object_size_bytes: result.object_size_bytes,
            range_start: result.range_start,
            range_length: result.range_length,
            bytes_transferred: result.bytes_downloaded,
        })
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

pub fn windows_download_stage_root(scope: &str) -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = base
        .join("ironmesh")
        .join("cfapi-downloads")
        .join(download_scope_label(scope));
    fs::create_dir_all(&path)
        .with_context(|| format!("failed to create download stage root {}", path.display()))?;
    Ok(path)
}

pub fn windows_download_stage_root_for_sync_root(sync_root: &Path) -> Result<PathBuf> {
    windows_download_stage_root(&sync_root.to_string_lossy())
}

fn download_scope_label(scope: &str) -> String {
    blake3::hash(scope.as_bytes()).to_hex().to_string()
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
