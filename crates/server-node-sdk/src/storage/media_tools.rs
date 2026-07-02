use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub(super) const FFPROBE_TIMEOUT_SECS: u64 = 60;
pub(super) const FFMPEG_TIMEOUT_SECS: u64 = 160;
pub(super) const VIDEO_THUMBNAIL_SEEK_FRACTION: f64 = 0.10;
pub(super) const VIDEO_THUMBNAIL_SEEK_MIN_SECS: f64 = 10.0;
pub(super) const VIDEO_THUMBNAIL_SEEK_MAX_SECS: f64 = 120.0;
pub(super) const VIDEO_THUMBNAIL_UNKNOWN_DURATION_SEEK_SECS: f64 = 60.0;

#[derive(Clone)]
pub(super) struct MediaToolPaths {
    pub(super) ffprobe: PathBuf,
    pub(super) ffmpeg: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostDependencyStatus {
    Ready,
    Missing,
    Builtin,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostDependencyCheck {
    pub id: String,
    pub feature: String,
    pub status: HostDependencyStatus,
    pub summary: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configured_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostDependencyReport {
    pub host_os: String,
    pub generated_at_unix: u64,
    pub checks: Vec<HostDependencyCheck>,
}

impl Default for MediaToolPaths {
    fn default() -> Self {
        Self {
            ffprobe: PathBuf::from("ffprobe"),
            ffmpeg: PathBuf::from("ffmpeg"),
        }
    }
}

impl MediaToolPaths {
    pub(super) fn host_dependency_report(&self) -> HostDependencyReport {
        HostDependencyReport {
            host_os: std::env::consts::OS.to_string(),
            generated_at_unix: super::unix_ts(),
            checks: vec![
                HostDependencyCheck {
                    id: "image-thumbnails".to_string(),
                    feature: "Image thumbnails and metadata".to_string(),
                    status: HostDependencyStatus::Builtin,
                    summary: "Ready without extra host packages".to_string(),
                    detail: "Server-side image thumbnails and metadata use the built-in Rust image pipeline on this node.".to_string(),
                    configured_path: None,
                    resolved_path: None,
                    install_hint: None,
                },
                binary_dependency_check(
                    "video-metadata",
                    "Video metadata extraction",
                    &self.ffprobe,
                    "Video metadata extraction needs ffprobe on the server host.",
                ),
                binary_dependency_check(
                    "video-thumbnails",
                    "Video thumbnail generation",
                    &self.ffmpeg,
                    "Video thumbnail generation needs ffmpeg on the server host.",
                ),
            ],
        }
    }
}

fn binary_dependency_check(
    id: &str,
    feature: &str,
    configured_path: &Path,
    feature_detail: &str,
) -> HostDependencyCheck {
    let configured_path_display = configured_path.display().to_string();
    let resolved_path = resolve_host_dependency_path(configured_path);
    let status = if resolved_path.is_some() {
        HostDependencyStatus::Ready
    } else {
        HostDependencyStatus::Missing
    };
    let summary = match resolved_path.as_ref() {
        Some(path) => format!("Resolved on host at {}", path.display()),
        None if dependency_uses_explicit_path(configured_path) => {
            format!(
                "Configured path {} is not executable",
                configured_path_display
            )
        }
        None => format!("Command {} was not found on PATH", configured_path_display),
    };
    let detail = match resolved_path.as_ref() {
        Some(path) => format!(
            "{feature_detail} The current server configuration resolves this dependency to {}.",
            path.display()
        ),
        None if dependency_uses_explicit_path(configured_path) => format!(
            "{feature_detail} The configured path {} does not exist or is not executable on this host.",
            configured_path_display
        ),
        None => format!(
            "{feature_detail} The configured command {} could not be resolved from PATH on this host.",
            configured_path_display
        ),
    };

    HostDependencyCheck {
        id: id.to_string(),
        feature: feature.to_string(),
        status: status.clone(),
        summary,
        detail,
        configured_path: Some(configured_path_display),
        resolved_path: resolved_path.map(|path| path.display().to_string()),
        install_hint: if id.starts_with("video-") && status == HostDependencyStatus::Missing {
            Some("Install the `ffmpeg` package on the server host to provide both `ffprobe` and `ffmpeg`.".to_string())
        } else {
            None
        },
    }
}

fn dependency_uses_explicit_path(path: &Path) -> bool {
    path.is_absolute() || path.components().count() > 1
}

fn resolve_host_dependency_path(configured_path: &Path) -> Option<PathBuf> {
    if dependency_uses_explicit_path(configured_path) {
        return dependency_path_is_executable(configured_path)
            .then(|| configured_path.to_path_buf());
    }

    let path_env = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path_env) {
        #[cfg(windows)]
        {
            for candidate in windows_dependency_candidates(&entry.join(configured_path)) {
                if dependency_path_is_executable(&candidate) {
                    return Some(candidate);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let candidate = entry.join(configured_path);
            if dependency_path_is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn dependency_path_is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(windows)]
fn windows_dependency_candidates(path: &Path) -> Vec<PathBuf> {
    if path.extension().is_some() {
        return vec![path.to_path_buf()];
    }

    let mut candidates = Vec::new();
    if let Some(path_exts) = std::env::var_os("PATHEXT") {
        let path_exts = path_exts.to_string_lossy();
        for extension in path_exts
            .split(';')
            .filter(|value| !value.trim().is_empty())
        {
            candidates.push(PathBuf::from(format!("{}{}", path.display(), extension)));
        }
    }
    if candidates.is_empty() {
        candidates.push(path.with_extension("exe"));
    }
    candidates
}

#[derive(Debug, Deserialize)]
pub(super) struct FfprobeOutput {
    #[serde(default)]
    pub(super) streams: Vec<FfprobeStream>,
    #[serde(default)]
    pub(super) format: Option<FfprobeFormat>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FfprobeStream {
    pub(super) width: Option<u32>,
    pub(super) height: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub(super) struct FfprobeFormat {
    pub(super) format_name: Option<String>,
    pub(super) duration: Option<String>,
}
