use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub(super) const FFPROBE_TIMEOUT_SECS: u64 = 60;
pub(super) const FFMPEG_TIMEOUT_SECS: u64 = 160;
pub(super) const VIDEO_THUMBNAIL_SEEK_FRACTION: f64 = 0.10;
pub(super) const VIDEO_THUMBNAIL_SEEK_MIN_SECS: f64 = 10.0;
pub(super) const VIDEO_THUMBNAIL_SEEK_MAX_SECS: f64 = 120.0;
pub(super) const VIDEO_THUMBNAIL_UNKNOWN_DURATION_SEEK_SECS: f64 = 60.0;
const NATURAL_EARTH_GDAL_COMMANDS: [&str; 5] = [
    "gdal_rasterize",
    "gdalwarp",
    "gdal_translate",
    "gdaladdo",
    "ogr2ogr",
];

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
    Optional,
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
                cockpit_dependency_check(),
                binary_dependency_check(
                    "video-metadata",
                    "Video metadata extraction",
                    &self.ffprobe,
                    "Video metadata extraction needs ffprobe on the server host.",
                    Some("Install the `ffmpeg` package on the server host to provide both `ffprobe` and `ffmpeg`."),
                ),
                binary_dependency_check(
                    "video-thumbnails",
                    "Video thumbnail generation",
                    &self.ffmpeg,
                    "Video thumbnail generation needs ffmpeg on the server host.",
                    Some("Install the `ffmpeg` package on the server host to provide both `ffprobe` and `ffmpeg`."),
                ),
                binary_dependency_check(
                    "natural-earth-unzip",
                    "Natural Earth archive extraction (unzip)",
                    Path::new("unzip"),
                    "Automatic Natural Earth map imports need unzip to extract the official source archive.",
                    Some("On Debian or Ubuntu, install the `unzip` package on the server host."),
                ),
                natural_earth_gdal_dependency_check(),
            ],
        }
    }
}

fn cockpit_dependency_check() -> HostDependencyCheck {
    let candidates = cockpit_ws_candidate_paths();
    cockpit_dependency_check_for_candidates(&candidates)
}

fn cockpit_dependency_check_for_candidates(candidates: &[PathBuf]) -> HostDependencyCheck {
    let resolved_path = candidates
        .iter()
        .find_map(|candidate| resolve_host_dependency_path(candidate));

    match resolved_path {
        Some(path) => HostDependencyCheck {
            id: "cockpit".to_string(),
            feature: "Cockpit host administration".to_string(),
            status: HostDependencyStatus::Ready,
            summary: format!("Cockpit web service found at {}", path.display()),
            detail: "Cockpit is available as a separate host-administration interface. Use its own sign-in and UI for host-level tasks such as restarting the IronMesh service, applying updates, or rebooting the host. IronMesh does not invoke Cockpit or share credentials with it.".to_string(),
            configured_path: None,
            resolved_path: Some(path.display().to_string()),
            install_hint: None,
        },
        None => HostDependencyCheck {
            id: "cockpit".to_string(),
            feature: "Cockpit host administration".to_string(),
            status: HostDependencyStatus::Optional,
            summary: "Cockpit web service was not found on this host".to_string(),
            detail: "Cockpit is optional and is not required by IronMesh. If you use Cockpit for host administration, install and access it separately to restart the IronMesh service, apply updates, or reboot the host.".to_string(),
            configured_path: None,
            resolved_path: None,
            install_hint: Some(
                "Install Cockpit with your host distribution's package manager if you want a separate web interface for host administration.".to_string(),
            ),
        },
    }
}

fn cockpit_ws_candidate_paths() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        let mut candidates = vec![PathBuf::from("cockpit-ws")];
        candidates.extend([
            PathBuf::from("/usr/lib/cockpit/cockpit-ws"),
            PathBuf::from("/usr/libexec/cockpit-ws"),
            PathBuf::from("/usr/libexec/cockpit/cockpit-ws"),
        ]);
        candidates
    }

    #[cfg(not(unix))]
    {
        vec![PathBuf::from("cockpit-ws")]
    }
}

fn binary_dependency_check(
    id: &str,
    feature: &str,
    configured_path: &Path,
    feature_detail: &str,
    missing_install_hint: Option<&str>,
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
        install_hint: (status == HostDependencyStatus::Missing)
            .then(|| missing_install_hint.map(str::to_string))
            .flatten(),
    }
}

fn natural_earth_gdal_dependency_check() -> HostDependencyCheck {
    let resolutions = NATURAL_EARTH_GDAL_COMMANDS
        .iter()
        .map(|command| (*command, resolve_host_dependency_path(Path::new(command))))
        .collect::<Vec<_>>();
    let resolved_commands = resolutions
        .iter()
        .filter_map(|(command, path)| {
            path.as_ref()
                .map(|path| format!("{command}: {}", path.display()))
        })
        .collect::<Vec<_>>();
    let missing_commands = resolutions
        .iter()
        .filter(|(_, path)| path.is_none())
        .map(|(command, _)| *command)
        .collect::<Vec<_>>();
    let status = if missing_commands.is_empty() {
        HostDependencyStatus::Ready
    } else {
        HostDependencyStatus::Missing
    };

    HostDependencyCheck {
        id: "natural-earth-gdal".to_string(),
        feature: "Natural Earth map conversion (GDAL)".to_string(),
        status: status.clone(),
        summary: if missing_commands.is_empty() {
            "All required GDAL map-conversion commands were resolved on PATH".to_string()
        } else {
            format!(
                "Required GDAL command(s) not found on PATH: {}",
                missing_commands.join(", ")
            )
        },
        detail: "Automatic Natural Earth map imports need GDAL to rasterize source layers, project them to Web Mercator, create MBTiles overviews, and generate the vector label overlay.".to_string(),
        configured_path: Some(NATURAL_EARTH_GDAL_COMMANDS.join(", ")),
        resolved_path: (!resolved_commands.is_empty()).then(|| resolved_commands.join("; ")),
        install_hint: (status == HostDependencyStatus::Missing).then(|| {
            "On Debian or Ubuntu, install the `gdal-bin` package; it provides gdal_rasterize, gdalwarp, gdal_translate, gdaladdo, and ogr2ogr.".to_string()
        }),
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn cockpit_dependency_check_reports_optional_and_ready_states() {
        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("ironmesh-cockpit-dependency-{unique_suffix}"));
        std::fs::create_dir_all(&root).unwrap();
        let missing_path = root.join("missing-cockpit-ws");

        let missing = cockpit_dependency_check_for_candidates(&[missing_path]);
        assert_eq!(missing.status, HostDependencyStatus::Optional);
        assert!(missing.resolved_path.is_none());

        let cockpit_ws_path = root.join("cockpit-ws");
        std::fs::write(&cockpit_ws_path, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&cockpit_ws_path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&cockpit_ws_path, permissions).unwrap();

        let ready = cockpit_dependency_check_for_candidates(std::slice::from_ref(&cockpit_ws_path));
        assert_eq!(ready.status, HostDependencyStatus::Ready);
        assert_eq!(
            ready.resolved_path.as_deref(),
            Some(cockpit_ws_path.to_string_lossy().as_ref())
        );

        let _ = std::fs::remove_dir_all(root);
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
