use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const GNOME_EXTENSION_UUID: &str = "ironmesh-status@ironmesh.io";

#[derive(Debug)]
pub struct GnomeExtensionInstallOutcome {
    pub install_dir: PathBuf,
    pub enable_note: Option<String>,
}

pub fn default_gnome_status_file_path() -> Result<PathBuf> {
    let runtime_dir = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or_else(|| anyhow!("XDG_RUNTIME_DIR is not set; pass --gnome-status-file"))?;
    Ok(PathBuf::from(runtime_dir)
        .join("ironmesh")
        .join("gnome-status.json"))
}

pub fn install_gnome_extension_from(
    source_dir: &Path,
    enable: bool,
) -> Result<GnomeExtensionInstallOutcome> {
    if !source_dir.exists() {
        return Err(anyhow!(
            "GNOME extension assets are missing at {}",
            source_dir.display()
        ));
    }

    let install_dir = extension_install_dir()?;
    if install_dir.exists() {
        fs::remove_dir_all(&install_dir)
            .with_context(|| format!("failed to remove {}", install_dir.display()))?;
    }

    copy_directory_recursive(source_dir, &install_dir)?;

    let enable_note = if enable {
        Some(enable_extension_command()?)
    } else {
        None
    };

    Ok(GnomeExtensionInstallOutcome {
        install_dir,
        enable_note,
    })
}

fn extension_install_dir() -> Result<PathBuf> {
    let home_dir =
        std::env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set for GNOME install"))?;
    Ok(PathBuf::from(home_dir)
        .join(".local")
        .join("share")
        .join("gnome-shell")
        .join("extensions")
        .join(GNOME_EXTENSION_UUID))
}

fn enable_extension_command() -> Result<String> {
    match Command::new("gnome-extensions")
        .arg("enable")
        .arg(GNOME_EXTENSION_UUID)
        .output()
    {
        Ok(output) if output.status.success() => Ok(format!(
            "Enabled extension {}; if the top bar does not update immediately, {}.",
            GNOME_EXTENSION_UUID,
            restart_hint()
        )),
        Ok(output) => {
            let detail = failure_output_detail(&output.stdout, &output.stderr);
            if detail
                .as_deref()
                .is_some_and(|detail| detail.contains("does not exist"))
            {
                return Ok(extension_pending_session_discovery_note(
                    output.status.to_string(),
                    detail.as_deref(),
                ));
            }

            Ok(format!(
                "Extension copied, but `gnome-extensions enable {}` exited with status {}{}. Enable it manually from Extensions or with `gnome-extensions enable {}`.",
                GNOME_EXTENSION_UUID,
                output.status,
                detail
                    .as_deref()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default(),
                GNOME_EXTENSION_UUID
            ))
        }
        Err(error) => Ok(format!(
            "Extension copied, but automatic enabling failed: {error}. Enable it manually from Extensions or with `gnome-extensions enable {}`.",
            GNOME_EXTENSION_UUID
        )),
    }
}

fn extension_pending_session_discovery_note(status: String, detail: Option<&str>) -> String {
    match queue_extension_for_next_login(GNOME_EXTENSION_UUID) {
        Ok(QueueExtensionResult::Queued) => format!(
            "Extension copied, but GNOME Shell has not discovered new user extensions in this session (`gnome-extensions enable {}` exited with status {}{}). Queued the extension in `org.gnome.shell enabled-extensions`; {} to activate it.",
            GNOME_EXTENSION_UUID,
            status,
            format_detail_suffix(detail),
            restart_hint()
        ),
        Ok(QueueExtensionResult::AlreadyQueued) => format!(
            "Extension copied, but GNOME Shell has not discovered new user extensions in this session (`gnome-extensions enable {}` exited with status {}{}). The extension is already queued in `org.gnome.shell enabled-extensions`; {} to activate it.",
            GNOME_EXTENSION_UUID,
            status,
            format_detail_suffix(detail),
            restart_hint()
        ),
        Err(error) => format!(
            "Extension copied, but GNOME Shell has not discovered new user extensions in this session (`gnome-extensions enable {}` exited with status {}{}). Automatic queueing for next login failed: {error}. Enable it manually after you {}.",
            GNOME_EXTENSION_UUID,
            status,
            format_detail_suffix(detail),
            restart_hint()
        ),
    }
}

fn restart_hint() -> &'static str {
    match std::env::var("XDG_SESSION_TYPE") {
        Ok(value) if value.eq_ignore_ascii_case("wayland") => "log out and back in",
        _ => "restart GNOME Shell or log out and back in",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueExtensionResult {
    Queued,
    AlreadyQueued,
}

fn queue_extension_for_next_login(uuid: &str) -> Result<QueueExtensionResult> {
    let output = Command::new("gsettings")
        .args(["get", "org.gnome.shell", "enabled-extensions"])
        .output()
        .context("failed to read org.gnome.shell enabled-extensions")?;
    if !output.status.success() {
        let detail = failure_output_detail(&output.stdout, &output.stderr)
            .unwrap_or_else(|| "unknown gsettings get failure".to_string());
        return Err(anyhow!(
            "`gsettings get org.gnome.shell enabled-extensions` failed: {detail}"
        ));
    }

    let raw = String::from_utf8(output.stdout)
        .context("org.gnome.shell enabled-extensions output was not valid UTF-8")?;
    let mut enabled = parse_enabled_extensions_value(&raw);
    if enabled.iter().any(|entry| entry == uuid) {
        return Ok(QueueExtensionResult::AlreadyQueued);
    }

    enabled.push(uuid.to_string());
    let formatted = format_enabled_extensions_value(&enabled);
    let output = Command::new("gsettings")
        .args(["set", "org.gnome.shell", "enabled-extensions", &formatted])
        .output()
        .context("failed to update org.gnome.shell enabled-extensions")?;
    if !output.status.success() {
        let detail = failure_output_detail(&output.stdout, &output.stderr)
            .unwrap_or_else(|| "unknown gsettings set failure".to_string());
        return Err(anyhow!(
            "`gsettings set org.gnome.shell enabled-extensions ...` failed: {detail}"
        ));
    }

    Ok(QueueExtensionResult::Queued)
}

fn parse_enabled_extensions_value(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let trimmed = trimmed.strip_prefix("@as ").unwrap_or(trimmed);
    let Some(inner) = trimmed.strip_prefix('[').and_then(|value| value.strip_suffix(']')) else {
        return Vec::new();
    };

    let mut values = Vec::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            continue;
        }

        let mut value = String::new();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    if let Some(next) = chars.next() {
                        value.push(next);
                    }
                }
                '\'' => break,
                _ => value.push(ch),
            }
        }
        values.push(value);
    }

    values
}

fn format_enabled_extensions_value(values: &[String]) -> String {
    let joined = values
        .iter()
        .map(|value| format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'")))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{joined}]")
}

fn format_detail_suffix(detail: Option<&str>) -> String {
    detail
        .filter(|detail| !detail.is_empty())
        .map(|detail| format!(" ({detail})"))
        .unwrap_or_default()
}

fn failure_output_detail(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    if !stdout.is_empty() {
        return Some(stdout);
    }

    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    if !stderr.is_empty() {
        return Some(stderr);
    }

    None
}

fn copy_directory_recursive(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)
        .with_context(|| format!("failed to create {}", destination.display()))?;

    for entry in
        fs::read_dir(source).with_context(|| format!("failed to read {}", source.display()))?
    {
        let entry = entry.with_context(|| format!("failed to enumerate {}", source.display()))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", source_path.display()))?;
        if file_type.is_dir() {
            copy_directory_recursive(&source_path, &destination_path)?;
        } else {
            fs::copy(&source_path, &destination_path).with_context(|| {
                format!(
                    "failed to copy {} to {}",
                    source_path.display(),
                    destination_path.display()
                )
            })?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{format_enabled_extensions_value, parse_enabled_extensions_value};

    #[test]
    fn parse_enabled_extensions_supports_plain_arrays() {
        assert_eq!(
            parse_enabled_extensions_value("['ding@rastersoft.com', 'ironmesh-status@ironmesh.io']"),
            vec![
                "ding@rastersoft.com".to_string(),
                "ironmesh-status@ironmesh.io".to_string(),
            ]
        );
    }

    #[test]
    fn parse_enabled_extensions_supports_typed_empty_arrays() {
        assert!(parse_enabled_extensions_value("@as []").is_empty());
    }

    #[test]
    fn format_enabled_extensions_round_trips() {
        let values = vec![
            "ding@rastersoft.com".to_string(),
            "ironmesh-status@ironmesh.io".to_string(),
        ];
        let formatted = format_enabled_extensions_value(&values);
        assert_eq!(parse_enabled_extensions_value(&formatted), values);
    }
}