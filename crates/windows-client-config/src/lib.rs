#![cfg(windows)]

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONFIG_APP_EXE: &str = "ironmesh-config-app.exe";
pub const BACKGROUND_LAUNCHER_EXE: &str = "ironmesh-background-launcher.exe";
pub const OS_INTEGRATION_EXE: &str = "os-integration.exe";
pub const FOLDER_AGENT_EXE: &str = "ironmesh-folder-agent.exe";
pub const STARTUP_TASK_ID: &str = "IronmeshBackgroundLauncher";

const LOCAL_STATE_ROOT_DIR: &str = "Ironmesh";
const CONFIG_SUBDIR: &str = "windows-client-config";
const INSTANCE_STORE_FILE_NAME: &str = "instances.json";
const LAST_LAUNCH_REPORT_FILE_NAME: &str = "last-launch-report.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManagedInstanceStore {
    #[serde(default)]
    pub os_integration_instances: Vec<OsIntegrationInstance>,
    #[serde(default)]
    pub folder_agent_instances: Vec<FolderAgentInstance>,
}

impl ManagedInstanceStore {
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed reading managed instance store {}", path.display()))?;
        if raw.trim().is_empty() {
            return Ok(Self::default());
        }

        serde_json::from_str(&raw)
            .with_context(|| format!("failed parsing managed instance store {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        ensure_parent_dir(path)?;
        let payload = serde_json::to_vec_pretty(self).context("failed serializing managed instance store")?;
        fs::write(path, payload)
            .with_context(|| format!("failed writing managed instance store {}", path.display()))
    }

    pub fn upsert_os_integration(&mut self, instance: OsIntegrationInstance) {
        if let Some(existing) = self
            .os_integration_instances
            .iter_mut()
            .find(|candidate| candidate.id == instance.id)
        {
            *existing = instance;
        } else {
            self.os_integration_instances.push(instance);
        }
        self.sort();
    }

    pub fn upsert_folder_agent(&mut self, instance: FolderAgentInstance) {
        if let Some(existing) = self
            .folder_agent_instances
            .iter_mut()
            .find(|candidate| candidate.id == instance.id)
        {
            *existing = instance;
        } else {
            self.folder_agent_instances.push(instance);
        }
        self.sort();
    }

    pub fn remove_os_integration(&mut self, id: &str) -> bool {
        let initial_len = self.os_integration_instances.len();
        self.os_integration_instances.retain(|candidate| candidate.id != id);
        initial_len != self.os_integration_instances.len()
    }

    pub fn remove_folder_agent(&mut self, id: &str) -> bool {
        let initial_len = self.folder_agent_instances.len();
        self.folder_agent_instances.retain(|candidate| candidate.id != id);
        initial_len != self.folder_agent_instances.len()
    }

    fn sort(&mut self) {
        self.os_integration_instances.sort_by(|left, right| {
            left.label
                .to_ascii_lowercase()
                .cmp(&right.label.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        self.folder_agent_instances.sort_by(|left, right| {
            left.label
                .to_ascii_lowercase()
                .cmp(&right.label.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsIntegrationInstance {
    pub id: String,
    pub label: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub sync_root_id: String,
    pub display_name: String,
    pub root_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_cert: Option<String>,
}

impl OsIntegrationInstance {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("os-integration instance id must not be empty");
        }
        if self.label.trim().is_empty() {
            bail!("os-integration instance label must not be empty");
        }
        if self.sync_root_id.trim().is_empty() {
            bail!("os-integration sync_root_id must not be empty");
        }
        if self.display_name.trim().is_empty() {
            bail!("os-integration display_name must not be empty");
        }
        if self.root_path.trim().is_empty() {
            bail!("os-integration root_path must not be empty");
        }
        Ok(())
    }

    pub fn command_args(&self) -> Vec<String> {
        let mut args = vec![
            "serve".to_string(),
            "--sync-root-id".to_string(),
            self.sync_root_id.clone(),
            "--display-name".to_string(),
            self.display_name.clone(),
            "--root-path".to_string(),
            self.root_path.clone(),
        ];

        push_optional_arg(&mut args, "--server-base-url", self.server_base_url.as_deref());
        push_optional_arg(&mut args, "--prefix", self.prefix.as_deref());
        push_optional_arg(&mut args, "--bootstrap-file", self.bootstrap_file.as_deref());
        push_optional_arg(
            &mut args,
            "--client-identity-file",
            self.client_identity_file.as_deref(),
        );
        push_optional_arg(&mut args, "--server-ca-cert", self.server_ca_cert.as_deref());

        args
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderAgentInstance {
    pub id: String,
    pub label: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub root_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_root_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_pem_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui_bind: Option<String>,
    #[serde(default)]
    pub run_once: bool,
    #[serde(default)]
    pub no_watch_local: bool,
}

impl FolderAgentInstance {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("folder-agent instance id must not be empty");
        }
        if self.label.trim().is_empty() {
            bail!("folder-agent instance label must not be empty");
        }
        if self.root_dir.trim().is_empty() {
            bail!("folder-agent root_dir must not be empty");
        }
        Ok(())
    }

    pub fn command_args(&self) -> Vec<String> {
        let mut args = vec!["--root-dir".to_string(), self.root_dir.clone()];

        push_optional_arg(&mut args, "--state-root-dir", self.state_root_dir.as_deref());
        push_optional_arg(&mut args, "--server-base-url", self.server_base_url.as_deref());
        push_optional_arg(&mut args, "--bootstrap-file", self.bootstrap_file.as_deref());
        push_optional_arg(
            &mut args,
            "--server-ca-pem-file",
            self.server_ca_pem_file.as_deref(),
        );
        push_optional_arg(
            &mut args,
            "--client-identity-file",
            self.client_identity_file.as_deref(),
        );
        push_optional_arg(&mut args, "--prefix", self.prefix.as_deref());
        push_optional_arg(&mut args, "--ui-bind", self.ui_bind.as_deref());

        if self.run_once {
            args.push("--run-once".to_string());
        }
        if self.no_watch_local {
            args.push("--no-watch-local".to_string());
        }

        args
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchReport {
    pub launched_at_unix_ms: u64,
    pub package_root: String,
    pub total_enabled: usize,
    pub outcomes: Vec<LaunchOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchOutcome {
    pub instance_kind: String,
    pub id: String,
    pub label: String,
    pub executable: String,
    pub command_line: Vec<String>,
    pub pid: Option<u32>,
    pub error: Option<String>,
}

pub fn default_instance_store_path() -> PathBuf {
    local_appdata_root()
        .join(CONFIG_SUBDIR)
        .join(INSTANCE_STORE_FILE_NAME)
}

pub fn default_launch_report_path() -> PathBuf {
    local_appdata_root()
        .join(CONFIG_SUBDIR)
        .join(LAST_LAUNCH_REPORT_FILE_NAME)
}

pub fn load_last_launch_report(path: &Path) -> Result<Option<LaunchReport>> {
    if !path.exists() {
        return Ok(None);
    }

    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading launch report {}", path.display()))?;
    if raw.trim().is_empty() {
        return Ok(None);
    }

    serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing launch report {}", path.display()))
        .map(Some)
}

pub fn save_launch_report(path: &Path, report: &LaunchReport) -> Result<()> {
    ensure_parent_dir(path)?;
    let payload = serde_json::to_vec_pretty(report).context("failed serializing launch report")?;
    fs::write(path, payload)
        .with_context(|| format!("failed writing launch report {}", path.display()))
}

pub fn package_root_from_current_exe() -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("failed locating current executable")?;
    current_exe
        .parent()
        .map(Path::to_path_buf)
        .context("failed locating package root from current executable path")
}

pub fn generate_instance_id(prefix: &str) -> String {
    format!("{}-{}", prefix, unix_ts_ms())
}

pub fn launch_enabled_instances(store: &ManagedInstanceStore, package_root: &Path) -> LaunchReport {
    let mut outcomes = Vec::new();

    for instance in &store.os_integration_instances {
        if !instance.enabled {
            continue;
        }
        outcomes.push(spawn_instance(
            "os-integration",
            &instance.id,
            &instance.label,
            package_root.join(OS_INTEGRATION_EXE),
            instance.command_args(),
        ));
    }

    for instance in &store.folder_agent_instances {
        if !instance.enabled {
            continue;
        }
        outcomes.push(spawn_instance(
            "folder-agent",
            &instance.id,
            &instance.label,
            package_root.join(FOLDER_AGENT_EXE),
            instance.command_args(),
        ));
    }

    LaunchReport {
        launched_at_unix_ms: unix_ts_ms(),
        package_root: package_root.display().to_string(),
        total_enabled: outcomes.len(),
        outcomes,
    }
}

fn spawn_instance(
    instance_kind: &str,
    id: &str,
    label: &str,
    executable_path: PathBuf,
    command_line: Vec<String>,
) -> LaunchOutcome {
    let executable = executable_path.display().to_string();
    let mut command = Command::new(&executable_path);
    command
        .args(&command_line)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    match command.spawn() {
        Ok(child) => LaunchOutcome {
            instance_kind: instance_kind.to_string(),
            id: id.to_string(),
            label: label.to_string(),
            executable,
            command_line,
            pid: Some(child.id()),
            error: None,
        },
        Err(error) => LaunchOutcome {
            instance_kind: instance_kind.to_string(),
            id: id.to_string(),
            label: label.to_string(),
            executable,
            command_line,
            pid: None,
            error: Some(error.to_string()),
        },
    }
}

fn push_optional_arg(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };

    args.push(flag.to_string());
    args.push(value.to_string());
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };

    fs::create_dir_all(parent)
        .with_context(|| format!("failed creating parent directory {}", parent.display()))
}

fn local_appdata_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(LOCAL_STATE_ROOT_DIR)
}

fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn default_enabled() -> bool {
    true
}