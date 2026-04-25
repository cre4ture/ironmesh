use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CONFIG_APP_EXE: &str = if cfg!(windows) {
    "ironmesh-config-app.exe"
} else {
    "ironmesh-config-app"
};
pub const BACKGROUND_LAUNCHER_EXE: &str = if cfg!(windows) {
    "ironmesh-background-launcher.exe"
} else {
    "ironmesh-background-launcher"
};
pub const OS_INTEGRATION_EXE: &str = if cfg!(windows) {
    "ironmesh-os-integration.exe"
} else {
    "ironmesh-os-integration"
};
pub const FOLDER_AGENT_EXE: &str = if cfg!(windows) {
    "ironmesh-folder-agent.exe"
} else {
    "ironmesh-folder-agent"
};
pub const STARTUP_TASK_ID: &str = "IronmeshBackgroundLauncher";
pub const PLATFORM_KIND: &str = env::consts::OS;
pub const STARTUP_INTEGRATION_LABEL: &str = if cfg!(windows) {
    "Startup Task"
} else {
    "Autostart"
};
pub const STARTUP_INTEGRATION_VALUE: &str = if cfg!(windows) {
    STARTUP_TASK_ID
} else {
    "Not configured"
};
pub const STARTUP_INTEGRATION_NOTE: &str = if cfg!(windows) {
    "Enabled services can restart after sign-in through the packaged startup task."
} else {
    "Run Enabled Services works on Linux, but login autostart is not wired yet."
};
pub const OS_INTEGRATION_MANAGEMENT_SUPPORTED: bool = cfg!(any(windows, target_os = "linux"));

const LOCAL_STATE_ROOT_DIR: &str = "Ironmesh";
const CONFIG_SUBDIR: &str = "desktop-client-config";
#[cfg(windows)]
const LEGACY_WINDOWS_CONFIG_SUBDIR: &str = "windows-client-config";
const INSTANCE_STORE_FILE_NAME: &str = "instances.json";
const LAST_LAUNCH_REPORT_FILE_NAME: &str = "last-launch-report.json";
const SERVICE_LOG_SUBDIR: &str = "service-logs";
const MANAGED_INSTANCE_STORE_VERSION: u32 = 1;
const LAUNCH_REPORT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedInstanceStore {
    #[serde(default = "managed_instance_store_version")]
    pub version: u32,
    #[serde(default)]
    pub client_identities: Vec<ClientIdentityConfig>,
    #[serde(default)]
    pub os_integration_instances: Vec<OsIntegrationInstance>,
    #[serde(default)]
    pub folder_agent_instances: Vec<FolderAgentInstance>,
}

impl Default for ManagedInstanceStore {
    fn default() -> Self {
        Self {
            version: MANAGED_INSTANCE_STORE_VERSION,
            client_identities: Vec::new(),
            os_integration_instances: Vec::new(),
            folder_agent_instances: Vec::new(),
        }
    }
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

        let store: ManagedInstanceStore = serde_json::from_str(&raw)
            .with_context(|| format!("failed parsing managed instance store {}", path.display()))?;
        store.validate_version(path)?;
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        ensure_parent_dir(path)?;
        let mut store = self.clone();
        store.version = MANAGED_INSTANCE_STORE_VERSION;
        let payload = serde_json::to_vec_pretty(&store)
            .context("failed serializing managed instance store")?;
        fs::write(path, payload)
            .with_context(|| format!("failed writing managed instance store {}", path.display()))
    }

    fn validate_version(&self, path: &Path) -> Result<()> {
        if self.version != MANAGED_INSTANCE_STORE_VERSION {
            bail!(
                "unsupported managed instance store version {} in {} (current={})",
                self.version,
                path.display(),
                MANAGED_INSTANCE_STORE_VERSION
            );
        }
        Ok(())
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

    pub fn upsert_client_identity(&mut self, identity: ClientIdentityConfig) {
        if let Some(existing) = self
            .client_identities
            .iter_mut()
            .find(|candidate| candidate.id == identity.id)
        {
            *existing = identity;
        } else {
            self.client_identities.push(identity);
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

    pub fn client_identity(&self, id: &str) -> Option<&ClientIdentityConfig> {
        self.client_identities
            .iter()
            .find(|candidate| candidate.id == id)
    }

    pub fn remove_client_identity(&mut self, id: &str) -> bool {
        let initial_len = self.client_identities.len();
        self.client_identities
            .retain(|candidate| candidate.id != id);
        initial_len != self.client_identities.len()
    }

    pub fn remove_os_integration(&mut self, id: &str) -> bool {
        let initial_len = self.os_integration_instances.len();
        self.os_integration_instances
            .retain(|candidate| candidate.id != id);
        initial_len != self.os_integration_instances.len()
    }

    pub fn remove_folder_agent(&mut self, id: &str) -> bool {
        let initial_len = self.folder_agent_instances.len();
        self.folder_agent_instances
            .retain(|candidate| candidate.id != id);
        initial_len != self.folder_agent_instances.len()
    }

    fn sort(&mut self) {
        self.client_identities.sort_by(|left, right| {
            left.label
                .to_ascii_lowercase()
                .cmp(&right.label.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
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
pub struct ClientIdentityConfig {
    pub id: String,
    pub label: String,
    pub bootstrap_file: String,
    pub client_identity_file: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_pem_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_enrolled_at_unix_ms: Option<u64>,
}

impl ClientIdentityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.id.trim().is_empty() {
            bail!("client identity id must not be empty");
        }
        if self.label.trim().is_empty() {
            bail!("client identity label must not be empty");
        }
        if self.bootstrap_file.trim().is_empty() {
            bail!("client identity bootstrap_file must not be empty");
        }
        if self.client_identity_file.trim().is_empty() {
            bail!("client identity client_identity_file must not be empty");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsIntegrationInstance {
    pub id: String,
    pub label: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_root_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub root_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_identity_file: Option<String>,
    #[serde(
        default,
        alias = "server_ca_cert",
        alias = "server_ca_pem_file",
        skip_serializing_if = "Option::is_none"
    )]
    pub server_ca_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_edge_state_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_name: Option<String>,
    #[serde(default)]
    pub allow_other: bool,
    #[serde(default)]
    pub publish_gnome_status: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gnome_status_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_refresh_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_status_poll_interval_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<usize>,
}

impl OsIntegrationInstance {
    pub fn validate(&self) -> Result<()> {
        if !OS_INTEGRATION_MANAGEMENT_SUPPORTED {
            bail!(
                "os-integration instances are only managed by this config surface on Windows and Linux"
            );
        }
        if self.id.trim().is_empty() {
            bail!("os-integration instance id must not be empty");
        }
        if self.label.trim().is_empty() {
            bail!("os-integration instance label must not be empty");
        }
        if self.root_path.trim().is_empty() {
            bail!("os-integration root_path must not be empty");
        }

        #[cfg(windows)]
        {
            let sync_root_id = self
                .sync_root_id
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            let display_name = self
                .display_name
                .as_deref()
                .map(str::trim)
                .unwrap_or_default();
            if sync_root_id.is_empty() {
                bail!("os-integration sync_root_id must not be empty");
            }
            if display_name.is_empty() {
                bail!("os-integration display_name must not be empty");
            }
        }

        #[cfg(target_os = "linux")]
        {
            let snapshot_file = self
                .snapshot_file
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let server_base_url = self
                .server_base_url
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let bootstrap_file = self
                .bootstrap_file
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());

            if snapshot_file.is_some() && (server_base_url.is_some() || bootstrap_file.is_some()) {
                bail!(
                    "linux os-integration snapshot_file cannot be combined with server_base_url or bootstrap_file"
                );
            }

            if snapshot_file.is_none() && server_base_url.is_none() && bootstrap_file.is_none() {
                bail!(
                    "linux os-integration requires snapshot_file, server_base_url, or bootstrap_file"
                );
            }

            if self.depth == Some(0) {
                bail!("linux os-integration depth must be greater than zero");
            }
            if self.remote_refresh_interval_ms == Some(0) {
                bail!("linux os-integration remote_refresh_interval_ms must be greater than zero");
            }
            if self.remote_status_poll_interval_ms == Some(0) {
                bail!(
                    "linux os-integration remote_status_poll_interval_ms must be greater than zero"
                );
            }
        }

        Ok(())
    }

    pub fn command_args(&self) -> Vec<String> {
        #[cfg(windows)]
        {
            let mut args = vec![
                "serve".to_string(),
                "--sync-root-id".to_string(),
                self.sync_root_id.clone().unwrap_or_default(),
                "--display-name".to_string(),
                self.display_name.clone().unwrap_or_default(),
                "--root-path".to_string(),
                self.root_path.clone(),
            ];

            push_optional_arg(
                &mut args,
                "--server-base-url",
                self.server_base_url.as_deref(),
            );
            push_optional_arg(&mut args, "--prefix", self.prefix.as_deref());
            push_optional_arg(
                &mut args,
                "--bootstrap-file",
                self.bootstrap_file.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--client-identity-file",
                self.client_identity_file.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--server-ca-cert",
                self.server_ca_path.as_deref(),
            );

            args
        }

        #[cfg(target_os = "linux")]
        {
            let mut args = vec!["--mountpoint".to_string(), self.root_path.clone()];

            push_optional_arg(&mut args, "--snapshot-file", self.snapshot_file.as_deref());
            push_optional_arg(
                &mut args,
                "--server-base-url",
                self.server_base_url.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--bootstrap-file",
                self.bootstrap_file.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--server-ca-pem-file",
                self.server_ca_path.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--client-identity-file",
                self.client_identity_file.as_deref(),
            );
            push_optional_arg(
                &mut args,
                "--client-edge-state-dir",
                self.client_edge_state_dir.as_deref(),
            );
            push_optional_arg(&mut args, "--prefix", self.prefix.as_deref());
            push_optional_arg(&mut args, "--fs-name", self.fs_name.as_deref());
            push_optional_arg(
                &mut args,
                "--gnome-status-file",
                self.gnome_status_file.as_deref(),
            );
            push_optional_u64(
                &mut args,
                "--remote-refresh-interval-ms",
                self.remote_refresh_interval_ms,
            );
            push_optional_u64(
                &mut args,
                "--remote-status-poll-interval-ms",
                self.remote_status_poll_interval_ms,
            );
            push_optional_usize(&mut args, "--depth", self.depth);

            if self.allow_other {
                args.push("--allow-other".to_string());
            }
            if self.publish_gnome_status {
                args.push("--publish-gnome-status".to_string());
            }

            args
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            Vec::new()
        }
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
    pub client_identity_id: Option<String>,
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

        push_optional_arg(
            &mut args,
            "--state-root-dir",
            self.state_root_dir.as_deref(),
        );
        push_optional_arg(
            &mut args,
            "--server-base-url",
            self.server_base_url.as_deref(),
        );
        push_optional_arg(
            &mut args,
            "--bootstrap-file",
            self.bootstrap_file.as_deref(),
        );
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchReport {
    #[serde(default = "launch_report_version")]
    pub version: u32,
    pub launched_at_unix_ms: u64,
    pub package_root: String,
    pub total_enabled: usize,
    pub outcomes: Vec<LaunchOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchOutcome {
    pub instance_kind: String,
    pub id: String,
    pub label: String,
    pub executable: String,
    pub command_line: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
    pub pid: Option<u32>,
    pub error: Option<String>,
}

pub fn default_instance_store_path() -> PathBuf {
    #[cfg(windows)]
    {
        return local_appdata_root()
            .join(CONFIG_SUBDIR)
            .join(INSTANCE_STORE_FILE_NAME);
    }

    #[cfg(not(windows))]
    {
        config_home_root()
            .join(CONFIG_SUBDIR)
            .join(INSTANCE_STORE_FILE_NAME)
    }
}

pub fn default_launch_report_path() -> PathBuf {
    #[cfg(windows)]
    {
        return local_appdata_root()
            .join(CONFIG_SUBDIR)
            .join(LAST_LAUNCH_REPORT_FILE_NAME);
    }

    #[cfg(not(windows))]
    {
        state_home_root()
            .join(CONFIG_SUBDIR)
            .join(LAST_LAUNCH_REPORT_FILE_NAME)
    }
}

pub fn default_service_log_dir() -> PathBuf {
    #[cfg(windows)]
    {
        return local_appdata_root()
            .join(CONFIG_SUBDIR)
            .join(SERVICE_LOG_SUBDIR);
    }

    #[cfg(not(windows))]
    {
        state_home_root()
            .join(CONFIG_SUBDIR)
            .join(SERVICE_LOG_SUBDIR)
    }
}

pub fn migrate_legacy_state_paths() -> Result<()> {
    #[cfg(windows)]
    {
        migrate_legacy_windows_file(
            &legacy_instance_store_path(),
            &default_instance_store_path(),
        )?;
        migrate_legacy_windows_file(&legacy_launch_report_path(), &default_launch_report_path())?;
    }

    Ok(())
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

    let report: LaunchReport = serde_json::from_str(&raw)
        .with_context(|| format!("failed parsing launch report {}", path.display()))?;
    validate_launch_report_version(&report, path)?;
    Ok(Some(report))
}

pub fn save_launch_report(path: &Path, report: &LaunchReport) -> Result<()> {
    ensure_parent_dir(path)?;
    let mut report = report.clone();
    report.version = LAUNCH_REPORT_VERSION;
    let payload = serde_json::to_vec_pretty(&report).context("failed serializing launch report")?;
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
    let launched_at_unix_ms = unix_ts_ms();
    let service_log_dir = default_service_log_dir();

    for instance in &store.os_integration_instances {
        if !instance.enabled {
            continue;
        }
        #[cfg(any(windows, target_os = "linux"))]
        {
            outcomes.push(spawn_instance(
                "os-integration",
                &instance.id,
                &instance.label,
                service_executable_candidates(package_root, OS_INTEGRATION_EXE),
                instance.command_args(),
                &service_log_dir,
                launched_at_unix_ms,
            ));
        }

        #[cfg(not(any(windows, target_os = "linux")))]
        {
            outcomes.push(unsupported_instance(
                "os-integration",
                &instance.id,
                &instance.label,
                package_root.join(OS_INTEGRATION_EXE),
                "os-integration instances are currently managed only on Windows",
            ));
        }
    }

    for instance in &store.folder_agent_instances {
        if !instance.enabled {
            continue;
        }
        outcomes.push(spawn_instance(
            "folder-agent",
            &instance.id,
            &instance.label,
            service_executable_candidates(package_root, FOLDER_AGENT_EXE),
            instance.command_args(),
            &service_log_dir,
            launched_at_unix_ms,
        ));
    }

    LaunchReport {
        version: LAUNCH_REPORT_VERSION,
        launched_at_unix_ms,
        package_root: package_root.display().to_string(),
        total_enabled: outcomes.len(),
        outcomes,
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
fn unsupported_instance(
    instance_kind: &str,
    id: &str,
    label: &str,
    executable_path: PathBuf,
    message: &str,
) -> LaunchOutcome {
    LaunchOutcome {
        instance_kind: instance_kind.to_string(),
        id: id.to_string(),
        label: label.to_string(),
        executable: executable_path.display().to_string(),
        command_line: Vec::new(),
        log_file: None,
        pid: None,
        error: Some(message.to_string()),
    }
}

fn spawn_instance(
    instance_kind: &str,
    id: &str,
    label: &str,
    executable_candidates: Vec<PathBuf>,
    command_line: Vec<String>,
    service_log_dir: &Path,
    launched_at_unix_ms: u64,
) -> LaunchOutcome {
    let executable_candidates = if executable_candidates.is_empty() {
        vec![PathBuf::from(instance_kind)]
    } else {
        executable_candidates
    };
    let executable_candidate_display = executable_candidates
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let mut executable = executable_candidate_display
        .first()
        .cloned()
        .unwrap_or_else(|| instance_kind.to_string());
    let log_file_path = service_log_file_path(service_log_dir, instance_kind, id);
    let log_file = Some(log_file_path.display().to_string());
    let mut log_setup_error = None;
    let mut log_handle = match open_service_log_file(&log_file_path) {
        Ok(file) => Some(file),
        Err(error) => {
            log_setup_error = Some(format!(
                "failed preparing service log file {}: {error}",
                log_file_path.display()
            ));
            None
        }
    };

    if let Some(file) = log_handle.as_mut() {
        if let Err(error) = write_launch_log_header(
            file,
            launched_at_unix_ms,
            instance_kind,
            id,
            label,
            &executable_candidate_display,
            &command_line,
        ) {
            log_setup_error = Some(format!(
                "failed writing service log header {}: {error}",
                log_file_path.display()
            ));
        }
    }

    let mut spawn_errors = Vec::new();
    for executable_path in &executable_candidates {
        executable = executable_path.display().to_string();
        let (stdout, stderr) = match service_log_stdio_pair(log_handle.as_ref()) {
            Ok(stdio) => stdio,
            Err(error) => {
                log_setup_error = Some(error);
                (Stdio::null(), Stdio::null())
            }
        };

        let mut command = Command::new(executable_path);
        command
            .args(&command_line)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(stderr);

        if let Some(file) = log_handle.as_mut() {
            let _ = writeln!(file, "spawn attempt executable={}", executable);
            let _ = file.flush();
        }

        match command.spawn() {
            Ok(child) => {
                let pid = child.id();
                if let Some(file) = log_handle.as_mut() {
                    let _ = writeln!(file, "spawned pid={pid} executable={}", executable);
                    let _ = file.flush();
                }
                return LaunchOutcome {
                    instance_kind: instance_kind.to_string(),
                    id: id.to_string(),
                    label: label.to_string(),
                    executable,
                    command_line,
                    log_file,
                    pid: Some(pid),
                    error: log_setup_error,
                };
            }
            Err(error) => {
                if let Some(file) = log_handle.as_mut() {
                    let _ = writeln!(
                        file,
                        "spawn attempt failed executable={} error={error}",
                        executable
                    );
                    let _ = file.flush();
                }
                spawn_errors.push(format!("{}: {error}", executable));
            }
        }
    }

    let spawn_error = if spawn_errors.is_empty() {
        "no executable candidates were available".to_string()
    } else {
        spawn_errors.join("; ")
    };
    let error = match log_setup_error {
        Some(log_setup_error) => format!("{spawn_error}; {log_setup_error}"),
        None => spawn_error,
    };
    LaunchOutcome {
        instance_kind: instance_kind.to_string(),
        id: id.to_string(),
        label: label.to_string(),
        executable,
        command_line,
        log_file,
        pid: None,
        error: Some(error),
    }
}

fn service_log_stdio_pair(file: Option<&fs::File>) -> Result<(Stdio, Stdio), String> {
    let Some(file) = file else {
        return Ok((Stdio::null(), Stdio::null()));
    };
    match (file.try_clone(), file.try_clone()) {
        (Ok(stdout), Ok(stderr)) => Ok((Stdio::from(stdout), Stdio::from(stderr))),
        (stdout_result, stderr_result) => {
            let stdout_error = stdout_result.err();
            let stderr_error = stderr_result.err();
            let error = match (stdout_error, stderr_error) {
                (Some(stdout_error), Some(stderr_error)) => {
                    format!("failed cloning service log handles: {stdout_error}; {stderr_error}")
                }
                (Some(error), None) | (None, Some(error)) => {
                    format!("failed cloning service log handle: {error}")
                }
                (None, None) => "failed cloning service log handles".to_string(),
            };
            Err(error)
        }
    }
}

fn service_executable_candidates(package_root: &Path, executable_name: &str) -> Vec<PathBuf> {
    let direct = package_root.join(executable_name);
    #[cfg(windows)]
    {
        if is_windows_apps_package_root(package_root) {
            if let Some(alias_path) = windows_app_execution_alias_path(executable_name) {
                if alias_path != direct {
                    return vec![alias_path, direct];
                }
            }
        }
    }
    vec![direct]
}

#[cfg(windows)]
fn is_windows_apps_package_root(path: &Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("WindowsApps")
    })
}

#[cfg(windows)]
fn windows_app_execution_alias_path(executable_name: &str) -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|path| {
            path.join("Microsoft")
                .join("WindowsApps")
                .join(executable_name)
        })
}

fn service_log_file_path(service_log_dir: &Path, instance_kind: &str, id: &str) -> PathBuf {
    service_log_dir.join(format!(
        "{}-{}.log",
        sanitize_log_file_component(instance_kind),
        sanitize_log_file_component(id)
    ))
}

fn sanitize_log_file_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('.').trim_matches('_');
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

fn open_service_log_file(path: &Path) -> Result<fs::File> {
    ensure_parent_dir(path)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed opening service log file {}", path.display()))
}

fn write_launch_log_header(
    file: &mut fs::File,
    launched_at_unix_ms: u64,
    instance_kind: &str,
    id: &str,
    label: &str,
    executable_candidates: &[String],
    command_line: &[String],
) -> Result<()> {
    writeln!(file)?;
    writeln!(file, "=== IronMesh service launch ===")?;
    writeln!(file, "launched_at_unix_ms={launched_at_unix_ms}")?;
    writeln!(file, "instance_kind={instance_kind}")?;
    writeln!(file, "id={id}")?;
    writeln!(file, "label={label}")?;
    writeln!(file, "executable_candidates={executable_candidates:?}")?;
    writeln!(file, "args={command_line:?}")?;
    file.flush()?;
    Ok(())
}

fn push_optional_arg(args: &mut Vec<String>, flag: &str, value: Option<&str>) {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return;
    };

    args.push(flag.to_string());
    args.push(value.to_string());
}

#[cfg(target_os = "linux")]
fn push_optional_u64(args: &mut Vec<String>, flag: &str, value: Option<u64>) {
    let Some(value) = value else {
        return;
    };

    args.push(flag.to_string());
    args.push(value.to_string());
}

#[cfg(target_os = "linux")]
fn push_optional_usize(args: &mut Vec<String>, flag: &str, value: Option<usize>) {
    let Some(value) = value else {
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

#[cfg(windows)]
fn local_appdata_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(LOCAL_STATE_ROOT_DIR)
}

#[cfg(windows)]
fn legacy_instance_store_path() -> PathBuf {
    local_appdata_root()
        .join(LEGACY_WINDOWS_CONFIG_SUBDIR)
        .join(INSTANCE_STORE_FILE_NAME)
}

#[cfg(windows)]
fn legacy_launch_report_path() -> PathBuf {
    local_appdata_root()
        .join(LEGACY_WINDOWS_CONFIG_SUBDIR)
        .join(LAST_LAUNCH_REPORT_FILE_NAME)
}

#[cfg(windows)]
fn migrate_legacy_windows_file(legacy_path: &Path, current_path: &Path) -> Result<()> {
    if current_path.exists() || !legacy_path.exists() {
        return Ok(());
    }

    ensure_parent_dir(current_path)?;
    match fs::rename(legacy_path, current_path) {
        Ok(()) => Ok(()),
        Err(rename_error) => {
            fs::copy(legacy_path, current_path).with_context(|| {
                format!(
                    "failed copying legacy config state from {} to {} after rename error: {}",
                    legacy_path.display(),
                    current_path.display(),
                    rename_error
                )
            })?;
            fs::remove_file(legacy_path).with_context(|| {
                format!(
                    "failed removing legacy config state {} after migration",
                    legacy_path.display()
                )
            })?;
            Ok(())
        }
    }
}

#[cfg(not(windows))]
fn config_home_root() -> PathBuf {
    xdg_dir("XDG_CONFIG_HOME", &[".config"])
        .unwrap_or_else(std::env::temp_dir)
        .join(LOCAL_STATE_ROOT_DIR)
}

#[cfg(not(windows))]
fn state_home_root() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", &[".local", "state"])
        .unwrap_or_else(std::env::temp_dir)
        .join(LOCAL_STATE_ROOT_DIR)
}

#[cfg(not(windows))]
fn xdg_dir(env_var: &str, home_suffix: &[&str]) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_var).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(path));
    }

    let home = std::env::var_os("HOME").filter(|value| !value.is_empty())?;
    let mut path = PathBuf::from(home);
    for segment in home_suffix {
        path.push(segment);
    }
    Some(path)
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

fn managed_instance_store_version() -> u32 {
    MANAGED_INSTANCE_STORE_VERSION
}

fn launch_report_version() -> u32 {
    LAUNCH_REPORT_VERSION
}

fn validate_launch_report_version(report: &LaunchReport, path: &Path) -> Result<()> {
    if report.version != LAUNCH_REPORT_VERSION {
        bail!(
            "unsupported launch report version {} in {} (current={})",
            report.version,
            path.display(),
            LAUNCH_REPORT_VERSION
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "desktop-client-config-{prefix}-{}-{}",
            std::process::id(),
            unix_ts_ms()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        dir.join("state.json")
    }

    #[test]
    fn managed_instance_store_roundtrip_persists_version() {
        let path = temp_path("instance-store-roundtrip");
        let store = ManagedInstanceStore {
            os_integration_instances: vec![OsIntegrationInstance {
                id: "os-1".to_string(),
                label: "Docs".to_string(),
                enabled: true,
                sync_root_id: None,
                display_name: None,
                root_path: "/tmp/docs".to_string(),
                server_base_url: Some("https://node.example".to_string()),
                prefix: None,
                bootstrap_file: None,
                client_identity_id: None,
                snapshot_file: None,
                client_identity_file: None,
                server_ca_path: None,
                client_edge_state_dir: None,
                fs_name: None,
                allow_other: false,
                publish_gnome_status: false,
                gnome_status_file: None,
                remote_refresh_interval_ms: None,
                remote_status_poll_interval_ms: None,
                depth: None,
            }],
            ..ManagedInstanceStore::default()
        };

        store.save(&path).expect("store should save");
        let loaded = ManagedInstanceStore::load_or_default(&path).expect("store should load");

        assert_eq!(loaded.version, MANAGED_INSTANCE_STORE_VERSION);
        assert_eq!(loaded.os_integration_instances.len(), 1);
        assert!(loaded.folder_agent_instances.is_empty());
        assert_eq!(loaded.os_integration_instances[0].id, "os-1");
        assert_eq!(loaded.os_integration_instances[0].label, "Docs");

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[test]
    fn managed_instance_store_accepts_legacy_missing_version() {
        let path = temp_path("instance-store-legacy");
        std::fs::write(
            &path,
            r#"{
  "os_integration_instances": [],
  "folder_agent_instances": []
}"#,
        )
        .expect("legacy store should write");

        let loaded =
            ManagedInstanceStore::load_or_default(&path).expect("legacy store should load");

        assert_eq!(loaded.version, MANAGED_INSTANCE_STORE_VERSION);

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[test]
    fn managed_instance_store_rejects_future_version() {
        let path = temp_path("instance-store-future");
        std::fs::write(
            &path,
            r#"{
  "version": 99,
  "os_integration_instances": [],
  "folder_agent_instances": []
}"#,
        )
        .expect("future store should write");

        let err = ManagedInstanceStore::load_or_default(&path)
            .expect_err("future store version should fail");
        assert!(
            err.to_string()
                .contains("unsupported managed instance store version 99")
        );

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[test]
    fn launch_report_roundtrip_persists_version() {
        let path = temp_path("launch-report-roundtrip");
        let report = LaunchReport {
            version: LAUNCH_REPORT_VERSION,
            launched_at_unix_ms: 1,
            package_root: "/opt/ironmesh".to_string(),
            total_enabled: 1,
            outcomes: vec![LaunchOutcome {
                instance_kind: "folder-agent".to_string(),
                id: "folder-1".to_string(),
                label: "Folder".to_string(),
                executable: "/opt/ironmesh/ironmesh-folder-agent".to_string(),
                command_line: vec!["--root-dir".to_string(), "/tmp/folder".to_string()],
                log_file: Some("/tmp/ironmesh/folder-agent-folder-1.log".to_string()),
                pid: Some(42),
                error: None,
            }],
        };

        save_launch_report(&path, &report).expect("launch report should save");
        let loaded = load_last_launch_report(&path)
            .expect("launch report should load")
            .expect("launch report should exist");

        assert_eq!(loaded, report);
        assert_eq!(
            OS_INTEGRATION_EXE,
            if cfg!(windows) {
                "ironmesh-os-integration.exe"
            } else {
                "ironmesh-os-integration"
            }
        );

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[test]
    fn spawn_instance_records_log_file_and_spawn_failure() {
        let path = temp_path("service-log-spawn-error");
        let dir = path.parent().expect("temp path should have parent");
        let log_dir = dir.join("logs");
        let missing_executable = dir.join(FOLDER_AGENT_EXE);

        let outcome = spawn_instance(
            "folder-agent",
            "folder/one",
            "Folder One",
            vec![missing_executable],
            vec!["--root-dir".to_string(), "/tmp/folder".to_string()],
            &log_dir,
            123,
        );

        assert_eq!(outcome.instance_kind, "folder-agent");
        assert_eq!(outcome.id, "folder/one");
        assert!(outcome.pid.is_none());
        assert!(outcome.error.is_some());
        let log_file = outcome.log_file.expect("log file should be reported");
        assert!(
            log_file.ends_with("folder-agent-folder_one.log"),
            "unexpected log file path: {log_file}"
        );
        let log = std::fs::read_to_string(&log_file).expect("log file should be readable");
        assert!(log.contains("=== IronMesh service launch ==="));
        assert!(log.contains("instance_kind=folder-agent"));
        assert!(log.contains("id=folder/one"));
        assert!(log.contains("spawn attempt failed executable="));

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[cfg(windows)]
    #[test]
    fn windows_apps_package_root_prefers_app_execution_alias() {
        let Some(local_appdata) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let package_root = PathBuf::from(
            r"C:\Program Files\WindowsApps\UlrichHornung.IronMesh_1.0.2.1_neutral__bnh81bg69mtt8",
        );

        let candidates = service_executable_candidates(&package_root, OS_INTEGRATION_EXE);

        assert_eq!(
            candidates,
            vec![
                PathBuf::from(local_appdata)
                    .join("Microsoft")
                    .join("WindowsApps")
                    .join(OS_INTEGRATION_EXE),
                package_root.join(OS_INTEGRATION_EXE),
            ]
        );
    }

    #[test]
    fn launch_report_accepts_legacy_missing_version() {
        let path = temp_path("launch-report-legacy");
        std::fs::write(
            &path,
            r#"{
  "launched_at_unix_ms": 1,
  "package_root": "/opt/ironmesh",
  "total_enabled": 0,
  "outcomes": []
}"#,
        )
        .expect("legacy launch report should write");

        let loaded = load_last_launch_report(&path)
            .expect("legacy launch report should load")
            .expect("launch report should exist");

        assert_eq!(loaded.version, LAUNCH_REPORT_VERSION);

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }

    #[test]
    fn launch_report_rejects_future_version() {
        let path = temp_path("launch-report-future");
        std::fs::write(
            &path,
            r#"{
  "version": 99,
  "launched_at_unix_ms": 1,
  "package_root": "/opt/ironmesh",
  "total_enabled": 0,
  "outcomes": []
}"#,
        )
        .expect("future launch report should write");

        let err =
            load_last_launch_report(&path).expect_err("future launch report version should fail");
        assert!(
            err.to_string()
                .contains("unsupported launch report version 99")
        );

        let _ = std::fs::remove_file(&path);
        let _ = path.parent().map(std::fs::remove_dir_all);
    }
}
