use crate::framework::{
    ChildGuard, TEST_ADMIN_TOKEN, binary_path, default_client_identity_path, fresh_data_dir,
    internal_base_url_from_public_bind, issue_bootstrap_bundle_and_enroll_client,
    lock_test_resources, mtls_client_from_data_dir, path_resource_key, register_node,
    start_authenticated_server_with_env_options, stop_server, wait_for_online_nodes,
};
use crate::framework_win::start_cfapi_adapter_with_bootstrap_and_local_appdata;
use anyhow::{Context, Result, bail};
use blake3::Hash;
use client_sdk::IronMeshClient;
use client_sdk::ironmesh_client::StoreIndexRequestOptions;
use reqwest::Client;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_FILE_COUNT: usize = 4_000;
const DEFAULT_MIN_BYTES: usize = 1 * 1024 * 1024;
const DEFAULT_MAX_BYTES: usize = 5 * 1024 * 1024;
const DEFAULT_SAMPLE_VERIFY_COUNT: usize = 24;
const DEFAULT_SUBDIR_COUNT: usize = 80;
const DEFAULT_MAX_DIR_DEPTH: usize = 4;
const DEFAULT_UPLOAD_TIMEOUT_SECS: u64 = 150 * 60;
const DEFAULT_REPLICATION_TIMEOUT_SECS: u64 = 60 * 60;
const STORE_INDEX_PROGRESS_LIMIT: usize = 1;
const IO_BUFFER_BYTES: usize = 256 * 1024;
const DEFAULT_RUNTIME_REFRESH_INTERVAL_MS: u64 = 250;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRuntimeKind {
    Cfapi,
    FolderAgent,
}

impl LocalRuntimeKind {
    fn workload_env(self) -> WorkloadEnvNames {
        match self {
            Self::Cfapi => WorkloadEnvNames {
                file_count: "IRONMESH_WINDOWS_CFAPI_LOAD_FILE_COUNT",
                min_bytes: "IRONMESH_WINDOWS_CFAPI_LOAD_MIN_BYTES",
                max_bytes: "IRONMESH_WINDOWS_CFAPI_LOAD_MAX_BYTES",
                sample_verify_count: "IRONMESH_WINDOWS_CFAPI_LOAD_VERIFY_SAMPLE_COUNT",
                subdir_count: "IRONMESH_WINDOWS_CFAPI_LOAD_SUBDIR_COUNT",
                max_dir_depth: "IRONMESH_WINDOWS_CFAPI_LOAD_MAX_DIR_DEPTH",
                upload_timeout_secs: "IRONMESH_WINDOWS_CFAPI_UPLOAD_TIMEOUT_SECS",
                replication_timeout_secs: "IRONMESH_WINDOWS_CFAPI_REPLICATION_TIMEOUT_SECS",
            },
            Self::FolderAgent => WorkloadEnvNames {
                file_count: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_FILE_COUNT",
                min_bytes: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MIN_BYTES",
                max_bytes: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MAX_BYTES",
                sample_verify_count: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_VERIFY_SAMPLE_COUNT",
                subdir_count: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_SUBDIR_COUNT",
                max_dir_depth: "IRONMESH_WINDOWS_FOLDER_AGENT_LOAD_MAX_DIR_DEPTH",
                upload_timeout_secs: "IRONMESH_WINDOWS_FOLDER_AGENT_UPLOAD_TIMEOUT_SECS",
                replication_timeout_secs: "IRONMESH_WINDOWS_FOLDER_AGENT_REPLICATION_TIMEOUT_SECS",
            },
        }
    }

    fn live_env(self) -> LiveEnvNames {
        match self {
            Self::Cfapi => LiveEnvNames {
                manifest_path: "IRONMESH_WINDOWS_CFAPI_LIVE_MANIFEST_PATH",
                continue_signal_path: "IRONMESH_WINDOWS_CFAPI_LIVE_CONTINUE_SIGNAL_PATH",
                cleanup_signal_path: "IRONMESH_WINDOWS_CFAPI_LIVE_CLEANUP_SIGNAL_PATH",
                hold_after_copy: "IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_COPY",
                hold_after_upload: "IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_UPLOAD",
                hold_after_replication: "IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_AFTER_REPLICATION",
                hold_on_failure: "IRONMESH_WINDOWS_CFAPI_LIVE_HOLD_ON_FAILURE",
            },
            Self::FolderAgent => LiveEnvNames {
                manifest_path: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_MANIFEST_PATH",
                continue_signal_path: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_CONTINUE_SIGNAL_PATH",
                cleanup_signal_path: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_CLEANUP_SIGNAL_PATH",
                hold_after_copy: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_HOLD_AFTER_COPY",
                hold_after_upload: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_HOLD_AFTER_UPLOAD",
                hold_after_replication: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_HOLD_AFTER_REPLICATION",
                hold_on_failure: "IRONMESH_WINDOWS_FOLDER_AGENT_LIVE_HOLD_ON_FAILURE",
            },
        }
    }

    fn runtime_state_stem(self) -> &'static str {
        match self {
            Self::Cfapi => "windows-cfapi-cluster-localappdata",
            Self::FolderAgent => "windows-folder-agent-cluster-state",
        }
    }

    fn runtime_state_dir_name(self) -> &'static str {
        match self {
            Self::Cfapi => "adapter-localappdata",
            Self::FolderAgent => "folder-agent-state",
        }
    }

    fn runtime_display_name(self) -> &'static str {
        match self {
            Self::Cfapi => "CFAPI adapter",
            Self::FolderAgent => "Folder Agent",
        }
    }

    fn runtime_manifest_kind(self) -> &'static str {
        match self {
            Self::Cfapi => "cfapi",
            Self::FolderAgent => "folder_agent",
        }
    }

    fn sync_root_label(self) -> &'static str {
        match self {
            Self::Cfapi => "CFAPI mount",
            Self::FolderAgent => "folder-agent root",
        }
    }

    fn progress_copy_label(self) -> &'static str {
        match self {
            Self::Cfapi => "CFAPI root",
            Self::FolderAgent => "folder-agent root",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WorkloadEnvNames {
    file_count: &'static str,
    min_bytes: &'static str,
    max_bytes: &'static str,
    sample_verify_count: &'static str,
    subdir_count: &'static str,
    max_dir_depth: &'static str,
    upload_timeout_secs: &'static str,
    replication_timeout_secs: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct LiveEnvNames {
    manifest_path: &'static str,
    continue_signal_path: &'static str,
    cleanup_signal_path: &'static str,
    hold_after_copy: &'static str,
    hold_after_upload: &'static str,
    hold_after_replication: &'static str,
    hold_on_failure: &'static str,
}

#[derive(Debug, Clone)]
struct WorkloadConfig {
    file_count: usize,
    min_bytes: usize,
    max_bytes: usize,
    sample_verify_count: usize,
    subdir_count: usize,
    max_dir_depth: usize,
    upload_timeout: Duration,
    replication_timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FolderAgentStartMode {
    BeforeCopy,
    AfterCopy,
}

impl FolderAgentStartMode {
    fn from_env() -> Result<Self> {
        match std::env::var("IRONMESH_WINDOWS_FOLDER_AGENT_START_MODE") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "before_copy" | "before-copy" | "before" => Ok(Self::BeforeCopy),
                "after_copy" | "after-copy" | "after" => Ok(Self::AfterCopy),
                other => bail!(
                    "failed parsing IRONMESH_WINDOWS_FOLDER_AGENT_START_MODE={other}; expected before_copy or after_copy"
                ),
            },
            Err(std::env::VarError::NotPresent) => Ok(Self::BeforeCopy),
            Err(err) => Err(err)
                .with_context(|| "failed reading IRONMESH_WINDOWS_FOLDER_AGENT_START_MODE"),
        }
    }
}

impl WorkloadConfig {
    fn from_env(kind: LocalRuntimeKind) -> Result<Self> {
        let env = kind.workload_env();
        let file_count = read_env_usize(env.file_count, DEFAULT_FILE_COUNT)?;
        let min_bytes = read_env_usize(env.min_bytes, DEFAULT_MIN_BYTES)?;
        let max_bytes = read_env_usize(env.max_bytes, DEFAULT_MAX_BYTES)?;
        let sample_verify_count =
            read_env_usize(env.sample_verify_count, DEFAULT_SAMPLE_VERIFY_COUNT)?;
        let subdir_count = read_env_usize(env.subdir_count, DEFAULT_SUBDIR_COUNT)?;
        let max_dir_depth = read_env_usize(env.max_dir_depth, DEFAULT_MAX_DIR_DEPTH)?;
        let upload_timeout =
            Duration::from_secs(read_env_u64(env.upload_timeout_secs, DEFAULT_UPLOAD_TIMEOUT_SECS)?);
        let replication_timeout = Duration::from_secs(read_env_u64(
            env.replication_timeout_secs,
            DEFAULT_REPLICATION_TIMEOUT_SECS,
        )?);

        if min_bytes == 0 {
            bail!("{} must be greater than zero", env.min_bytes);
        }
        if max_bytes < min_bytes {
            bail!("{} must be >= {}", env.max_bytes, env.min_bytes);
        }
        if file_count == 0 {
            bail!("{} must be greater than zero", env.file_count);
        }
        if subdir_count == 0 {
            bail!("{} must be greater than zero", env.subdir_count);
        }
        if max_dir_depth == 0 {
            bail!("{} must be greater than zero", env.max_dir_depth);
        }
        if subdir_count > file_count {
            bail!(
                "{} must be <= {} so each subdir can receive at least one file",
                env.subdir_count,
                env.file_count
            );
        }

        Ok(Self {
            file_count,
            min_bytes,
            max_bytes,
            sample_verify_count: sample_verify_count.max(1),
            subdir_count,
            max_dir_depth,
            upload_timeout,
            replication_timeout,
        })
    }

    fn average_bytes(&self) -> usize {
        self.min_bytes + ((self.max_bytes - self.min_bytes) / 2)
    }
}

#[derive(Debug, Clone)]
struct FileSpec {
    relative_path: PathBuf,
    store_path: String,
    size_bytes: usize,
    content_hash: Hash,
}

struct ClusterNodeFixture {
    label: &'static str,
    node_id: String,
    base_url: String,
    internal_base_url: String,
    internal_http: Client,
    data_dir: PathBuf,
    client_dir: PathBuf,
    bootstrap_file: PathBuf,
    sdk: IronMeshClient,
    server: ChildGuard,
}

impl ClusterNodeFixture {
    fn server_pid(&self) -> Option<u32> {
        self.server.id()
    }

    fn stdout_log(&self) -> PathBuf {
        self.data_dir.join("server-node.stdout.log")
    }

    fn stderr_log(&self) -> PathBuf {
        self.data_dir.join("server-node.stderr.log")
    }

    async fn stop_and_cleanup(&mut self) {
        stop_server(&mut self.server).await;
        let _ = fs::remove_dir_all(&self.data_dir);
        let _ = fs::remove_dir_all(&self.client_dir);
    }
}

enum LocalRuntimeFixture {
    Cfapi {
        local_appdata_dir: PathBuf,
        adapter: ChildGuard,
    },
    FolderAgent {
        state_root_dir: PathBuf,
        agent: ChildGuard,
    },
}

impl LocalRuntimeFixture {
    fn pid(&self) -> Option<u32> {
        match self {
            Self::Cfapi { adapter, .. } => adapter.id(),
            Self::FolderAgent { agent, .. } => agent.id(),
        }
    }

    fn stdout_log(&self) -> PathBuf {
        match self {
            Self::Cfapi {
                local_appdata_dir, ..
            } => local_appdata_dir.join("os-integration.stdout.log"),
            Self::FolderAgent { state_root_dir, .. } => {
                state_root_dir.join("folder-agent.stdout.log")
            }
        }
    }

    fn stderr_log(&self) -> PathBuf {
        match self {
            Self::Cfapi {
                local_appdata_dir, ..
            } => local_appdata_dir.join("os-integration.stderr.log"),
            Self::FolderAgent { state_root_dir, .. } => {
                state_root_dir.join("folder-agent.stderr.log")
            }
        }
    }

    fn state_root_dir(&self) -> &Path {
        match self {
            Self::Cfapi {
                local_appdata_dir, ..
            } => local_appdata_dir.as_path(),
            Self::FolderAgent { state_root_dir, .. } => state_root_dir.as_path(),
        }
    }

    fn manifest_json(&self, kind: LocalRuntimeKind) -> serde_json::Value {
        json!({
            "kind": kind.runtime_manifest_kind(),
            "display_name": kind.runtime_display_name(),
            "pid": self.pid(),
            "state_root_dir": self.state_root_dir().display().to_string(),
            "stdout_log": self.stdout_log().display().to_string(),
            "stderr_log": self.stderr_log().display().to_string(),
        })
    }

    async fn stop_and_cleanup(&mut self) {
        match self {
            Self::Cfapi {
                local_appdata_dir,
                adapter,
            } => {
                stop_server(adapter).await;
                let _ = fs::remove_dir_all(local_appdata_dir);
            }
            Self::FolderAgent {
                state_root_dir,
                agent,
            } => {
                stop_server(agent).await;
                let _ = fs::remove_dir_all(state_root_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        let state = if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        };
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[derive(Debug, Clone)]
struct InvestigationControl {
    run_root: PathBuf,
    manifest_path: PathBuf,
    continue_signal_path: PathBuf,
    cleanup_signal_path: PathBuf,
    hold_after_copy: bool,
    hold_after_upload: bool,
    hold_after_replication: bool,
    hold_on_failure: bool,
}

impl InvestigationControl {
    fn from_env(kind: LocalRuntimeKind) -> Result<Self> {
        let env = kind.live_env();
        let manifest_path = PathBuf::from(
            std::env::var(env.manifest_path)
                .with_context(|| format!("{} is required", env.manifest_path))?,
        );
        let run_root = manifest_path
            .parent()
            .map(Path::to_path_buf)
            .with_context(|| {
                format!(
                    "manifest path {} must have a parent directory",
                    manifest_path.display()
                )
            })?;
        let continue_signal_path = PathBuf::from(
            std::env::var(env.continue_signal_path).unwrap_or_else(|_| {
                run_root.join("continue.signal").display().to_string()
            }),
        );
        let cleanup_signal_path = PathBuf::from(
            std::env::var(env.cleanup_signal_path).unwrap_or_else(|_| {
                run_root.join("cleanup.signal").display().to_string()
            }),
        );

        Ok(Self {
            run_root,
            manifest_path,
            continue_signal_path,
            cleanup_signal_path,
            hold_after_copy: env_truthy(env.hold_after_copy),
            hold_after_upload: env_truthy(env.hold_after_upload),
            hold_after_replication: env_truthy(env.hold_after_replication),
            hold_on_failure: env_truthy(env.hold_on_failure),
        })
    }
}

enum RuntimeMode {
    Managed,
    Live(InvestigationControl),
}

#[derive(Debug, Clone, Copy)]
enum PauseOutcome {
    Continue,
    CleanupRequested,
}

#[derive(Debug, Clone, Copy)]
enum WorkloadOutcome {
    Completed,
    CleanupRequested,
}

struct RuntimePaths {
    sync_root: PathBuf,
    source_dir: PathBuf,
    runtime_state_dir: PathBuf,
    node_a_data_dir: PathBuf,
    node_a_client_dir: PathBuf,
    node_b_data_dir: PathBuf,
    node_b_client_dir: PathBuf,
    node_c_data_dir: PathBuf,
    node_c_client_dir: PathBuf,
}

impl RuntimePaths {
    fn managed(kind: LocalRuntimeKind) -> Self {
        Self {
            sync_root: fresh_data_dir(match kind {
                LocalRuntimeKind::Cfapi => "windows-cfapi-cluster-sync-root",
                LocalRuntimeKind::FolderAgent => "windows-folder-agent-cluster-sync-root",
            }),
            source_dir: fresh_data_dir(match kind {
                LocalRuntimeKind::Cfapi => "windows-cfapi-cluster-source",
                LocalRuntimeKind::FolderAgent => "windows-folder-agent-cluster-source",
            }),
            runtime_state_dir: fresh_data_dir(kind.runtime_state_stem()),
            node_a_data_dir: fresh_data_dir("cluster-a-server"),
            node_a_client_dir: fresh_data_dir("cluster-a-client"),
            node_b_data_dir: fresh_data_dir("cluster-b-server"),
            node_b_client_dir: fresh_data_dir("cluster-b-client"),
            node_c_data_dir: fresh_data_dir("cluster-c-server"),
            node_c_client_dir: fresh_data_dir("cluster-c-client"),
        }
    }

    fn live(kind: LocalRuntimeKind, run_root: &Path) -> Self {
        Self {
            sync_root: run_root.join("sync-root"),
            source_dir: run_root.join("staged-source"),
            runtime_state_dir: run_root.join(kind.runtime_state_dir_name()),
            node_a_data_dir: run_root.join("cluster-a-server"),
            node_a_client_dir: run_root.join("cluster-a-client"),
            node_b_data_dir: run_root.join("cluster-b-server"),
            node_b_client_dir: run_root.join("cluster-b-client"),
            node_c_data_dir: run_root.join("cluster-c-server"),
            node_c_client_dir: run_root.join("cluster-c-client"),
        }
    }

    fn create_all(&self) -> Result<()> {
        for path in [
            &self.sync_root,
            &self.source_dir,
            &self.runtime_state_dir,
            &self.node_a_data_dir,
            &self.node_a_client_dir,
            &self.node_b_data_dir,
            &self.node_b_client_dir,
            &self.node_c_data_dir,
            &self.node_c_client_dir,
        ] {
            fs::create_dir_all(path)
                .with_context(|| format!("failed to create {}", path.display()))?;
        }
        Ok(())
    }
}

pub async fn run_managed_test_workload_for(kind: LocalRuntimeKind) -> Result<()> {
    run_workload(kind, RuntimeMode::Managed).await
}

pub async fn run_live_driver_from_env_for(kind: LocalRuntimeKind) -> Result<()> {
    run_workload(kind, RuntimeMode::Live(InvestigationControl::from_env(kind)?)).await
}

async fn run_workload(kind: LocalRuntimeKind, mode: RuntimeMode) -> Result<()> {
    let config = WorkloadConfig::from_env(kind)?;
    let folder_agent_start_mode = if kind == LocalRuntimeKind::FolderAgent {
        Some(FolderAgentStartMode::from_env()?)
    } else {
        None
    };
    let cluster_id = Uuid::new_v4().to_string();
    let http = Client::new();
    let paths = match &mode {
        RuntimeMode::Managed => RuntimePaths::managed(kind),
        RuntimeMode::Live(live) => RuntimePaths::live(kind, &live.run_root),
    };
    paths.create_all()?;

    let mut node_a = start_cluster_node(
        "127.0.0.1:19341",
        "cluster-a",
        "00000000-0000-0000-0000-00000000a341",
        &cluster_id,
        3,
        paths.node_a_data_dir.clone(),
        paths.node_a_client_dir.clone(),
    )
    .await?;
    let mut node_b = start_cluster_node(
        "127.0.0.1:19342",
        "cluster-b",
        "00000000-0000-0000-0000-00000000b342",
        &cluster_id,
        3,
        paths.node_b_data_dir.clone(),
        paths.node_b_client_dir.clone(),
    )
    .await?;
    let mut node_c = start_cluster_node(
        "127.0.0.1:19343",
        "cluster-c",
        "00000000-0000-0000-0000-00000000c343",
        &cluster_id,
        3,
        paths.node_c_data_dir.clone(),
        paths.node_c_client_dir.clone(),
    )
    .await?;

    let mut runtime = None;

    let workload_result = execute_workload(
        kind,
        &config,
        &http,
        &cluster_id,
        &paths,
        &mode,
        &mut node_a,
        &mut node_b,
        &mut node_c,
        &mut runtime,
        folder_agent_start_mode,
    )
    .await;

    let final_result = match workload_result {
        Ok(WorkloadOutcome::Completed) => {
            update_manifest(
                kind,
                &mode,
                &config,
                &cluster_id,
                "completed",
                "success",
                Some("workload completed successfully"),
                &paths,
                &node_a,
                &node_b,
                &node_c,
                runtime.as_ref(),
            )?;
            Ok(())
        }
        Ok(WorkloadOutcome::CleanupRequested) => {
            update_manifest(
                kind,
                &mode,
                &config,
                &cluster_id,
                "cleanup_requested",
                "success",
                Some("cleanup requested before workload completion"),
                &paths,
                &node_a,
                &node_b,
                &node_c,
                runtime.as_ref(),
            )?;
            Ok(())
        }
        Err(error) => {
            update_manifest(
                kind,
                &mode,
                &config,
                &cluster_id,
                "failed",
                "error",
                Some(&format!("{error:#}")),
                &paths,
                &node_a,
                &node_b,
                &node_c,
                runtime.as_ref(),
            )?;

            if let RuntimeMode::Live(live) = &mode
                && live.hold_on_failure
            {
                match pause_for_investigation(
                    kind,
                    live,
                    &config,
                    &cluster_id,
                    "failed",
                    "workload failed; cluster is paused for investigation",
                    &paths,
                    &node_a,
                    &node_b,
                    &node_c,
                    runtime.as_ref(),
                    Some(&format!("{error:#}")),
                )
                .await?
                {
                    PauseOutcome::Continue | PauseOutcome::CleanupRequested => {}
                }
            }

            Err(error)
        }
    };

    cleanup_runtime(&paths, &mut node_a, &mut node_b, &mut node_c, runtime.as_mut()).await;

    if final_result.is_ok() {
        let _ = update_manifest(
            kind,
            &mode,
            &config,
            &cluster_id,
            "cleaned_up",
            "success",
            Some("runtime cleaned up"),
            &paths,
            &node_a,
            &node_b,
            &node_c,
            None,
        );
    }

    final_result
}

#[allow(clippy::too_many_arguments)]
async fn execute_workload(
    kind: LocalRuntimeKind,
    config: &WorkloadConfig,
    http: &Client,
    cluster_id: &str,
    paths: &RuntimePaths,
    mode: &RuntimeMode,
    node_a: &mut ClusterNodeFixture,
    node_b: &mut ClusterNodeFixture,
    node_c: &mut ClusterNodeFixture,
    runtime: &mut Option<LocalRuntimeFixture>,
    folder_agent_start_mode: Option<FolderAgentStartMode>,
) -> Result<WorkloadOutcome> {
    eprintln!(
        "[cluster] starting workload: files={} min_bytes={} max_bytes={} average_bytes={} subdirs={} max_depth={} upload_timeout_secs={} replication_timeout_secs={}",
        config.file_count,
        config.min_bytes,
        config.max_bytes,
        config.average_bytes(),
        config.subdir_count,
        config.max_dir_depth,
        config.upload_timeout.as_secs(),
        config.replication_timeout.as_secs()
    );

    update_manifest(
        kind,
        mode,
        config,
        cluster_id,
        "starting",
        "running",
        Some("cluster nodes are starting"),
        paths,
        node_a,
        node_b,
        node_c,
        runtime.as_ref(),
    )?;

    register_full_mesh(http, &[node_a, node_b, node_c]).await?;

    for node in [&*node_a, &*node_b, &*node_c] {
        wait_for_online_nodes(http, &node.base_url, 3, 240).await?;
        eprintln!("[cluster] {} reports 3 online nodes", node.label);
    }

    update_manifest(
        kind,
        mode,
        config,
        cluster_id,
        "cluster_ready",
        "running",
        Some(match (kind, folder_agent_start_mode) {
            (LocalRuntimeKind::Cfapi, _) => "cluster online; starting CFAPI adapter",
            (LocalRuntimeKind::FolderAgent, Some(FolderAgentStartMode::AfterCopy)) => {
                "cluster online; workload will be copied before starting Folder Agent"
            }
            (LocalRuntimeKind::FolderAgent, Some(FolderAgentStartMode::BeforeCopy)) => {
                "cluster online; starting Folder Agent before workload copy"
            }
            (LocalRuntimeKind::FolderAgent, None) => {
                "cluster online; workload will be copied before starting Folder Agent"
            }
        }),
        paths,
        node_a,
        node_b,
        node_c,
        runtime.as_ref(),
    )?;

    if kind == LocalRuntimeKind::Cfapi
        || matches!(folder_agent_start_mode, Some(FolderAgentStartMode::BeforeCopy))
    {
        *runtime = Some(start_local_runtime(kind, paths, node_a).await?);
    }

    let file_specs = stage_workload(config, &paths.source_dir)?;
    copy_staged_workload_into_sync_root(kind, &file_specs, &paths.source_dir, &paths.sync_root)?;

    update_manifest(
        kind,
        mode,
        config,
        cluster_id,
        "files_copied",
        "running",
        Some(&format!(
            "staged files copied into {}",
            kind.sync_root_label()
        )),
        paths,
        node_a,
        node_b,
        node_c,
        runtime.as_ref(),
    )?;

    if let Some(live) = live_control(mode)
        && live.hold_after_copy
    {
        match pause_for_investigation(
            kind,
            live,
            config,
            cluster_id,
            "files_copied",
            &format!(
                "files copied into {}; create continue signal to resume upload observation",
                kind.sync_root_label()
            ),
            paths,
            node_a,
            node_b,
            node_c,
            runtime.as_ref(),
            None,
        )
        .await?
        {
            PauseOutcome::Continue => {}
            PauseOutcome::CleanupRequested => return Ok(WorkloadOutcome::CleanupRequested),
        }
    }

    if runtime.is_none() {
        *runtime = Some(start_local_runtime(kind, paths, node_a).await?);
    }

    let expected_paths = file_specs
        .iter()
        .map(|spec| spec.store_path.clone())
        .collect::<BTreeSet<_>>();

    eprintln!(
        "[cluster-a] waiting for {} uploaded files to appear on the ingress node",
        expected_paths.len()
    );
    wait_for_store_file_paths(
        &node_a.sdk,
        &expected_paths,
        node_a.label,
        config.upload_timeout,
    )
    .await?;
    wait_for_local_subjects(
        &node_a.internal_http,
        &node_a.internal_base_url,
        &expected_paths,
        node_a.label,
        config.upload_timeout,
    )
    .await?;
    eprintln!("[cluster-a] upload convergence complete");

    update_manifest(
        kind,
        mode,
        config,
        cluster_id,
        "upload_converged",
        "running",
        Some("ingress upload convergence complete"),
        paths,
        node_a,
        node_b,
        node_c,
        runtime.as_ref(),
    )?;

    if let Some(live) = live_control(mode)
        && live.hold_after_upload
    {
        match pause_for_investigation(
            kind,
            live,
            config,
            cluster_id,
            "upload_converged",
            "upload converged; create continue signal to begin replication checks",
            paths,
            node_a,
            node_b,
            node_c,
            runtime.as_ref(),
            None,
        )
        .await?
        {
            PauseOutcome::Continue => {}
            PauseOutcome::CleanupRequested => return Ok(WorkloadOutcome::CleanupRequested),
        }
    }

    eprintln!(
        "[cluster] driving replication to completion from {}",
        node_a.internal_base_url
    );
    drive_replication_to_completion(
        &node_a.internal_http,
        &node_a.internal_base_url,
        config.replication_timeout,
    )
    .await?;

    for node in [&*node_a, &*node_b, &*node_c] {
        wait_for_store_file_paths(
            &node.sdk,
            &expected_paths,
            node.label,
            config.replication_timeout,
        )
        .await?;
        wait_for_local_subjects(
            &node.internal_http,
            &node.internal_base_url,
            &expected_paths,
            node.label,
            config.replication_timeout,
        )
        .await?;
        eprintln!(
            "[{}] replication convergence complete for {} files",
            node.label,
            expected_paths.len()
        );
    }

    update_manifest(
        kind,
        mode,
        config,
        cluster_id,
        "replication_converged",
        "running",
        Some("replication convergence complete across all nodes"),
        paths,
        node_a,
        node_b,
        node_c,
        runtime.as_ref(),
    )?;

    if let Some(live) = live_control(mode)
        && live.hold_after_replication
    {
        match pause_for_investigation(
            kind,
            live,
            config,
            cluster_id,
            "replication_converged",
            "replication converged; create continue signal to run sampled verification and cleanup",
            paths,
            node_a,
            node_b,
            node_c,
            runtime.as_ref(),
            None,
        )
        .await?
        {
            PauseOutcome::Continue => {}
            PauseOutcome::CleanupRequested => return Ok(WorkloadOutcome::CleanupRequested),
        }
    }

    let samples = select_sample_specs(&file_specs, config.sample_verify_count);
    for node in [&*node_a, &*node_b, &*node_c] {
        verify_sample_content(&node.sdk, node.label, &samples).await?;
    }

    let under_replicated =
        current_under_replicated(&node_a.internal_http, &node_a.internal_base_url).await?;
    if under_replicated != 0 {
        bail!("replication plan still reports under_replicated={under_replicated}");
    }

    let total_bytes = file_specs
        .iter()
        .fold(0usize, |acc, spec| acc.saturating_add(spec.size_bytes));
    eprintln!(
        "[cluster] workload complete: files={} logical_gib={:.2} sampled_verifications={}",
        file_specs.len(),
        total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
        samples.len()
    );

    Ok(WorkloadOutcome::Completed)
}

fn live_control(mode: &RuntimeMode) -> Option<&InvestigationControl> {
    match mode {
        RuntimeMode::Managed => None,
        RuntimeMode::Live(live) => Some(live),
    }
}

#[allow(clippy::too_many_arguments)]
fn update_manifest(
    kind: LocalRuntimeKind,
    mode: &RuntimeMode,
    config: &WorkloadConfig,
    cluster_id: &str,
    phase: &str,
    status: &str,
    detail: Option<&str>,
    paths: &RuntimePaths,
    node_a: &ClusterNodeFixture,
    node_b: &ClusterNodeFixture,
    node_c: &ClusterNodeFixture,
    runtime: Option<&LocalRuntimeFixture>,
) -> Result<()> {
    let Some(live) = live_control(mode) else {
        return Ok(());
    };

    fs::create_dir_all(&live.run_root)
        .with_context(|| format!("failed creating {}", live.run_root.display()))?;

    let manifest = json!({
        "cluster_id": cluster_id,
        "phase": phase,
        "status": status,
        "detail": detail,
        "admin_token": TEST_ADMIN_TOKEN,
        "continue_signal_path": live.continue_signal_path.display().to_string(),
        "cleanup_signal_path": live.cleanup_signal_path.display().to_string(),
        "paths": {
            "run_root": live.run_root.display().to_string(),
            "manifest": live.manifest_path.display().to_string(),
            "sync_root": paths.sync_root.display().to_string(),
            "source_dir": paths.source_dir.display().to_string(),
            "runtime_state_dir": paths.runtime_state_dir.display().to_string(),
            "adapter_local_appdata_dir": match kind {
                LocalRuntimeKind::Cfapi => Some(paths.runtime_state_dir.display().to_string()),
                LocalRuntimeKind::FolderAgent => None,
            },
            "folder_agent_state_dir": match kind {
                LocalRuntimeKind::Cfapi => None,
                LocalRuntimeKind::FolderAgent => Some(paths.runtime_state_dir.display().to_string()),
            },
        },
        "workload": {
            "file_count": config.file_count,
            "min_bytes": config.min_bytes,
            "max_bytes": config.max_bytes,
            "average_bytes": config.average_bytes(),
            "sample_verify_count": config.sample_verify_count,
            "subdir_count": config.subdir_count,
            "max_dir_depth": config.max_dir_depth,
            "upload_timeout_secs": config.upload_timeout.as_secs(),
            "replication_timeout_secs": config.replication_timeout.as_secs(),
        },
        "holds": {
            "after_copy": live.hold_after_copy,
            "after_upload": live.hold_after_upload,
            "after_replication": live.hold_after_replication,
            "on_failure": live.hold_on_failure,
        },
        "runtime": runtime.map(|runtime| runtime.manifest_json(kind)),
        "adapter": match (kind, runtime) {
            (LocalRuntimeKind::Cfapi, Some(runtime)) => Some(runtime.manifest_json(kind)),
            _ => None,
        },
        "folder_agent": match (kind, runtime) {
            (LocalRuntimeKind::FolderAgent, Some(runtime)) => Some(runtime.manifest_json(kind)),
            _ => None,
        },
        "nodes": [
            node_manifest(node_a),
            node_manifest(node_b),
            node_manifest(node_c),
        ],
    });

    fs::write(
        &live.manifest_path,
        serde_json::to_vec_pretty(&manifest).context("failed serializing investigation manifest")?,
    )
    .with_context(|| format!("failed writing {}", live.manifest_path.display()))?;

    Ok(())
}

fn node_manifest(node: &ClusterNodeFixture) -> serde_json::Value {
    json!({
        "label": node.label,
        "node_id": node.node_id,
        "public_base_url": node.base_url,
        "internal_base_url": node.internal_base_url,
        "server_pid": node.server_pid(),
        "data_dir": node.data_dir.display().to_string(),
        "client_dir": node.client_dir.display().to_string(),
        "bootstrap_file": node.bootstrap_file.display().to_string(),
        "stdout_log": node.stdout_log().display().to_string(),
        "stderr_log": node.stderr_log().display().to_string(),
        "logs_endpoint": format!("{}/logs?limit=200", node.base_url),
        "runtime_log_config_endpoint": format!("{}/api/v1/auth/logging/config", node.base_url),
    })
}

#[allow(clippy::too_many_arguments)]
async fn pause_for_investigation(
    kind: LocalRuntimeKind,
    live: &InvestigationControl,
    config: &WorkloadConfig,
    cluster_id: &str,
    phase: &str,
    detail: &str,
    paths: &RuntimePaths,
    node_a: &ClusterNodeFixture,
    node_b: &ClusterNodeFixture,
    node_c: &ClusterNodeFixture,
    runtime: Option<&LocalRuntimeFixture>,
    failure: Option<&str>,
) -> Result<PauseOutcome> {
    let _ = fs::remove_file(&live.continue_signal_path);
    let _ = fs::remove_file(&live.cleanup_signal_path);

    update_manifest(
        kind,
        &RuntimeMode::Live(live.clone()),
        config,
        cluster_id,
        phase,
        "paused",
        Some(failure.unwrap_or(detail)),
        paths,
        node_a,
        node_b,
        node_c,
        runtime,
    )?;

    eprintln!(
        "[live] paused at phase={phase}: {detail}\n[live] continue signal: {}\n[live] cleanup signal : {}\n[live] manifest       : {}",
        live.continue_signal_path.display(),
        live.cleanup_signal_path.display(),
        live.manifest_path.display()
    );

    loop {
        if live.cleanup_signal_path.exists() {
            let _ = fs::remove_file(&live.cleanup_signal_path);
            eprintln!("[live] cleanup requested at phase={phase}");
            return Ok(PauseOutcome::CleanupRequested);
        }
        if live.continue_signal_path.exists() {
            let _ = fs::remove_file(&live.continue_signal_path);
            update_manifest(
                kind,
                &RuntimeMode::Live(live.clone()),
                config,
                cluster_id,
                phase,
                "running",
                Some(&format!("{detail} (resumed)")),
                paths,
                node_a,
                node_b,
                node_c,
                runtime,
            )?;
            eprintln!("[live] continuing from phase={phase}");
            return Ok(PauseOutcome::Continue);
        }

        tokio::select! {
            _ = sleep(Duration::from_secs(2)) => {}
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    eprintln!("[live] received Ctrl+C at phase={phase}; cleaning up");
                    return Ok(PauseOutcome::CleanupRequested);
                }
            }
        }
    }
}

async fn cleanup_runtime(
    paths: &RuntimePaths,
    node_a: &mut ClusterNodeFixture,
    node_b: &mut ClusterNodeFixture,
    node_c: &mut ClusterNodeFixture,
    runtime: Option<&mut LocalRuntimeFixture>,
) {
    if let Some(runtime) = runtime {
        runtime.stop_and_cleanup().await;
    }
    let _ = fs::remove_dir_all(&paths.source_dir);
    let _ = fs::remove_dir_all(&paths.sync_root);
    node_c.stop_and_cleanup().await;
    node_b.stop_and_cleanup().await;
    node_a.stop_and_cleanup().await;
}

fn normalized_store_path(relative_path: &Path) -> Result<String> {
    let components = relative_path
        .iter()
        .map(|component| {
            component.to_str().with_context(|| {
                format!(
                    "relative path {} contains a non-utf8 component",
                    relative_path.display()
                )
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(components.join("/"))
}

fn read_env_usize(name: &str, default: usize) -> Result<usize> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("failed parsing {name}={value} as usize")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("failed reading {name}")),
    }
}

fn read_env_u64(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("failed parsing {name}={value} as u64")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(err) => Err(err).with_context(|| format!("failed reading {name}")),
    }
}

fn env_truthy(name: &str) -> bool {
    matches!(
        std::env::var(name)
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

fn file_size_for_index(config: &WorkloadConfig, index: usize) -> usize {
    let range = config.max_bytes - config.min_bytes + 1;
    let mix = 0xA076_1D64_78BD_642Fu64.wrapping_mul((index as u64).wrapping_add(1));
    config.min_bytes + (mix as usize % range)
}

fn file_seed_for_index(index: usize) -> u64 {
    0xD1B5_4A32_D192_ED03u64 ^ ((index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
}

fn build_directory_layout(config: &WorkloadConfig) -> Vec<PathBuf> {
    let mut rng = XorShift64::new(0x8D51_AA23_7F34_9C17);
    let mut directories: Vec<PathBuf> = Vec::with_capacity(config.subdir_count);
    let mut by_depth = vec![Vec::<usize>::new(); config.max_dir_depth + 1];

    for dir_index in 0..config.subdir_count {
        let desired_depth = if dir_index < config.max_dir_depth {
            dir_index + 1
        } else {
            1 + (rng.next_u64() as usize % config.max_dir_depth)
        };
        let parent_path = if desired_depth == 1 || by_depth[desired_depth - 1].is_empty() {
            PathBuf::new()
        } else {
            let candidates = &by_depth[desired_depth - 1];
            directories[candidates[rng.next_u64() as usize % candidates.len()]].clone()
        };
        let path = parent_path.join(format!("dir-{dir_index:03}"));
        by_depth[desired_depth].push(directories.len());
        directories.push(path);
    }

    directories
}

fn fill_pseudorandom(buffer: &mut [u8], rng: &mut XorShift64) {
    let mut offset = 0usize;
    while offset + 8 <= buffer.len() {
        buffer[offset..offset + 8].copy_from_slice(&rng.next_u64().to_le_bytes());
        offset += 8;
    }
    if offset < buffer.len() {
        let tail = rng.next_u64().to_le_bytes();
        let remaining = buffer.len() - offset;
        buffer[offset..].copy_from_slice(&tail[..remaining]);
    }
}

fn write_random_file(path: &Path, size_bytes: usize, seed: u64) -> Result<Hash> {
    let file = File::create(path)
        .with_context(|| format!("failed to create staged file {}", path.display()))?;
    let mut writer = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
    let mut buffer = vec![0u8; IO_BUFFER_BYTES];
    let mut rng = XorShift64::new(seed);
    let mut hasher = blake3::Hasher::new();
    let mut remaining = size_bytes;

    while remaining > 0 {
        let chunk_len = remaining.min(buffer.len());
        fill_pseudorandom(&mut buffer[..chunk_len], &mut rng);
        writer
            .write_all(&buffer[..chunk_len])
            .with_context(|| format!("failed writing staged file {}", path.display()))?;
        hasher.update(&buffer[..chunk_len]);
        remaining -= chunk_len;
    }

    writer
        .flush()
        .with_context(|| format!("failed flushing staged file {}", path.display()))?;
    writer
        .into_inner()
        .with_context(|| format!("failed finalizing staged file {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed syncing staged file {}", path.display()))?;
    Ok(hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
async fn start_cluster_node(
    bind: &str,
    label: &'static str,
    node_id: &str,
    cluster_id: &str,
    replication_factor: usize,
    data_dir: PathBuf,
    client_dir: PathBuf,
) -> Result<ClusterNodeFixture> {
    fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;
    fs::create_dir_all(&client_dir)
        .with_context(|| format!("failed to create {}", client_dir.display()))?;

    let env = [
        ("IRONMESH_CLUSTER_ID", cluster_id),
        ("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "true"),
    ];

    let server = start_authenticated_server_with_env_options(
        bind,
        &data_dir,
        node_id,
        replication_factor,
        None,
        Some(60 * 60),
        &env,
    )
    .await?;

    let base_url = format!("http://{bind}");
    let internal_base_url = internal_base_url_from_public_bind(bind)?;
    let internal_http = mtls_client_from_data_dir(&data_dir)?;
    let enrolled = issue_bootstrap_bundle_and_enroll_client(
        &Client::new(),
        &base_url,
        TEST_ADMIN_TOKEN,
        &client_dir,
        &format!("{label}.bootstrap.json"),
        Some(label),
        Some(12 * 60 * 60),
    )
    .await?;
    let sdk = enrolled.build_client_async().await?;

    Ok(ClusterNodeFixture {
        label,
        node_id: node_id.to_string(),
        base_url,
        internal_base_url,
        internal_http,
        data_dir,
        client_dir,
        bootstrap_file: enrolled.bootstrap_path,
        sdk,
        server,
    })
}

async fn start_local_runtime(
    kind: LocalRuntimeKind,
    paths: &RuntimePaths,
    node_a: &ClusterNodeFixture,
) -> Result<LocalRuntimeFixture> {
    match kind {
        LocalRuntimeKind::Cfapi => {
            let adapter = start_cfapi_adapter_with_bootstrap_and_local_appdata(
                "ironmesh.systemtest.cluster.load",
                "Ironmesh Cluster Load Test",
                &paths.sync_root,
                DEFAULT_RUNTIME_REFRESH_INTERVAL_MS,
                &node_a.bootstrap_file,
                &paths.runtime_state_dir,
            )
            .await?;
            Ok(LocalRuntimeFixture::Cfapi {
                local_appdata_dir: paths.runtime_state_dir.clone(),
                adapter,
            })
        }
        LocalRuntimeKind::FolderAgent => {
            start_folder_agent_with_bootstrap_and_state_root(
                &paths.sync_root,
                &node_a.bootstrap_file,
                &default_client_identity_path(&node_a.bootstrap_file),
                &paths.runtime_state_dir,
                DEFAULT_RUNTIME_REFRESH_INTERVAL_MS,
                DEFAULT_RUNTIME_REFRESH_INTERVAL_MS,
            )
            .await
            .map(|agent| LocalRuntimeFixture::FolderAgent {
                state_root_dir: paths.runtime_state_dir.clone(),
                agent,
            })
        }
    }
}

async fn start_folder_agent_with_bootstrap_and_state_root(
    root_dir: &Path,
    bootstrap_file: &Path,
    client_identity_file: &Path,
    state_root_dir: &Path,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
) -> Result<ChildGuard> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;
    let resource_guards = lock_test_resources([
        "folder-agent-process".to_string(),
        path_resource_key(root_dir),
    ])
    .await;

    fs::create_dir_all(state_root_dir)
        .with_context(|| format!("failed creating {}", state_root_dir.display()))?;
    let stdout_log = state_root_dir.join("folder-agent.stdout.log");
    let stderr_log = state_root_dir.join("folder-agent.stderr.log");
    let stdout_file = File::create(&stdout_log).with_context(|| {
        format!(
            "failed creating folder-agent stdout log {}",
            stdout_log.display()
        )
    })?;
    let stderr_file = File::create(&stderr_log).with_context(|| {
        format!(
            "failed creating folder-agent stderr log {}",
            stderr_log.display()
        )
    })?;

    let mut command = Command::new(agent_bin);
    command
        .arg("--root-dir")
        .arg(root_dir)
        .arg("--state-root-dir")
        .arg(state_root_dir)
        .arg("--bootstrap-file")
        .arg(bootstrap_file)
        .arg("--client-identity-file")
        .arg(client_identity_file)
        .arg("--remote-refresh-interval-ms")
        .arg(remote_refresh_interval_ms.to_string())
        .arg("--local-scan-interval-ms")
        .arg(local_scan_interval_ms.to_string())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let mut child = command
        .spawn()
        .context("failed to spawn ironmesh-folder-agent")?;

    sleep(Duration::from_millis(300)).await;
    if let Some(status) = child
        .try_wait()
        .context("failed to query folder-agent process state")?
    {
        bail!("ironmesh-folder-agent exited early with status {status}");
    }

    Ok(ChildGuard::with_resources(child, resource_guards))
}

async fn register_full_mesh(http: &Client, nodes: &[&ClusterNodeFixture]) -> Result<()> {
    for (controller_index, controller) in nodes.iter().enumerate() {
        for (peer_index, peer) in nodes.iter().enumerate() {
            if controller_index == peer_index {
                continue;
            }
            let dc = match peer_index {
                0 => "dc-a",
                1 => "dc-b",
                _ => "dc-c",
            };
            let rack = match peer_index {
                0 => "rack-a",
                1 => "rack-b",
                _ => "rack-c",
            };
            register_node(
                http,
                &controller.base_url,
                &peer.node_id,
                &peer.base_url,
                dc,
                rack,
            )
            .await?;
        }
    }
    Ok(())
}

async fn fetch_all_store_file_paths(sdk: &IronMeshClient) -> Result<BTreeSet<String>> {
    let response = sdk
        .store_index_with_options(
            None,
            8,
            None,
            StoreIndexRequestOptions {
                synthesize_missing_folder_markers: false,
                ..StoreIndexRequestOptions::default()
            },
        )
        .await?;

    Ok(response
        .entries
        .into_iter()
        .filter(|entry| !entry.path.ends_with('/'))
        .map(|entry| entry.path)
        .collect())
}

async fn fetch_store_entry_count(sdk: &IronMeshClient) -> Result<usize> {
    let response = sdk
        .store_index_with_options(
            None,
            8,
            None,
            StoreIndexRequestOptions {
                limit: Some(STORE_INDEX_PROGRESS_LIMIT),
                synthesize_missing_folder_markers: false,
                ..StoreIndexRequestOptions::default()
            },
        )
        .await?;

    Ok(response.total_entry_count)
}

fn expected_store_entry_count(expected_paths: &BTreeSet<String>) -> usize {
    let mut directory_paths = BTreeSet::new();

    for path in expected_paths {
        let mut prefix = String::new();
        let mut parts = path.split('/').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                break;
            }
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            directory_paths.insert(format!("{prefix}/"));
        }
    }

    expected_paths.len() + directory_paths.len()
}

async fn wait_for_store_file_paths(
    sdk: &IronMeshClient,
    expected_paths: &BTreeSet<String>,
    label: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let mut last_log = Instant::now();
    let expected_entry_count = expected_store_entry_count(expected_paths);
    let minimum_entries_for_full_scan = expected_paths.len();
    loop {
        match fetch_store_entry_count(sdk).await {
            // The store index can legitimately omit some intermediate directory markers even when
            // the full file set has converged, so gate the expensive full scan on file-count
            // reachability instead of the synthesized directory total.
            Ok(actual_count) if actual_count >= minimum_entries_for_full_scan => {
                match fetch_all_store_file_paths(sdk).await {
                    Ok(actual_paths) if actual_paths == *expected_paths => return Ok(()),
                    Ok(actual_paths) => {
                        if last_log.elapsed() >= Duration::from_secs(10) {
                            let missing = expected_paths
                                .difference(&actual_paths)
                                .take(5)
                                .cloned()
                                .collect::<Vec<_>>();
                            let extra = actual_paths
                                .difference(expected_paths)
                                .take(5)
                                .cloned()
                                .collect::<Vec<_>>();
                            eprintln!(
                                "[{label}] store index progress: have_files={} expected_files={} have_entries={} expected_entries={} missing_sample={missing:?} extra_sample={extra:?}",
                                actual_paths.len(),
                                expected_paths.len(),
                                actual_count,
                                expected_entry_count
                            );
                            last_log = Instant::now();
                        }
                    }
                    Err(err) if last_log.elapsed() >= Duration::from_secs(10) => {
                        eprintln!("[{label}] store index retry after full scan error: {err:#}");
                        last_log = Instant::now();
                    }
                    Err(_) => {}
                }
            }
            Ok(actual_count) => {
                if last_log.elapsed() >= Duration::from_secs(10) {
                    eprintln!(
                        "[{label}] store index progress: have_entries={} expected_entries={} expected_files={}",
                        actual_count,
                        expected_entry_count,
                        expected_paths.len()
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) if last_log.elapsed() >= Duration::from_secs(10) => {
                eprintln!("[{label}] store index retry after error: {err:#}");
                last_log = Instant::now();
            }
            Err(_) => {}
        }

        if started.elapsed() >= timeout {
            let actual_paths = fetch_all_store_file_paths(sdk).await.unwrap_or_default();
            let missing = expected_paths
                .difference(&actual_paths)
                .take(10)
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "[{label}] timed out waiting for store index convergence: have={} expected={} missing_sample={missing:?}",
                actual_paths.len(),
                expected_paths.len()
            );
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn local_available_subjects(http: &Client, base_url: &str) -> Result<BTreeSet<String>> {
    let payload = http
        .get(format!("{base_url}/cluster/availability/subjects/local"))
        .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    Ok(payload
        .get("subjects")
        .and_then(|value| value.as_array())
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str().map(ToString::to_string))
        .collect())
}

async fn wait_for_local_subjects(
    http: &Client,
    base_url: &str,
    expected_paths: &BTreeSet<String>,
    label: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let mut last_log = Instant::now();
    loop {
        match local_available_subjects(http, base_url).await {
            Ok(subjects) => {
                let missing = expected_paths
                    .iter()
                    .filter(|path| !subjects.contains(*path))
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>();
                if missing.is_empty() {
                    return Ok(());
                }

                if last_log.elapsed() >= Duration::from_secs(10) {
                    eprintln!(
                        "[{label}] local availability progress: available={} expected={} missing_sample={missing:?}",
                        subjects.len(),
                        expected_paths.len()
                    );
                    last_log = Instant::now();
                }
            }
            Err(err) if last_log.elapsed() >= Duration::from_secs(10) => {
                eprintln!("[{label}] local availability retry after error: {err:#}");
                last_log = Instant::now();
            }
            Err(_) => {}
        }

        if started.elapsed() >= timeout {
            let subjects = local_available_subjects(http, base_url)
                .await
                .unwrap_or_default();
            let missing = expected_paths
                .iter()
                .filter(|path| !subjects.contains(*path))
                .take(10)
                .cloned()
                .collect::<Vec<_>>();
            bail!(
                "[{label}] timed out waiting for local availability convergence: available={} expected={} missing_sample={missing:?}",
                subjects.len(),
                expected_paths.len()
            );
        }

        sleep(Duration::from_secs(2)).await;
    }
}

async fn current_under_replicated(http: &Client, base_url: &str) -> Result<u64> {
    let payload = http
        .get(format!("{base_url}/cluster/replication/plan"))
        .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;
    payload
        .get("under_replicated")
        .and_then(|value| value.as_u64())
        .context("replication plan response missing under_replicated")
}

async fn drive_replication_to_completion(
    http: &Client,
    base_url: &str,
    timeout: Duration,
) -> Result<()> {
    let started = Instant::now();
    let mut last_repair = Instant::now()
        .checked_sub(Duration::from_secs(30))
        .unwrap_or_else(Instant::now);

    loop {
        let under_replicated = current_under_replicated(http, base_url).await?;
        if under_replicated == 0 {
            return Ok(());
        }

        if last_repair.elapsed() >= Duration::from_secs(15) {
            let report = http
                .post(format!("{base_url}/cluster/replication/repair"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .send()
                .await?
                .error_for_status()?
                .json::<serde_json::Value>()
                .await?;
            let successful = report
                .get("successful_transfers")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            let failed = report
                .get("failed_transfers")
                .and_then(|value| value.as_u64())
                .unwrap_or(0);
            eprintln!(
                "[cluster] repair pass: under_replicated={under_replicated} successful_transfers={successful} failed_transfers={failed}"
            );
            last_repair = Instant::now();
        }

        if started.elapsed() >= timeout {
            bail!(
                "timed out waiting for replication repair to finish at {base_url}; under_replicated={under_replicated}"
            );
        }

        sleep(Duration::from_secs(5)).await;
    }
}

fn select_sample_specs(file_specs: &[FileSpec], sample_count: usize) -> Vec<FileSpec> {
    if file_specs.len() <= sample_count {
        return file_specs.to_vec();
    }

    let last_index = file_specs.len() - 1;
    let mut indices = BTreeSet::new();
    for slot in 0..sample_count {
        let index = if sample_count == 1 {
            0
        } else {
            slot.saturating_mul(last_index) / (sample_count - 1)
        };
        indices.insert(index);
    }

    indices
        .into_iter()
        .filter_map(|index| file_specs.get(index).cloned())
        .collect()
}

async fn verify_sample_content(
    sdk: &IronMeshClient,
    label: &str,
    sample_specs: &[FileSpec],
) -> Result<()> {
    for (index, spec) in sample_specs.iter().enumerate() {
        let bytes = sdk
            .get(&spec.store_path)
            .await
            .with_context(|| format!("[{label}] failed to fetch {}", spec.store_path))?;
        let hash = blake3::hash(bytes.as_ref());
        if bytes.len() != spec.size_bytes {
            bail!(
                "[{label}] size mismatch for {}: expected={} actual={}",
                spec.store_path,
                spec.size_bytes,
                bytes.len()
            );
        }
        if hash != spec.content_hash {
            bail!(
                "[{label}] hash mismatch for {}: expected={} actual={}",
                spec.store_path,
                spec.content_hash.to_hex(),
                hash.to_hex()
            );
        }

        if (index + 1) % 4 == 0 || index + 1 == sample_specs.len() {
            eprintln!(
                "[{label}] verified {}/{} sampled files",
                index + 1,
                sample_specs.len()
            );
        }
    }

    Ok(())
}

fn stage_workload(config: &WorkloadConfig, source_dir: &Path) -> Result<Vec<FileSpec>> {
    fs::create_dir_all(source_dir)
        .with_context(|| format!("failed to create {}", source_dir.display()))?;
    let mut specs = Vec::with_capacity(config.file_count);
    let directory_layout = build_directory_layout(config);
    let mut directory_rng = XorShift64::new(0x61C8_A1D4_08E7_395B);
    let mut total_bytes = 0usize;

    for index in 0..config.file_count {
        let file_name = format!("load-{index:05}.bin");
        let directory_index = if index < directory_layout.len() {
            index
        } else {
            directory_rng.next_u64() as usize % directory_layout.len()
        };
        let relative_path = directory_layout[directory_index].join(file_name);
        let staged_path = source_dir.join(&relative_path);
        let staged_parent = staged_path.parent().with_context(|| {
            format!(
                "staged path {} is unexpectedly missing a parent directory",
                staged_path.display()
            )
        })?;
        fs::create_dir_all(staged_parent)
            .with_context(|| format!("failed to create staged directory {}", staged_parent.display()))?;
        let size_bytes = file_size_for_index(config, index);
        let seed = file_seed_for_index(index);
        let content_hash = write_random_file(&staged_path, size_bytes, seed)?;
        let store_path = normalized_store_path(&relative_path)?;

        specs.push(FileSpec {
            relative_path,
            store_path,
            size_bytes,
            content_hash,
        });
        total_bytes = total_bytes.saturating_add(size_bytes);

        if (index + 1) % 100 == 0 || index + 1 == config.file_count {
            eprintln!(
                "[workload] staged {}/{} files in source tree across {} subdirs (logical {:.2} GiB)",
                index + 1,
                config.file_count,
                config.subdir_count,
                total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
        }
    }

    Ok(specs)
}

fn copy_staged_workload_into_sync_root(
    kind: LocalRuntimeKind,
    file_specs: &[FileSpec],
    source_dir: &Path,
    sync_root: &Path,
) -> Result<()> {
    let mut total_bytes = 0usize;

    for (index, spec) in file_specs.iter().enumerate() {
        let staged_path = source_dir.join(&spec.relative_path);
        let target_path = sync_root.join(&spec.relative_path);
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create sync-root directory {}", parent.display()))?;
        }

        let copied = fs::copy(&staged_path, &target_path).with_context(|| {
            format!(
                "failed to copy staged file {} into sync root {}",
                staged_path.display(),
                target_path.display()
            )
        })?;
        if copied as usize != spec.size_bytes {
            bail!(
                "copy size mismatch for {}: expected={} copied={copied}",
                target_path.display(),
                spec.size_bytes
            );
        }

        total_bytes = total_bytes.saturating_add(spec.size_bytes);
        if (index + 1) % 100 == 0 || index + 1 == file_specs.len() {
            eprintln!(
                "[workload] copied {}/{} staged files into {} (logical {:.2} GiB)",
                index + 1,
                file_specs.len(),
                kind.progress_copy_label(),
                total_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
            );
        }
    }

    Ok(())
}
