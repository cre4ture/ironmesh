mod saf_sync;

use anyhow::{Context, Result};
use bytes::Bytes;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile(
        profile_id: &str,
        label: &str,
        state: &str,
        message: &str,
        last_success_unix_ms: Option<u64>,
    ) -> AndroidFolderSyncProfileStatus {
        AndroidFolderSyncProfileStatus {
            profile_id: profile_id.to_string(),
            label: label.to_string(),
            state: state.to_string(),
            message: message.to_string(),
            last_success_unix_ms,
            ..AndroidFolderSyncProfileStatus::default()
        }
    }

    #[test]
    fn rebuild_service_summary_reports_stopped_when_no_profiles_are_active() {
        let mut status = AndroidFolderSyncServiceStatus::default();

        rebuild_service_summary(&mut status);

        assert_eq!(status.service_state, "stopped");
        assert_eq!(status.service_message, "Continuous sync is stopped");
        assert_eq!(status.active_profile_count, 0);
        assert!(status.current_activity.is_empty());
        assert!(status.active_summary.is_empty());
        assert_eq!(status.last_success_unix_ms, None);
    }

    #[test]
    fn rebuild_service_summary_prioritizes_errors_and_tracks_latest_success() {
        let mut status = AndroidFolderSyncServiceStatus {
            profiles: vec![
                sample_profile(
                    "profile-a",
                    "Photos",
                    "running",
                    "Watching for changes",
                    Some(100),
                ),
                sample_profile(
                    "profile-b",
                    "Docs",
                    "error",
                    "Folder sync runtime failed: boom",
                    Some(250),
                ),
                sample_profile(
                    "profile-c",
                    "Media",
                    "syncing",
                    "Applying 4 remote change(s)",
                    Some(200),
                ),
            ],
            ..AndroidFolderSyncServiceStatus::default()
        };

        rebuild_service_summary(&mut status);

        assert_eq!(status.service_state, "error");
        assert_eq!(status.active_profile_count, 3);
        assert_eq!(status.error_profile_count, 1);
        assert_eq!(status.syncing_profile_count, 1);
        assert_eq!(status.running_profile_count, 1);
        assert_eq!(status.last_success_unix_ms, Some(250));
        assert_eq!(
            status.current_activity,
            "Docs: Folder sync runtime failed: boom"
        );
        assert!(status.service_message.contains("1 with errors"));
        assert!(status.active_summary.contains("Photos: running"));
    }
}
use client_sdk::{
    BootstrapEnrollmentResult, ClientIdentityMaterial, ClientNode, ConnectionBootstrap,
    IronMeshClient, enroll_connection_input_blocking,
};
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jlong, jstring};
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use sync_agent_core::{
    FolderAgentRuntimeMetrics, FolderAgentRuntimeOptions, FolderAgentRuntimeStatus,
    FolderAgentStatusCallback, build_configured_client, describe_connection_target,
    run_folder_agent, run_folder_agent_with_control,
};
use tokio::task::JoinHandle;

use crate::saf_sync::{initialize_android_saf_bridge, run_saf_folder_agent_with_control};

fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }

    common::logging::init_compact_tracing_default("info");

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to initialize android rust runtime")?;

    let _ = RUNTIME.set(rt);
    RUNTIME
        .get()
        .ok_or_else(|| anyhow::anyhow!("runtime initialization race"))
}

struct WebUiServer {
    connection_input: String,
    server_ca_pem: Option<String>,
    client_identity_json: Option<String>,
    local_url: String,
    task: JoinHandle<()>,
}

fn web_ui_server_state() -> &'static Mutex<Option<WebUiServer>> {
    static STATE: OnceLock<Mutex<Option<WebUiServer>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(None))
}

struct AndroidPreferencesBridgeState {
    vm: JavaVM,
    class: GlobalRef,
}

fn android_preferences_bridge_state() -> &'static OnceLock<AndroidPreferencesBridgeState> {
    static STATE: OnceLock<AndroidPreferencesBridgeState> = OnceLock::new();
    &STATE
}

fn initialize_android_preferences_bridge(env: &mut JNIEnv) -> Result<()> {
    if android_preferences_bridge_state().get().is_some() {
        return Ok(());
    }

    let vm = env
        .get_java_vm()
        .context("failed to capture Java VM for preferences bridge")?;
    let class = env
        .find_class("io/ironmesh/android/data/RustPreferencesBridge")
        .context("failed to find RustPreferencesBridge class")?;
    let global = env
        .new_global_ref(class)
        .context("failed to globalize RustPreferencesBridge class")?;
    let _ =
        android_preferences_bridge_state().set(AndroidPreferencesBridgeState { vm, class: global });
    Ok(())
}

fn with_android_preferences_env<T>(
    f: impl for<'local> FnOnce(&mut JNIEnv<'local>, JClass<'local>) -> Result<T>,
) -> Result<T> {
    let state = android_preferences_bridge_state()
        .get()
        .ok_or_else(|| anyhow::anyhow!("android preferences bridge has not been initialized"))?;
    let mut env = state
        .vm
        .attach_current_thread()
        .context("failed to attach web UI thread to JVM")?;
    let class_ref = env
        .new_local_ref(state.class.as_obj())
        .context("failed to create local RustPreferencesBridge class ref")?;
    let class = JClass::from(class_ref);
    f(&mut env, class)
}

fn persist_android_connection_bootstrap(bootstrap: &ConnectionBootstrap) -> Result<()> {
    let json = bootstrap
        .to_json_pretty()
        .context("failed to serialize android bootstrap for persistence")?;
    with_android_preferences_env(|env, class| {
        let bootstrap_json = env
            .new_string(&json)
            .context("failed to allocate bootstrap JSON string")?;
        env.call_static_method(
            &class,
            "updateDeviceAuthBootstrapJson",
            "(Ljava/lang/String;)V",
            &[JValue::Object(bootstrap_json.as_ref())],
        )
        .context("failed to persist updated bootstrap JSON to Android preferences")?;
        Ok(())
    })
}

fn android_cache_dir() -> Result<PathBuf> {
    with_android_preferences_env(|env, class| {
        let value = env
            .call_static_method(&class, "cacheDirPath", "()Ljava/lang/String;", &[])
            .context("failed to query Android cache dir path")?
            .l()
            .context("Android cache dir path returned invalid value")?;
        let value = JString::from(value);
        let value: String = env
            .get_string(&value)
            .context("failed to decode Android cache dir path")?
            .into();
        Ok(PathBuf::from(value))
    })
}

fn android_download_stage_root(category: &str, scope: &str) -> Result<PathBuf> {
    let cache_dir = android_cache_dir()?;
    let scope = scope.trim();
    if scope.is_empty() {
        anyhow::bail!("android download staging scope cannot be empty");
    }
    let scope_hash = blake3::hash(scope.as_bytes()).to_hex().to_string();
    Ok(cache_dir
        .join("ironmesh-downloads")
        .join(category)
        .join(scope_hash))
}

fn android_folder_sync_state_root() -> Result<PathBuf> {
    Ok(android_cache_dir()?.join("ironmesh-folder-sync-state"))
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AndroidFolderSyncServiceStatus {
    service_state: String,
    service_message: String,
    profiles: Vec<AndroidFolderSyncProfileStatus>,
    updated_unix_ms: u64,
    profile_count: u64,
    active_profile_count: u64,
    syncing_profile_count: u64,
    error_profile_count: u64,
    starting_profile_count: u64,
    running_profile_count: u64,
    current_activity: String,
    active_summary: String,
    last_success_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AndroidFolderSyncProfileStatus {
    profile_id: String,
    label: String,
    state: String,
    message: String,
    updated_unix_ms: u64,
    phase: String,
    activity: String,
    scope_label: String,
    root_dir: String,
    local_tree_uri: Option<String>,
    connection_target: Option<String>,
    storage_mode: String,
    watch_mode: String,
    run_mode: String,
    last_success_unix_ms: Option<u64>,
    last_error: Option<String>,
    metrics: FolderAgentRuntimeMetrics,
}

fn android_storage_mode_label(options: &FolderAgentRuntimeOptions) -> &'static str {
    if options
        .local_tree_uri
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        "android-saf"
    } else {
        "filesystem"
    }
}

fn android_watch_mode_label(options: &FolderAgentRuntimeOptions) -> &'static str {
    if options.run_once {
        "not-watching"
    } else if options
        .local_tree_uri
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
    {
        "saf-observer+polling"
    } else if options.no_watch_local {
        "polling-only"
    } else {
        "fs-notify+polling"
    }
}

fn profile_status_from_runtime(
    profile_id: impl Into<String>,
    label: impl Into<String>,
    status: FolderAgentRuntimeStatus,
) -> AndroidFolderSyncProfileStatus {
    AndroidFolderSyncProfileStatus {
        profile_id: profile_id.into(),
        label: label.into(),
        state: status.state,
        message: status.message,
        updated_unix_ms: status.updated_unix_ms,
        phase: status.phase,
        activity: status.activity,
        scope_label: status.scope_label,
        root_dir: status.root_dir,
        local_tree_uri: status.local_tree_uri,
        connection_target: status.connection_target,
        storage_mode: status.storage_mode,
        watch_mode: status.watch_mode,
        run_mode: status.run_mode,
        last_success_unix_ms: status.last_success_unix_ms,
        last_error: status.last_error,
        metrics: status.metrics,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_profile_status(
    profile_id: impl Into<String>,
    label: impl Into<String>,
    options: &FolderAgentRuntimeOptions,
    connection_target: Option<&str>,
    state: &str,
    phase: &str,
    activity: &str,
    message: impl Into<String>,
    last_success_unix_ms: Option<u64>,
    last_error: Option<String>,
) -> AndroidFolderSyncProfileStatus {
    profile_status_from_runtime(
        profile_id,
        label,
        FolderAgentRuntimeStatus::new(
            options,
            connection_target,
            android_storage_mode_label(options),
            android_watch_mode_label(options),
            state,
            phase,
            activity,
            message,
            FolderAgentRuntimeMetrics::default(),
            last_success_unix_ms,
            last_error,
        ),
    )
}

struct AndroidFolderSyncRun {
    running: Arc<AtomicBool>,
    thread: thread::JoinHandle<()>,
}

struct AndroidFolderSyncManager {
    runs: BTreeMap<String, AndroidFolderSyncRun>,
    status: Arc<Mutex<AndroidFolderSyncServiceStatus>>,
}

impl AndroidFolderSyncManager {
    fn new() -> Self {
        Self {
            runs: BTreeMap::new(),
            status: Arc::new(Mutex::new(AndroidFolderSyncServiceStatus {
                service_state: "stopped".to_string(),
                service_message: "Continuous sync is stopped".to_string(),
                updated_unix_ms: now_unix_ms(),
                ..AndroidFolderSyncServiceStatus::default()
            })),
        }
    }

    fn start_profile(
        &mut self,
        profile_id: String,
        label: String,
        options: FolderAgentRuntimeOptions,
    ) -> Result<()> {
        let previous = self.runs.remove(&profile_id);
        if let Some(previous) = previous {
            stop_folder_sync_run(previous);
        }

        let connection_target = describe_connection_target(
            options.server_base_url.as_deref(),
            options.client_bootstrap_json.as_deref(),
        )
        .ok();

        update_profile_status(
            &self.status,
            build_profile_status(
                profile_id.clone(),
                label.clone(),
                &options,
                connection_target.as_deref(),
                "starting",
                "startup",
                "initializing",
                "Starting continuous sync",
                None,
                None,
            ),
        );
        refresh_service_summary(&self.status);

        let running = Arc::new(AtomicBool::new(true));
        let status_store = self.status.clone();
        let callback_profile_id = profile_id.clone();
        let callback_label = label.clone();
        let status_callback: FolderAgentStatusCallback =
            Arc::new(move |status: FolderAgentRuntimeStatus| {
                update_profile_status(
                    &status_store,
                    profile_status_from_runtime(
                        callback_profile_id.clone(),
                        callback_label.clone(),
                        status,
                    ),
                );
                refresh_service_summary(&status_store);
            });

        let thread_profile_id = profile_id.clone();
        let thread_label = label.clone();
        let thread_connection_target = connection_target.clone();
        let thread_running = running.clone();
        let status_store = self.status.clone();
        let thread = thread::Builder::new()
            .name(format!("ironmesh-folder-sync-{profile_id}"))
            .spawn(move || {
                let result = if options.local_tree_uri.is_some() {
                    run_saf_folder_agent_with_control(
                        &options,
                        thread_running,
                        Some(status_callback),
                    )
                } else {
                    run_folder_agent_with_control(
                        &options,
                        thread_running,
                        false,
                        Some(status_callback),
                    )
                };
                if let Err(error) = result {
                    let needs_fallback_error = status_store
                        .lock()
                        .ok()
                        .and_then(|status| {
                            status
                                .profiles
                                .iter()
                                .find(|profile| profile.profile_id == thread_profile_id)
                                .cloned()
                        })
                        .is_none_or(|profile| profile.state != "error");
                    if needs_fallback_error {
                        update_profile_status(
                            &status_store,
                            build_profile_status(
                                thread_profile_id,
                                thread_label,
                                &options,
                                thread_connection_target.as_deref(),
                                "error",
                                "error",
                                "failed",
                                format!("{error:#}"),
                                None,
                                Some(format!("{error:#}")),
                            ),
                        );
                    }
                    refresh_service_summary(&status_store);
                }
            })
            .context("failed to spawn continuous folder sync thread")?;

        self.runs
            .insert(profile_id, AndroidFolderSyncRun { running, thread });
        refresh_service_summary(&self.status);
        Ok(())
    }

    fn stop_profile(&mut self, profile_id: &str) {
        let previous = self.runs.remove(profile_id);
        if let Some(previous) = previous {
            stop_folder_sync_run(previous);
        }
        if let Ok(mut status) = self.status.lock() {
            status
                .profiles
                .retain(|profile| profile.profile_id != profile_id);
            status.updated_unix_ms = now_unix_ms();
        }
        refresh_service_summary(&self.status);
    }

    fn stop_all(&mut self) {
        let runs = std::mem::take(&mut self.runs);
        for (_, run) in runs {
            stop_folder_sync_run(run);
        }
        if let Ok(mut status) = self.status.lock() {
            *status = AndroidFolderSyncServiceStatus {
                service_state: "stopped".to_string(),
                service_message: "Continuous sync is stopped".to_string(),
                updated_unix_ms: now_unix_ms(),
                ..AndroidFolderSyncServiceStatus::default()
            };
        }
    }
}

fn folder_sync_manager() -> &'static Mutex<AndroidFolderSyncManager> {
    static MANAGER: OnceLock<Mutex<AndroidFolderSyncManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(AndroidFolderSyncManager::new()))
}

fn stop_folder_sync_run(run: AndroidFolderSyncRun) {
    run.running.store(false, Ordering::SeqCst);
    let _ = run.thread.join();
}

fn update_profile_status(
    status_store: &Arc<Mutex<AndroidFolderSyncServiceStatus>>,
    profile_status: AndroidFolderSyncProfileStatus,
) {
    if let Ok(mut status) = status_store.lock() {
        if let Some(existing) = status
            .profiles
            .iter_mut()
            .find(|existing| existing.profile_id == profile_status.profile_id)
        {
            *existing = profile_status;
        } else {
            status.profiles.push(profile_status);
            status.profiles.sort_by(|left, right| {
                left.label
                    .cmp(&right.label)
                    .then_with(|| left.profile_id.cmp(&right.profile_id))
            });
        }
        status.updated_unix_ms = now_unix_ms();
    }
}

fn refresh_service_summary(status_store: &Arc<Mutex<AndroidFolderSyncServiceStatus>>) {
    if let Ok(mut status) = status_store.lock() {
        rebuild_service_summary(&mut status);
    }
}

fn rebuild_service_summary(status: &mut AndroidFolderSyncServiceStatus) {
    let active_profiles = status
        .profiles
        .iter()
        .filter(|profile| profile.state != "stopped")
        .collect::<Vec<_>>();
    let syncing_profiles = active_profiles
        .iter()
        .filter(|profile| profile.state == "syncing")
        .count();
    let error_profiles = active_profiles
        .iter()
        .filter(|profile| profile.state == "error")
        .count();
    let starting_profiles = active_profiles
        .iter()
        .filter(|profile| profile.state == "starting")
        .count();
    let running_profiles = active_profiles
        .iter()
        .filter(|profile| profile.state == "running")
        .count();

    status.profile_count = usize_to_u64(status.profiles.len());
    status.active_profile_count = usize_to_u64(active_profiles.len());
    status.syncing_profile_count = usize_to_u64(syncing_profiles);
    status.error_profile_count = usize_to_u64(error_profiles);
    status.starting_profile_count = usize_to_u64(starting_profiles);
    status.running_profile_count = usize_to_u64(running_profiles);
    status.last_success_unix_ms = active_profiles
        .iter()
        .filter_map(|profile| profile.last_success_unix_ms)
        .max();

    let primary_profile =
        active_profiles
            .iter()
            .copied()
            .min_by_key(|profile| match profile.state.as_str() {
                "error" => 0,
                "syncing" => 1,
                "starting" => 2,
                "running" => 3,
                _ => 4,
            });

    status.current_activity = primary_profile
        .map(|profile| {
            let detail = if !profile.message.trim().is_empty() {
                profile.message.as_str()
            } else if !profile.activity.trim().is_empty() {
                profile.activity.as_str()
            } else {
                profile.state.as_str()
            };
            format!("{}: {detail}", profile.label)
        })
        .unwrap_or_default();

    let mut summary_parts = active_profiles
        .iter()
        .take(3)
        .map(|profile| format!("{}: {}", profile.label, profile.state))
        .collect::<Vec<_>>();
    if active_profiles.len() > 3 {
        summary_parts.push(format!("+{} more", active_profiles.len() - 3));
    }
    status.active_summary = summary_parts.join(" | ");

    status.service_state = if active_profiles.is_empty() {
        "stopped".to_string()
    } else if error_profiles > 0 {
        "error".to_string()
    } else if syncing_profiles > 0 {
        "syncing".to_string()
    } else {
        "running".to_string()
    };

    status.service_message = if active_profiles.is_empty() {
        "Continuous sync is stopped".to_string()
    } else if error_profiles > 0 {
        format!(
            "{} active profile(s), {} with errors",
            active_profiles.len(),
            error_profiles
        )
    } else if syncing_profiles > 0 {
        format!(
            "Syncing {} of {} active profile(s)",
            syncing_profiles,
            active_profiles.len()
        )
    } else if starting_profiles > 0 {
        format!(
            "Starting {} profile(s); {} already watching",
            starting_profiles, running_profiles
        )
    } else {
        format!("Watching {} profile(s)", running_profiles)
    };

    status.updated_unix_ms = now_unix_ms();
}

fn usize_to_u64(value: usize) -> u64 {
    value.try_into().unwrap_or(u64::MAX)
}

fn current_folder_sync_status_json() -> Result<String> {
    let status_store = folder_sync_manager()
        .lock()
        .map_err(|_| anyhow::anyhow!("folder sync manager lock poisoned"))?
        .status
        .clone();
    let status = status_store
        .lock()
        .map_err(|_| anyhow::anyhow!("folder sync status lock poisoned"))?
        .clone();
    serde_json::to_string(&status).context("failed to serialize continuous folder sync status")
}

fn start_embedded_web_ui(
    connection_input: String,
    server_ca_pem: Option<String>,
    client_identity_json: Option<String>,
) -> Result<String> {
    let rt = runtime()?;
    let connection_input = normalized_connection_input_string(connection_input)?;
    let server_ca_pem = normalize_optional_string(server_ca_pem);
    let client_identity_json = normalize_optional_string(client_identity_json);
    let mut state = web_ui_server_state()
        .lock()
        .map_err(|_| anyhow::anyhow!("web ui state lock poisoned"))?;

    if let Some(existing) = state.as_ref()
        && existing.connection_input == connection_input
        && existing.server_ca_pem == server_ca_pem
        && existing.client_identity_json == client_identity_json
        && !existing.task.is_finished()
    {
        return Ok(existing.local_url.clone());
    }

    if let Some(previous) = state.take() {
        previous.task.abort();
    }

    let listener = rt
        .block_on(async { tokio::net::TcpListener::bind(("127.0.0.1", 0)).await })
        .context("failed to bind embedded web ui listener")?;
    let address = listener
        .local_addr()
        .context("failed to read embedded web ui listener address")?;
    let local_url = format!("http://127.0.0.1:{}/", address.port());
    let client = configured_sdk(
        connection_input.clone(),
        server_ca_pem.clone(),
        client_identity_json.clone(),
    )?;
    let mut web_ui_config =
        web_ui_backend::WebUiConfig::from_client(client).with_service_name("ironmesh-android");
    let (_, client_bootstrap_json) = split_connection_input(connection_input.clone())?;
    if let Some(raw_bootstrap) = client_bootstrap_json {
        let mut bootstrap = ConnectionBootstrap::from_json_str(&raw_bootstrap)
            .context("failed to parse android bootstrap for embedded web ui")?;
        if let Some(server_ca_pem) = server_ca_pem.as_ref() {
            bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
        }
        web_ui_config = web_ui_config
            .with_connection_bootstrap(bootstrap)
            .with_connection_bootstrap_persistence(web_ui_backend::WebUiBootstrapPersistence::new(
                "android_preferences",
                persist_android_connection_bootstrap,
            ));
    }
    if let Some(identity) = parse_client_identity_json(client_identity_json.clone())? {
        web_ui_config = web_ui_config.with_client_identity(identity);
    }
    let app = web_ui_backend::router(web_ui_config);

    let task = rt.spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    *state = Some(WebUiServer {
        connection_input,
        server_ca_pem,
        client_identity_json,
        local_url: local_url.clone(),
        task,
    });

    Ok(local_url)
}

fn throw_java_error(env: &mut JNIEnv, message: impl AsRef<str>) {
    if env.exception_check().unwrap_or(false) {
        return;
    }
    let _ = env.throw_new("java/lang/RuntimeException", message.as_ref());
}

#[allow(unsafe_code)]
fn optional_jstring(env: &mut JNIEnv, value: jstring) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }

    let value = unsafe { JString::from_raw(value) };
    let value: String = env.get_string(&value)?.into();
    Ok(Some(value))
}

#[allow(unsafe_code)]
fn as_jbyte_slice(bytes: &[u8]) -> &[jbyte] {
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const jbyte, bytes.len()) }
}

#[allow(unsafe_code)]
fn as_mut_jbyte_slice(bytes: &mut [u8]) -> &mut [jbyte] {
    unsafe { std::slice::from_raw_parts_mut(bytes.as_mut_ptr() as *mut jbyte, bytes.len()) }
}

struct JavaInputStreamReader<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    input_stream: JObject<'local>,
    java_buffer: JByteArray<'local>,
}

impl<'env, 'local> JavaInputStreamReader<'env, 'local> {
    const BUFFER_SIZE: usize = 64 * 1024;

    fn new(env: &'env mut JNIEnv<'local>, input_stream: JObject<'local>) -> Result<Self> {
        let java_buffer = env.new_byte_array(Self::BUFFER_SIZE as i32)?;
        Ok(Self {
            env,
            input_stream,
            java_buffer,
        })
    }
}

impl Read for JavaInputStreamReader<'_, '_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let requested = out.len().min(Self::BUFFER_SIZE);
        let read = self
            .env
            .call_method(
                &self.input_stream,
                "read",
                "([BII)I",
                &[
                    JValue::Object(self.java_buffer.as_ref()),
                    JValue::Int(0),
                    JValue::Int(requested as i32),
                ],
            )
            .and_then(|value| value.i())
            .map_err(|err| std::io::Error::other(err.to_string()))?;

        if read < 0 {
            return Ok(0);
        }

        let read = read as usize;
        self.env
            .get_byte_array_region(&self.java_buffer, 0, as_mut_jbyte_slice(&mut out[..read]))
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        Ok(read)
    }
}

struct JavaOutputStreamWriter<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    output_stream: JObject<'local>,
    java_buffer: JByteArray<'local>,
}

impl<'env, 'local> JavaOutputStreamWriter<'env, 'local> {
    const BUFFER_SIZE: usize = 64 * 1024;

    fn new(env: &'env mut JNIEnv<'local>, output_stream: JObject<'local>) -> Result<Self> {
        let java_buffer = env.new_byte_array(Self::BUFFER_SIZE as i32)?;
        Ok(Self {
            env,
            output_stream,
            java_buffer,
        })
    }
}

impl Write for JavaOutputStreamWriter<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0usize;

        while written < buf.len() {
            let chunk_len = (buf.len() - written).min(Self::BUFFER_SIZE);
            let chunk = &buf[written..written + chunk_len];
            self.env
                .set_byte_array_region(&self.java_buffer, 0, as_jbyte_slice(chunk))
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            self.env
                .call_method(
                    &self.output_stream,
                    "write",
                    "([BII)V",
                    &[
                        JValue::Object(self.java_buffer.as_ref()),
                        JValue::Int(0),
                        JValue::Int(chunk_len as i32),
                    ],
                )
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            written += chunk_len;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.env
            .call_method(&self.output_stream, "flush", "()V", &[])
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        Ok(())
    }
}

pub struct AndroidStorageApp {
    client: ClientNode,
}

impl AndroidStorageApp {
    pub fn new(connection_input: impl Into<String>) -> Result<Self> {
        Self::configured(connection_input, None, None)
    }

    pub fn configured(
        connection_input: impl Into<String>,
        server_ca_pem: Option<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        Ok(Self::with_client(configured_client_node(
            connection_input,
            server_ca_pem,
            client_identity_json,
        )?))
    }

    pub fn configured_from_bootstrap(
        bootstrap_json: impl Into<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        Self::configured(bootstrap_json, None, client_identity_json)
    }

    pub fn with_client(client: ClientNode) -> Self {
        Self { client }
    }

    pub async fn store(&self, key: impl Into<String>, data: Vec<u8>) -> Result<()> {
        self.client.put(key, Bytes::from(data)).await?;
        Ok(())
    }

    pub async fn fetch(&self, key: impl AsRef<str>) -> Result<Vec<u8>> {
        let bytes = self.client.get_cached_or_fetch(key).await?;
        Ok(bytes.to_vec())
    }

    pub fn web_gui_html(&self) -> String {
        web_ui_backend::assets::app_html()
    }
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn normalized_connection_input_string(connection_input: impl Into<String>) -> Result<String> {
    let connection_input = connection_input.into();
    let trimmed = connection_input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("android client requires a non-empty connection input");
    }

    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }

    Ok(client_sdk::normalize_server_base_url(trimmed)?.to_string())
}

fn split_connection_input(
    connection_input: impl Into<String>,
) -> Result<(Option<String>, Option<String>)> {
    let normalized = normalized_connection_input_string(connection_input)?;
    if normalized.starts_with('{') {
        Ok((None, Some(normalized)))
    } else {
        Ok((Some(normalized), None))
    }
}

fn configured_sdk(
    connection_input: impl Into<String>,
    server_ca_pem: Option<String>,
    client_identity_json: Option<String>,
) -> Result<IronMeshClient> {
    let server_ca_pem = normalize_optional_string(server_ca_pem);
    let client_identity_json = normalize_optional_string(client_identity_json);
    let (server_base_url, client_bootstrap_json) = split_connection_input(connection_input)?;
    build_configured_client(
        server_base_url.as_deref(),
        client_bootstrap_json.as_deref(),
        server_ca_pem.as_deref(),
        client_identity_json.as_deref(),
    )
}

fn configured_client_node(
    connection_input: impl Into<String>,
    server_ca_pem: Option<String>,
    client_identity_json: Option<String>,
) -> Result<ClientNode> {
    Ok(ClientNode::with_client(configured_sdk(
        connection_input,
        server_ca_pem,
        client_identity_json,
    )?))
}

fn parse_client_identity_json(
    client_identity_json: Option<String>,
) -> Result<Option<ClientIdentityMaterial>> {
    let client_identity_json = normalize_optional_string(client_identity_json);
    client_identity_json
        .as_deref()
        .map(|raw| {
            ClientIdentityMaterial::from_json_str(raw)
                .context("failed to parse android client identity JSON")
        })
        .transpose()
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_startWebUi(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jstring {
    let result = (|| -> Result<String> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        initialize_android_preferences_bridge(&mut env)?;
        start_embedded_web_ui(connection_input, server_ca_pem, client_identity_json)
    })();

    match result {
        Ok(url) => match env.new_string(url) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust startWebUi failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust startWebUi failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_enrollWithBootstrap(
    mut env: JNIEnv,
    _class: JClass,
    bootstrap_json: JString,
    device_id: jstring,
    label: jstring,
) -> jstring {
    let result = (|| -> Result<String> {
        let bootstrap_json: String = env.get_string(&bootstrap_json)?.into();
        let device_id = normalize_optional_string(optional_jstring(&mut env, device_id)?);
        let label = normalize_optional_string(optional_jstring(&mut env, label)?);
        let enrolled: BootstrapEnrollmentResult = enroll_connection_input_blocking(
            &bootstrap_json,
            device_id.as_deref(),
            label.as_deref(),
        )?;
        serde_json::to_string(&enrolled)
            .context("failed to serialize bootstrap enrollment response")
    })();

    match result {
        Ok(json) => match env.new_string(json) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust enrollWithBootstrap failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(
                &mut env,
                format!("rust enrollWithBootstrap failed: {err:#}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_putObject(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    key: JString,
    payload: jbyteArray,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let payload_ref = unsafe { JByteArray::from_raw(payload) };
        let payload = env.convert_byte_array(&payload_ref)?;

        let rt = runtime()?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        let report = rt.block_on(client.put_large_aware(key, Bytes::from(payload)))?;
        Ok(report.meta.size_bytes as jint)
    })();

    match result {
        Ok(size) => size,
        Err(err) => {
            throw_java_error(&mut env, format!("rust putObject failed: {err:#}"));
            0
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_getObject(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    key: JString,
    snapshot: jstring,
    version: jstring,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jbyteArray {
    let result = (|| -> Result<Vec<u8>> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        initialize_android_preferences_bridge(&mut env)?;
        let stage_root = android_download_stage_root("jni-downloads", &connection_input)?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        let mut bytes = Vec::new();
        client.download_to_writer_resumable_staged(
            key,
            snapshot.as_deref(),
            version.as_deref(),
            &mut bytes,
            &stage_root,
        )?;
        Ok(bytes)
    })();

    match result {
        Ok(bytes) => match env.byte_array_from_slice(&bytes) {
            Ok(arr) => arr.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust getObject failed to create byte[]: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust getObject failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_storeIndex(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    prefix: jstring,
    depth: jint,
    snapshot: jstring,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jstring {
    let result = (|| -> Result<String> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let prefix = optional_jstring(&mut env, prefix)?;
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let sdk = configured_sdk(connection_input, server_ca_pem, client_identity_json)?;
        let response = sdk.store_index_blocking(
            prefix.as_deref(),
            usize::try_from(depth).unwrap_or(1).max(1),
            snapshot.as_deref(),
        )?;

        serde_json::to_string(&response).context("failed to serialize store index response")
    })();

    match result {
        Ok(json) => match env.new_string(json) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!("rust storeIndex failed to create java string: {err:#}"),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(&mut env, format!("rust storeIndex failed: {err:#}"));
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamPutObject<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    connection_input: JString<'local>,
    key: JString<'local>,
    input_stream: JObject<'local>,
    size_bytes: jlong,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let size_bytes =
            u64::try_from(size_bytes).context("streamPutObject requires non-negative sizeBytes")?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let mut reader = JavaInputStreamReader::new(&mut env, input_stream)?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        let report = client.put_large_aware_reader(key, &mut reader, size_bytes)?;
        Ok(report.meta.size_bytes as jint)
    })();

    match result {
        Ok(size) => size,
        Err(err) => {
            throw_java_error(&mut env, format!("rust streamPutObject failed: {err:#}"));
            0
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_deleteObject(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    key: JString,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let rt = runtime()?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        rt.block_on(client.delete_path(key))?;
        Ok(204)
    })();

    match result {
        Ok(code) => code,
        Err(err) => {
            throw_java_error(&mut env, format!("rust deleteObject failed: {err:#}"));
            0
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamObjectTo<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    connection_input: JString<'local>,
    key: JString<'local>,
    output_stream: JObject<'local>,
    snapshot: jstring,
    version: jstring,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) {
    let result = (|| -> Result<()> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let snapshot = optional_jstring(&mut env, snapshot)?;
        let version = optional_jstring(&mut env, version)?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        initialize_android_preferences_bridge(&mut env)?;
        let stage_root = android_download_stage_root("jni-downloads", &connection_input)?;
        let mut writer = JavaOutputStreamWriter::new(&mut env, output_stream)?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        client.download_to_writer_resumable_staged(
            key,
            snapshot.as_deref(),
            version.as_deref(),
            &mut writer,
            &stage_root,
        )
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust streamObjectTo failed: {err:#}"));
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamRelativeUrlTo<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    connection_input: JString<'local>,
    relative_url: JString<'local>,
    output_stream: JObject<'local>,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) {
    let result = (|| -> Result<()> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let relative_url: String = env.get_string(&relative_url)?.into();
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let mut writer = JavaOutputStreamWriter::new(&mut env, output_stream)?;
        let rt = runtime()?;
        let client = configured_sdk(connection_input, server_ca_pem, client_identity_json)?;
        let response = rt.block_on(client.get_relative_path(&relative_url))?;
        if !response.status.is_success() {
            anyhow::bail!(
                "relative URL request returned non-success status: {}",
                response.status
            );
        }
        writer
            .write_all(&response.body)
            .context("failed streaming relative URL response body")?;
        writer
            .flush()
            .context("failed flushing relative URL output")?;
        Ok(())
    })();

    if let Err(err) = result {
        throw_java_error(
            &mut env,
            format!("rust streamRelativeUrlTo failed: {err:#}"),
        );
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_runFolderSyncOnce(
    mut env: JNIEnv,
    _class: JClass,
    connection_input: JString,
    local_folder: JString,
    local_tree_uri: jstring,
    prefix: jstring,
    depth: jint,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) {
    let result = (|| -> Result<()> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let local_folder: String = env.get_string(&local_folder)?.into();
        let local_tree_uri = optional_jstring(&mut env, local_tree_uri)?;
        let prefix = optional_jstring(&mut env, prefix)?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let (server_base_url, client_bootstrap_json) = split_connection_input(connection_input)?;
        initialize_android_preferences_bridge(&mut env)?;

        if local_tree_uri.is_some() {
            initialize_android_saf_bridge(&mut env)?;
        }

        let options = FolderAgentRuntimeOptions {
            root_dir: PathBuf::from(local_folder),
            state_root_dir: Some(android_folder_sync_state_root()?),
            local_tree_uri,
            server_base_url,
            client_bootstrap_json,
            server_ca_pem,
            client_identity_json,
            prefix,
            depth: usize::try_from(depth).unwrap_or(1).max(1),
            remote_refresh_interval_ms: 3_000,
            local_scan_interval_ms: 2_000,
            no_watch_local: true,
            run_once: true,
            ui_bind: None,
        };

        if options.local_tree_uri.is_some() {
            run_saf_folder_agent_with_control(&options, Arc::new(AtomicBool::new(true)), None)
        } else {
            run_folder_agent(&options)
        }
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust runFolderSyncOnce failed: {err:#}"));
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_startContinuousFolderSync(
    mut env: JNIEnv,
    _class: JClass,
    profile_id: JString,
    label: JString,
    connection_input: JString,
    local_folder: JString,
    local_tree_uri: jstring,
    prefix: jstring,
    depth: jint,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) {
    let result = (|| -> Result<()> {
        let profile_id: String = env.get_string(&profile_id)?.into();
        let label: String = env.get_string(&label)?.into();
        let connection_input: String = env.get_string(&connection_input)?.into();
        let local_folder: String = env.get_string(&local_folder)?.into();
        let local_tree_uri = optional_jstring(&mut env, local_tree_uri)?;
        let prefix = optional_jstring(&mut env, prefix)?;
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let (server_base_url, client_bootstrap_json) = split_connection_input(connection_input)?;
        initialize_android_preferences_bridge(&mut env)?;

        if local_tree_uri.is_some() {
            initialize_android_saf_bridge(&mut env)?;
        }

        let options = FolderAgentRuntimeOptions {
            root_dir: PathBuf::from(local_folder),
            state_root_dir: Some(android_folder_sync_state_root()?),
            local_tree_uri,
            server_base_url,
            client_bootstrap_json,
            server_ca_pem,
            client_identity_json,
            prefix,
            depth: usize::try_from(depth).unwrap_or(1).max(1),
            remote_refresh_interval_ms: 3_000,
            local_scan_interval_ms: 2_000,
            no_watch_local: false,
            run_once: false,
            ui_bind: None,
        };

        folder_sync_manager()
            .lock()
            .map_err(|_| anyhow::anyhow!("folder sync manager lock poisoned"))?
            .start_profile(profile_id, label, options)
    })();

    if let Err(err) = result {
        throw_java_error(
            &mut env,
            format!("rust startContinuousFolderSync failed: {err:#}"),
        );
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_stopContinuousFolderSync(
    mut env: JNIEnv,
    _class: JClass,
    profile_id: JString,
) {
    let result = (|| -> Result<()> {
        let profile_id: String = env.get_string(&profile_id)?.into();
        folder_sync_manager()
            .lock()
            .map_err(|_| anyhow::anyhow!("folder sync manager lock poisoned"))?
            .stop_profile(&profile_id);
        Ok(())
    })();

    if let Err(err) = result {
        throw_java_error(
            &mut env,
            format!("rust stopContinuousFolderSync failed: {err:#}"),
        );
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_stopAllContinuousFolderSync(
    mut env: JNIEnv,
    _class: JClass,
) {
    let result = (|| -> Result<()> {
        folder_sync_manager()
            .lock()
            .map_err(|_| anyhow::anyhow!("folder sync manager lock poisoned"))?
            .stop_all();
        Ok(())
    })();

    if let Err(err) = result {
        throw_java_error(
            &mut env,
            format!("rust stopAllContinuousFolderSync failed: {err:#}"),
        );
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_getContinuousFolderSyncStatus(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    match current_folder_sync_status_json() {
        Ok(json) => match env.new_string(json) {
            Ok(value) => value.into_raw(),
            Err(err) => {
                throw_java_error(
                    &mut env,
                    format!(
                        "rust getContinuousFolderSyncStatus failed to create java string: {err:#}"
                    ),
                );
                std::ptr::null_mut()
            }
        },
        Err(err) => {
            throw_java_error(
                &mut env,
                format!("rust getContinuousFolderSyncStatus failed: {err:#}"),
            );
            std::ptr::null_mut()
        }
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_hasContinuousFolderSyncActive(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    let active = folder_sync_manager()
        .lock()
        .ok()
        .map(|manager| !manager.runs.is_empty())
        .unwrap_or(false);
    if active { 1 } else { 0 }
}
