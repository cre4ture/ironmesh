mod saf_sync;

use anyhow::{Context, Result};
use bytes::Bytes;
use client_sdk::{
    BootstrapEnrollmentResult, ClientIdentityMaterial, ClientNode, ConnectionBootstrap,
    IronMeshClient, build_reqwest_client_from_pem, build_signed_request_headers,
};
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jbyte, jbyteArray, jint, jstring};
use reqwest::Method;
use reqwest::Url;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use sync_agent_core::{
    FolderAgentRuntimeOptions, FolderAgentRuntimeStatus, FolderAgentStatusCallback,
    build_configured_client, run_folder_agent, run_folder_agent_with_control,
};
use tokio::task::JoinHandle;

use crate::saf_sync::{initialize_android_saf_bridge, run_saf_folder_agent_with_control};

fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }

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

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AndroidFolderSyncServiceStatus {
    service_state: String,
    service_message: String,
    profiles: Vec<AndroidFolderSyncProfileStatus>,
    updated_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct AndroidFolderSyncProfileStatus {
    profile_id: String,
    label: String,
    state: String,
    message: String,
    updated_unix_ms: u64,
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
                profiles: Vec::new(),
                updated_unix_ms: now_unix_ms(),
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

        update_profile_status(
            &self.status,
            AndroidFolderSyncProfileStatus {
                profile_id: profile_id.clone(),
                label: label.clone(),
                state: "starting".to_string(),
                message: "Starting continuous sync".to_string(),
                updated_unix_ms: now_unix_ms(),
            },
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
                    AndroidFolderSyncProfileStatus {
                        profile_id: callback_profile_id.clone(),
                        label: callback_label.clone(),
                        state: status.state,
                        message: status.message,
                        updated_unix_ms: status.updated_unix_ms,
                    },
                );
                refresh_service_summary(&status_store);
            });

        let thread_profile_id = profile_id.clone();
        let thread_label = label.clone();
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
                    update_profile_status(
                        &status_store,
                        AndroidFolderSyncProfileStatus {
                            profile_id: thread_profile_id,
                            label: thread_label,
                            state: "error".to_string(),
                            message: format!("{error:#}"),
                            updated_unix_ms: now_unix_ms(),
                        },
                    );
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
            status.profiles.clear();
            status.service_state = "stopped".to_string();
            status.service_message = "Continuous sync is stopped".to_string();
            status.updated_unix_ms = now_unix_ms();
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
        let active_profiles = status
            .profiles
            .iter()
            .filter(|profile| profile.state != "stopped")
            .count();
        let has_error = status
            .profiles
            .iter()
            .any(|profile| profile.state == "error");
        let has_syncing = status
            .profiles
            .iter()
            .any(|profile| profile.state == "syncing");

        status.service_state = if active_profiles == 0 {
            "stopped".to_string()
        } else if has_error {
            "error".to_string()
        } else if has_syncing {
            "syncing".to_string()
        } else {
            "running".to_string()
        };
        status.service_message = if active_profiles == 0 {
            "Continuous sync is stopped".to_string()
        } else if has_error {
            format!("Continuous sync has errors across {active_profiles} profile(s)")
        } else if has_syncing {
            format!("Continuous sync is active for {active_profiles} profile(s)")
        } else {
            format!("Watching {active_profiles} profile(s)")
        };
        status.updated_unix_ms = now_unix_ms();
    }
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

fn optional_jstring(env: &mut JNIEnv, value: jstring) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }

    let value = unsafe { JString::from_raw(value) };
    let value: String = env.get_string(&value)?.into();
    Ok(Some(value))
}

fn as_jbyte_slice(bytes: &[u8]) -> &[jbyte] {
    unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const jbyte, bytes.len()) }
}

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

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn url_path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

#[derive(Debug, Clone)]
struct ResolvedDirectConnectionTarget {
    server_base_url: String,
    server_ca_pem: Option<String>,
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

fn resolve_direct_connection_target(
    connection_input: impl Into<String>,
    server_ca_pem: Option<String>,
) -> Result<ResolvedDirectConnectionTarget> {
    let server_ca_pem = normalize_optional_string(server_ca_pem);
    let (server_base_url, client_bootstrap_json) = split_connection_input(connection_input)?;
    if let Some(server_base_url) = server_base_url {
        return Ok(ResolvedDirectConnectionTarget {
            server_base_url,
            server_ca_pem,
        });
    }

    let bootstrap_json =
        client_bootstrap_json.ok_or_else(|| anyhow::anyhow!("missing connection input"))?;
    let mut bootstrap = ConnectionBootstrap::from_json_str(&bootstrap_json)
        .context("failed to parse android connection bootstrap JSON")?;
    if let Some(server_ca_pem) = server_ca_pem.as_ref() {
        bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
    }
    let resolved = bootstrap
        .resolve_direct_http_target_blocking()
        .context("failed to resolve direct public API target from android bootstrap")?;
    Ok(ResolvedDirectConnectionTarget {
        server_base_url: resolved.server_base_url,
        server_ca_pem: resolved.server_ca_pem.or(server_ca_pem),
    })
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
        let bootstrap = ConnectionBootstrap::from_json_str(&bootstrap_json)?;
        let enrolled: BootstrapEnrollmentResult =
            bootstrap.enroll_blocking(device_id.as_deref(), label.as_deref())?;
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
        let rt = runtime()?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        let bytes = rt
            .block_on(client.get_with_selector(key, snapshot.as_deref(), version.as_deref()))?
            .to_vec();
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
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_android_data_RustClientBridge_streamPutObject<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    connection_input: JString<'local>,
    key: JString<'local>,
    input_stream: JObject<'local>,
    server_ca_pem: jstring,
    client_identity_json: jstring,
) -> jint {
    let result = (|| -> Result<jint> {
        let connection_input: String = env.get_string(&connection_input)?.into();
        let key: String = env.get_string(&key)?.into();
        let server_ca_pem = optional_jstring(&mut env, server_ca_pem)?;
        let client_identity_json = optional_jstring(&mut env, client_identity_json)?;
        let mut reader = JavaInputStreamReader::new(&mut env, input_stream)?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        let report = client.put_chunked_reader(key, &mut reader)?;
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
        let mut writer = JavaOutputStreamWriter::new(&mut env, output_stream)?;
        let client = configured_client_node(connection_input, server_ca_pem, client_identity_json)?;
        client.get_with_selector_writer(key, snapshot.as_deref(), version.as_deref(), &mut writer)
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust streamObjectTo failed: {err:#}"));
    }
}

/// # Safety
/// This function is intended to be called from Java via JNI.
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
        let resolved_target =
            resolve_direct_connection_target(connection_input, server_ca_pem.clone())
                .context("relative streaming requires a direct public API endpoint")?;
        let base = Url::parse(&resolved_target.server_base_url)
            .context("invalid direct base URL for relative stream")?;
        let target = base
            .join(&relative_url)
            .with_context(|| format!("failed to resolve relative URL {relative_url}"))?;
        let client = build_reqwest_client_from_pem(resolved_target.server_ca_pem.as_deref())?;
        let client_identity = parse_client_identity_json(client_identity_json)?;
        let mut request = client.get(target.clone());
        if let Some(identity) = client_identity.as_ref() {
            let signed_headers = build_signed_request_headers(
                identity,
                Method::GET.as_str(),
                &url_path_and_query(&target),
                now_unix_secs(),
                None,
            )?;
            request = signed_headers.apply_to_reqwest(request);
        }

        let rt = runtime()?;
        let response = rt.block_on(async {
            request
                .send()
                .await
                .context("failed to request relative URL")?
                .error_for_status()
                .context("relative URL request returned non-success status")
        })?;

        let body = rt.block_on(async {
            response
                .bytes()
                .await
                .context("failed reading relative URL response body")
        })?;
        writer
            .write_all(&body)
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

        if local_tree_uri.is_some() {
            initialize_android_saf_bridge(&mut env)?;
        }

        let options = FolderAgentRuntimeOptions {
            root_dir: PathBuf::from(local_folder),
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

        if local_tree_uri.is_some() {
            initialize_android_saf_bridge(&mut env)?;
        }

        let options = FolderAgentRuntimeOptions {
            root_dir: PathBuf::from(local_folder),
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
