#![allow(unsafe_code)]

use anyhow::{Context, Result};
use client_sdk::IronMeshClient;
use common::content_fingerprint::FingerprintingReader;
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use serde::Deserialize;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use sync_agent_core::{
    FolderAgentLocalBackend, FolderAgentRuntimeOptions, FolderAgentStatusCallback,
    LocalEntryKind, LocalEntryState, LocalTreeScanProgress, LocalTreeState, PathScope,
    run_folder_agent_with_backend_control,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidSafSnapshotEntry {
    path: String,
    kind: String,
    size_bytes: u64,
    modified_unix_ms: u128,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidSafTreeScanProgress {
    scanned_entry_count: u64,
    scanned_directory_count: u64,
    pending_directory_count: u64,
    current_path: Option<String>,
}

struct AndroidSafBridgeState {
    vm: JavaVM,
    class: GlobalRef,
}

static ANDROID_SAF_BRIDGE_STATE: OnceLock<AndroidSafBridgeState> = OnceLock::new();

const SAF_SCAN_PROGRESS_INTERVAL: Duration = Duration::from_millis(750);
const SAF_SCAN_PROGRESS_ENTRY_STRIDE: u64 = 256;
const SAF_SCAN_PROGRESS_POLL_INTERVAL: Duration = Duration::from_millis(150);

fn bridge_state() -> Result<&'static AndroidSafBridgeState> {
    ANDROID_SAF_BRIDGE_STATE
        .get()
        .ok_or_else(|| anyhow::anyhow!("android SAF bridge has not been initialized"))
}

pub(crate) fn initialize_backend_bridge(env: &mut JNIEnv) -> Result<()> {
    if ANDROID_SAF_BRIDGE_STATE.get().is_some() {
        return Ok(());
    }

    let vm = env
        .get_java_vm()
        .context("failed to capture Java VM for SAF bridge")?;
    let class = env
        .find_class("io/ironmesh/android/data/RustSafBridge")
        .context("failed to find RustSafBridge class")?;
    let global = env
        .new_global_ref(class)
        .context("failed to globalize RustSafBridge class")?;
    let _ = ANDROID_SAF_BRIDGE_STATE.set(AndroidSafBridgeState { vm, class: global });
    Ok(())
}

pub(crate) fn backend_identity_root(tree_uri: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    tree_uri.hash(&mut hasher);
    PathBuf::from(format!("/android-saf/{:016x}", hasher.finish()))
}

pub(crate) fn run_backend_with_control(
    options: &FolderAgentRuntimeOptions,
    running: Arc<AtomicBool>,
    status_callback: Option<FolderAgentStatusCallback>,
) -> Result<()> {
    let mut backend = AndroidSafBackend::default();
    run_folder_agent_with_backend_control(options, running, false, status_callback, &mut backend)
}

fn with_bridge_env<T>(
    f: impl for<'local> FnOnce(&mut JNIEnv<'local>, JClass<'local>) -> Result<T>,
) -> Result<T> {
    let state = bridge_state()?;
    let mut env = state
        .vm
        .attach_current_thread()
        .context("failed to attach SAF sync thread to JVM")?;
    let class_ref = env
        .new_local_ref(state.class.as_obj())
        .context("failed to create local SAF bridge class ref")?;
    let class = JClass::from(class_ref);
    f(&mut env, class)
}

fn optional_tree_uri(options: &FolderAgentRuntimeOptions) -> Result<&str> {
    options
        .local_tree_uri
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("SAF runtime requires a non-empty local_tree_uri"))
}

fn list_tree_snapshot_json(tree_uri: &str) -> Result<String> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let value = env
            .call_static_method(
                &class,
                "listTreeSnapshot",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(j_tree_uri.as_ref())],
            )
            .context("RustSafBridge.listTreeSnapshot failed")?
            .l()
            .context("RustSafBridge.listTreeSnapshot returned invalid value")?;
        let value = JString::from(value);
        let value: String = env
            .get_string(&value)
            .context("failed to decode SAF snapshot JSON")?
            .into();
        Ok(value)
    })
}

fn prepare_tree_observer(tree_uri: &str) -> Result<()> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        env.call_static_method(
            &class,
            "prepareTreeObserver",
            "(Ljava/lang/String;)V",
            &[JValue::Object(j_tree_uri.as_ref())],
        )
        .context("RustSafBridge.prepareTreeObserver failed")?;
        Ok(())
    })
}

fn release_tree_observer(tree_uri: &str) -> Result<()> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        env.call_static_method(
            &class,
            "releaseTreeObserver",
            "(Ljava/lang/String;)V",
            &[JValue::Object(j_tree_uri.as_ref())],
        )
        .context("RustSafBridge.releaseTreeObserver failed")?;
        Ok(())
    })
}

fn tree_change_version(tree_uri: &str) -> Result<u64> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let version = env
            .call_static_method(
                &class,
                "getTreeChangeVersion",
                "(Ljava/lang/String;)J",
                &[JValue::Object(j_tree_uri.as_ref())],
            )
            .context("RustSafBridge.getTreeChangeVersion failed")?
            .j()
            .context("RustSafBridge.getTreeChangeVersion returned invalid value")?;
        Ok(version.max(0) as u64)
    })
}

fn tree_scan_progress(tree_uri: &str) -> Result<Option<AndroidSafTreeScanProgress>> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let value = env
            .call_static_method(
                &class,
                "getTreeScanProgress",
                "(Ljava/lang/String;)Ljava/lang/String;",
                &[JValue::Object(j_tree_uri.as_ref())],
            )
            .context("RustSafBridge.getTreeScanProgress failed")?
            .l()
            .context("RustSafBridge.getTreeScanProgress returned invalid value")?;
        if value.is_null() {
            return Ok(None);
        }

        let value = JString::from(value);
        let value: String = env
            .get_string(&value)
            .context("failed to decode SAF scan progress JSON")?
            .into();
        let progress: AndroidSafTreeScanProgress =
            serde_json::from_str(&value).context("failed to parse SAF scan progress JSON")?;
        Ok(Some(progress))
    })
}

fn scan_saf_tree(tree_uri: &str) -> Result<LocalTreeState> {
    let snapshot_json = list_tree_snapshot_json(tree_uri)?;
    let entries: Vec<AndroidSafSnapshotEntry> =
        serde_json::from_str(&snapshot_json).context("failed to decode SAF snapshot JSON")?;
    let mut state = LocalTreeState::new();
    for entry in entries {
        let kind = match entry.kind.as_str() {
            "directory" => LocalEntryKind::Directory,
            _ => LocalEntryKind::File,
        };
        state.insert(
            entry.path,
            LocalEntryState {
                kind,
                size_bytes: entry.size_bytes,
                modified_unix_ms: entry.modified_unix_ms,
            },
        );
    }
    Ok(state)
}

struct AndroidSafObserverGuard {
    tree_uri: String,
}

impl AndroidSafObserverGuard {
    fn new(tree_uri: &str) -> Result<Self> {
        prepare_tree_observer(tree_uri)?;
        Ok(Self {
            tree_uri: tree_uri.to_string(),
        })
    }
}

impl Drop for AndroidSafObserverGuard {
    fn drop(&mut self) {
        let _ = release_tree_observer(&self.tree_uri);
    }
}

#[derive(Default)]
struct AndroidSafBackend {
    tree_uri: Option<String>,
    observer_guard: Option<AndroidSafObserverGuard>,
    last_observed_tree_change_version: u64,
    pending_tree_change_version: Option<u64>,
}

impl AndroidSafBackend {
    fn tree_uri(&self) -> Result<&str> {
        self.tree_uri
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("SAF backend has not been prepared"))
    }
}

impl FolderAgentLocalBackend for AndroidSafBackend {
    fn storage_mode_label(&self, _options: &FolderAgentRuntimeOptions) -> &'static str {
        "android-saf"
    }

    fn watch_mode_label(&self, options: &FolderAgentRuntimeOptions) -> &'static str {
        if options.run_once {
            "not-watching"
        } else {
            "saf-observer+polling"
        }
    }

    fn local_tree_label(&self, _options: &FolderAgentRuntimeOptions) -> &'static str {
        "SAF tree"
    }

    fn file_hash_label(&self, _options: &FolderAgentRuntimeOptions) -> &'static str {
        "SAF file"
    }

    fn watch_idle_message(&self, _options: &FolderAgentRuntimeOptions) -> String {
        "Watching SAF tree for changes; local and remote state are aligned".to_string()
    }

    fn watch_after_local_sync_message(
        &self,
        _options: &FolderAgentRuntimeOptions,
        summary: &str,
    ) -> String {
        format!("Watching SAF tree for changes after local sync: {summary}")
    }

    fn state_identity_root(&self, options: &FolderAgentRuntimeOptions) -> Result<PathBuf> {
        Ok(backend_identity_root(optional_tree_uri(options)?))
    }

    fn prepare(&mut self, options: &FolderAgentRuntimeOptions) -> Result<()> {
        let tree_uri = optional_tree_uri(options)?.to_string();
        self.observer_guard = Some(AndroidSafObserverGuard::new(&tree_uri)?);
        self.tree_uri = Some(tree_uri);
        self.last_observed_tree_change_version = 0;
        self.pending_tree_change_version = None;
        Ok(())
    }

    fn scan_local_tree_with_progress(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        on_progress: &mut dyn FnMut(&LocalTreeScanProgress),
    ) -> Result<LocalTreeState> {
        let poll_tree_uri = self.tree_uri()?.to_string();
        let operation_tree_uri = poll_tree_uri.clone();
        let (result_tx, result_rx) = mpsc::sync_channel::<Result<LocalTreeState>>(1);
        let worker = thread::Builder::new()
            .name("ironmesh-saf-tree-scan".to_string())
            .spawn(move || {
                let _ = result_tx.send(scan_saf_tree(operation_tree_uri.as_str()));
            })
            .context("failed to spawn SAF tree scan worker")?;

        let mut last_reported_at = Instant::now() - SAF_SCAN_PROGRESS_INTERVAL;
        let mut last_reported_entry_count = 0u64;

        loop {
            match result_rx.recv_timeout(SAF_SCAN_PROGRESS_POLL_INTERVAL) {
                Ok(result) => {
                    let _ = worker.join();
                    return result;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let Ok(Some(progress)) = tree_scan_progress(&poll_tree_uri) else {
                        continue;
                    };

                    let enough_entries = progress.scanned_entry_count
                        >= last_reported_entry_count
                            .saturating_add(SAF_SCAN_PROGRESS_ENTRY_STRIDE);
                    let enough_time = last_reported_at.elapsed() >= SAF_SCAN_PROGRESS_INTERVAL;
                    if !enough_entries && !enough_time && progress.pending_directory_count != 0 {
                        continue;
                    }

                    last_reported_at = Instant::now();
                    last_reported_entry_count = progress.scanned_entry_count;
                    on_progress(&LocalTreeScanProgress {
                        scanned_entry_count: progress.scanned_entry_count,
                        scanned_directory_count: progress.scanned_directory_count,
                        pending_directory_count: progress.pending_directory_count,
                        current_path: progress.current_path.clone(),
                    });
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                    return Err(anyhow::anyhow!("SAF tree scan worker disconnected"));
                }
            }
        }
    }

    fn local_entry_state(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        relative_path: &str,
    ) -> Result<Option<LocalEntryState>> {
        stat_tree_entry(self.tree_uri()?, relative_path)
    }

    fn file_content_fingerprint(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        relative_path: &str,
    ) -> Result<String> {
        saf_file_content_fingerprint(self.tree_uri()?, relative_path)
    }

    fn ensure_local_directory(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        relative_path: &str,
    ) -> Result<()> {
        ensure_tree_directory(self.tree_uri()?, relative_path)
    }

    fn upload_local_file(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        client: &IronMeshClient,
        scope: &PathScope,
        relative_path: &str,
        size_bytes: u64,
    ) -> Result<String> {
        upload_saf_file(self.tree_uri()?, client, scope, relative_path, size_bytes)
    }

    fn download_remote_file(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        client: &IronMeshClient,
        local_relative_path: &str,
        remote_key: &str,
    ) -> Result<()> {
        download_remote_file_to_saf(self.tree_uri()?, client, local_relative_path, remote_key)
    }

    fn remove_local_path(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
        relative_path: &str,
    ) -> Result<()> {
        delete_tree_path(self.tree_uri()?, relative_path).map(|_| ())
    }

    fn start_local_change_monitor(&mut self, options: &FolderAgentRuntimeOptions) -> Result<()> {
        if options.run_once {
            self.last_observed_tree_change_version = 0;
            self.pending_tree_change_version = None;
            return Ok(());
        }

        self.last_observed_tree_change_version = tree_change_version(self.tree_uri()?).unwrap_or(0);
        self.pending_tree_change_version = None;
        Ok(())
    }

    fn local_change_hint_pending(&mut self, options: &FolderAgentRuntimeOptions) -> Result<bool> {
        if options.run_once {
            return Ok(false);
        }

        let current_version =
            tree_change_version(self.tree_uri()?).unwrap_or(self.last_observed_tree_change_version);
        if current_version != self.last_observed_tree_change_version {
            self.pending_tree_change_version = Some(current_version);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn acknowledge_local_change_hint(
        &mut self,
        _options: &FolderAgentRuntimeOptions,
    ) -> Result<()> {
        let fallback = self
            .pending_tree_change_version
            .unwrap_or(self.last_observed_tree_change_version);
        self.last_observed_tree_change_version =
            tree_change_version(self.tree_uri()?).unwrap_or(fallback);
        self.pending_tree_change_version = None;
        Ok(())
    }
}

fn open_tree_input_stream<'local>(
    env: &mut JNIEnv<'local>,
    class: &JClass<'local>,
    tree_uri: &str,
    relative_path: &str,
) -> Result<JObject<'local>> {
    let j_tree_uri = env
        .new_string(tree_uri)
        .context("failed to allocate tree URI string")?;
    let j_relative_path = env
        .new_string(relative_path)
        .context("failed to allocate relative path string")?;
    env.call_static_method(
        class,
        "openTreeFileInput",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/io/InputStream;",
        &[
            JValue::Object(j_tree_uri.as_ref()),
            JValue::Object(j_relative_path.as_ref()),
        ],
    )
    .context("RustSafBridge.openTreeFileInput failed")?
    .l()
    .context("RustSafBridge.openTreeFileInput returned invalid value")
}

fn open_tree_output_stream<'local>(
    env: &mut JNIEnv<'local>,
    class: &JClass<'local>,
    tree_uri: &str,
    relative_path: &str,
) -> Result<JObject<'local>> {
    let j_tree_uri = env
        .new_string(tree_uri)
        .context("failed to allocate tree URI string")?;
    let j_relative_path = env
        .new_string(relative_path)
        .context("failed to allocate relative path string")?;
    env.call_static_method(
        class,
        "openTreeFileOutput",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/io/OutputStream;",
        &[
            JValue::Object(j_tree_uri.as_ref()),
            JValue::Object(j_relative_path.as_ref()),
        ],
    )
    .context("RustSafBridge.openTreeFileOutput failed")?
    .l()
    .context("RustSafBridge.openTreeFileOutput returned invalid value")
}

fn stat_tree_path_json(tree_uri: &str, relative_path: &str) -> Result<Option<String>> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let j_relative_path = env
            .new_string(relative_path)
            .context("failed to allocate relative path string")?;
        let value = env
            .call_static_method(
                &class,
                "statTreePath",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                &[
                    JValue::Object(j_tree_uri.as_ref()),
                    JValue::Object(j_relative_path.as_ref()),
                ],
            )
            .context("RustSafBridge.statTreePath failed")?
            .l()
            .context("RustSafBridge.statTreePath returned invalid value")?;
        if value.is_null() {
            return Ok(None);
        }

        let value = JString::from(value);
        let value: String = env
            .get_string(&value)
            .context("failed to decode SAF stat JSON")?
            .into();
        Ok(Some(value))
    })
}

fn stat_tree_entry(tree_uri: &str, relative_path: &str) -> Result<Option<LocalEntryState>> {
    let Some(stat_json) = stat_tree_path_json(tree_uri, relative_path)? else {
        return Ok(None);
    };

    let entry: AndroidSafSnapshotEntry =
        serde_json::from_str(&stat_json).context("failed to decode SAF stat JSON")?;
    let kind = match entry.kind.as_str() {
        "directory" => LocalEntryKind::Directory,
        _ => LocalEntryKind::File,
    };

    Ok(Some(LocalEntryState {
        kind,
        size_bytes: entry.size_bytes,
        modified_unix_ms: entry.modified_unix_ms,
    }))
}

fn ensure_tree_directory(tree_uri: &str, relative_path: &str) -> Result<()> {
    if relative_path.trim().is_empty() {
        return Ok(());
    }

    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let j_relative_path = env
            .new_string(relative_path)
            .context("failed to allocate relative path string")?;
        env.call_static_method(
            &class,
            "ensureTreeDirectory",
            "(Ljava/lang/String;Ljava/lang/String;)V",
            &[
                JValue::Object(j_tree_uri.as_ref()),
                JValue::Object(j_relative_path.as_ref()),
            ],
        )
        .context("RustSafBridge.ensureTreeDirectory failed")?;
        Ok(())
    })
}

fn delete_tree_path(tree_uri: &str, relative_path: &str) -> Result<bool> {
    with_bridge_env(|env, class| {
        let j_tree_uri = env
            .new_string(tree_uri)
            .context("failed to allocate tree URI string")?;
        let j_relative_path = env
            .new_string(relative_path)
            .context("failed to allocate relative path string")?;
        env.call_static_method(
            &class,
            "deleteTreePath",
            "(Ljava/lang/String;Ljava/lang/String;)Z",
            &[
                JValue::Object(j_tree_uri.as_ref()),
                JValue::Object(j_relative_path.as_ref()),
            ],
        )
        .context("RustSafBridge.deleteTreePath failed")?
        .z()
        .context("RustSafBridge.deleteTreePath returned invalid value")
    })
}

struct JavaInputStreamReader<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    input_stream: JObject<'local>,
    java_buffer: jni::objects::JByteArray<'local>,
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
        let byte_slice = unsafe {
            std::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut jni::sys::jbyte, read)
        };
        self.env
            .get_byte_array_region(&self.java_buffer, 0, byte_slice)
            .map_err(|err| std::io::Error::other(err.to_string()))?;
        Ok(read)
    }
}

impl Drop for JavaInputStreamReader<'_, '_> {
    fn drop(&mut self) {
        let _ = self
            .env
            .call_method(&self.input_stream, "close", "()V", &[]);
    }
}

struct JavaOutputStreamWriter<'env, 'local> {
    env: &'env mut JNIEnv<'local>,
    output_stream: JObject<'local>,
    java_buffer: jni::objects::JByteArray<'local>,
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
            let byte_slice = unsafe {
                std::slice::from_raw_parts(chunk.as_ptr() as *const jni::sys::jbyte, chunk.len())
            };
            self.env
                .set_byte_array_region(&self.java_buffer, 0, byte_slice)
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

impl Drop for JavaOutputStreamWriter<'_, '_> {
    fn drop(&mut self) {
        let _ = self
            .env
            .call_method(&self.output_stream, "flush", "()V", &[]);
        let _ = self
            .env
            .call_method(&self.output_stream, "close", "()V", &[]);
    }
}

fn upload_saf_file(
    tree_uri: &str,
    client: &IronMeshClient,
    scope: &PathScope,
    relative_path: &str,
    size_bytes: u64,
) -> Result<String> {
    let remote_key = scope.local_to_remote(relative_path).ok_or_else(|| {
        anyhow::anyhow!("refusing to upload local root without concrete scoped path")
    })?;

    with_bridge_env(|env, class| {
        let input_stream = open_tree_input_stream(env, &class, tree_uri, relative_path)?;
        let mut reader = JavaInputStreamReader::new(env, input_stream)?;
        let mut fingerprinting_reader = FingerprintingReader::new(&mut reader, size_bytes);
        client
            .put_large_aware_reader(remote_key.clone(), &mut fingerprinting_reader, size_bytes)
            .with_context(|| {
                format!("failed to upload local file {relative_path} to {remote_key}")
            })?;
        fingerprinting_reader.finish()
    })
}

fn saf_file_content_fingerprint(tree_uri: &str, relative_path: &str) -> Result<String> {
    let entry = stat_tree_entry(tree_uri, relative_path)?
        .ok_or_else(|| anyhow::anyhow!("missing SAF file {relative_path}"))?;
    anyhow::ensure!(
        entry.kind == LocalEntryKind::File,
        "refusing to fingerprint non-file SAF path {relative_path}"
    );

    with_bridge_env(|env, class| {
        let input_stream = open_tree_input_stream(env, &class, tree_uri, relative_path)?;
        let mut reader = JavaInputStreamReader::new(env, input_stream)?;
        let mut fingerprinting_reader =
            FingerprintingReader::new(&mut reader, entry.size_bytes);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = fingerprinting_reader
                .read(&mut buffer)
                .with_context(|| {
                    format!("failed to read SAF file for fingerprinting {relative_path}")
                })?;
            if read == 0 {
                break;
            }
        }
        fingerprinting_reader.finish()
    })
}

fn download_remote_file_to_saf(
    tree_uri: &str,
    client: &IronMeshClient,
    local_relative_path: &str,
    remote_key: &str,
) -> Result<()> {
    let staging_root = crate::android_download_stage_root("saf-sync-downloads", tree_uri)?;
    with_bridge_env(|env, class| {
        let output_stream = open_tree_output_stream(env, &class, tree_uri, local_relative_path)?;
        let mut writer = JavaOutputStreamWriter::new(env, output_stream)?;
        client
            .download_to_writer_resumable_staged(remote_key, None, None, &mut writer, &staging_root)
            .with_context(|| format!("failed to download remote file {remote_key}"))?;
        writer
            .flush()
            .with_context(|| format!("failed to flush downloaded SAF file {local_relative_path}"))?;
        Ok(())
    })
}
