use anyhow::{Context, Result};
use client_sdk::{
    IronMeshClient, RemoteSnapshotFetcher, RemoteSnapshotPoller, RemoteSnapshotScope,
    build_http_client_from_pem, normalize_server_base_url,
};
use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::{JNIEnv, JavaVM};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sync_agent_core::{
    FolderAgentRuntimeOptions, FolderAgentRuntimeStatus, FolderAgentStatusCallback, LocalEntryKind,
    LocalEntryState, LocalTreeState, PathScope, RemoteTreeIndex, StartupStateStore,
    delete_remote_file, diff_local_trees, load_local_baseline_hashes_with_retries,
    load_local_baseline_with_retries, parent_directories, remote_file_hashes_by_local_path,
    remote_file_paths_by_local_path, startup_add_delete_conflicts,
    startup_baseline_state_from_remote_index,
};
use sync_core::{EntryKind, SyncSnapshot};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AndroidSafSnapshotEntry {
    path: String,
    kind: String,
    size_bytes: u64,
    modified_unix_ms: u128,
}

struct AndroidSafBridgeState {
    vm: JavaVM,
    class: GlobalRef,
}

fn bridge_state() -> Result<&'static AndroidSafBridgeState> {
    static STATE: OnceLock<AndroidSafBridgeState> = OnceLock::new();
    STATE
        .get()
        .ok_or_else(|| anyhow::anyhow!("android SAF bridge has not been initialized"))
}

pub(crate) fn initialize_android_saf_bridge(env: &mut JNIEnv) -> Result<()> {
    static STATE: OnceLock<AndroidSafBridgeState> = OnceLock::new();
    if STATE.get().is_some() {
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
    let _ = STATE.set(AndroidSafBridgeState { vm, class: global });
    Ok(())
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

fn configured_client(
    base_url: &str,
    options: &FolderAgentRuntimeOptions,
) -> Result<IronMeshClient> {
    let server_ca_pem = normalized_optional_string(options.server_ca_pem.as_deref());
    let auth_token = normalized_optional_string(options.auth_token.as_deref());
    build_http_client_from_pem(server_ca_pem.as_deref(), base_url, &auth_token)
}

fn normalized_optional_string(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn emit_status(
    callback: Option<&FolderAgentStatusCallback>,
    state: impl Into<String>,
    message: impl Into<String>,
) {
    let Some(callback) = callback else {
        return;
    };
    callback(FolderAgentRuntimeStatus {
        state: state.into(),
        message: message.into(),
        updated_unix_ms: now_unix_ms(),
    });
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn sample_local_paths(local_state: &LocalTreeState, limit: usize) -> String {
    let mut sample = local_state
        .keys()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if sample.is_empty() {
        sample.push_str("<none>");
    }
    sample
}

fn state_identity_root(tree_uri: &str) -> PathBuf {
    let mut hasher = DefaultHasher::new();
    tree_uri.hash(&mut hasher);
    PathBuf::from(format!("/android-saf/{:016x}", hasher.finish()))
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

fn delete_tree_path(tree_uri: &str, relative_path: &str) -> Result<()> {
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
        .context("RustSafBridge.deleteTreePath failed")?;
        Ok(())
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

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
        }
    }

    fn content_hash_hex(&self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        if read > 0 {
            self.hasher.update(&buf[..read]);
        }
        Ok(read)
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
        let mut hashing_reader = HashingReader::new(&mut reader);
        client
            .put_large_aware_reader(remote_key.clone(), &mut hashing_reader, size_bytes)
            .with_context(|| {
                format!("failed to upload local file {relative_path} to {remote_key}")
            })?;
        Ok(hashing_reader.content_hash_hex())
    })
}

fn saf_file_content_hash(tree_uri: &str, relative_path: &str) -> Result<String> {
    with_bridge_env(|env, class| {
        let input_stream = open_tree_input_stream(env, &class, tree_uri, relative_path)?;
        let mut reader = JavaInputStreamReader::new(env, input_stream)?;
        let mut hasher = blake3::Hasher::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = reader
                .read(&mut buffer)
                .with_context(|| format!("failed to read SAF file for hashing {relative_path}"))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().to_hex().to_string())
    })
}

fn ensure_remote_directory_marker(
    client: &IronMeshClient,
    scope: &PathScope,
    directory_path: &str,
) -> Result<()> {
    let Some(remote_directory) = scope.local_to_remote(directory_path) else {
        return Ok(());
    };

    let marker_key = format!("{remote_directory}/");
    let mut empty = std::io::Cursor::new(Vec::<u8>::new());
    client
        .put_large_aware_reader(marker_key, &mut empty, 0)
        .with_context(|| format!("failed to upload directory marker for {remote_directory}"))?;

    Ok(())
}

fn download_remote_file_to_saf(
    tree_uri: &str,
    client: &IronMeshClient,
    local_relative_path: &str,
    remote_key: &str,
) -> Result<()> {
    with_bridge_env(|env, class| {
        let output_stream = open_tree_output_stream(env, &class, tree_uri, local_relative_path)?;
        let mut writer = JavaOutputStreamWriter::new(env, output_stream)?;
        client
            .get_with_selector_writer(remote_key, None, None, &mut writer)
            .with_context(|| format!("failed to download remote file {remote_key}"))?;
        writer.flush().with_context(|| {
            format!("failed to flush downloaded SAF file {local_relative_path}")
        })?;
        Ok(())
    })
}

fn local_paths_to_preserve_on_startup_saf(
    tree_uri: &str,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    remote_hashes: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut preserve = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match saf_file_content_hash(tree_uri, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash SAF file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
            continue;
        };

        if previous != entry_state {
            if let Some(remote_hash) = remote_hashes.get(path) {
                match saf_file_content_hash(tree_uri, path) {
                    Ok(local_hash) if local_hash == *remote_hash => continue,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!(
                            "startup-state: failed to hash SAF file {path}: {error}; preserving local bytes"
                        );
                    }
                }
            }
            preserve.insert(path.clone());
        }
    }

    preserve
}

fn startup_remote_delete_wins_paths_saf(
    tree_uri: &str,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_files: &BTreeSet<String>,
    preserve_local_files: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut delete_wins = BTreeSet::new();

    for (path, entry_state) in local_state {
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }
        if remote_files.contains(path) {
            continue;
        }
        let Some(previous) = baseline.and_then(|state| state.get(path)) else {
            continue;
        };

        if previous == entry_state {
            delete_wins.insert(path.clone());
            continue;
        }

        if preserve_local_files.contains(path) {
            let Some(expected_hash) = baseline_hashes.get(path) else {
                continue;
            };
            match saf_file_content_hash(tree_uri, path) {
                Ok(local_hash) if local_hash == *expected_hash => {
                    delete_wins.insert(path.clone());
                }
                Ok(_) => {}
                Err(error) => {
                    eprintln!(
                        "startup-state: failed to hash SAF file {path} for remote-delete check: {error}; preserving local bytes"
                    );
                }
            }
        }
    }

    delete_wins
}

fn startup_dual_modify_conflicts_saf(
    tree_uri: &str,
    local_state: &LocalTreeState,
    baseline: Option<&LocalTreeState>,
    baseline_hashes: &BTreeMap<String, String>,
    remote_hashes: &BTreeMap<String, String>,
    preserve_local_files: &BTreeSet<String>,
) -> Vec<sync_agent_core::StartupConflict> {
    let mut conflicts = Vec::new();

    for path in preserve_local_files {
        let Some(entry_state) = local_state.get(path) else {
            continue;
        };
        if entry_state.kind != LocalEntryKind::File {
            continue;
        }

        let Some(remote_hash) = remote_hashes.get(path) else {
            continue;
        };

        let local_hash = match saf_file_content_hash(tree_uri, path) {
            Ok(value) => value,
            Err(error) => {
                eprintln!(
                    "startup-state: failed to hash SAF file {path} for dual-modify check: {error}; treating as conflict"
                );
                let stored_baseline = baseline.and_then(|state| state.get(path));
                let reason = match stored_baseline {
                    None => Some("dual_modify_missing_baseline"),
                    Some(_) => match baseline_hashes.get(path) {
                        Some(baseline_hash) if baseline_hash != remote_hash => {
                            Some("dual_modify_conflict")
                        }
                        _ => None,
                    },
                };

                if let Some(reason) = reason {
                    conflicts.push(sync_agent_core::StartupConflict {
                        path: path.clone(),
                        reason: reason.to_string(),
                        details_json: serde_json::json!({
                            "policy": "keep_local_bytes",
                            "local_action": "upload_local",
                            "remote_action": "overwrite_possible",
                        })
                        .to_string(),
                        created_unix_ms: sync_agent_core::current_unix_ms(),
                    });
                }
                continue;
            }
        };

        let stored_baseline = baseline.and_then(|state| state.get(path));
        let reason = match stored_baseline {
            None => Some("dual_modify_missing_baseline"),
            Some(_) => match baseline_hashes.get(path) {
                Some(baseline_hash) if baseline_hash != remote_hash => Some("dual_modify_conflict"),
                _ => None,
            },
        };

        if local_hash != *remote_hash
            && let Some(reason) = reason
        {
            conflicts.push(sync_agent_core::StartupConflict {
                path: path.clone(),
                reason: reason.to_string(),
                details_json: serde_json::json!({
                    "policy": "keep_local_bytes",
                    "local_action": "upload_local",
                    "remote_action": "overwrite_possible",
                })
                .to_string(),
                created_unix_ms: sync_agent_core::current_unix_ms(),
            });
        }
    }

    conflicts
}

#[allow(clippy::too_many_arguments)]
fn apply_remote_snapshot_saf(
    tree_uri: &str,
    current_local_state: &LocalTreeState,
    client: &IronMeshClient,
    snapshot: &SyncSnapshot,
    changed_paths: Option<&[String]>,
    preserve_local_files: Option<&BTreeSet<String>>,
    scope: &PathScope,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
    remote_index: &mut RemoteTreeIndex,
) -> Result<LocalTreeState> {
    let mut next_index = RemoteTreeIndex::default();
    let mut entry_kinds: BTreeMap<String, (EntryKind, String)> = BTreeMap::new();

    for entry in &snapshot.remote {
        let remote_path = sync_agent_core::normalize_relative_path(&entry.path);
        let Some(local_path) = scope.remote_to_local(&remote_path) else {
            continue;
        };
        if local_path.is_empty() {
            continue;
        }

        match entry.kind {
            EntryKind::Directory => {
                next_index.directories.insert(local_path.clone());
            }
            EntryKind::File => {
                next_index.files.insert(local_path.clone());
            }
        }
        entry_kinds.insert(local_path, (entry.kind, remote_path));
    }

    match changed_paths {
        Some(changed_paths) => {
            let mut changed_local_paths = BTreeSet::new();
            for changed in changed_paths {
                let Some(path) = scope.remote_to_local(changed) else {
                    continue;
                };
                if path.is_empty() {
                    continue;
                }
                changed_local_paths.insert(path);
            }

            for path in &changed_local_paths {
                match entry_kinds.get(path.as_str()) {
                    Some((EntryKind::Directory, _)) => {
                        ensure_tree_directory(tree_uri, path)?;
                    }
                    Some((EntryKind::File, remote_key)) => {
                        download_remote_file_to_saf(tree_uri, client, path, remote_key)?;
                    }
                    None => {
                        delete_tree_path(tree_uri, path)?;
                        suppressed_uploads.remove(path);
                    }
                }
            }
            *remote_index = next_index;

            let scanned = scan_saf_tree(tree_uri)?;
            for path in changed_local_paths {
                if let Some(entry_state) = scanned.get(&path)
                    && entry_state.kind == LocalEntryKind::File
                {
                    suppressed_uploads.insert(path, entry_state.clone());
                }
            }
            Ok(scanned)
        }
        None => {
            for directory in &next_index.directories {
                ensure_tree_directory(tree_uri, directory)?;
            }

            for file in &next_index.files {
                let Some((EntryKind::File, remote_key)) = entry_kinds.get(file) else {
                    continue;
                };
                if preserve_local_files.is_some_and(|set| set.contains(file))
                    && current_local_state
                        .get(file)
                        .is_some_and(|entry| entry.kind == LocalEntryKind::File)
                {
                    continue;
                }
                download_remote_file_to_saf(tree_uri, client, file, remote_key)?;
            }

            *remote_index = next_index;

            let scanned = scan_saf_tree(tree_uri)?;
            for file in &remote_index.files {
                if let Some(entry_state) = scanned.get(file)
                    && entry_state.kind == LocalEntryKind::File
                {
                    suppressed_uploads.insert(file.clone(), entry_state.clone());
                }
            }
            Ok(scanned)
        }
    }
}

fn sync_local_changes_saf(
    tree_uri: &str,
    client: &IronMeshClient,
    local_state: &mut LocalTreeState,
    state_store: Option<&StartupStateStore>,
    scope: &PathScope,
    remote_index: &mut RemoteTreeIndex,
    suppressed_uploads: &mut BTreeMap<String, LocalEntryState>,
) -> Result<()> {
    let current = scan_saf_tree(tree_uri).context("failed to scan SAF tree")?;
    let diff = diff_local_trees(local_state, &current);

    for path in &diff.created_directories {
        if remote_index.directories.contains(path) {
            continue;
        }

        ensure_remote_directory_marker(client, scope, path)?;
        remote_index.directories.insert(path.clone());
        if let Some(store) = state_store
            && let Some(entry_state) = current.get(path)
        {
            store
                .upsert_baseline_entry(path, entry_state)
                .with_context(|| {
                    format!("failed to persist baseline directory entry for {path}")
                })?;
        }
    }

    for path in &diff.created_or_modified_files {
        let Some(entry_state) = current.get(path) else {
            continue;
        };

        if let Some(expected) = suppressed_uploads.get(path)
            && expected == entry_state
        {
            suppressed_uploads.remove(path);
            continue;
        }

        let content_hash = upload_saf_file(tree_uri, client, scope, path, entry_state.size_bytes)?;
        remote_index.files.insert(path.clone());
        for parent in parent_directories(path) {
            remote_index.directories.insert(parent);
        }
        if let Some(store) = state_store {
            store
                .upsert_baseline_entry_with_hash(path, entry_state, Some(content_hash.as_str()))
                .with_context(|| format!("failed to persist baseline file entry for {path}"))?;
        }
    }

    if !diff.deleted_paths.is_empty() {
        let mut deleted_paths = diff.deleted_paths.clone();
        deleted_paths.sort_by(|left, right| {
            right
                .matches('/')
                .count()
                .cmp(&left.matches('/').count())
                .then_with(|| right.cmp(left))
        });

        for path in deleted_paths {
            let Some(previous) = local_state.get(&path) else {
                continue;
            };

            if previous.kind != LocalEntryKind::File {
                suppressed_uploads.remove(&path);
                continue;
            }
            let known_remote_file =
                remote_index.files.contains(&path) || suppressed_uploads.contains_key(&path);
            if !known_remote_file {
                suppressed_uploads.remove(&path);
                continue;
            }

            delete_remote_file(client, scope, &path)?;
            suppressed_uploads.remove(&path);
            remote_index.files.remove(&path);
            if let Some(store) = state_store {
                store
                    .remove_baseline_entry(&path)
                    .with_context(|| format!("failed to remove baseline entry for {path}"))?;
            }
        }
    }

    *local_state = current;
    Ok(())
}

pub(crate) fn run_saf_folder_agent_with_control(
    options: &FolderAgentRuntimeOptions,
    running: Arc<AtomicBool>,
    status_callback: Option<FolderAgentStatusCallback>,
) -> Result<()> {
    let tree_uri = optional_tree_uri(options)?;
    let scope = PathScope::new(options.prefix.clone());
    let base_url = normalize_server_base_url(&options.server_base_url)?;
    let state_store =
        StartupStateStore::new(&state_identity_root(tree_uri), &scope, base_url.as_str());
    let client = configured_client(base_url.as_str(), options)?;
    let snapshot_scope = RemoteSnapshotScope::new(
        scope.remote_prefix().map(ToString::to_string),
        options.depth,
        None,
    );

    let prefix_label = options.prefix.as_deref().unwrap_or("<root>");
    emit_status(
        status_callback.as_ref(),
        "starting",
        format!(
            "Starting SAF folder sync runtime for prefix={prefix_label} root={} treeUri={tree_uri}",
            options.root_dir.display()
        ),
    );
    emit_status(
        status_callback.as_ref(),
        "starting",
        "Fetching initial remote snapshot",
    );

    let local_state_before_remote_sync =
        scan_saf_tree(tree_uri).context("failed to scan SAF tree before initial remote sync")?;
    emit_status(
        status_callback.as_ref(),
        "starting",
        format!(
            "Initial local SAF scan found {} path(s) under root={} sample=[{}]",
            local_state_before_remote_sync.len(),
            options.root_dir.display(),
            sample_local_paths(&local_state_before_remote_sync, 5)
        ),
    );

    let baseline_before_remote_sync =
        match load_local_baseline_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(state) => Some(state),
            Err(error) => {
                eprintln!("startup-state: failed to load sqlite baseline: {error}");
                state_store.quarantine_corrupt().ok();
                None
            }
        };
    let baseline_hashes_before_remote_sync = if baseline_before_remote_sync.is_some() {
        match load_local_baseline_hashes_with_retries(&state_store, 6, Duration::from_millis(100)) {
            Ok(hashes) => hashes,
            Err(error) => {
                eprintln!("startup-state: failed to load sqlite baseline hashes: {error}");
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };

    let initial_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope.clone());
    let initial_snapshot = initial_fetcher
        .fetch_snapshot_blocking()
        .context("failed to fetch initial remote snapshot")?;
    let remote_files_before_remote_sync =
        remote_file_paths_by_local_path(&initial_snapshot, &scope);
    let remote_hashes_before_remote_sync =
        remote_file_hashes_by_local_path(&initial_snapshot, &scope);
    let preserve_local_files = local_paths_to_preserve_on_startup_saf(
        tree_uri,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &remote_hashes_before_remote_sync,
    );
    let remote_delete_wins_paths = startup_remote_delete_wins_paths_saf(
        tree_uri,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &baseline_hashes_before_remote_sync,
        &remote_files_before_remote_sync,
        &preserve_local_files,
    );
    let mut startup_conflicts = startup_add_delete_conflicts(
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &remote_files_before_remote_sync,
        &preserve_local_files,
        &remote_delete_wins_paths,
    );
    startup_conflicts.extend(startup_dual_modify_conflicts_saf(
        tree_uri,
        &local_state_before_remote_sync,
        baseline_before_remote_sync.as_ref(),
        &baseline_hashes_before_remote_sync,
        &remote_hashes_before_remote_sync,
        &preserve_local_files,
    ));

    let mut remote_index = RemoteTreeIndex::default();
    let mut suppressed_uploads: BTreeMap<String, LocalEntryState> = BTreeMap::new();
    let mut local_state = apply_remote_snapshot_saf(
        tree_uri,
        &local_state_before_remote_sync,
        &client,
        &initial_snapshot,
        None,
        Some(&preserve_local_files),
        &scope,
        &mut suppressed_uploads,
        &mut remote_index,
    )?;
    for path in &remote_delete_wins_paths {
        delete_tree_path(tree_uri, path)?;
        suppressed_uploads.remove(path);
    }
    if !remote_delete_wins_paths.is_empty() {
        local_state = scan_saf_tree(tree_uri)
            .context("failed to rescan SAF tree after remote delete wins")?;
    }

    local_state = startup_baseline_state_from_remote_index(
        &local_state,
        &remote_index,
        &preserve_local_files,
    );
    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after remote apply during startup")?;

    sync_local_changes_saf(
        tree_uri,
        &client,
        &mut local_state,
        Some(&state_store),
        &scope,
        &mut remote_index,
        &mut suppressed_uploads,
    )?;

    state_store
        .persist_local_baseline(&local_state)
        .context("failed to persist sqlite baseline after startup reconciliation")?;
    state_store
        .persist_startup_conflicts(&startup_conflicts)
        .context("failed to persist startup conflicts")?;

    if options.run_once {
        emit_status(
            status_callback.as_ref(),
            "stopped",
            "Folder sync run completed",
        );
        return Ok(());
    }

    emit_status(
        status_callback.as_ref(),
        "running",
        "Initial sync complete; polling SAF tree for changes",
    );

    let refresh_interval = Duration::from_millis(options.remote_refresh_interval_ms.max(250));
    let local_scan_interval = Duration::from_millis(options.local_scan_interval_ms.max(250));

    let refresh_poller = RemoteSnapshotPoller::polling(refresh_interval);
    let refresh_fetcher = RemoteSnapshotFetcher::new(client.clone(), snapshot_scope);
    let (remote_tx, remote_rx) = mpsc::channel();
    let remote_running = running.clone();
    let remote_stop_signal = running.clone();
    let remote_thread = refresh_poller.spawn_fetcher_loop(
        remote_running,
        Some(initial_snapshot),
        refresh_fetcher,
        move |update| {
            if remote_tx.send(update).is_err() {
                remote_stop_signal.store(false, Ordering::SeqCst);
            }
        },
    );

    let mut next_local_scan = Instant::now() + local_scan_interval;

    while running.load(Ordering::SeqCst) {
        let mut baseline_dirty = false;
        while let Ok(update) = remote_rx.try_recv() {
            emit_status(
                status_callback.as_ref(),
                "syncing",
                format!("Applying {} remote change(s)", update.changed_paths.len()),
            );
            local_state = apply_remote_snapshot_saf(
                tree_uri,
                &local_state,
                &client,
                &update.snapshot,
                Some(&update.changed_paths),
                None,
                &scope,
                &mut suppressed_uploads,
                &mut remote_index,
            )?;
            baseline_dirty = true;
        }

        if Instant::now() >= next_local_scan {
            let previous_local_state = local_state.clone();
            emit_status(
                status_callback.as_ref(),
                "syncing",
                "Scanning SAF tree for changes",
            );
            sync_local_changes_saf(
                tree_uri,
                &client,
                &mut local_state,
                Some(&state_store),
                &scope,
                &mut remote_index,
                &mut suppressed_uploads,
            )?;
            if local_state != previous_local_state {
                baseline_dirty = true;
            }
            next_local_scan = Instant::now() + local_scan_interval;
            emit_status(
                status_callback.as_ref(),
                "running",
                "Polling SAF tree for changes",
            );
        }

        if baseline_dirty {
            state_store
                .persist_local_baseline(&local_state)
                .context("failed to persist sqlite baseline during SAF runtime")?;
        }

        thread::sleep(Duration::from_millis(250));
    }

    running.store(false, Ordering::SeqCst);
    let _ = remote_thread.join();
    emit_status(
        status_callback.as_ref(),
        "stopped",
        "Folder sync runtime stopped",
    );
    Ok(())
}
