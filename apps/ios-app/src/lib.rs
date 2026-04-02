use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, ObjectHeadInfo, StoreIndexEntry,
    VersionGraphSummary, normalize_server_base_url,
};
use common::StorageObjectMeta;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use tokio::runtime::{Builder, Runtime};

const FFI_OK: c_int = 0;
const FFI_ERR: c_int = 1;

pub struct IosStorageApp {
    runtime: Runtime,
    client: ClientNode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AppleItemKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppleListEntry {
    pub path: String,
    pub item_id: String,
    pub kind: AppleItemKind,
    pub entry_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_head_version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppleListResponse {
    pub prefix: String,
    pub depth: usize,
    pub entry_count: usize,
    pub entries: Vec<AppleListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleMetadataResponse {
    pub key: String,
    pub item_id: String,
    pub kind: AppleItemKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_object: Option<ObjectHeadInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_graph: Option<VersionGraphSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplePutResponse {
    pub meta: StorageObjectMeta,
    pub item_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_graph: Option<VersionGraphSummary>,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct IronmeshIosBytes {
    pub data: *mut u8,
    pub len: usize,
    pub capacity: usize,
}

impl IosStorageApp {
    pub fn new(connection_input: impl Into<String>) -> Result<Self> {
        Self::configured(connection_input, None, None)
    }

    pub fn configured(
        connection_input: impl Into<String>,
        server_ca_pem: Option<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        let connection_input = normalized_connection_input_string(connection_input)?;
        let server_ca_pem = normalize_optional_string(server_ca_pem);
        let client_identity_json = normalize_optional_string(client_identity_json);
        let client_identity = client_identity_json
            .as_deref()
            .map(ClientIdentityMaterial::from_json_str)
            .transpose()
            .context("failed to parse iOS client identity JSON")?;

        let client = if connection_input.starts_with('{') {
            let mut bootstrap = ConnectionBootstrap::from_json_str(&connection_input)
                .context("failed to parse iOS connection bootstrap JSON")?;
            if let Some(server_ca_pem) = server_ca_pem.as_ref() {
                bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
            }
            match client_identity.as_ref() {
                Some(identity) => bootstrap.build_client_with_identity(identity)?,
                None => bootstrap.build_client()?,
            }
        } else {
            match client_identity.as_ref() {
                Some(identity) => client_sdk::build_http_client_with_identity_from_pem(
                    server_ca_pem.as_deref(),
                    &connection_input,
                    identity,
                )?,
                None => client_sdk::build_http_client_from_pem(
                    server_ca_pem.as_deref(),
                    &connection_input,
                )?,
            }
        };

        Self::with_client(ClientNode::with_client(client))
    }

    pub fn configured_from_bootstrap(
        bootstrap_json: impl Into<String>,
        client_identity_json: Option<String>,
    ) -> Result<Self> {
        Self::configured(bootstrap_json, None, client_identity_json)
    }

    pub fn with_client(client: ClientNode) -> Result<Self> {
        Ok(Self {
            runtime: build_runtime()?,
            client,
        })
    }

    pub fn put(&self, key: impl Into<String>, data: Vec<u8>) -> Result<ApplePutResponse> {
        let key = key.into();
        self.runtime.block_on(self.put_async(key, data))
    }

    pub fn fetch(&self, key: impl AsRef<str>) -> Result<Vec<u8>> {
        let key = key.as_ref().to_string();
        self.runtime.block_on(self.fetch_async(key))
    }

    pub fn list(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<AppleListResponse> {
        self.runtime
            .block_on(self.list_async(prefix, depth, snapshot))
    }

    pub fn metadata(&self, key: impl AsRef<str>) -> Result<AppleMetadataResponse> {
        let key = key.as_ref().to_string();
        self.runtime.block_on(self.metadata_async(key))
    }

    pub fn delete_path(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref().to_string();
        self.runtime.block_on(self.client.delete_path(key))
    }

    pub fn move_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        self.runtime
            .block_on(self.client.rename_path(from_path, to_path, overwrite))
    }

    pub fn web_gui_html(&self) -> String {
        web_ui_backend::assets::app_html()
    }

    async fn put_async(&self, key: String, data: Vec<u8>) -> Result<ApplePutResponse> {
        let meta = self.client.put(key.clone(), Bytes::from(data)).await?;
        let version_graph = self.client.list_versions(&key).await?;
        let object_id = version_graph.as_ref().map(|graph| graph.object_id.clone());
        let item_id = apple_item_id_for_file(&key, object_id.as_deref());

        Ok(ApplePutResponse {
            meta,
            item_id,
            object_id,
            version_graph,
        })
    }

    async fn fetch_async(&self, key: String) -> Result<Vec<u8>> {
        Ok(self.client.get_cached_or_fetch(&key).await?.to_vec())
    }

    async fn list_async(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<AppleListResponse> {
        let response = self.client.store_index(prefix, depth, snapshot).await?;
        let mut entries = Vec::with_capacity(response.entries.len());

        for entry in response.entries {
            entries.push(self.enrich_store_index_entry(entry).await?);
        }

        Ok(AppleListResponse {
            prefix: response.prefix,
            depth: response.depth,
            entry_count: entries.len(),
            entries,
        })
    }

    async fn metadata_async(&self, key: String) -> Result<AppleMetadataResponse> {
        let version_graph = self.client.list_versions(&key).await?;
        let head_object = self.client.head_object(&key, None, None).await.ok();
        let object_id = version_graph.as_ref().map(|graph| graph.object_id.clone());
        let kind = apple_item_kind_for_key(&key);
        let item_id = match kind {
            AppleItemKind::Directory => apple_item_id_for_directory(&key),
            AppleItemKind::File => apple_item_id_for_file(&key, object_id.as_deref()),
        };

        Ok(AppleMetadataResponse {
            key,
            item_id,
            kind,
            object_id,
            head_object,
            version_graph,
        })
    }

    async fn enrich_store_index_entry(&self, entry: StoreIndexEntry) -> Result<AppleListEntry> {
        let kind = apple_item_kind_for_store_index_entry(&entry);
        let (object_id, preferred_head_version_id) = if matches!(kind, AppleItemKind::File) {
            match self.client.list_versions(&entry.path).await? {
                Some(version_graph) => (
                    Some(version_graph.object_id.clone()),
                    version_graph.preferred_head_version_id,
                ),
                None => (None, None),
            }
        } else {
            (None, None)
        };

        let item_id = match kind {
            AppleItemKind::Directory => apple_item_id_for_directory(&entry.path),
            AppleItemKind::File => apple_item_id_for_file(&entry.path, object_id.as_deref()),
        };

        Ok(AppleListEntry {
            path: entry.path,
            item_id,
            kind,
            entry_type: entry.entry_type,
            object_id,
            preferred_head_version_id,
            version: entry.version,
            content_hash: entry.content_hash,
            size_bytes: entry.size_bytes,
            modified_at_unix: entry.modified_at_unix,
            content_fingerprint: entry.content_fingerprint,
        })
    }
}

pub fn create_handle(
    connection_input: impl Into<String>,
    server_ca_pem: Option<String>,
    client_identity_json: Option<String>,
) -> Result<*mut c_void> {
    let facade = IosStorageApp::configured(connection_input, server_ca_pem, client_identity_json)?;
    Ok(Box::into_raw(Box::new(facade)) as *mut c_void)
}

pub fn free_handle(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }

    unsafe {
        drop(Box::from_raw(handle as *mut IosStorageApp));
    }
}

fn list_json(
    handle: *mut c_void,
    prefix: Option<&str>,
    depth: usize,
    snapshot: Option<&str>,
) -> Result<String> {
    let app = unsafe { handle_to_app(handle)? };
    serde_json::to_string(&app.list(prefix, depth, snapshot)?)
        .context("failed to serialize Apple list response")
}

fn metadata_json(handle: *mut c_void, key: impl AsRef<str>) -> Result<String> {
    let app = unsafe { handle_to_app(handle)? };
    serde_json::to_string(&app.metadata(key)?)
        .context("failed to serialize Apple metadata response")
}

fn fetch_bytes(handle: *mut c_void, key: impl AsRef<str>) -> Result<Vec<u8>> {
    let app = unsafe { handle_to_app(handle)? };
    app.fetch(key)
}

fn put_json(handle: *mut c_void, key: impl Into<String>, data: Vec<u8>) -> Result<String> {
    let app = unsafe { handle_to_app(handle)? };
    serde_json::to_string(&app.put(key, data)?).context("failed to serialize Apple put response")
}

fn delete_path(handle: *mut c_void, key: impl AsRef<str>) -> Result<()> {
    let app = unsafe { handle_to_app(handle)? };
    app.delete_path(key)
}

fn move_path(
    handle: *mut c_void,
    from_path: impl Into<String>,
    to_path: impl Into<String>,
    overwrite: bool,
) -> Result<()> {
    let app = unsafe { handle_to_app(handle)? };
    app.move_path(from_path, to_path, overwrite)
}

pub fn web_gui_html() -> String {
    web_ui_backend::assets::app_html()
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_create(
    connection_input: *const c_char,
    server_ca_pem: *const c_char,
    client_identity_json: *const c_char,
    out_error: *mut *mut c_char,
) -> *mut c_void {
    clear_error(out_error);
    let result = (|| -> Result<*mut c_void> {
        let connection_input = required_c_string(connection_input, "connection_input")?;
        let server_ca_pem = optional_c_string(server_ca_pem)?;
        let client_identity_json = optional_c_string(client_identity_json)?;
        create_handle(connection_input, server_ca_pem, client_identity_json)
    })();

    match result {
        Ok(handle) => handle,
        Err(err) => {
            write_error(out_error, err);
            ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_free(handle: *mut c_void) {
    free_handle(handle);
}

/// # Safety
///
/// `value` must be a pointer previously returned by this library via
/// `CString::into_raw`, and it must not be freed more than once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ironmesh_ios_string_free(value: *mut c_char) {
    if value.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(value));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_bytes_free(value: IronmeshIosBytes) {
    if value.data.is_null() && value.len == 0 && value.capacity == 0 {
        return;
    }

    unsafe {
        drop(Vec::from_raw_parts(value.data, value.len, value.capacity));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_list_json(
    handle: *mut c_void,
    prefix: *const c_char,
    depth: usize,
    snapshot: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_string_out(out_json);
    clear_error(out_error);
    run_ffi_string_result(out_json, out_error, || {
        let prefix = optional_c_string(prefix)?;
        let snapshot = optional_c_string(snapshot)?;
        list_json(handle, prefix.as_deref(), depth, snapshot.as_deref())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_metadata_json(
    handle: *mut c_void,
    key: *const c_char,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_string_out(out_json);
    clear_error(out_error);
    run_ffi_string_result(out_json, out_error, || {
        metadata_json(handle, required_c_string(key, "key")?)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_fetch_bytes(
    handle: *mut c_void,
    key: *const c_char,
    out_bytes: *mut IronmeshIosBytes,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_bytes_out(out_bytes);
    clear_error(out_error);
    run_ffi_bytes_result(out_bytes, out_error, || {
        let bytes = fetch_bytes(handle, required_c_string(key, "key")?)?;
        Ok(bytes)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_put_bytes(
    handle: *mut c_void,
    key: *const c_char,
    data: *const u8,
    len: usize,
    out_json: *mut *mut c_char,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_string_out(out_json);
    clear_error(out_error);
    run_ffi_string_result(out_json, out_error, || {
        let key = required_c_string(key, "key")?;
        let payload = raw_bytes_to_vec(data, len)?;
        put_json(handle, key, payload)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_delete_path(
    handle: *mut c_void,
    key: *const c_char,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    run_ffi_unit_result(out_error, || {
        delete_path(handle, required_c_string(key, "key")?)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn ironmesh_ios_facade_move_path(
    handle: *mut c_void,
    from_path: *const c_char,
    to_path: *const c_char,
    overwrite: c_int,
    out_error: *mut *mut c_char,
) -> c_int {
    clear_error(out_error);
    run_ffi_unit_result(out_error, || {
        move_path(
            handle,
            required_c_string(from_path, "from_path")?,
            required_c_string(to_path, "to_path")?,
            overwrite != 0,
        )
    })
}

fn build_runtime() -> Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to create iOS facade runtime")
}

unsafe fn handle_to_app<'a>(handle: *mut c_void) -> Result<&'a IosStorageApp> {
    if handle.is_null() {
        bail!("iOS facade handle is null");
    }

    Ok(unsafe { &*(handle as *mut IosStorageApp) })
}

fn apple_item_kind_for_store_index_entry(entry: &StoreIndexEntry) -> AppleItemKind {
    if entry.entry_type == "prefix" || entry.path.ends_with('/') {
        AppleItemKind::Directory
    } else {
        AppleItemKind::File
    }
}

fn apple_item_kind_for_key(key: &str) -> AppleItemKind {
    if key.trim().ends_with('/') {
        AppleItemKind::Directory
    } else {
        AppleItemKind::File
    }
}

fn apple_item_id_for_directory(path: &str) -> String {
    let normalized = normalize_item_path(path);
    if normalized.is_empty() {
        "dir:root".to_string()
    } else {
        format!("dir:path:{normalized}")
    }
}

fn apple_item_id_for_file(path: &str, object_id: Option<&str>) -> String {
    match object_id {
        Some(object_id) if !object_id.trim().is_empty() => format!("file:object:{object_id}"),
        _ => {
            let normalized = normalize_item_path(path);
            if normalized.is_empty() {
                "file:root".to_string()
            } else {
                format!("file:path:{normalized}")
            }
        }
    }
}

fn normalize_item_path(path: &str) -> String {
    path.trim().trim_matches('/').to_string()
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

fn normalized_connection_input_string(connection_input: impl Into<String>) -> Result<String> {
    let connection_input = connection_input.into();
    let trimmed = connection_input.trim();
    if trimmed.is_empty() {
        anyhow::bail!("iOS client requires a non-empty connection input");
    }

    if trimmed.starts_with('{') {
        return Ok(trimmed.to_string());
    }

    Ok(normalize_server_base_url(trimmed)?.to_string())
}

fn required_c_string(value: *const c_char, name: &str) -> Result<String> {
    let value = optional_c_string(value)?;
    value.ok_or_else(|| anyhow!("{name} pointer must not be null"))
}

fn optional_c_string(value: *const c_char) -> Result<Option<String>> {
    if value.is_null() {
        return Ok(None);
    }

    let c_str = unsafe { CStr::from_ptr(value) };
    let text = c_str
        .to_str()
        .context("C string contained invalid UTF-8")?
        .trim()
        .to_string();
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(text))
    }
}

fn raw_bytes_to_vec(data: *const u8, len: usize) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }

    if data.is_null() {
        bail!("byte buffer pointer must not be null when len > 0");
    }

    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    Ok(bytes.to_vec())
}

fn write_error(out_error: *mut *mut c_char, error: anyhow::Error) {
    if out_error.is_null() {
        return;
    }

    let message = error.to_string().replace('\0', " ");
    let c_string = CString::new(message).expect("sanitized error string should be valid");
    unsafe {
        *out_error = c_string.into_raw();
    }
}

fn clear_error(out_error: *mut *mut c_char) {
    if out_error.is_null() {
        return;
    }

    unsafe {
        *out_error = ptr::null_mut();
    }
}

fn clear_string_out(out_value: *mut *mut c_char) {
    if out_value.is_null() {
        return;
    }

    unsafe {
        *out_value = ptr::null_mut();
    }
}

fn clear_bytes_out(out_value: *mut IronmeshIosBytes) {
    if out_value.is_null() {
        return;
    }

    unsafe {
        *out_value = IronmeshIosBytes {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
    }
}

fn write_string(out_value: *mut *mut c_char, value: String) -> Result<()> {
    if out_value.is_null() {
        bail!("output string pointer must not be null");
    }

    let c_string = CString::new(value).context("output string contained an interior NUL")?;
    unsafe {
        *out_value = c_string.into_raw();
    }
    Ok(())
}

fn write_bytes(out_value: *mut IronmeshIosBytes, bytes: Vec<u8>) -> Result<()> {
    if out_value.is_null() {
        bail!("output byte buffer pointer must not be null");
    }

    let mut bytes = bytes;
    let value = IronmeshIosBytes {
        data: bytes.as_mut_ptr(),
        len: bytes.len(),
        capacity: bytes.capacity(),
    };
    std::mem::forget(bytes);

    unsafe {
        *out_value = value;
    }
    Ok(())
}

fn run_ffi_string_result<F>(out_value: *mut *mut c_char, out_error: *mut *mut c_char, f: F) -> c_int
where
    F: FnOnce() -> Result<String>,
{
    match f() {
        Ok(value) => match write_string(out_value, value) {
            Ok(()) => FFI_OK,
            Err(err) => {
                write_error(out_error, err);
                FFI_ERR
            }
        },
        Err(err) => {
            write_error(out_error, err);
            FFI_ERR
        }
    }
}

fn run_ffi_bytes_result<F>(
    out_value: *mut IronmeshIosBytes,
    out_error: *mut *mut c_char,
    f: F,
) -> c_int
where
    F: FnOnce() -> Result<Vec<u8>>,
{
    match f() {
        Ok(value) => match write_bytes(out_value, value) {
            Ok(()) => FFI_OK,
            Err(err) => {
                write_error(out_error, err);
                FFI_ERR
            }
        },
        Err(err) => {
            write_error(out_error, err);
            FFI_ERR
        }
    }
}

fn run_ffi_unit_result<F>(out_error: *mut *mut c_char, f: F) -> c_int
where
    F: FnOnce() -> Result<()>,
{
    match f() {
        Ok(()) => FFI_OK,
        Err(err) => {
            write_error(out_error, err);
            FFI_ERR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path, State};
    use axum::http::{HeaderValue, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post, put};
    use axum::{Json, Router};
    use client_sdk::{
        PreferredHeadReason, StoreIndexEntry, StoreIndexResponse, VersionConsistencyState,
        VersionRecordSummary,
    };
    use serde::Deserialize;
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct TestServerState {
        objects: Arc<Mutex<BTreeMap<String, TestObject>>>,
    }

    #[derive(Clone)]
    struct TestObject {
        bytes: Vec<u8>,
        object_id: String,
    }

    #[derive(Deserialize)]
    struct PathMutationRequest {
        from_path: String,
        to_path: String,
        overwrite: bool,
    }

    fn test_router(state: TestServerState) -> Router {
        Router::new()
            .route("/store/index", get(list_store_index))
            .route("/store/delete", post(delete_by_query))
            .route("/store/rename", post(rename_path))
            .route(
                "/store/{*key}",
                put(put_object)
                    .get(get_object)
                    .head(head_object)
                    .delete(delete_object),
            )
            .route("/versions/{*key}", get(list_versions))
            .with_state(state)
    }

    async fn put_object(
        State(state): State<TestServerState>,
        Path(key): Path<String>,
        body: axum::body::Bytes,
    ) -> impl IntoResponse {
        let mut objects = state.objects.lock().expect("lock poisoned");
        let object_id = objects
            .get(&key)
            .map(|existing| existing.object_id.clone())
            .unwrap_or_else(|| format!("object-{}", key.replace('/', "_")));
        objects.insert(
            key,
            TestObject {
                bytes: body.to_vec(),
                object_id,
            },
        );
        StatusCode::CREATED
    }

    async fn get_object(
        State(state): State<TestServerState>,
        Path(key): Path<String>,
    ) -> impl IntoResponse {
        let objects = state.objects.lock().expect("lock poisoned");
        match objects.get(&key) {
            Some(object) => (StatusCode::OK, object.bytes.clone()).into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn head_object(
        State(state): State<TestServerState>,
        Path(key): Path<String>,
    ) -> impl IntoResponse {
        let objects = state.objects.lock().expect("lock poisoned");
        match objects.get(&key) {
            Some(object) => {
                let mut response = StatusCode::OK.into_response();
                response.headers_mut().insert(
                    "x-ironmesh-object-size",
                    HeaderValue::from_str(&object.bytes.len().to_string()).expect("valid header"),
                );
                response.headers_mut().insert(
                    "content-length",
                    HeaderValue::from_str(&object.bytes.len().to_string()).expect("valid header"),
                );
                response
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn delete_object(
        State(state): State<TestServerState>,
        Path(key): Path<String>,
    ) -> impl IntoResponse {
        let mut objects = state.objects.lock().expect("lock poisoned");
        if objects.remove(&key).is_some() {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::NOT_FOUND
        }
    }

    async fn delete_by_query(
        State(state): State<TestServerState>,
        axum::extract::Query(query): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> impl IntoResponse {
        let Some(key) = query.get("key") else {
            return StatusCode::BAD_REQUEST.into_response();
        };
        let recursive = query
            .get("recursive")
            .map(|value| value == "true")
            .unwrap_or(false);
        let mut objects = state.objects.lock().expect("lock poisoned");
        let removed = if recursive && key.ends_with('/') {
            let prefix = key.trim_end_matches('/');
            let keys = objects
                .keys()
                .filter(|candidate| {
                    candidate == &key || candidate.starts_with(&format!("{prefix}/"))
                })
                .cloned()
                .collect::<Vec<_>>();
            let count = keys.len();
            for candidate in keys {
                objects.remove(&candidate);
            }
            count > 0
        } else {
            objects.remove(key).is_some()
        };
        if removed {
            StatusCode::NO_CONTENT.into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }

    async fn rename_path(
        State(state): State<TestServerState>,
        Json(request): Json<PathMutationRequest>,
    ) -> impl IntoResponse {
        let mut objects = state.objects.lock().expect("lock poisoned");
        if objects.contains_key(&request.to_path) && !request.overwrite {
            return StatusCode::CONFLICT.into_response();
        }
        let Some(object) = objects.remove(&request.from_path) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        objects.insert(request.to_path, object);
        StatusCode::NO_CONTENT.into_response()
    }

    async fn list_versions(
        State(state): State<TestServerState>,
        Path(key): Path<String>,
    ) -> impl IntoResponse {
        let objects = state.objects.lock().expect("lock poisoned");
        let Some(object) = objects.get(&key) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let response = VersionGraphSummary {
            key: key.clone(),
            object_id: object.object_id.clone(),
            preferred_head_version_id: Some(format!("version-{}", object.object_id)),
            preferred_head_reason: Some(PreferredHeadReason::ConfirmedPreferredOverProvisional),
            head_version_ids: vec![format!("version-{}", object.object_id)],
            versions: vec![VersionRecordSummary {
                version_id: format!("version-{}", object.object_id),
                logical_path: Some(key),
                parent_version_ids: Vec::new(),
                state: VersionConsistencyState::Confirmed,
                created_at_unix: 123,
                copied_from_object_id: None,
                copied_from_version_id: None,
                copied_from_path: None,
            }],
        };
        (StatusCode::OK, Json(response)).into_response()
    }

    async fn list_store_index(State(state): State<TestServerState>) -> impl IntoResponse {
        let objects = state.objects.lock().expect("lock poisoned");
        let mut prefixes = std::collections::BTreeSet::new();
        let mut entries = Vec::new();

        for (key, object) in objects.iter() {
            let parts: Vec<&str> = key.split('/').filter(|part| !part.is_empty()).collect();
            if parts.len() > 1 {
                for depth in 1..parts.len() {
                    prefixes.insert(format!("{}/", parts[..depth].join("/")));
                }
            }
            entries.push(StoreIndexEntry {
                path: key.clone(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: Some(format!("hash-{}", object.object_id)),
                size_bytes: Some(object.bytes.len() as u64),
                modified_at_unix: Some(123),
                content_fingerprint: Some(format!("fingerprint-{}", object.object_id)),
                media: None,
            });
        }

        for prefix in prefixes {
            entries.push(StoreIndexEntry {
                path: prefix,
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            });
        }

        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let response = StoreIndexResponse {
            prefix: String::new(),
            depth: 1,
            entry_count: entries.len(),
            entries,
        };
        (StatusCode::OK, Json(response)).into_response()
    }

    fn spawn_test_server() -> SocketAddr {
        let state = TestServerState::default();
        let app = test_router(state);
        let std_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("test server should bind");
        std_listener
            .set_nonblocking(true)
            .expect("listener should become nonblocking");
        let addr = std_listener
            .local_addr()
            .expect("listener should have address");

        std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("server runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("listener should convert");
                let _ = axum::serve(listener, app.into_make_service()).await;
            });
        });

        addr
    }

    fn create_handle_for_server(addr: SocketAddr) -> *mut c_void {
        let url = format!("http://{addr}");
        let url = CString::new(url).expect("url should be valid");
        let mut error = ptr::null_mut();
        let handle = ironmesh_ios_facade_create(url.as_ptr(), ptr::null(), ptr::null(), &mut error);
        if !error.is_null() {
            let message = unsafe { CStr::from_ptr(error).to_string_lossy().into_owned() };
            unsafe { ironmesh_ios_string_free(error) };
            panic!("failed to create facade: {message}");
        }
        handle
    }

    fn read_string(ptr: *mut c_char) -> String {
        unsafe {
            let value = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            ironmesh_ios_string_free(ptr);
            value
        }
    }

    fn read_bytes(value: IronmeshIosBytes) -> Vec<u8> {
        unsafe {
            let bytes = std::slice::from_raw_parts(value.data, value.len).to_vec();
            ironmesh_ios_bytes_free(value);
            bytes
        }
    }

    #[test]
    fn blocking_facade_round_trips_list_metadata_fetch_put_move_and_delete() {
        let addr = spawn_test_server();
        let handle = create_handle_for_server(addr);

        let payload = b"hello apple facade";
        let key = CString::new("docs/readme.txt").expect("key should be valid");
        let mut json_out = ptr::null_mut();
        let mut error_out = ptr::null_mut();
        let status = ironmesh_ios_facade_put_bytes(
            handle,
            key.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            &mut json_out,
            &mut error_out,
        );
        assert_eq!(status, FFI_OK);
        assert!(error_out.is_null());
        let put_response: ApplePutResponse =
            serde_json::from_str(&read_string(json_out)).expect("put response should parse");
        assert_eq!(put_response.meta.key, "docs/readme.txt");
        assert_eq!(put_response.meta.size_bytes, payload.len());
        assert!(put_response.object_id.is_some());

        let mut list_json = ptr::null_mut();
        let mut list_error = ptr::null_mut();
        let prefix = CString::new("docs/").expect("prefix should be valid");
        let snapshot = CString::new("").expect("empty snapshot is valid");
        let status = ironmesh_ios_facade_list_json(
            handle,
            prefix.as_ptr(),
            1,
            snapshot.as_ptr(),
            &mut list_json,
            &mut list_error,
        );
        assert_eq!(status, FFI_OK);
        assert!(list_error.is_null());
        let list_response: AppleListResponse =
            serde_json::from_str(&read_string(list_json)).expect("list response should parse");
        assert_eq!(list_response.entries.len(), 2);
        assert!(
            list_response.entries.iter().any(
                |entry| entry.path == "docs/" && matches!(entry.kind, AppleItemKind::Directory)
            )
        );
        assert!(
            list_response
                .entries
                .iter()
                .any(|entry| entry.path == "docs/readme.txt")
        );

        let mut metadata_json = ptr::null_mut();
        let mut metadata_error = ptr::null_mut();
        let status = ironmesh_ios_facade_metadata_json(
            handle,
            key.as_ptr(),
            &mut metadata_json,
            &mut metadata_error,
        );
        assert_eq!(status, FFI_OK);
        let metadata: AppleMetadataResponse =
            serde_json::from_str(&read_string(metadata_json)).expect("metadata should parse");
        assert_eq!(metadata.key, "docs/readme.txt");
        assert!(metadata.version_graph.is_some());
        assert!(metadata.head_object.is_some());

        let mut bytes_out = IronmeshIosBytes {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
        let mut fetch_error = ptr::null_mut();
        let status =
            ironmesh_ios_facade_fetch_bytes(handle, key.as_ptr(), &mut bytes_out, &mut fetch_error);
        assert_eq!(status, FFI_OK);
        assert!(fetch_error.is_null());
        assert_eq!(read_bytes(bytes_out), payload);

        let new_key = CString::new("docs/guide.txt").expect("new key should be valid");
        let mut move_error = ptr::null_mut();
        let status = ironmesh_ios_facade_move_path(
            handle,
            key.as_ptr(),
            new_key.as_ptr(),
            0,
            &mut move_error,
        );
        assert_eq!(status, FFI_OK);
        assert!(move_error.is_null());

        let mut moved_bytes = IronmeshIosBytes {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
        let mut moved_fetch_error = ptr::null_mut();
        let status = ironmesh_ios_facade_fetch_bytes(
            handle,
            new_key.as_ptr(),
            &mut moved_bytes,
            &mut moved_fetch_error,
        );
        assert_eq!(status, FFI_OK);
        assert_eq!(read_bytes(moved_bytes), payload);

        let mut delete_error = ptr::null_mut();
        let status = ironmesh_ios_facade_delete_path(handle, new_key.as_ptr(), &mut delete_error);
        assert_eq!(status, FFI_OK);
        assert!(delete_error.is_null());

        let mut post_delete_error = ptr::null_mut();
        let mut post_delete_bytes = IronmeshIosBytes {
            data: ptr::null_mut(),
            len: 0,
            capacity: 0,
        };
        let status = ironmesh_ios_facade_fetch_bytes(
            handle,
            new_key.as_ptr(),
            &mut post_delete_bytes,
            &mut post_delete_error,
        );
        assert_eq!(status, FFI_ERR);
        assert!(!post_delete_error.is_null());
        unsafe { ironmesh_ios_string_free(post_delete_error) };

        ironmesh_ios_facade_free(handle);
    }
}
