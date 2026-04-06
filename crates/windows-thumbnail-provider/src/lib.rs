#![cfg(windows)]
#![allow(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::ptr::{copy_nonoverlapping, null_mut};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use adapter_windows_cfapi::auth::{
    inspect_persisted_client_identity_paths, is_internal_client_identity_relative_path,
    load_persisted_client_identity,
};
use adapter_windows_cfapi::connection_config::{
    is_internal_connection_bootstrap_relative_path, resolve_connection_config,
};
use adapter_windows_cfapi::helpers::{normalize_path, path_to_relative};
use adapter_windows_cfapi::hydration_control::{
    is_active_hydration_marked, request_hydration_cancel,
};
use adapter_windows_cfapi::sync_root_identity::{
    RegisteredSyncRootContext, load_registered_sync_root_context,
};
use anyhow::{Context, Result as AnyhowResult, anyhow, bail};
use image::{DynamicImage, RgbaImage};
use reqwest::{StatusCode, Url};
use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_NOINTERFACE, E_NOTIMPL, E_POINTER, S_FALSE,
};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateDIBSection, DIB_RGB_COLORS, HBITMAP,
};
use windows::Win32::System::Com::{CoTaskMemFree, IClassFactory, IClassFactory_Impl};
use windows::Win32::UI::Shell::{
    ECF_DEFAULT, ECS_ENABLED, ECS_HIDDEN, IEnumExplorerCommand, IExplorerCommand,
    IExplorerCommand_Impl, IInitializeWithItem, IInitializeWithItem_Impl, IShellItem,
    IShellItemArray, IThumbnailProvider, IThumbnailProvider_Impl, SHStrDupW, SIGDN_FILESYSPATH,
    WTS_ALPHATYPE, WTS_E_EXTRACTIONPENDING, WTS_E_FAILEDEXTRACTION, WTSAT_ARGB, WTSAT_UNKNOWN,
};
use windows_core::{
    BOOL, GUID, HRESULT, IUnknown, Interface, PCWSTR, PWSTR, Ref, Result, implement,
};

pub const THUMBNAIL_PROVIDER_CLSID: GUID = GUID::from_u128(0xd2e0fd2a_1d7b_4be4_920a_8a6d019454cb);
pub const CUSTOM_STATE_HANDLER_CLSID: GUID =
    GUID::from_u128(0x2a69ab09_87fb_4af7_93c4_6ca7d4853fd0);
pub const EXTENDED_PROPERTY_HANDLER_CLSID: GUID =
    GUID::from_u128(0x7d0f3be1_4d8f_4f40_b4fd_8c098d7b96a2);
pub const BANNERS_HANDLER_CLSID: GUID = GUID::from_u128(0x8a98e31d_1d95_4d26_9dd9_32e2bb3c652a);
pub const CONTEXT_MENU_HANDLER_CLSID: GUID =
    GUID::from_u128(0x8d3bf08a_6c23_40bf_9fcb_46bb6f6be13a);
pub const CONTENT_URI_SOURCE_CLSID: GUID = GUID::from_u128(0xf1aa7371_0c71_4519_8c04_a41dc77f6af1);
pub const STATUS_UI_SOURCE_FACTORY_CLSID: GUID =
    GUID::from_u128(0x47e87ba5_1eb9_4f16_a944_4684850839b5);

const PROVIDER_VERSION: &str = env!("CARGO_PKG_VERSION");
const PROVIDER_BUILD_REVISION: &str = git_version::git_version!(fallback = "unknown");
const MIN_THUMBNAIL_SIZE: u32 = 32;
const MAX_THUMBNAIL_SIZE: u32 = 512;
const MAX_CACHED_THUMBNAILS: usize = 128;

#[derive(Debug, Clone)]
pub struct DebugThumbnailFetchResult {
    pub remote_key: String,
    pub request_path: String,
    pub bootstrap_path: PathBuf,
    pub identity_path: Option<PathBuf>,
    pub candidate_identity_paths: Vec<PathBuf>,
    pub auth_mode: String,
    pub payload_len: usize,
    pub decoded_width: u32,
    pub decoded_height: u32,
}

#[derive(Debug, Clone)]
pub struct DebugThumbnailFailure {
    pub error_kind: String,
    pub hresult: i32,
    pub message: String,
}

#[derive(Debug, Clone)]
pub enum DebugThumbnailOutcome {
    Success(DebugThumbnailFetchResult),
    Failure(DebugThumbnailFailure),
}

type ThumbnailProviderResult<T> = std::result::Result<T, ThumbnailProviderError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThumbnailFailureKind {
    Permanent,
    RetryLater,
}

#[derive(Debug)]
struct ThumbnailProviderError {
    kind: ThumbnailFailureKind,
    error: anyhow::Error,
}

impl ThumbnailProviderError {
    fn permanent(error: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ThumbnailFailureKind::Permanent,
            error: error.into(),
        }
    }

    fn retry_later(error: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: ThumbnailFailureKind::RetryLater,
            error: error.into(),
        }
    }

    fn with_context<C>(self, context: C) -> Self
    where
        C: std::fmt::Display + Send + Sync + 'static,
    {
        Self {
            kind: self.kind,
            error: self.error.context(context),
        }
    }

    fn hresult(&self) -> HRESULT {
        match self.kind {
            ThumbnailFailureKind::Permanent => WTS_E_FAILEDEXTRACTION,
            ThumbnailFailureKind::RetryLater => WTS_E_EXTRACTIONPENDING,
        }
    }

    fn kind_label(&self) -> &'static str {
        match self.kind {
            ThumbnailFailureKind::Permanent => "failed-extraction",
            ThumbnailFailureKind::RetryLater => "extraction-pending",
        }
    }
}

impl std::fmt::Display for ThumbnailProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl std::error::Error for ThumbnailProviderError {}

#[allow(unsafe_code)]
#[implement(IInitializeWithItem, IThumbnailProvider)]
struct IronmeshThumbnailProvider {
    source_path: Mutex<Option<String>>,
}

impl IronmeshThumbnailProvider {
    fn new() -> Self {
        Self {
            source_path: Mutex::new(None),
        }
    }
}

#[allow(unsafe_code)]
#[implement(IExplorerCommand)]
struct IronmeshCancelHydrationCommand;

impl IronmeshCancelHydrationCommand {
    fn new() -> Self {
        Self
    }
}

#[derive(Default)]
struct ThumbnailBytesCache {
    order: VecDeque<String>,
    items: HashMap<String, Vec<u8>>,
}

impl ThumbnailBytesCache {
    fn get(&mut self, key: &str) -> Option<Vec<u8>> {
        let value = self.items.get(key)?.clone();
        self.touch(key);
        Some(value)
    }

    fn insert(&mut self, key: String, value: Vec<u8>) {
        if self.items.contains_key(&key) {
            self.items.insert(key.clone(), value);
            self.touch(&key);
            return;
        }

        self.items.insert(key.clone(), value);
        self.order.push_back(key);

        while self.items.len() > MAX_CACHED_THUMBNAILS {
            if let Some(stale) = self.order.pop_front() {
                self.items.remove(&stale);
            }
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(index) = self.order.iter().position(|candidate| candidate == key) {
            self.order.remove(index);
        }
        self.order.push_back(key.to_string());
    }
}

fn thumbnail_bytes_cache() -> &'static Mutex<ThumbnailBytesCache> {
    static CACHE: OnceLock<Mutex<ThumbnailBytesCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ThumbnailBytesCache::default()))
}

fn append_diagnostic_log(message: &str) {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Ironmesh");
    if create_dir_all(&root).is_err() {
        return;
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();
    let line = format!("[{timestamp}] {message}\r\n");
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("thumbnail-provider.log"))
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

fn log_provider_banner_once() {
    static LOGGED: OnceLock<()> = OnceLock::new();
    if LOGGED.set(()).is_ok() {
        append_diagnostic_log(&format!(
            "thumbnail-provider version={} build_revision={}",
            PROVIDER_VERSION, PROVIDER_BUILD_REVISION
        ));
    }
}

fn format_path_list(paths: &[PathBuf]) -> String {
    if paths.is_empty() {
        return "-".to_string();
    }

    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join("|")
}

#[allow(unsafe_code)]
fn duplicate_shell_text(value: &str) -> Result<PWSTR> {
    let utf16 = value.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    unsafe { SHStrDupW(PCWSTR::from_raw(utf16.as_ptr())) }
}

#[allow(unsafe_code)]
#[allow(non_snake_case)]
impl IInitializeWithItem_Impl for IronmeshThumbnailProvider_Impl {
    fn Initialize(&self, psi: Ref<'_, IShellItem>, _grfmode: u32) -> Result<()> {
        let resolved = psi
            .as_ref()
            .and_then(|item| unsafe { shell_item_path(item) });
        append_diagnostic_log(&format!(
            "Initialize path={}",
            resolved.as_deref().unwrap_or("<unresolved>")
        ));
        *self
            .source_path
            .lock()
            .expect("thumbnail path lock poisoned") = resolved;
        Ok(())
    }
}

#[allow(unsafe_code)]
#[allow(non_snake_case)]
impl IThumbnailProvider_Impl for IronmeshThumbnailProvider_Impl {
    fn GetThumbnail(
        &self,
        cx: u32,
        phbmp: *mut HBITMAP,
        pdwalpha: *mut WTS_ALPHATYPE,
    ) -> Result<()> {
        if phbmp.is_null() || pdwalpha.is_null() {
            return Err(E_POINTER.into());
        }

        unsafe {
            *phbmp = HBITMAP::default();
            *pdwalpha = WTSAT_UNKNOWN;
        }

        log_provider_banner_once();
        let clamped_size = cx.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE);
        let source_path = self
            .source_path
            .lock()
            .expect("thumbnail path lock poisoned")
            .clone()
            .unwrap_or_else(|| String::from("<uninitialized>"));
        append_diagnostic_log(&format!(
            "GetThumbnail size={} source_path={}",
            clamped_size, source_path
        ));

        let bitmap = match try_create_real_thumbnail_bitmap(&source_path, clamped_size) {
            Ok(bitmap) => {
                append_diagnostic_log(&format!(
                    "GetThumbnail source=server size={} source_path={}",
                    clamped_size, source_path
                ));
                bitmap
            }
            Err(error) => {
                let hresult = error.hresult();
                append_diagnostic_log(&format!(
                    "GetThumbnail source=error size={} source_path={} error_kind={} hresult=0x{:08X} error={:#}",
                    clamped_size,
                    source_path,
                    error.kind_label(),
                    hresult.0 as u32,
                    error
                ));
                return Err(windows_core::Error::new(hresult, format!("{error:#}")));
            }
        };

        unsafe {
            *phbmp = bitmap;
            *pdwalpha = WTSAT_ARGB;
        }
        Ok(())
    }
}

#[allow(non_snake_case)]
impl IExplorerCommand_Impl for IronmeshCancelHydrationCommand_Impl {
    fn GetTitle(&self, _psiitemarray: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        duplicate_shell_text("Cancel Hydration")
    }

    fn GetIcon(&self, _psiitemarray: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetToolTip(&self, _psiitemarray: Ref<'_, IShellItemArray>) -> Result<PWSTR> {
        duplicate_shell_text(
            "Abort an active Ironmesh on-demand hydration for the selected placeholder",
        )
    }

    fn GetCanonicalName(&self) -> Result<GUID> {
        Ok(CONTEXT_MENU_HANDLER_CLSID)
    }

    fn GetState(&self, psiitemarray: Ref<'_, IShellItemArray>, _foktobeslow: BOOL) -> Result<u32> {
        let has_cancelable_selection =
            selected_shell_item_paths(psiitemarray)
                .into_iter()
                .any(|source_path| {
                    is_cancel_hydration_available_for_source_path(&source_path).unwrap_or(false)
                });
        Ok(if has_cancelable_selection {
            ECS_ENABLED.0 as u32
        } else {
            ECS_HIDDEN.0 as u32
        })
    }

    fn Invoke(
        &self,
        psiitemarray: Ref<'_, IShellItemArray>,
        _pbc: Ref<'_, windows::Win32::System::Com::IBindCtx>,
    ) -> Result<()> {
        let selected_paths = selected_shell_item_paths(psiitemarray);
        let mut requested = 0usize;
        let mut skipped = 0usize;
        let mut failures = Vec::new();

        for source_path in selected_paths {
            match request_cancel_hydration_for_source_path(&source_path) {
                Ok(true) => requested += 1,
                Ok(false) => skipped += 1,
                Err(error) => failures.push(format!("{source_path}: {error:#}")),
            }
        }

        append_diagnostic_log(&format!(
            "CancelHydration requested={} skipped={} failures={} failure_sample={}",
            requested,
            skipped,
            failures.len(),
            if failures.is_empty() {
                "-".to_string()
            } else {
                failures.join(" | ")
            }
        ));
        Ok(())
    }

    fn GetFlags(&self) -> Result<u32> {
        Ok(ECF_DEFAULT.0 as u32)
    }

    fn EnumSubCommands(&self) -> Result<IEnumExplorerCommand> {
        Err(E_NOTIMPL.into())
    }
}

#[allow(unsafe_code)]
#[implement(IClassFactory)]
struct IronmeshThumbnailProviderFactory;

#[allow(unsafe_code)]
#[allow(non_snake_case)]
impl IClassFactory_Impl for IronmeshThumbnailProviderFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        if riid.is_null() || ppvobject.is_null() {
            return Err(E_POINTER.into());
        }

        unsafe {
            *ppvobject = null_mut();
        }

        let unknown: IUnknown = IronmeshThumbnailProvider::new().into();
        unsafe { unknown.query(riid, ppvobject).ok() }
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[allow(unsafe_code)]
#[implement(IClassFactory)]
struct IronmeshCancelHydrationCommandFactory;

#[allow(unsafe_code)]
#[allow(non_snake_case)]
impl IClassFactory_Impl for IronmeshCancelHydrationCommandFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        if riid.is_null() || ppvobject.is_null() {
            return Err(E_POINTER.into());
        }

        unsafe {
            *ppvobject = null_mut();
        }

        let unknown: IUnknown = IronmeshCancelHydrationCommand::new().into();
        unsafe { unknown.query(riid, ppvobject).ok() }
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[allow(unsafe_code)]
#[implement(IClassFactory)]
struct UnsupportedHandlerFactory;

#[allow(non_snake_case)]
impl IClassFactory_Impl for UnsupportedHandlerFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: Ref<'_, IUnknown>,
        _riid: *const GUID,
        _ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if !punkouter.is_null() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }

        Err(E_NOINTERFACE.into())
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
/// # Safety
///
/// COM/Explorer must provide valid output pointers when requesting the class object.
/// The `rclsid`, `riid`, and `ppv` pointers must be non-null and valid for reads/writes
/// according to the standard `DllGetClassObject` contract.
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_POINTER;
    }

    unsafe {
        *ppv = null_mut();
    }

    let clsid = unsafe { *rclsid };
    let factory: IUnknown = if clsid == THUMBNAIL_PROVIDER_CLSID {
        IronmeshThumbnailProviderFactory.into()
    } else if clsid == CONTEXT_MENU_HANDLER_CLSID {
        IronmeshCancelHydrationCommandFactory.into()
    } else if is_unsupported_handler_clsid(clsid) {
        UnsupportedHandlerFactory.into()
    } else {
        return CLASS_E_CLASSNOTAVAILABLE;
    };

    match unsafe { factory.query(riid, ppv.cast()).ok() } {
        Ok(()) => HRESULT(0),
        Err(error) => error.code(),
    }
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

fn is_unsupported_handler_clsid(clsid: GUID) -> bool {
    clsid == CUSTOM_STATE_HANDLER_CLSID
        || clsid == EXTENDED_PROPERTY_HANDLER_CLSID
        || clsid == BANNERS_HANDLER_CLSID
        || clsid == CONTENT_URI_SOURCE_CLSID
        || clsid == STATUS_UI_SOURCE_FACTORY_CLSID
}

#[allow(unsafe_code)]
unsafe fn shell_item_path(item: &IShellItem) -> Option<String> {
    let value = unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }.ok()?;
    let result = pwstr_to_string(value);
    unsafe {
        CoTaskMemFree(Some(value.0.cast()));
    }
    result
}

#[allow(unsafe_code)]
fn pwstr_to_string(value: PWSTR) -> Option<String> {
    if value.is_null() {
        return None;
    }
    unsafe { value.to_string().ok() }
}

#[allow(unsafe_code)]
fn selected_shell_item_paths(psiitemarray: Ref<'_, IShellItemArray>) -> Vec<String> {
    let Some(item_array) = psiitemarray.as_ref() else {
        return Vec::new();
    };

    let count = unsafe { item_array.GetCount() }.unwrap_or(0);
    let mut paths = Vec::with_capacity(count as usize);
    for index in 0..count {
        if let Ok(item) = unsafe { item_array.GetItemAt(index) }
            && let Some(path) = unsafe { shell_item_path(&item) }
        {
            paths.push(path);
        }
    }
    paths
}

fn is_cancel_hydration_available_for_source_path(source_path: &str) -> AnyhowResult<bool> {
    let source_path = PathBuf::from(source_path);
    let (sync_root_path, _) = find_registered_sync_root(&source_path)?;
    let relative_path = path_to_relative(&sync_root_path, &source_path.to_string_lossy());
    if relative_path.is_empty() {
        return Ok(false);
    }
    if is_internal_connection_bootstrap_relative_path(&relative_path)
        || is_internal_client_identity_relative_path(&relative_path)
    {
        return Ok(false);
    }
    Ok(is_active_hydration_marked(&sync_root_path, &relative_path))
}

fn request_cancel_hydration_for_source_path(source_path: &str) -> AnyhowResult<bool> {
    let source_path = PathBuf::from(source_path);
    let (sync_root_path, _) = find_registered_sync_root(&source_path)?;
    let relative_path = path_to_relative(&sync_root_path, &source_path.to_string_lossy());
    if relative_path.is_empty() {
        bail!(
            "resolved empty sync-root relative path for {} under {}",
            source_path.display(),
            sync_root_path.display()
        );
    }
    if is_internal_connection_bootstrap_relative_path(&relative_path)
        || is_internal_client_identity_relative_path(&relative_path)
    {
        return Ok(false);
    }
    request_hydration_cancel(&sync_root_path, &relative_path)
}

fn try_create_real_thumbnail_bitmap(
    source_path: &str,
    requested_size: u32,
) -> ThumbnailProviderResult<HBITMAP> {
    let fetched = fetch_thumbnail_for_source_path(source_path)
        .map_err(|error| error.with_context("failed to resolve thumbnail"))?;
    create_bitmap_from_thumbnail_bytes(
        &fetched.thumbnail_bytes,
        requested_size.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE),
    )
    .map_err(ThumbnailProviderError::permanent)
    .map_err(|error| {
        error.with_context(format!(
            "failed to decode thumbnail payload for {}",
            fetched.remote_key
        ))
    })
}

struct ThumbnailIdentityLoad {
    candidate_paths: Vec<PathBuf>,
    selected_path: Option<PathBuf>,
    client_identity: Option<client_sdk::ClientIdentityMaterial>,
}

struct ThumbnailClientBuild {
    client: client_sdk::IronMeshClient,
    auth_mode: &'static str,
    candidate_paths: Vec<PathBuf>,
    selected_path: Option<PathBuf>,
}

struct FetchedThumbnail {
    remote_key: String,
    request_path: String,
    bootstrap_path: PathBuf,
    client_build: ThumbnailClientBuild,
    thumbnail_bytes: Vec<u8>,
}

fn build_debug_fetch_result(
    fetched: FetchedThumbnail,
    requested_size: u32,
) -> AnyhowResult<DebugThumbnailFetchResult> {
    let decoded = resize_for_requested_size(
        image::load_from_memory(&fetched.thumbnail_bytes)
            .context("failed to decode thumbnail image")?,
        requested_size.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE),
    );
    Ok(DebugThumbnailFetchResult {
        remote_key: fetched.remote_key,
        request_path: fetched.request_path,
        bootstrap_path: fetched.bootstrap_path,
        identity_path: fetched.client_build.selected_path,
        candidate_identity_paths: fetched.client_build.candidate_paths,
        auth_mode: fetched.client_build.auth_mode.to_string(),
        payload_len: fetched.thumbnail_bytes.len(),
        decoded_width: decoded.width(),
        decoded_height: decoded.height(),
    })
}

fn debug_failure_from_error(error: ThumbnailProviderError) -> DebugThumbnailFailure {
    DebugThumbnailFailure {
        error_kind: error.kind_label().to_string(),
        hresult: error.hresult().0,
        message: format!("{error:#}"),
    }
}

fn build_thumbnail_client(
    sync_root_path: &Path,
    resolved: &adapter_windows_cfapi::connection_config::ResolvedConnectionConfig,
) -> ThumbnailProviderResult<ThumbnailClientBuild> {
    match load_thumbnail_client_identity(sync_root_path, &resolved.bootstrap_path) {
        Ok(identity_load) => {
            let candidate_paths = format_path_list(&identity_load.candidate_paths);
            let selected_path = identity_load
                .selected_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string());

            if let Some(identity) = identity_load.client_identity.as_ref() {
                append_diagnostic_log(&format!(
                    "thumbnail-auth version={} build_revision={} bootstrap_path={} bootstrap_version={} identity_state=loaded identity_path={} device_id={} label={} auth_mode=client-identity candidate_paths={}",
                    PROVIDER_VERSION,
                    PROVIDER_BUILD_REVISION,
                    resolved.bootstrap_path.display(),
                    resolved.bootstrap.version,
                    selected_path,
                    identity.device_id,
                    identity.label.as_deref().unwrap_or("-"),
                    candidate_paths
                ));
                match resolved.build_client(Some(identity)) {
                    Ok(client) => {
                        return Ok(ThumbnailClientBuild {
                            client,
                            auth_mode: "client-identity",
                            candidate_paths: identity_load.candidate_paths,
                            selected_path: identity_load.selected_path,
                        });
                    }
                    Err(error) => {
                        append_diagnostic_log(&format!(
                            "thumbnail-auth version={} build_revision={} bootstrap_path={} bootstrap_version={} identity_state=loaded identity_path={} device_id={} label={} auth_mode=client-identity-build-failed fallback_auth_mode=anonymous candidate_paths={} error={:#}",
                            PROVIDER_VERSION,
                            PROVIDER_BUILD_REVISION,
                            resolved.bootstrap_path.display(),
                            resolved.bootstrap.version,
                            selected_path,
                            identity.device_id,
                            identity.label.as_deref().unwrap_or("-"),
                            candidate_paths,
                            error
                        ));
                    }
                }
            } else {
                append_diagnostic_log(&format!(
                    "thumbnail-auth version={} build_revision={} bootstrap_path={} bootstrap_version={} identity_state=missing identity_path={} auth_mode=anonymous candidate_paths={}",
                    PROVIDER_VERSION,
                    PROVIDER_BUILD_REVISION,
                    resolved.bootstrap_path.display(),
                    resolved.bootstrap.version,
                    selected_path,
                    candidate_paths
                ));
            }
        }
        Err(error) => {
            let discovery = inspect_persisted_client_identity_paths(
                sync_root_path,
                Some(&resolved.bootstrap_path),
                None,
            );
            let candidate_paths = format_path_list(&discovery.candidate_paths);
            let selected_path = discovery
                .selected_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "-".to_string());
            append_diagnostic_log(&format!(
                "thumbnail-auth version={} build_revision={} bootstrap_path={} bootstrap_version={} identity_state=load-error identity_path={} auth_mode=anonymous candidate_paths={} error={:#}",
                PROVIDER_VERSION,
                PROVIDER_BUILD_REVISION,
                resolved.bootstrap_path.display(),
                resolved.bootstrap.version,
                selected_path,
                candidate_paths,
                error
            ));
        }
    }

    let discovery = inspect_persisted_client_identity_paths(
        sync_root_path,
        Some(&resolved.bootstrap_path),
        None,
    );
    resolved
        .build_client(None)
        .map(|client| ThumbnailClientBuild {
            client,
            auth_mode: "anonymous",
            candidate_paths: discovery.candidate_paths,
            selected_path: discovery.selected_path,
        })
        .map_err(ThumbnailProviderError::permanent)
        .map_err(|error| {
            error.with_context(format!(
                "failed to build anonymous client for thumbnail requests using bootstrap {}",
                resolved.bootstrap_path.display()
            ))
        })
}

fn load_thumbnail_client_identity(
    sync_root_path: &Path,
    bootstrap_path: &Path,
) -> AnyhowResult<ThumbnailIdentityLoad> {
    let discovery =
        inspect_persisted_client_identity_paths(sync_root_path, Some(bootstrap_path), None);
    let client_identity =
        load_persisted_client_identity(sync_root_path, Some(bootstrap_path), None).with_context(
            || {
                format!(
                    "failed to load persisted client identity for {}",
                    sync_root_path.display()
                )
            },
        )?;
    Ok(ThumbnailIdentityLoad {
        candidate_paths: discovery.candidate_paths,
        selected_path: discovery.selected_path,
        client_identity,
    })
}

fn fetch_thumbnail_for_source_path(source_path: &str) -> ThumbnailProviderResult<FetchedThumbnail> {
    let source_path = PathBuf::from(source_path);
    let (sync_root_path, sync_root_context) = find_registered_sync_root(&source_path)
        .map_err(ThumbnailProviderError::permanent)
        .map_err(|error| {
            error.with_context(format!(
                "failed to resolve sync root for {}",
                source_path.display()
            ))
        })?;
    let relative_path = path_to_relative(&sync_root_path, &source_path.to_string_lossy());
    if relative_path.is_empty() {
        return Err(ThumbnailProviderError::permanent(anyhow!(
            "resolved empty sync-root relative path for {} under {}",
            source_path.display(),
            sync_root_path.display()
        )));
    }
    if is_internal_connection_bootstrap_relative_path(&relative_path)
        || is_internal_client_identity_relative_path(&relative_path)
    {
        return Err(ThumbnailProviderError::permanent(anyhow!(
            "skipping internal sync-root metadata file {relative_path}"
        )));
    }

    let remote_key = remote_key_for_item(&sync_root_context.identity.prefix, &relative_path);
    let request_path =
        media_thumbnail_request_path(&remote_key).map_err(ThumbnailProviderError::permanent)?;
    let resolved = resolve_connection_config(&sync_root_path, None, None, None, None, None, None)
        .map_err(ThumbnailProviderError::permanent)
        .map_err(|error| {
            error.with_context(format!(
                "failed to resolve connection config for {}",
                sync_root_path.display()
            ))
        })?;
    let client_build = build_thumbnail_client(&sync_root_path, &resolved).map_err(|error| {
        error.with_context(format!(
            "failed to build client for {}",
            sync_root_path.display()
        ))
    })?;
    let thumbnail_bytes =
        fetch_thumbnail_bytes(&client_build.client, &request_path).map_err(|error| {
            error.with_context(format!(
                "failed to fetch thumbnail for remote key {}",
                remote_key
            ))
        })?;

    append_diagnostic_log(&format!(
        "thumbnail-fetch remote_key={} request_path={} bytes={}",
        remote_key,
        request_path,
        thumbnail_bytes.len()
    ));

    Ok(FetchedThumbnail {
        remote_key,
        request_path,
        bootstrap_path: resolved.bootstrap_path,
        client_build,
        thumbnail_bytes,
    })
}

pub fn debug_fetch_thumbnail_for_source_path(
    source_path: &str,
    requested_size: u32,
) -> AnyhowResult<DebugThumbnailFetchResult> {
    log_provider_banner_once();
    let fetched = fetch_thumbnail_for_source_path(source_path)?;
    build_debug_fetch_result(fetched, requested_size)
}

pub fn debug_thumbnail_outcome_for_source_path(
    source_path: &str,
    requested_size: u32,
) -> DebugThumbnailOutcome {
    log_provider_banner_once();
    match fetch_thumbnail_for_source_path(source_path) {
        Ok(fetched) => match build_debug_fetch_result(fetched, requested_size) {
            Ok(result) => DebugThumbnailOutcome::Success(result),
            Err(error) => {
                let error = ThumbnailProviderError::permanent(error);
                DebugThumbnailOutcome::Failure(debug_failure_from_error(error))
            }
        },
        Err(error) => DebugThumbnailOutcome::Failure(debug_failure_from_error(error)),
    }
}

fn find_registered_sync_root(path: &Path) -> AnyhowResult<(PathBuf, RegisteredSyncRootContext)> {
    let mut last_error = None;
    let mut current_context = None;
    let mut current_root = None;

    for ancestor in path.ancestors() {
        match load_registered_sync_root_context(ancestor) {
            Ok(Some(context)) => {
                if let Some(existing) = current_context.as_ref() {
                    if existing == &context {
                        current_root = Some(ancestor.to_path_buf());
                        continue;
                    }
                    break;
                }

                current_root = Some(ancestor.to_path_buf());
                current_context = Some(context);
            }
            Ok(None) => {
                if current_context.is_some() {
                    break;
                }
            }
            Err(error) => {
                last_error = Some((ancestor.to_path_buf(), error));
            }
        }
    }

    if let (Some(root), Some(context)) = (current_root, current_context) {
        return Ok((root, context));
    }

    if let Some((ancestor, error)) = last_error {
        return Err(error).with_context(|| {
            format!(
                "encountered sync-root lookup error while walking ancestors of {} (last ancestor {})",
                path.display(),
                ancestor.display()
            )
        });
    }

    Err(anyhow!(
        "{} is not under a registered Ironmesh sync root",
        path.display()
    ))
}

fn remote_key_for_item(prefix: &str, relative_path: &str) -> String {
    let prefix = normalize_path(prefix).trim_matches('/').to_string();
    let relative_path = normalize_path(relative_path);

    match (prefix.is_empty(), relative_path.is_empty()) {
        (true, true) => String::new(),
        (true, false) => relative_path,
        (false, true) => prefix,
        (false, false) => format!("{prefix}/{relative_path}"),
    }
}

fn media_thumbnail_request_path(remote_key: &str) -> AnyhowResult<String> {
    if remote_key.trim().is_empty() {
        bail!("remote key is empty");
    }

    let mut url = Url::parse("https://ironmesh.invalid/media/thumbnail")
        .context("invalid base thumbnail URL")?;
    url.query_pairs_mut().append_pair("key", remote_key);
    Ok(relative_request_path(&url))
}

fn relative_request_path(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn fetch_thumbnail_bytes(
    client: &client_sdk::IronMeshClient,
    request_path: &str,
) -> ThumbnailProviderResult<Vec<u8>> {
    if let Some(cached) = thumbnail_bytes_cache()
        .lock()
        .expect("thumbnail cache lock poisoned")
        .get(request_path)
    {
        append_diagnostic_log(&format!("thumbnail-cache hit request_path={request_path}"));
        return Ok(cached);
    }

    let response = client
        .get_relative_path_blocking(request_path)
        .map_err(ThumbnailProviderError::retry_later)
        .map_err(|error| error.with_context(format!("request failed for {request_path}")))?;
    match response.status {
        StatusCode::OK => {
            if response.body.is_empty() {
                return Err(ThumbnailProviderError::permanent(anyhow!(
                    "thumbnail endpoint returned an empty body"
                )));
            }
            let payload = response.body.to_vec();
            thumbnail_bytes_cache()
                .lock()
                .expect("thumbnail cache lock poisoned")
                .insert(request_path.to_string(), payload.clone());
            Ok(payload)
        }
        StatusCode::NOT_FOUND => Err(ThumbnailProviderError::permanent(anyhow!(
            "thumbnail not available"
        ))),
        status if thumbnail_status_should_retry(status) => Err(
            ThumbnailProviderError::retry_later(anyhow!("thumbnail endpoint returned {status}")),
        ),
        status => Err(ThumbnailProviderError::permanent(anyhow!(
            "thumbnail endpoint returned {status}"
        ))),
    }
}

fn thumbnail_status_should_retry(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn create_bitmap_from_thumbnail_bytes(bytes: &[u8], requested_size: u32) -> AnyhowResult<HBITMAP> {
    let image = image::load_from_memory(bytes).context("failed to decode thumbnail image")?;
    let image = resize_for_requested_size(
        image,
        requested_size.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE),
    );
    create_bitmap_from_rgba_image(&image.to_rgba8())
}

fn resize_for_requested_size(image: DynamicImage, requested_size: u32) -> DynamicImage {
    if image.width() > requested_size || image.height() > requested_size {
        image.thumbnail(requested_size, requested_size)
    } else {
        image
    }
}

#[allow(unsafe_code)]
fn create_bitmap_from_rgba_image(image: &RgbaImage) -> AnyhowResult<HBITMAP> {
    let pixels = rgba_pixels_to_bgra(image.as_raw());
    unsafe { create_bitmap_from_bgra_pixels(image.width(), image.height(), &pixels) }
}

fn rgba_pixels_to_bgra(rgba: &[u8]) -> Vec<u8> {
    let mut bgra = Vec::with_capacity(rgba.len());
    for pixel in rgba.chunks_exact(4) {
        bgra.extend_from_slice(&[pixel[2], pixel[1], pixel[0], pixel[3]]);
    }
    bgra
}

#[allow(unsafe_code)]
unsafe fn create_bitmap_from_bgra_pixels(
    width: u32,
    height: u32,
    pixels: &[u8],
) -> AnyhowResult<HBITMAP> {
    let mut bits = null_mut();
    let bitmap_info = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            biSizeImage: pixels.len() as u32,
            ..Default::default()
        },
        ..Default::default()
    };

    let bitmap =
        unsafe { CreateDIBSection(None, &bitmap_info, DIB_RGB_COLORS, &mut bits, None, 0)? };
    if bits.is_null() {
        bail!("CreateDIBSection returned a null bitmap buffer");
    }

    unsafe {
        copy_nonoverlapping(pixels.as_ptr(), bits.cast::<u8>(), pixels.len());
    }
    Ok(bitmap)
}

#[cfg(test)]
fn prototype_bgra_pixels(size: u32) -> Vec<u8> {
    let size = size.clamp(MIN_THUMBNAIL_SIZE, MAX_THUMBNAIL_SIZE) as usize;
    let mut pixels = vec![0u8; size * size * 4];

    let background_top = [24u8, 48u8, 70u8, 255u8];
    let background_bottom = [9u8, 26u8, 44u8, 255u8];
    let mesh = [109u8, 223u8, 212u8, 255u8];
    let node = [234u8, 252u8, 251u8, 255u8];

    for y in 0..size {
        let blend = y as f32 / (size.saturating_sub(1).max(1)) as f32;
        let color = lerp_color(background_top, background_bottom, blend);
        for x in 0..size {
            put_pixel(&mut pixels, size, x, y, color);
        }
    }

    let margin = size / 5;
    let center = size / 2;
    let upper = size / 3;
    let lower = size - upper;

    draw_line(&mut pixels, size, margin, upper, center, margin, mesh);
    draw_line(
        &mut pixels,
        size,
        center,
        margin,
        size - margin,
        upper,
        mesh,
    );
    draw_line(&mut pixels, size, margin, upper, center, lower, mesh);
    draw_line(&mut pixels, size, size - margin, upper, center, lower, mesh);
    draw_line(&mut pixels, size, center, margin, center, lower, mesh);

    let radius = (size / 14).max(3);
    fill_circle(&mut pixels, size, margin, upper, radius, node);
    fill_circle(&mut pixels, size, center, margin, radius, node);
    fill_circle(&mut pixels, size, size - margin, upper, radius, node);
    fill_circle(&mut pixels, size, center, lower, radius, node);

    pixels
}

#[cfg(test)]
fn lerp_color(a: [u8; 4], b: [u8; 4], t: f32) -> [u8; 4] {
    let mix = |start: u8, end: u8| -> u8 {
        ((start as f32) + ((end as f32) - (start as f32)) * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    [
        mix(a[0], b[0]),
        mix(a[1], b[1]),
        mix(a[2], b[2]),
        mix(a[3], b[3]),
    ]
}

#[cfg(test)]
fn rgba_to_bgra(color: [u8; 4]) -> [u8; 4] {
    [color[2], color[1], color[0], color[3]]
}

#[cfg(test)]
fn put_pixel(buffer: &mut [u8], size: usize, x: usize, y: usize, color: [u8; 4]) {
    if x >= size || y >= size {
        return;
    }
    let offset = (y * size + x) * 4;
    buffer[offset..offset + 4].copy_from_slice(&rgba_to_bgra(color));
}

#[cfg(test)]
fn draw_line(
    buffer: &mut [u8],
    size: usize,
    x0: usize,
    y0: usize,
    x1: usize,
    y1: usize,
    color: [u8; 4],
) {
    let (mut x0, mut y0, x1, y1) = (x0 as isize, y0 as isize, x1 as isize, y1 as isize);
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut err = dx + dy;

    loop {
        for offset_y in -1..=1 {
            for offset_x in -1..=1 {
                let px = x0 + offset_x;
                let py = y0 + offset_y;
                if px >= 0 && py >= 0 {
                    put_pixel(buffer, size, px as usize, py as usize, color);
                }
            }
        }

        if x0 == x1 && y0 == y1 {
            break;
        }

        let e2 = 2 * err;
        if e2 >= dy {
            err += dy;
            x0 += sx;
        }
        if e2 <= dx {
            err += dx;
            y0 += sy;
        }
    }
}

#[cfg(test)]
fn fill_circle(
    buffer: &mut [u8],
    size: usize,
    center_x: usize,
    center_y: usize,
    radius: usize,
    color: [u8; 4],
) {
    let radius_sq = (radius * radius) as isize;
    let center_x = center_x as isize;
    let center_y = center_y as isize;

    for y in -(radius as isize)..=(radius as isize) {
        for x in -(radius as isize)..=(radius as isize) {
            if x * x + y * y <= radius_sq {
                let px = center_x + x;
                let py = center_y + y;
                if px >= 0 && py >= 0 {
                    put_pixel(buffer, size, px as usize, py as usize, color);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_THUMBNAIL_SIZE, MIN_THUMBNAIL_SIZE, ThumbnailFailureKind, ThumbnailProviderError,
        media_thumbnail_request_path, prototype_bgra_pixels, remote_key_for_item,
        rgba_pixels_to_bgra, thumbnail_status_should_retry,
    };
    use anyhow::anyhow;
    use reqwest::StatusCode;
    use windows::Win32::UI::Shell::{WTS_E_EXTRACTIONPENDING, WTS_E_FAILEDEXTRACTION};

    #[test]
    fn prototype_bitmap_respects_size_bounds() {
        let tiny = prototype_bgra_pixels(1);
        assert_eq!(
            tiny.len(),
            (MIN_THUMBNAIL_SIZE * MIN_THUMBNAIL_SIZE * 4) as usize
        );

        let huge = prototype_bgra_pixels(10_000);
        assert_eq!(
            huge.len(),
            (MAX_THUMBNAIL_SIZE * MAX_THUMBNAIL_SIZE * 4) as usize
        );
    }

    #[test]
    fn prototype_bitmap_is_opaque() {
        let pixels = prototype_bgra_pixels(64);
        assert!(pixels.chunks_exact(4).all(|pixel| pixel[3] == 255));
    }

    #[test]
    fn prototype_bitmap_writes_pixels_in_bgra_order() {
        let pixels = prototype_bgra_pixels(64);
        assert_eq!(&pixels[..4], &[70, 48, 24, 255]);
    }

    #[test]
    fn remote_key_joins_prefix_and_relative_path() {
        assert_eq!(
            remote_key_for_item("docs/team", r"folder\photo.jpg"),
            "docs/team/folder/photo.jpg"
        );
        assert_eq!(
            remote_key_for_item("", "gallery/cat.png"),
            "gallery/cat.png"
        );
    }

    #[test]
    fn media_thumbnail_request_path_percent_encodes_remote_key() {
        let path = media_thumbnail_request_path("gallery/cat one.png")
            .expect("thumbnail request path should build");
        assert_eq!(path, "/media/thumbnail?key=gallery%2Fcat+one.png");
    }

    #[test]
    fn rgba_pixels_are_repacked_to_bgra() {
        let bgra = rgba_pixels_to_bgra(&[10, 20, 30, 255, 40, 50, 60, 128]);
        assert_eq!(bgra, vec![30, 20, 10, 255, 60, 50, 40, 128]);
    }

    #[test]
    fn transient_http_statuses_request_retry() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ] {
            assert!(
                thumbnail_status_should_retry(status),
                "{status} should retry"
            );
        }
    }

    #[test]
    fn permanent_http_statuses_do_not_request_retry() {
        for status in [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ] {
            assert!(
                !thumbnail_status_should_retry(status),
                "{status} should not retry"
            );
        }
    }

    #[test]
    fn failure_kind_maps_to_expected_shell_hresult() {
        let permanent = ThumbnailProviderError::permanent(anyhow!("no thumbnail"));
        assert_eq!(permanent.kind, ThumbnailFailureKind::Permanent);
        assert_eq!(permanent.hresult(), WTS_E_FAILEDEXTRACTION);

        let retry_later = ThumbnailProviderError::retry_later(anyhow!("server busy"));
        assert_eq!(retry_later.kind, ThumbnailFailureKind::RetryLater);
        assert_eq!(retry_later.hresult(), WTS_E_EXTRACTIONPENDING);
    }
}
