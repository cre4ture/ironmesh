use crate::{CfapiAction, CfapiActionPlan};
use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::os::windows::ffi::OsStrExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRootRegistration {
    pub sync_root_id: String,
    pub display_name: String,
    pub root_path: PathBuf,
}

impl SyncRootRegistration {
    pub fn new(
        sync_root_id: impl Into<String>,
        display_name: impl Into<String>,
        root_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            sync_root_id: sync_root_id.into(),
            display_name: display_name.into(),
            root_path: root_path.into(),
        }
    }
}

pub trait Hydrator: Send + Sync + 'static {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>>;
}

pub trait Uploader: Send + Sync + 'static {
    fn upload(&self, path: &str, payload: &[u8]) -> Result<Option<String>>;
}

#[derive(Debug, Default, Clone)]
pub struct DemoHydrator;

impl Hydrator for DemoHydrator {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>> {
        Ok(format!("ironmesh cfapi hydration: path={path} version={remote_version}\n").into_bytes())
    }
}

#[derive(Debug, Default, Clone)]
pub struct DemoUploader;

impl Uploader for DemoUploader {
    fn upload(&self, path: &str, payload: &[u8]) -> Result<Option<String>> {
        eprintln!("demo upload: path={path} bytes={}", payload.len());
        Ok(Some("demo-upload".to_string()))
    }
}

#[derive(Debug, Default)]
pub struct CfapiRuntime {
    remote_versions_by_path: Mutex<BTreeMap<String, String>>,
}

impl CfapiRuntime {
    pub fn from_action_plan(plan: &CfapiActionPlan) -> Self {
        let mut remote_versions_by_path = BTreeMap::new();

        for action in &plan.actions {
            match action {
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                } => {
                    remote_versions_by_path.insert(normalize_path(path), remote_version.clone());
                }
                CfapiAction::EnsureDirectory { .. }
                | CfapiAction::QueueUploadOnClose { .. }
                | CfapiAction::MarkConflict { .. } => {}
            }
        }

        Self {
            remote_versions_by_path: Mutex::new(remote_versions_by_path),
        }
    }

    pub fn known_paths(&self) -> Vec<String> {
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .keys()
            .cloned()
            .collect()
    }

    pub fn handle_fetch_data(
        &self,
        relative_path: &str,
        hydrator: &dyn Hydrator,
    ) -> Result<Vec<u8>> {
        let normalized = normalize_path(relative_path);
        let remote_versions = self
            .remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned");
        let remote_version = remote_versions
            .get(&normalized)
            .ok_or_else(|| anyhow!("unknown placeholder path: {relative_path}"))?;

        hydrator.hydrate(&normalized, remote_version)
    }

    pub fn set_remote_version(&self, relative_path: &str, remote_version: impl Into<String>) {
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .insert(normalize_path(relative_path), remote_version.into());
    }
}

fn normalize_path(path: &str) -> String {
    path.trim().trim_start_matches(['/', '\\']).replace('\\', "/")
}

#[cfg(windows)]
pub fn create_placeholder(sync_root: &std::path::Path, rel_path: &str) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::*;
    use std::ptr::null_mut;
    let full_path = sync_root.join(rel_path.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
    let wide: Vec<u16> = full_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut create_info = CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: wide.as_ptr(),
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        FileIdentity: null_mut(),
        FileIdentityLength: 0,
        FsMetadata: unsafe { std::mem::zeroed() },
        Result: 0,
        CreateUsn: 0,
    };
    let hr = unsafe {
        CfCreatePlaceholders(
            sync_root.as_os_str().encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr(),
            &mut create_info,
            1,
            CF_CREATE_FLAG_STOP_ON_ERROR,
            std::ptr::null_mut(),
        )
    };
    hresult_to_result(hr, "CfCreatePlaceholders (monitor)")
}
pub fn hresult_to_result(hr: i32, operation: &str) -> anyhow::Result<()> {
    if hr == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("{} failed with HRESULT 0x{:08x}", operation, hr))
    }
}
mod windows_impl {
    use super::{
        CfapiAction, CfapiActionPlan, CfapiRuntime, Hydrator, SyncRootRegistration, Uploader,
        normalize_path,
    };
    use anyhow::{Result, anyhow};
    use std::collections::{BTreeMap, HashSet};
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::null;
    use std::slice;
    use std::sync::Mutex;
    use windows_sys::Win32::Storage::CloudFilters::*;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO};

    pub struct SyncRootConnection {
        connection_key: CF_CONNECTION_KEY,
        _callback_table: Box<[CF_CALLBACK_REGISTRATION]>,
        _callback_context: Box<CallbackContext>,
    }

    impl Drop for SyncRootConnection {
        fn drop(&mut self) {
            unsafe {
                let _ = CfDisconnectSyncRoot(self.connection_key);
            }
        }
    }

    struct CallbackContext {
        sync_root: PathBuf,
        runtime: CfapiRuntime,
        hydrator: Box<dyn Hydrator>,
        uploader: std::sync::Arc<dyn Uploader>,
        hydrated_once_paths: Mutex<HashSet<String>>,
    }

    pub fn register_sync_root(registration: &SyncRootRegistration) -> Result<()> {
        validate_registration(registration)?;
        std::fs::create_dir_all(&registration.root_path)?;

        let root_path = utf16_path(&registration.root_path);
        let provider_name = utf16_string(&registration.display_name);
        let provider_version = utf16_string("0.1.0");
        let sync_root_identity = registration.sync_root_id.as_bytes();

        let registration_desc = CF_SYNC_REGISTRATION {
            StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: provider_name.as_ptr(),
            ProviderVersion: provider_version.as_ptr(),
            SyncRootIdentity: sync_root_identity.as_ptr().cast::<c_void>(),
            SyncRootIdentityLength: sync_root_identity.len() as u32,
            FileIdentity: sync_root_identity.as_ptr().cast::<c_void>(),
            FileIdentityLength: sync_root_identity.len() as u32,
            ProviderId: unsafe { zeroed() },
        };

        let policies = CF_SYNC_POLICIES {
            StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_PROGRESSIVE,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
            },
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            InSync: CF_INSYNC_POLICY_NONE,
            HardLink: CF_HARDLINK_POLICY_NONE,
            PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
        };

        let hr = unsafe {
            CfRegisterSyncRoot(
                root_path.as_ptr(),
                &registration_desc,
                &policies,
                CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT | CF_REGISTER_FLAG_UPDATE,
            )
        };

        hresult_to_result(hr, "CfRegisterSyncRoot")
    }

    pub fn unregister_sync_root(root_path: &Path) -> Result<()> {
        let root_path_utf16 = utf16_path(root_path);
        let hr = unsafe { CfUnregisterSyncRoot(root_path_utf16.as_ptr()) };
        hresult_to_result(hr, "CfUnregisterSyncRoot")
    }

    pub fn apply_action_plan(root_path: &Path, plan: &CfapiActionPlan) -> Result<()> {
        std::fs::create_dir_all(root_path)?;

        let mut placeholders: BTreeMap<String, String> = BTreeMap::new();
        for action in &plan.actions {
            match action {
                CfapiAction::EnsureDirectory { path } => {
                    std::fs::create_dir_all(root_path.join(path.replace('/', "\\")))?;
                }
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                } => {
                    let normalized = normalize_path(path);
                    let full_path = root_path.join(normalized.replace('/', "\\"));
                    if full_path.exists() {
                        continue;
                    }
                    if let Some(parent) = Path::new(&normalized).parent() {
                        if !parent.as_os_str().is_empty() {
                            std::fs::create_dir_all(root_path.join(parent))?;
                        }
                    }
                    placeholders.insert(normalized, remote_version.clone());
                }
                CfapiAction::QueueUploadOnClose { .. } | CfapiAction::MarkConflict { .. } => {}
            }
        }

        if placeholders.is_empty() {
            return Ok(());
        }

        struct PlaceholderInput {
            relative_name_utf16: Vec<u16>,
            identity: Vec<u8>,
            metadata: CF_FS_METADATA,
        }

        let mut inputs = Vec::with_capacity(placeholders.len());
        for (relative_path, remote_version) in placeholders {
            let mut basic_info = FILE_BASIC_INFO::default();
            basic_info.FileAttributes = FILE_ATTRIBUTE_NORMAL;
            let metadata = CF_FS_METADATA {
                BasicInfo: basic_info,
                FileSize: 0,
            };

            inputs.push(PlaceholderInput {
                relative_name_utf16: utf16_string(&relative_path),
                identity: remote_version.into_bytes(),
                metadata,
            });
        }

        let mut create_infos = Vec::with_capacity(inputs.len());
        for input in &mut inputs {
            create_infos.push(CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: input.relative_name_utf16.as_ptr(),
                FsMetadata: input.metadata,
                FileIdentity: input.identity.as_ptr().cast::<c_void>(),
                FileIdentityLength: input.identity.len() as u32,
                Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
                Result: 0,
                CreateUsn: 0,
            });
        }

        let base_path = utf16_path(root_path);
        let mut entries_processed = 0u32;
        let hr = unsafe {
            CfCreatePlaceholders(
                base_path.as_ptr(),
                create_infos.as_mut_ptr(),
                create_infos.len() as u32,
                CF_CREATE_FLAG_STOP_ON_ERROR,
                &mut entries_processed,
            )
        };

        hresult_to_result(hr, "CfCreatePlaceholders")
    }

    fn monitor_sync_root_changes(sync_root_clone: PathBuf, uploader_thread: std::sync::Arc<dyn Uploader>) {
        use std::collections::HashSet;
        use std::time::Duration;
        let mut seen: HashSet<String> = HashSet::new();
        loop {
            let walker = walkdir::WalkDir::new(&sync_root_clone).into_iter();
            for entry in walker {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    let rel_path = path_to_relative(&sync_root_clone, &path.to_string_lossy());
                    if rel_path.is_empty() { continue; }
                    if seen.contains(&rel_path) { continue; }
                    let metadata = match std::fs::metadata(path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if metadata.is_dir() {
                        eprintln!("monitor: detected new directory {}", rel_path);
                        let _ = uploader_thread.upload(&rel_path, b"<DIR>");
                    } else {
                        // Check if file is already a CFAPI placeholder using Windows file attributes
                        use std::os::windows::fs::MetadataExt;
                        use windows_sys::Win32::Storage::CloudFilters::*;
                        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
                        const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
                        let attrs = metadata.file_attributes();
                        let is_placeholder = (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0) || (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN != 0);
                        let file_path = sync_root_clone.join(&rel_path);
                        if is_placeholder {
                            eprintln!("monitor: skipping placeholder creation for CFAPI placeholder file {}", rel_path);
                        } else if file_path.exists() {
                            // File is materialized, convert to placeholder using a file HANDLE
                            use std::os::windows::io::AsRawHandle;
                            // Diagnostic info before conversion
                            {
                                use std::os::windows::fs::MetadataExt;
                                let attrs = metadata.file_attributes();
                                eprintln!("monitor: attempting convert path={} attrs=0x{:08x} size={}", file_path.display(), attrs, metadata.len());
                            }
                            match std::fs::OpenOptions::new().read(true).write(true).open(&file_path) {
                                Ok(fh_file) => {
                                    let raw = fh_file.as_raw_handle();
                                    let handle = raw as windows_sys::Win32::Foundation::HANDLE;

                                    // Diagnostic: query placeholder info before conversion
                                    let mut info_buf = vec![0u8; 1024];
                                    let mut returned: u32 = 0;
                                    let hr_info = unsafe {
                                        CfGetPlaceholderInfo(handle, 0, info_buf.as_mut_ptr() as *mut c_void, info_buf.len() as u32, &mut returned)
                                    };
                                    if hr_info == 0 {
                                        eprintln!("monitor: CfGetPlaceholderInfo pre-convert succeeded for {} returned={}", rel_path, returned);
                                    } else {
                                        eprintln!("monitor: CfGetPlaceholderInfo pre-convert failed for {} hr=0x{:08x}", rel_path, hr_info as u32);
                                    }

                                    // If CfGetPlaceholderInfo returned data, the file already has
                                    // placeholder information and conversion is not needed.
                                    if hr_info == 0 && returned > 0 {
                                        eprintln!("monitor: skipping convert for {} because placeholder info present (returned={})", rel_path, returned);
                                    } else {
                                        let hr = unsafe { CfConvertToPlaceholder(handle, std::ptr::null(), 0, 0, std::ptr::null_mut(), std::ptr::null_mut()) };
                                        if hr == 0 {
                                            eprintln!("monitor: converted materialized file to placeholder: {}", rel_path);
                                        } else {
                                            eprintln!("monitor: failed to convert materialized file to placeholder {}: HRESULT 0x{:08x}", rel_path, hr as u32);
                                            // Additional diagnostic: print file attributes and size again
                                            if let Ok(m) = std::fs::metadata(&file_path) {
                                                use std::os::windows::fs::MetadataExt;
                                                let attrs = m.file_attributes();
                                                eprintln!("monitor: post-fail attrs=0x{:08x} size={}", attrs, m.len());
                                            }

                                            // Diagnostic: query placeholder info after conversion attempt
                                            let mut info_buf2 = vec![0u8; 1024];
                                            let mut returned2: u32 = 0;
                                            let hr_info2 = unsafe { CfGetPlaceholderInfo(handle, 0, info_buf2.as_mut_ptr() as *mut c_void, info_buf2.len() as u32, &mut returned2) };
                                            if hr_info2 == 0 {
                                                eprintln!("monitor: CfGetPlaceholderInfo post-convert succeeded for {} returned={}", rel_path, returned2);
                                            } else {
                                                eprintln!("monitor: CfGetPlaceholderInfo post-convert failed for {} hr=0x{:08x}", rel_path, hr_info2 as u32);
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    eprintln!("monitor: failed to open materialized file {} for conversion: {}", rel_path, err);
                                }
                            }
                        } else {
                            // File does not exist, create placeholder
                            use crate::runtime::create_placeholder;
                            if let Err(e) = create_placeholder(&sync_root_clone, &rel_path) {
                                eprintln!("monitor: failed to create placeholder for {}: {}", rel_path, e);
                            } else {
                                eprintln!("monitor: created placeholder for {}", rel_path);
                            }
                        }
                    }
                    seen.insert(rel_path);
                }
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    pub fn connect_sync_root(
        registration: &SyncRootRegistration,
        runtime: CfapiRuntime,
        hydrator: Box<dyn Hydrator>,
        uploader: std::sync::Arc<dyn Uploader>,
    ) -> Result<SyncRootConnection> {
        let sync_root = registration.root_path.clone();
        eprintln!("startup-scan: scanning {} for pre-existing files", sync_root.display());
        let walker = walkdir::WalkDir::new(&sync_root).into_iter();
        for entry in walker {
            if let Ok(entry) = entry {
                let path = entry.path();
                let rel_path = path_to_relative(&sync_root, &path.to_string_lossy());
                if rel_path.is_empty() { continue; }
                let metadata = match std::fs::metadata(path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                    if metadata.is_dir() {
                    eprintln!("startup-scan: uploading directory {}", rel_path);
                    if let Ok(Some(version)) = uploader.upload(&rel_path, b"<DIR>") {
                        runtime.set_remote_version(&rel_path, version);
                    }
                } else {
                    // Skip files that are already CFAPI placeholders
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
                    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
                    let attrs = metadata.file_attributes();
                    let is_placeholder = (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0) || (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN != 0);
                    if is_placeholder {
                        eprintln!("startup-scan: skipping placeholder file {}", rel_path);
                        continue;
                    }
                    match std::fs::read(path) {
                        Ok(data) => {
                            eprintln!("startup-scan: uploading file {} ({} bytes)", rel_path, data.len());
                            match uploader.upload(&rel_path, &data) {
                                Ok(Some(version)) => {
                                    runtime.set_remote_version(&rel_path, version);
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    eprintln!("startup-scan: upload failed for {}: {}", rel_path, err);
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("startup-scan: failed to read {}: {}", rel_path, err);
                        }
                    }
                }
            }
        }

        // Spawn a background thread to monitor the sync root for new files/folders
        // use std::sync::Arc; // Removed unused import
        let sync_root_clone = sync_root.clone();
        let uploader_thread = uploader.clone();

        // Perform a synchronous pre-conversion pass: try to convert existing
        // materialized files to CFAPI placeholders before startup-scan uploads
        // to avoid a race where startup-scan uploads files before conversion.
        {
            use walkdir::WalkDir;
            use std::os::windows::fs::MetadataExt;
            use std::os::windows::io::AsRawHandle;
            use std::ptr::null_mut;
            let walker = WalkDir::new(&sync_root_clone).into_iter();
            for entry in walker {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    let rel_path = path_to_relative(&sync_root_clone, &path.to_string_lossy());
                    if rel_path.is_empty() { continue; }
                    let metadata = match std::fs::metadata(path) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    if metadata.is_dir() { continue; }
                    // Skip if already placeholder
                    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
                    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
                    let attrs = metadata.file_attributes();
                    let is_placeholder = (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0) || (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN != 0);
                    if is_placeholder { continue; }

                    let file_path = sync_root_clone.join(&rel_path);
                    match std::fs::OpenOptions::new().read(true).write(true).open(&file_path) {
                        Ok(fh_file) => {
                            let raw = fh_file.as_raw_handle();
                            let handle = raw as windows_sys::Win32::Foundation::HANDLE;
                            // Query placeholder info; if present skip conversion
                            let mut info_buf = vec![0u8; 256];
                            let mut returned: u32 = 0;
                            let hr_info = unsafe { CfGetPlaceholderInfo(handle, 0, info_buf.as_mut_ptr() as *mut c_void, info_buf.len() as u32, &mut returned) };
                            if hr_info == 0 {
                                if returned > 0 {
                                    eprintln!("pre-convert: file {} already has placeholder info returned={} skipping", rel_path, returned);
                                    continue;
                                }
                            }
                            let hr = unsafe { CfConvertToPlaceholder(handle, std::ptr::null(), 0, 0, null_mut(), null_mut()) };
                            if hr == 0 {
                                eprintln!("pre-convert: converted {}", rel_path);
                            } else {
                                eprintln!("pre-convert: failed to convert {} hr=0x{:08x}", rel_path, hr as u32);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }

        std::thread::spawn(move || monitor_sync_root_changes(sync_root_clone, uploader_thread));

        // Startup scan: enumerate and upload pre-existing files and directories
        let sync_root = registration.root_path.clone();
        eprintln!("startup-scan: scanning {} for pre-existing files", sync_root.display());
        let walker = walkdir::WalkDir::new(&sync_root).into_iter();
        for entry in walker {
            if let Ok(entry) = entry {
                let path = entry.path();
                let rel_path = path_to_relative(&sync_root, &path.to_string_lossy());
                if rel_path.is_empty() { continue; }
                let metadata = match std::fs::metadata(path) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if metadata.is_dir() {
                    eprintln!("startup-scan: uploading directory {}", rel_path);
                    if let Ok(Some(version)) = uploader.upload(&rel_path, b"<DIR>") {
                        runtime.set_remote_version(&rel_path, version);
                    }
                } else {
                    // Skip files that are already CFAPI placeholders
                    use std::os::windows::fs::MetadataExt;
                    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x00400000;
                    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x00040000;
                    let attrs = metadata.file_attributes();
                    let is_placeholder = (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS != 0) || (attrs & FILE_ATTRIBUTE_RECALL_ON_OPEN != 0);
                    if is_placeholder {
                        eprintln!("startup-scan: skipping placeholder file {}", rel_path);
                        continue;
                    }
                    match std::fs::read(path) {
                        Ok(data) => {
                            eprintln!("startup-scan: uploading file {} ({} bytes)", rel_path, data.len());
                            match uploader.upload(&rel_path, &data) {
                                Ok(Some(version)) => {
                                    runtime.set_remote_version(&rel_path, version);
                                }
                                Ok(None) => {}
                                Err(err) => {
                                    eprintln!("startup-scan: upload failed for {}: {}", rel_path, err);
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("startup-scan: failed to read {}: {}", rel_path, err);
                        }
                    }
                }
            }
        }

        let root_path = utf16_path(&registration.root_path);
        let mut callback_context = Box::new(CallbackContext {
            sync_root: registration.root_path.clone(),
            runtime,
            hydrator,
            uploader: uploader.clone(),
            hydrated_once_paths: Mutex::new(HashSet::new()),
        });

        let callback_table = vec![
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
                Callback: Some(file_close_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ]
        .into_boxed_slice();

        let mut connection_key: CF_CONNECTION_KEY = 0;
        let hr = unsafe {
            CfConnectSyncRoot(
                root_path.as_ptr(),
                callback_table.as_ptr(),
                (&mut *callback_context as *mut CallbackContext).cast::<c_void>(),
                CF_CONNECT_FLAG_NONE,
                &mut connection_key,
            )
        };
        hresult_to_result(hr, "CfConnectSyncRoot")?;

        Ok(SyncRootConnection {
            connection_key,
            _callback_table: callback_table,
            _callback_context: callback_context,
        })
    }

    unsafe extern "system" fn fetch_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() || callback_parameters.is_null() {
            return;
        }

        let callback_info_ref = unsafe { &*callback_info };
        let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
        if context_ptr.is_null() {
            return;
        }
        let context = unsafe { &*context_ptr };

        let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
        let relative_path = path_to_relative(&context.sync_root, &normalized_path);

        let payload = match context
            .runtime
            .handle_fetch_data(&relative_path, context.hydrator.as_ref())
        {
            Ok(data) => data,
            Err(err) => {
                eprintln!("cfapi fetch-data hydration error: {err}");
                return;
            }
        };

        if let Ok(mut hydrated_paths) = context.hydrated_once_paths.lock() {
            hydrated_paths.insert(relative_path.clone());
        }

        if let Err(err) = execute_transfer_data(callback_info_ref, callback_parameters, &payload) {
            eprintln!("cfapi transfer-data execution error: {err}");
        }
    }

    unsafe extern "system" fn file_close_completion_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() || callback_parameters.is_null() {
            eprintln!("close-completion: null callback_info or callback_parameters");
            return;
        }

        let callback_info_ref = unsafe { &*callback_info };
        let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
        if context_ptr.is_null() {
            eprintln!("close-completion: null context ptr");
            return;
        }
        let context = unsafe { &*context_ptr };

        let close_completion = unsafe { (*callback_parameters).Anonymous.CloseCompletion };
        eprintln!("close-completion: flags={:x} path={}", close_completion.Flags, string_from_pcwstr(callback_info_ref.NormalizedPath));
        if (close_completion.Flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED) != 0 {
            eprintln!("close-completion: file deleted, skipping upload");
            return;
        }

        let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
        if normalized_path.is_empty() {
            eprintln!("close-completion: empty normalized path");
            return;
        }

        let relative_path = path_to_relative(&context.sync_root, &normalized_path);
        eprintln!("close-completion: relative_path={}", relative_path);

        // Remove hydrated_once_paths logic: always handle upload for any file closed in sync root
        // This allows new files and folders to be uploaded, matching OneDrive behavior
        // Log for diagnostics
        eprintln!("close-completion: checking upload for {}", relative_path);

        // Resolve full path relative to the registered sync root to handle
        // CFAPI NormalizedPath values that may omit the drive letter and
        // start with a leading backslash (e.g. "\\ironmesh-sync2\\file.txt").
        let full_path = context.sync_root.join(&relative_path);
        let metadata = match std::fs::metadata(&full_path) {
            Ok(metadata) => metadata,
            Err(err) => {
                eprintln!("close-completion: metadata error for {}: {}", full_path.display(), err);
                return;
            },
        };
        if metadata.is_dir() {
            eprintln!("close-completion: {} is a directory, uploading directory metadata", normalized_path);
            // Optionally: upload directory metadata or create remote folder
            match context.uploader.upload(&relative_path, b"<DIR>") {
                Ok(_) => {
                    eprintln!("cfapi uploaded directory: path={}", relative_path);
                }
                Err(err) => {
                    eprintln!("cfapi upload error (dir): path={} error={}", relative_path, err);
                }
            }
            return;
        }

        let payload = match std::fs::read(&full_path) {
            Ok(data) => data,
            Err(err) => {
                eprintln!("cfapi close-completion read error: path={} error={}", full_path.display(), err);
                return;
            }
        };

        eprintln!("close-completion: uploading {} ({} bytes)", relative_path, payload.len());
        match context.uploader.upload(&relative_path, &payload) {
            Ok(remote_version) => {
                if let Some(version) = remote_version {
                    context.runtime.set_remote_version(&relative_path, version);
                }
                eprintln!(
                    "cfapi uploaded local file: path={} bytes={}",
                    relative_path,
                    payload.len()
                );
            }
            Err(err) => {
                eprintln!(
                    "cfapi upload error: path={} bytes={} error={}",
                    relative_path,
                    payload.len(),
                    err
                );
            }
        }
    }

    fn execute_transfer_data(
        callback_info: &CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
        payload: &[u8],
    ) -> Result<()> {
        let fetch_data = unsafe { (*callback_parameters).Anonymous.FetchData };
        let required_offset = fetch_data.RequiredFileOffset.max(0) as usize;
        let required_length = fetch_data.RequiredLength.max(0) as usize;

        let start = required_offset.min(payload.len());
        let max_len = payload.len().saturating_sub(start);
        let transfer_len = required_length.min(max_len);
        let transfer_slice = &payload[start..start + transfer_len];

        let transfer_data = CF_OPERATION_PARAMETERS_0_0 {
            Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            CompletionStatus: 0,
            Buffer: transfer_slice.as_ptr().cast::<c_void>(),
            Offset: required_offset as i64,
            Length: transfer_slice.len() as i64,
        };

        let mut op_params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferData: transfer_data,
            },
        };

        let op_info = CF_OPERATION_INFO {
            StructSize: size_of::<CF_OPERATION_INFO>() as u32,
            Type: CF_OPERATION_TYPE_TRANSFER_DATA,
            ConnectionKey: callback_info.ConnectionKey,
            TransferKey: callback_info.TransferKey,
            CorrelationVector: callback_info.CorrelationVector,
            SyncStatus: null(),
            RequestKey: callback_info.RequestKey,
        };

        let hr = unsafe { CfExecute(&op_info, &mut op_params) };
        hresult_to_result(hr, "CfExecute")
    }

    fn hresult_to_result(hr: i32, operation: &str) -> Result<()> {
        if hr >= 0 {
            Ok(())
        } else {
            Err(anyhow!("{operation} failed with HRESULT 0x{:08X}", hr as u32))
        }
    }

    fn validate_registration(registration: &SyncRootRegistration) -> Result<()> {
        if registration.sync_root_id.trim().is_empty() {
            return Err(anyhow!("sync root id cannot be empty"));
        }
        if registration.display_name.trim().is_empty() {
            return Err(anyhow!("display name cannot be empty"));
        }
        if registration.root_path.as_os_str().is_empty() {
            return Err(anyhow!("root path cannot be empty"));
        }
        Ok(())
    }

    fn utf16_string(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn utf16_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn string_from_pcwstr(value: windows_sys::core::PCWSTR) -> String {
        if value.is_null() {
            return String::new();
        }

        let mut len = 0usize;
        unsafe {
            while *value.add(len) != 0 {
                len += 1;
            }
            let raw = slice::from_raw_parts(value, len);
            String::from_utf16_lossy(raw)
        }
    }

    fn path_to_relative(sync_root: &Path, normalized_path: &str) -> String {
        let normalized_root = sync_root
            .as_os_str()
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_string();

        let mut candidate = normalized_path.replace('/', "\\");
        if let Some(stripped) = candidate.strip_prefix(&normalized_root) {
            candidate = stripped.to_string();
        } else {
            // CFAPI sometimes provides a NormalizedPath that starts with a leading
            // backslash and the sync-root name (e.g. "\\ironmesh-sync2\\file.txt").
            // In that case, strip the leading separators and then remove the
            // sync-root folder name if present.
            let trimmed_leading = candidate.trim_start_matches(['\\', '/']).to_string();
            if let Some(root_name_os) = sync_root.file_name() {
                let root_name = root_name_os.to_string_lossy();
                if let Some(stripped) = trimmed_leading.strip_prefix(root_name.as_ref()) {
                    candidate = stripped.to_string();
                }
            }
        }

        normalize_path(candidate.trim_start_matches(['\\', '/']))
    }
}

#[cfg(windows)]
pub use windows_impl::{
    SyncRootConnection, apply_action_plan, connect_sync_root, register_sync_root,
    unregister_sync_root,
};

#[cfg(not(windows))]
pub fn register_sync_root(registration: &SyncRootRegistration) -> Result<()> {
    if registration.sync_root_id.trim().is_empty() {
        return Err(anyhow!("sync root id cannot be empty"));
    }
    if registration.display_name.trim().is_empty() {
        return Err(anyhow!("display name cannot be empty"));
    }
    if registration.root_path.as_os_str().is_empty() {
        return Err(anyhow!("root path cannot be empty"));
    }
    Err(anyhow!("CFAPI runtime is only available on Windows"))
}

#[cfg(not(windows))]
pub fn unregister_sync_root(_root_path: &std::path::Path) -> Result<()> {
    Err(anyhow!("CFAPI runtime is only available on Windows"))
}

#[cfg(not(windows))]
pub fn apply_action_plan(_root_path: &std::path::Path, _plan: &CfapiActionPlan) -> Result<()> {
    Err(anyhow!("CFAPI runtime is only available on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_validation_rejects_empty_inputs() {
        let registration = SyncRootRegistration::new("", "Ironmesh", "C:/ironmesh");
        assert!(register_sync_root(&registration).is_err());

        let registration = SyncRootRegistration::new("id", "", "C:/ironmesh");
        assert!(register_sync_root(&registration).is_err());
    }

    #[test]
    fn runtime_fetches_hydration_for_known_file() {
        let plan = CfapiActionPlan {
            actions: vec![CfapiAction::HydrateOnDemand {
                path: "docs/readme.md".to_string(),
                remote_version: "v7".to_string(),
            }],
        };

        let runtime = CfapiRuntime::from_action_plan(&plan);
        let hydrated = runtime
            .handle_fetch_data("docs/readme.md", &DemoHydrator)
            .expect("hydration should succeed for known file");

        let payload = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(payload.contains("docs/readme.md"));
        assert!(payload.contains("v7"));
    }

    #[test]
    fn runtime_rejects_unknown_file() {
        let runtime = CfapiRuntime::default();
        assert!(runtime
            .handle_fetch_data("missing.txt", &DemoHydrator)
            .is_err());
    }

    #[test]
    fn runtime_normalizes_backslash_paths() {
        let plan = CfapiActionPlan {
            actions: vec![CfapiAction::HydrateOnDemand {
                path: "docs\\notes.txt".to_string(),
                remote_version: "v3".to_string(),
            }],
        };

        let runtime = CfapiRuntime::from_action_plan(&plan);
        let hydrated = runtime
            .handle_fetch_data("docs/notes.txt", &DemoHydrator)
            .expect("path normalization should resolve equivalent separators");

        let payload = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(payload.contains("docs/notes.txt"));
    }
}
