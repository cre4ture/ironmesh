use crate::{CfapiAction, CfapiActionPlan};
use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use std::path::PathBuf;

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

#[derive(Debug, Default, Clone)]
pub struct DemoHydrator;

impl Hydrator for DemoHydrator {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>> {
        Ok(format!("ironmesh cfapi hydration: path={path} version={remote_version}\n").into_bytes())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CfapiRuntime {
    remote_versions_by_path: BTreeMap<String, String>,
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
            remote_versions_by_path,
        }
    }

    pub fn known_paths(&self) -> impl Iterator<Item = &str> {
        self.remote_versions_by_path.keys().map(String::as_str)
    }

    pub fn handle_fetch_data(
        &self,
        relative_path: &str,
        hydrator: &dyn Hydrator,
    ) -> Result<Vec<u8>> {
        let normalized = normalize_path(relative_path);
        let remote_version = self
            .remote_versions_by_path
            .get(&normalized)
            .ok_or_else(|| anyhow!("unknown placeholder path: {relative_path}"))?;

        hydrator.hydrate(&normalized, remote_version)
    }
}

fn normalize_path(path: &str) -> String {
    path.trim().trim_start_matches(['/', '\\']).replace('\\', "/")
}

#[cfg(windows)]
mod windows_impl {
    use super::{CfapiAction, CfapiActionPlan, CfapiRuntime, Hydrator, SyncRootRegistration, normalize_path};
    use anyhow::{Result, anyhow};
    use std::collections::BTreeMap;
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::null;
    use std::slice;
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
                Primary: CF_POPULATION_POLICY_PARTIAL,
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
                CF_REGISTER_FLAG_NONE,
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

    pub fn connect_sync_root(
        registration: &SyncRootRegistration,
        runtime: CfapiRuntime,
        hydrator: Box<dyn Hydrator>,
    ) -> Result<SyncRootConnection> {
        validate_registration(registration)?;

        let root_path = utf16_path(&registration.root_path);
        let mut callback_context = Box::new(CallbackContext {
            sync_root: registration.root_path.clone(),
            runtime,
            hydrator,
        });

        let callback_table = vec![
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch_data_callback),
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

        if let Err(err) = execute_transfer_data(callback_info_ref, callback_parameters, &payload) {
            eprintln!("cfapi transfer-data execution error: {err}");
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
pub fn unregister_sync_root(_root_path: &Path) -> Result<()> {
    Err(anyhow!("CFAPI runtime is only available on Windows"))
}

#[cfg(not(windows))]
pub fn apply_action_plan(_root_path: &Path, _plan: &CfapiActionPlan) -> Result<()> {
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
