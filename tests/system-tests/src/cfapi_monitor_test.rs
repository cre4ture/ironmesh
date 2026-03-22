#![cfg(windows)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        TEST_ADMIN_TOKEN, fresh_data_dir, https_client_with_root_from_data_dir,
        issue_bootstrap_bundle, start_authenticated_server,
        start_open_server_with_public_https_env, stop_server,
    };
    use crate::framework_win::{pin_cfapi_placeholder, start_cfapi_adapter_with_bootstrap};
    use bytes::Bytes;
    use client_sdk::{
        ClientIdentityMaterial, ConnectionBootstrap, IronMeshClient,
        enroll_connection_input_blocking,
    };
    use reqwest::Client;
    use std::ffi::c_void;
    use std::fs::File;
    use std::io::Write;
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};
    use std::time::Duration;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_PINNED, CF_PLACEHOLDER_INFO_STANDARD,
        CF_PLACEHOLDER_STANDARD_INFO, CF_PLACEHOLDER_STATE_PLACEHOLDER, CfGetPlaceholderInfo,
        CfGetPlaceholderStateFromAttributeTag,
    };
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};

    const DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME: &str = ".ironmesh-connection.json";
    const DEFAULT_CLIENT_IDENTITY_FILE_NAME: &str = ".ironmesh-client-identity.json";

    struct AuthenticatedCfapiFixture {
        server: crate::framework::ChildGuard,
        server_data_dir: PathBuf,
        sdk: IronMeshClient,
        bootstrap_file: PathBuf,
    }

    async fn start_authenticated_cfapi_fixture(
        bind: &str,
        sync_root: &Path,
        label: &str,
    ) -> anyhow::Result<AuthenticatedCfapiFixture> {
        let nonce = bind.replace(['.', ':'], "-");
        let server_data_dir = fresh_data_dir(&format!("cfapi-auth-server-{nonce}"));
        let node_id = Uuid::new_v4().to_string();
        let server = start_authenticated_server(bind, &server_data_dir, &node_id, 1).await?;
        let base_url = format!("http://{bind}");
        let http = Client::new();
        let bootstrap =
            issue_bootstrap_bundle(&http, &base_url, TEST_ADMIN_TOKEN, Some(label), Some(600))
                .await?;

        let bootstrap_file = sync_root.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
        bootstrap.write_to_path(&bootstrap_file)?;

        let bootstrap_json = bootstrap.to_json_pretty()?;
        let label = label.to_string();
        let enrolled = tokio::task::spawn_blocking(move || {
            enroll_connection_input_blocking(&bootstrap_json, None, Some(label.as_str()))
        })
        .await
        .expect("bootstrap enrollment task should join")?;

        let persisted_bootstrap_json = enrolled
            .connection_bootstrap_json
            .clone()
            .expect("enrollment response should include persisted bootstrap json");
        let persisted_bootstrap = ConnectionBootstrap::from_json_str(&persisted_bootstrap_json)
            .expect("failed to parse persisted bootstrap json");
        persisted_bootstrap
            .write_to_path(&bootstrap_file)
            .expect("failed to persist enrolled bootstrap");

        let identity = enrolled
            .client_identity_material()
            .expect("failed to build client identity material from enrollment response");
        let client_identity_file = sync_root.join(DEFAULT_CLIENT_IDENTITY_FILE_NAME);
        identity
            .write_to_path(&client_identity_file)
            .expect("failed to persist client identity");

        let sdk = tokio::task::spawn_blocking(move || {
            persisted_bootstrap.build_client_with_identity(&identity)
        })
        .await
        .expect("bootstrap client builder task should join")
        .expect("failed to build authenticated SDK client from bootstrap");

        Ok(AuthenticatedCfapiFixture {
            server,
            server_data_dir,
            sdk,
            bootstrap_file,
        })
    }

    async fn run_cfapi_monitor_case(bind: &str, initial_content: &str, modified_content: &str) {
        let sync_root = fresh_data_dir("cfapi-monitor-sync-root-parameterized");
        std::fs::create_dir_all(&sync_root).expect("Failed to create sync root");
        let mut fixture = start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-monitor")
            .await
            .expect("Failed to start authenticated CFAPI fixture");

        let test_file = sync_root.join("monitor_test.txt");

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        file.write_all(initial_content.as_bytes())
            .expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

        // start CFAPI adapter to monitor the sync root and upload changes to server
        let _adapter = start_cfapi_adapter_with_bootstrap(
            "ironmesh.systemtest.syncroot",
            "ironmesh System Test Sync Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("Failed to register and serve CFAPI adapter");

        // Wait for monitor to detect and upload
        wait_for_remote_payload(
            &fixture.sdk,
            "monitor_test.txt",
            initial_content.as_bytes(),
            220,
        )
        .await;

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        file.write_all(modified_content.as_bytes())
            .expect("Failed to write modified content");
        file.sync_all().expect("Failed to sync file");
        file.flush().expect("Failed to flush file");
        drop(file); // close file to ensure changes are flushed

        // Wait for monitor to detect and upload
        wait_for_remote_payload(
            &fixture.sdk,
            "monitor_test.txt",
            modified_content.as_bytes(),
            220,
        )
        .await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn wait_for_path(path: &Path, retries: usize) {
        for _ in 0..retries {
            if path.exists() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        panic!("timed out waiting for path {}", path.display());
    }

    async fn wait_for_hydrated_payload(path: &Path, expected: &[u8], retries: usize) {
        for _ in 0..retries {
            if let Ok(bytes) = std::fs::read(path)
                && bytes == expected
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_bytes = std::fs::read(path).unwrap_or_default();
        panic!(
            "placeholder did not hydrate at {} (expected {} bytes, got {} bytes)",
            path.display(),
            expected.len(),
            final_bytes.len()
        );
    }

    async fn wait_for_remote_payload(
        sdk: &IronMeshClient,
        key: &str,
        expected: &[u8],
        retries: usize,
    ) {
        for _ in 0..retries {
            if let Ok(bytes) = sdk.get(key).await
                && bytes.as_ref() == expected
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_bytes = sdk.get(key).await.unwrap_or_default();
        panic!(
            "remote payload did not match for {key} (expected {} bytes, got {} bytes)",
            expected.len(),
            final_bytes.len()
        );
    }

    fn placeholder_standard_info_for_file(
        file: &File,
    ) -> anyhow::Result<CF_PLACEHOLDER_STANDARD_INFO> {
        const HRESULT_MORE_DATA: i32 = 0x800700EAu32 as i32;

        let mut buffer_len = 4096usize.max(size_of::<CF_PLACEHOLDER_STANDARD_INFO>());

        loop {
            let mut info_buf = vec![0u8; buffer_len];
            let mut returned = 0u32;
            let hr = unsafe {
                CfGetPlaceholderInfo(
                    file.as_raw_handle() as _,
                    CF_PLACEHOLDER_INFO_STANDARD,
                    info_buf.as_mut_ptr().cast::<c_void>(),
                    info_buf.len() as u32,
                    &mut returned,
                )
            };

            if hr == HRESULT_MORE_DATA && returned as usize > info_buf.len() {
                buffer_len = returned as usize;
                continue;
            }

            if hr < 0 {
                anyhow::bail!(
                    "CfGetPlaceholderInfo failed with HRESULT 0x{:08X}",
                    hr as u32
                );
            }

            let info = unsafe {
                std::ptr::read_unaligned(info_buf.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>())
            };
            return Ok(info);
        }
    }

    fn placeholder_standard_info(path: &Path) -> anyhow::Result<CF_PLACEHOLDER_STANDARD_INFO> {
        let file = File::open(path)?;
        placeholder_standard_info_for_file(&file)
    }

    fn path_placeholder_state(path: &Path) -> anyhow::Result<u32> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut find_data = WIN32_FIND_DATAW::default();
        let handle = unsafe { FindFirstFileW(wide.as_ptr(), &mut find_data) };
        if handle == INVALID_HANDLE_VALUE {
            anyhow::bail!(
                "FindFirstFileW failed for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }

        let state = unsafe {
            CfGetPlaceholderStateFromAttributeTag(find_data.dwFileAttributes, find_data.dwReserved0)
        };
        unsafe {
            FindClose(handle);
        }
        Ok(state)
    }

    async fn wait_for_placeholder_state(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(state) = path_placeholder_state(path)
                && (state & CF_PLACEHOLDER_STATE_PLACEHOLDER) != 0
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_state = path_placeholder_state(path)
            .map(|state| format!("placeholder_state=0x{state:08x}"))
            .unwrap_or_else(|err| err.to_string());
        panic!(
            "placeholder state never appeared at {}: {}",
            path.display(),
            final_state
        );
    }

    async fn wait_for_placeholder_in_sync(path: &Path, retries: usize) {
        let file = File::open(path).expect("failed to open placeholder while waiting for in-sync");
        for _ in 0..retries {
            if let Ok(info) = placeholder_standard_info_for_file(&file)
                && info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC
                && info.ModifiedDataSize == 0
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_state = placeholder_standard_info(path)
            .map(|info| {
                format!(
                    "InSyncState={} ModifiedDataSize={} OnDiskDataSize={}",
                    info.InSyncState, info.ModifiedDataSize, info.OnDiskDataSize
                )
            })
            .unwrap_or_else(|err| err.to_string());
        panic!(
            "placeholder never returned to in-sync state at {}: {}",
            path.display(),
            final_state
        );
    }

    async fn wait_for_placeholder_present(path: &Path, retries: usize) {
        let file =
            File::open(path).expect("failed to open placeholder while waiting for placeholder");
        for _ in 0..retries {
            if placeholder_standard_info_for_file(&file).is_ok() {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let final_state = placeholder_standard_info_for_file(&file)
            .map(|info| {
                format!(
                    "InSyncState={} ModifiedDataSize={} OnDiskDataSize={}",
                    info.InSyncState, info.ModifiedDataSize, info.OnDiskDataSize
                )
            })
            .unwrap_or_else(|err| err.to_string());
        panic!(
            "file never became a placeholder at {}: {}",
            path.display(),
            final_state
        );
    }

    async fn wait_for_remote_directory_marker_shape(
        sdk: &IronMeshClient,
        dir_name: &str,
        retries: usize,
    ) {
        let normalized = dir_name.trim_matches('/').replace('\\', "/");
        let expected_marker = format!("{normalized}/");

        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 64, None).await {
                let has_directory_marker = index
                    .entries
                    .iter()
                    .any(|entry| entry.path == expected_marker);
                let has_plain_file = index
                    .entries
                    .iter()
                    .any(|entry| entry.path == normalized && !entry.path.ends_with('/'));

                if has_directory_marker && !has_plain_file {
                    return;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let snapshot = sdk
            .store_index(None, 64, None)
            .await
            .map(|index| {
                index
                    .entries
                    .into_iter()
                    .map(|entry| format!("{} [{}]", entry.path, entry.entry_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|err| format!("store-index-error: {err}"));
        panic!(
            "remote directory marker shape not observed for {expected_marker}; index={snapshot}"
        );
    }

    async fn wait_for_remote_directory_absence(
        sdk: &IronMeshClient,
        dir_name: &str,
        retries: usize,
    ) {
        let normalized = dir_name.trim_matches('/').replace('\\', "/");
        let expected_prefix = format!("{normalized}/");

        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 64, None).await {
                let found = index.entries.iter().any(|entry| {
                    entry.path == normalized
                        || entry.path == expected_prefix
                        || entry.path.starts_with(&expected_prefix)
                });

                if !found {
                    return;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let snapshot = sdk
            .store_index(None, 64, None)
            .await
            .map(|index| {
                index
                    .entries
                    .into_iter()
                    .map(|entry| format!("{} [{}]", entry.path, entry.entry_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|err| format!("store-index-error: {err}"));
        panic!("remote directory subtree still present for {expected_prefix}; index={snapshot}");
    }

    async fn wait_for_remote_directory_presence_any_shape(
        sdk: &IronMeshClient,
        dir_name: &str,
        retries: usize,
    ) {
        let normalized = dir_name.trim_matches('/').replace('\\', "/");
        let expected_prefix = format!("{normalized}/");

        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 64, None).await {
                let found = index.entries.iter().any(|entry| {
                    entry.path == normalized
                        || entry.path == expected_prefix
                        || entry.path.starts_with(&expected_prefix)
                });

                if found {
                    return;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let snapshot = sdk
            .store_index(None, 64, None)
            .await
            .map(|index| {
                index
                    .entries
                    .into_iter()
                    .map(|entry| format!("{} [{}]", entry.path, entry.entry_type))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_else(|err| format!("store-index-error: {err}"));
        panic!("remote directory subtree not present for {expected_prefix}; index={snapshot}");
    }

    async fn run_cfapi_hydration_case(bind: &str, key: &str, payload: &[u8]) {
        let sync_root = fresh_data_dir("cfapi-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture = start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-hydration")
            .await
            .expect("failed to start authenticated CFAPI fixture");

        let path_parts: Vec<&str> = key.split('/').collect();
        let mut current_dir = String::new();
        for dir in path_parts.iter().take(path_parts.len() - 1) {
            if !current_dir.is_empty() {
                current_dir.push('/');
            }
            current_dir.push_str(dir);
            let dir_key = format!("{current_dir}/");
            fixture
                .sdk
                .put(dir_key, Bytes::new())
                .await
                .expect("failed to put folder");
        }
        fixture
            .sdk
            .put_large_aware(key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote object");

        let sync_root_id = format!(
            "ironmesh.systemtest.hydration.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Hydration Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 200).await;
        wait_for_hydrated_payload(&local_file, payload, 150).await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_pin_hydration_case(bind: &str, key: &str, payload: &[u8]) {
        let sync_root = fresh_data_dir("cfapi-pin-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-pin-hydration")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        let path_parts: Vec<&str> = key.split('/').collect();
        let mut current_dir = String::new();
        for dir in path_parts.iter().take(path_parts.len() - 1) {
            if !current_dir.is_empty() {
                current_dir.push('/');
            }
            current_dir.push_str(dir);
            let dir_key = format!("{current_dir}/");
            fixture
                .sdk
                .put(dir_key, Bytes::new())
                .await
                .expect("failed to put folder");
        }
        fixture
            .sdk
            .put_large_aware(key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote object");

        let sync_root_id = format!(
            "ironmesh.systemtest.pin.hydration.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Pin Hydration Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 200).await;
        wait_for_placeholder_state(&local_file, 60).await;

        pin_cfapi_placeholder(&sync_root, key, true)
            .await
            .expect("failed to pin placeholder locally");
        wait_for_hydrated_payload(&local_file, payload, 200).await;

        let after_pin = placeholder_standard_info(&local_file)
            .expect("failed to read placeholder info after pin");
        assert!(
            after_pin.OnDiskDataSize >= payload.len() as i64,
            "expected pin to hydrate file locally, got on_disk={} payload_len={}",
            after_pin.OnDiskDataSize,
            payload.len()
        );
        assert_eq!(
            after_pin.PinState, CF_PIN_STATE_PINNED,
            "expected pin request to mark the placeholder as pinned"
        );

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_remote_additions_case(
        bind: &str,
        folder_key: &str,
        file_key: &str,
        payload: &[u8],
    ) {
        let sync_root = fresh_data_dir("cfapi-remote-additions-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-remote-additions")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        let sync_root_id = format!(
            "ironmesh.systemtest.remote.additions.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Remote Additions Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        fixture
            .sdk
            .put(folder_key, Bytes::new())
            .await
            .expect("failed to seed remote folder marker");
        fixture
            .sdk
            .put_large_aware(file_key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote file");

        let folder_path = sync_root.join(folder_key.trim_end_matches('/').replace('/', "\\"));
        let local_file = sync_root.join(file_key.replace('/', "\\"));
        wait_for_path(&folder_path, 250).await;
        wait_for_path(&local_file, 250).await;
        wait_for_hydrated_payload(&local_file, payload, 200).await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file_small() {
        run_cfapi_monitor_case("127.0.0.1:19090", "initial content", "modified content").await;
    }

    #[tokio::test]
    async fn test_cfapi_monitor_detects_new_and_modified_file_large() {
        let large_initial = format!("{}{}", "A".repeat(5 * 1024 * 1024 + 1024), "\ninitial-tail");
        let large_modified = format!(
            "{}{}",
            "B".repeat(5 * 1024 * 1024 + 1024),
            "\nmodified-tail"
        );

        run_cfapi_monitor_case("127.0.0.1:19091", &large_initial, &large_modified).await;
    }

    #[tokio::test]
    async fn test_cfapi_placeholder_hydrates_from_remote_on_read_small() {
        run_cfapi_hydration_case(
            "127.0.0.1:19092",
            "hydrate/small.txt",
            b"hydrated payload from remote",
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_placeholder_hydrates_from_remote_on_read_large() {
        let payload = format!(
            "{}{}",
            "Z".repeat(2 * 1024 * 1024),
            "\nlarge-hydration-tail"
        );
        run_cfapi_hydration_case("127.0.0.1:19093", "hydrate/large.bin", payload.as_bytes()).await;
    }

    #[tokio::test]
    async fn test_cfapi_placeholder_pin_hydrates_from_remote_large() {
        let payload = format!("{}{}", "P".repeat(3 * 1024 * 1024), "\npin-hydration-tail");
        run_cfapi_pin_hydration_case(
            "127.0.0.1:19101",
            "hydrate/pinned-large.bin",
            payload.as_bytes(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_remote_additions_materialize_placeholders() {
        run_cfapi_remote_additions_case(
            "127.0.0.1:19094",
            "remote-added/folder/",
            "remote-added/folder/new-file.txt",
            b"remote addition hydrated",
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_local_empty_folder_is_uploaded_as_directory_marker() {
        let sync_root = fresh_data_dir("cfapi-local-empty-folder-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture = start_authenticated_cfapi_fixture(
            "127.0.0.1:19095",
            &sync_root,
            "cfapi-local-empty-folder",
        )
        .await
        .expect("failed to start authenticated CFAPI fixture");

        let _adapter = start_cfapi_adapter_with_bootstrap(
            "ironmesh.systemtest.local.empty.folder",
            "ironmesh System Test Local Empty Folder",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let empty_dir = sync_root.join("created-empty-folder");
        std::fs::create_dir_all(&empty_dir)
            .expect("failed to create empty folder inside sync root");
        wait_for_path(&empty_dir, 50).await;

        wait_for_remote_directory_marker_shape(&fixture.sdk, "created-empty-folder", 220).await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    #[tokio::test]
    async fn test_cfapi_local_empty_folder_rename_updates_remote_namespace() {
        let sync_root = fresh_data_dir("cfapi-local-empty-folder-rename-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture = start_authenticated_cfapi_fixture(
            "127.0.0.1:19096",
            &sync_root,
            "cfapi-empty-folder-rename",
        )
        .await
        .expect("failed to start authenticated CFAPI fixture");
        fixture
            .sdk
            .put("rename-empty/from/", Bytes::new())
            .await
            .expect("failed to seed remote empty folder marker");

        let _adapter = start_cfapi_adapter_with_bootstrap(
            "ironmesh.systemtest.local.empty.folder.rename",
            "ironmesh System Test Local Empty Folder Rename",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let old_dir = sync_root.join("rename-empty").join("from");
        let new_dir = sync_root.join("rename-empty").join("to");
        wait_for_path(&old_dir, 220).await;
        std::fs::rename(&old_dir, &new_dir)
            .expect("failed to rename empty folder inside sync root");
        wait_for_path(&new_dir, 50).await;

        wait_for_remote_directory_presence_any_shape(&fixture.sdk, "rename-empty/to", 220).await;
        wait_for_remote_directory_absence(&fixture.sdk, "rename-empty/from", 220).await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    #[tokio::test]
    async fn test_cfapi_adapter_enrolls_and_uses_client_auth() {
        let bind = "127.0.0.1:19097";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-auth-server");
        let sync_root = fresh_data_dir("cfapi-auth-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let rendezvous_urls = base_url.clone();

        let mut server = start_open_server_with_public_https_env(
            bind,
            &server_data_dir,
            "",
            1,
            &[
                ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
                ("IRONMESH_ADMIN_TOKEN", admin_token),
                ("IRONMESH_RENDEZVOUS_URLS", rendezvous_urls.as_str()),
            ],
        )
        .await
        .expect("failed to start auth-enabled server-node");

        let result = async {
            let http = https_client_with_root_from_data_dir(&server_data_dir)?;
            let bootstrap = issue_bootstrap_bundle(
                &http,
                &base_url,
                admin_token,
                Some("cfapi-system-test"),
                Some(600),
            )
            .await?;

            let sync_root_id = format!(
                "ironmesh.systemtest.authenticated.{}",
                bind.replace(['.', ':'], "_")
            );
            let bootstrap_file = sync_root.join(".ironmesh-connection.json");
            bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");
            let _adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Authenticated Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            let client_identity_file = sync_root.join(".ironmesh-client-identity.json");
            wait_for_path(&client_identity_file, 120).await;

            let client_identity = ClientIdentityMaterial::from_path(&client_identity_file)
                .expect("failed to load persisted client identity file");
            let persisted_bootstrap = ConnectionBootstrap::from_path(&bootstrap_file)
                .expect("failed to reload persisted bootstrap bundle");
            let sdk = tokio::task::spawn_blocking(move || {
                persisted_bootstrap.build_client_with_identity(&client_identity)
            })
            .await
            .expect("bootstrap client builder task should join")
            .expect("failed to build authenticated SDK client from bootstrap");

            let local_file = sync_root.join("authenticated-upload.txt");
            std::fs::write(&local_file, b"cfapi auth upload")
                .expect("failed to write local file for authenticated upload");
            wait_for_remote_payload(&sdk, "authenticated-upload.txt", b"cfapi auth upload", 220)
                .await;
            let index = sdk
                .store_index(None, 64, None)
                .await
                .expect("failed to inspect remote index after authenticated upload");
            assert!(
                index.entries.iter().all(|entry| {
                    entry.path != ".ironmesh-client-identity.json"
                        && entry.path != ".ironmesh-connection.json"
                }),
                "internal auth/bootstrap file leaked into remote namespace"
            );

            sdk.put_large_aware(
                "remote-auth/seeded.txt",
                Bytes::from_static(b"remote auth payload"),
            )
            .await
            .expect("failed to seed authenticated remote file");

            let remote_file = sync_root.join("remote-auth").join("seeded.txt");
            wait_for_path(&remote_file, 250).await;
            wait_for_hydrated_payload(&remote_file, b"remote auth payload", 200).await;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);

        result.expect("authenticated CFAPI adapter flow failed");
    }

    #[tokio::test]
    async fn test_cfapi_modified_placeholder_returns_to_in_sync_state_after_upload() {
        let bind = "127.0.0.1:19098";

        let result = async {
            let sync_root = fresh_data_dir("cfapi-in-sync-state-sync-root");
            std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
            let mut fixture =
                start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-in-sync-state").await?;

            fixture
                .sdk
                .put_large_aware("sync-status/check.txt", Bytes::from_static(b"remote seed"))
                .await
                .expect("failed to seed remote object");

            let _adapter = start_cfapi_adapter_with_bootstrap(
                "ironmesh.systemtest.sync.status.check",
                "ironmesh System Test Sync Status",
                &sync_root,
                500,
                &fixture.bootstrap_file,
            )
            .await
            .expect("failed to register and serve CFAPI adapter");

            let local_file = sync_root.join("sync-status").join("check.txt");
            wait_for_path(&local_file, 220).await;
            wait_for_hydrated_payload(&local_file, b"remote seed", 200).await;

            std::fs::write(&local_file, b"modified locally via cfapi")
                .expect("failed to modify hydrated placeholder");
            wait_for_remote_payload(
                &fixture.sdk,
                "sync-status/check.txt",
                b"modified locally via cfapi",
                220,
            )
            .await;
            wait_for_placeholder_in_sync(&local_file, 220).await;

            stop_server(&mut fixture.server).await;
            let _ = std::fs::remove_dir_all(&fixture.server_data_dir);

            Ok::<(std::path::PathBuf,), anyhow::Error>((sync_root,))
        }
        .await;

        match result {
            Ok((sync_root,)) => {
                let _ = std::fs::remove_dir_all(sync_root);
            }
            Err(err) => panic!("CFAPI in-sync status flow failed: {err:#}"),
        }
    }

    #[tokio::test]
    async fn test_cfapi_overwrite_waits_for_quiet_period_before_uploading_latest_bytes() {
        let bind = "127.0.0.1:19099";

        let result = async {
            let sync_root = fresh_data_dir("cfapi-overwrite-quiet-period-sync-root");
            std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
            let mut fixture =
                start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-overwrite-quiet")
                    .await?;

            fixture
                .sdk
                .put_large_aware(
                    "overwrite/check.txt",
                    Bytes::from_static(b"original remote"),
                )
                .await
                .expect("failed to seed remote object");

            let _adapter = start_cfapi_adapter_with_bootstrap(
                "ironmesh.systemtest.overwrite.quiet.period",
                "ironmesh System Test Overwrite Quiet Period",
                &sync_root,
                500,
                &fixture.bootstrap_file,
            )
            .await
            .expect("failed to register and serve CFAPI adapter");

            let local_file = sync_root.join("overwrite").join("check.txt");
            wait_for_path(&local_file, 220).await;
            wait_for_hydrated_payload(&local_file, b"original remote", 200).await;

            {
                let truncated = File::create(&local_file)
                    .expect("failed to truncate local placeholder for overwrite");
                truncated
                    .sync_all()
                    .expect("failed to sync truncated local placeholder");
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
            let still_remote = fixture
                .sdk
                .get("overwrite/check.txt")
                .await
                .expect("failed to fetch remote payload during quiet period");
            assert_eq!(
                still_remote,
                Bytes::from_static(b"original remote"),
                "remote payload changed before quiet period expired"
            );

            std::fs::write(&local_file, b"final overwrite payload")
                .expect("failed to write final overwrite payload");
            wait_for_remote_payload(
                &fixture.sdk,
                "overwrite/check.txt",
                b"final overwrite payload",
                220,
            )
            .await;
            wait_for_placeholder_in_sync(&local_file, 220).await;

            stop_server(&mut fixture.server).await;
            let _ = std::fs::remove_dir_all(&fixture.server_data_dir);

            Ok::<std::path::PathBuf, anyhow::Error>(sync_root)
        }
        .await;

        match result {
            Ok(sync_root) => {
                let _ = std::fs::remove_dir_all(sync_root);
            }
            Err(err) => panic!("CFAPI overwrite quiet-period flow failed: {err:#}"),
        }
    }

    #[tokio::test]
    async fn test_cfapi_overwriting_already_uploaded_local_file_returns_to_placeholder() {
        let bind = "127.0.0.1:19100";

        let result = async {
            let sync_root = fresh_data_dir("cfapi-overwrite-uploaded-file-sync-root");
            std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
            let mut fixture =
                start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-overwrite-uploaded")
                    .await?;

            let _adapter = start_cfapi_adapter_with_bootstrap(
                "ironmesh.systemtest.overwrite.uploaded.file",
                "ironmesh System Test Overwrite Uploaded File",
                &sync_root,
                500,
                &fixture.bootstrap_file,
            )
            .await
            .expect("failed to register and serve CFAPI adapter");

            let local_file = sync_root.join("overwrite-local").join("photo.jpg");
            let parent = local_file
                .parent()
                .expect("local test file should have parent");
            std::fs::create_dir_all(parent).expect("failed to create local test directory");

            let initial_payload = b"initial local upload";
            std::fs::write(&local_file, initial_payload)
                .expect("failed to write initial local file");
            wait_for_remote_payload(
                &fixture.sdk,
                "overwrite-local/photo.jpg",
                initial_payload,
                220,
            )
            .await;
            wait_for_placeholder_present(&local_file, 220).await;

            let overwritten_payload = b"overwritten local upload";
            let mut file =
                File::create(&local_file).expect("failed to reopen local file for overwrite");
            file.write_all(overwritten_payload)
                .expect("failed to write overwritten local file");
            file.sync_all()
                .expect("failed to sync overwritten local file");
            drop(file);

            wait_for_remote_payload(
                &fixture.sdk,
                "overwrite-local/photo.jpg",
                overwritten_payload,
                220,
            )
            .await;
            wait_for_placeholder_in_sync(&local_file, 220).await;
            wait_for_hydrated_payload(&local_file, overwritten_payload, 200).await;

            stop_server(&mut fixture.server).await;
            let _ = std::fs::remove_dir_all(&fixture.server_data_dir);

            Ok::<std::path::PathBuf, anyhow::Error>(sync_root)
        }
        .await;

        match result {
            Ok(sync_root) => {
                let _ = std::fs::remove_dir_all(sync_root);
            }
            Err(err) => {
                panic!("CFAPI overwritten uploaded file placeholder flow failed: {err:#}")
            }
        }
    }
}
