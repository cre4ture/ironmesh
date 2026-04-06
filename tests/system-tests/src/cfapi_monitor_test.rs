#![cfg(windows)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        TEST_ADMIN_TOKEN, binary_path, default_client_identity_path, fresh_data_dir,
        https_client_with_root_from_data_dir, issue_bootstrap_bundle, start_authenticated_server,
        start_open_server_with_public_https_env, stop_server, stop_server_without_cleanup,
    };
    use crate::framework_win::{
        cancel_cfapi_placeholder_hydration, pin_cfapi_placeholder,
        start_cfapi_adapter_with_bootstrap, start_cfapi_adapter_with_bootstrap_and_local_appdata,
        start_cfapi_adapter_with_local_appdata,
    };
    use adapter_windows_cfapi::hydration_control::{
        clear_active_hydration, clear_hydration_cancel_request, has_hydration_cancel_request,
        mark_active_hydration,
    };
    use anyhow::Context;
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
    use std::os::windows::fs::{FileExt, MetadataExt};
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;
    use tokio::process::Command;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_PINNED, CF_PLACEHOLDER_INFO_STANDARD,
        CF_PLACEHOLDER_STANDARD_INFO, CfGetPlaceholderInfo,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_UNPINNED, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FindClose, FindFirstStreamW, FindNextStreamW, FindStreamInfoStandard,
        OPEN_EXISTING, WIN32_FIND_STREAM_DATA,
    };
    use windows_sys::Win32::UI::Shell::{WTS_E_EXTRACTIONPENDING, WTS_E_FAILEDEXTRACTION};
    use windows_thumbnail_provider::{
        DebugThumbnailOutcome, debug_fetch_thumbnail_for_source_path,
        debug_thumbnail_outcome_for_source_path,
    };

    const DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME: &str = "ironmesh-client-bootstrap.json";
    const LOCAL_STATE_ROOT_DIR: &str = "Ironmesh";
    const LOCAL_STATE_SYNC_ROOTS_DIR: &str = "sync-roots";
    const LOCAL_STATE_CONNECTION_BOOTSTRAP_FILE_NAME: &str = "connection-bootstrap.json";
    const LOCAL_STATE_CLIENT_IDENTITY_FILE_NAME: &str = "client-identity.json";

    fn sample_png_bytes() -> Vec<u8> {
        let image = image::DynamicImage::new_rgba8(4, 3);
        let mut cursor = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, image::ImageFormat::Png)
            .expect("sample PNG encode should succeed");
        cursor.into_inner()
    }

    fn actual_local_appdata_root() -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .expect("LOCALAPPDATA should be set on Windows")
    }

    fn local_appdata_sync_root_state_dir(
        local_appdata_root: &Path,
        sync_root_path: &Path,
    ) -> PathBuf {
        local_appdata_root
            .join(LOCAL_STATE_ROOT_DIR)
            .join(LOCAL_STATE_SYNC_ROOTS_DIR)
            .join(sync_root_state_label(sync_root_path))
    }

    fn local_appdata_connection_bootstrap_path(
        local_appdata_root: &Path,
        sync_root_path: &Path,
    ) -> PathBuf {
        local_appdata_sync_root_state_dir(local_appdata_root, sync_root_path)
            .join(LOCAL_STATE_CONNECTION_BOOTSTRAP_FILE_NAME)
    }

    fn local_appdata_client_identity_path(
        local_appdata_root: &Path,
        sync_root_path: &Path,
    ) -> PathBuf {
        local_appdata_sync_root_state_dir(local_appdata_root, sync_root_path)
            .join(LOCAL_STATE_CLIENT_IDENTITY_FILE_NAME)
    }

    fn sync_root_state_label(sync_root_path: &Path) -> String {
        let normalized = sync_root_path
            .to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let hash = blake3::hash(normalized.as_bytes()).to_hex().to_string();
        let leaf = sync_root_path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("sync-root");
        let sanitized_leaf = leaf
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() {
                    value.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
            .trim_matches('_')
            .to_string();
        let label = if sanitized_leaf.is_empty() {
            "sync_root".to_string()
        } else {
            sanitized_leaf
        };
        format!("{label}-{hash}")
    }

    struct AuthenticatedCfapiFixture {
        server: crate::framework::ChildGuard,
        server_data_dir: PathBuf,
        sdk: IronMeshClient,
        bootstrap_file: PathBuf,
    }

    async fn start_authenticated_cfapi_fixture(
        bind: &str,
        _sync_root: &Path,
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

        let client_config_dir = server_data_dir.join("client-config");
        std::fs::create_dir_all(&client_config_dir)?;
        let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
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
        let client_identity_file = default_client_identity_path(&bootstrap_file);
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

        let test_file = sync_root.join("monitor_test.txt");

        // Step 1: Create new file after the sync root has been registered.
        let mut file = File::create(&test_file).expect("Failed to create file");
        file.write_all(initial_content.as_bytes())
            .expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

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

    async fn wait_for_path_absence(path: &Path, retries: usize) {
        for _ in 0..retries {
            if !path.exists() {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        panic!("timed out waiting for path absence {}", path.display());
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

    fn read_exact_at(file: &File, offset: u64, len: usize) -> anyhow::Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        let mut filled = 0usize;
        while filled < len {
            let read = file
                .seek_read(&mut buffer[filled..], offset + filled as u64)
                .with_context(|| {
                    format!(
                        "seek_read failed at offset={} remaining={}",
                        offset + filled as u64,
                        len - filled
                    )
                })?;
            if read == 0 {
                anyhow::bail!(
                    "unexpected EOF while reading offset={} len={} filled={}",
                    offset,
                    len,
                    filled
                );
            }
            filled += read;
        }
        Ok(buffer)
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

    async fn wait_for_remote_file_absence(sdk: &IronMeshClient, key: &str, retries: usize) {
        for _ in 0..retries {
            if sdk.get(key).await.is_err() {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        let lingering = sdk
            .get(key)
            .await
            .map(|bytes| bytes.len())
            .unwrap_or_default();
        panic!("remote file did not disappear for {key} (last observed size {lingering} bytes)");
    }

    async fn wait_for_remote_store_index_file_absence(
        sdk: &IronMeshClient,
        key: &str,
        retries: usize,
    ) {
        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 64, None).await
                && !index.entries.iter().any(|entry| entry.path == key)
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
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
        panic!("remote store index did not drop file {key}; index={snapshot}");
    }

    async fn wait_for_remote_version_graph(
        sdk: &IronMeshClient,
        key: &str,
        retries: usize,
    ) -> client_sdk::ironmesh_client::VersionGraphSummary {
        for _ in 0..retries {
            if let Ok(Some(summary)) = sdk.list_versions(key).await {
                return summary;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        panic!("remote version graph did not appear for {key}");
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

    fn open_sync_item(path: &Path) -> anyhow::Result<File> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            anyhow::bail!(
                "CreateFileW failed for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }

        Ok(unsafe { File::from_raw_handle(handle as _) })
    }

    fn placeholder_standard_info(path: &Path) -> anyhow::Result<CF_PLACEHOLDER_STANDARD_INFO> {
        let file = open_sync_item(path)?;
        placeholder_standard_info_for_file(&file)
    }

    fn sync_item_state_summary(path: &Path) -> String {
        placeholder_standard_info(path)
            .map(|info| {
                format!(
                    "attrs=0x{:08x} InSyncState={} ModifiedDataSize={} OnDiskDataSize={}",
                    std::fs::metadata(path)
                        .map(|metadata| metadata.file_attributes())
                        .unwrap_or_default(),
                    info.InSyncState,
                    info.ModifiedDataSize,
                    info.OnDiskDataSize
                )
            })
            .unwrap_or_else(|err| err.to_string())
    }

    fn file_attributes(path: &Path) -> anyhow::Result<u32> {
        Ok(std::fs::metadata(path)?.file_attributes())
    }

    fn file_stream_names(path: &Path) -> anyhow::Result<Vec<String>> {
        let wide = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut stream_data = WIN32_FIND_STREAM_DATA::default();
        let handle = unsafe {
            FindFirstStreamW(
                wide.as_ptr(),
                FindStreamInfoStandard,
                (&mut stream_data as *mut WIN32_FIND_STREAM_DATA).cast(),
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            anyhow::bail!(
                "FindFirstStreamW failed for {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }

        let mut streams = Vec::new();
        loop {
            let nul = stream_data
                .cStreamName
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(stream_data.cStreamName.len());
            streams.push(String::from_utf16_lossy(&stream_data.cStreamName[..nul]));
            let has_next = unsafe {
                FindNextStreamW(
                    handle,
                    (&mut stream_data as *mut WIN32_FIND_STREAM_DATA).cast(),
                )
            } != 0;
            if !has_next {
                break;
            }
        }
        unsafe {
            FindClose(handle);
        }
        Ok(streams)
    }

    async fn wait_for_file_attribute_unpinned(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(attributes) = file_attributes(path)
                && (attributes & FILE_ATTRIBUTE_UNPINNED) != 0
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        panic!(
            "file never became unpinned at {}: {}",
            path.display(),
            sync_item_state_summary(path)
        );
    }

    async fn wait_for_placeholder_dehydrated(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(info) = placeholder_standard_info(path)
                && info.OnDiskDataSize == 0
                && info.ModifiedDataSize == 0
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }

        let streams = file_stream_names(path)
            .map(|value| format!("{value:?}"))
            .unwrap_or_else(|err| format!("stream-enum-error={err}"));
        panic!(
            "placeholder never dehydrated at {}: {} streams={}",
            path.display(),
            sync_item_state_summary(path),
            streams
        );
    }

    async fn assert_placeholder_stays_dehydrated(
        path: &Path,
        duration: Duration,
        poll_interval: Duration,
    ) {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            let info = placeholder_standard_info(path).unwrap_or_else(|err| {
                panic!(
                    "failed to read placeholder info while verifying dehydration at {}: {err:#}",
                    path.display()
                )
            });
            if info.OnDiskDataSize != 0 || info.ModifiedDataSize != 0 {
                let streams = file_stream_names(path)
                    .map(|value| format!("{value:?}"))
                    .unwrap_or_else(|err| format!("stream-enum-error={err}"));
                panic!(
                    "placeholder hydrated unexpectedly at {}: {} streams={}",
                    path.display(),
                    sync_item_state_summary(path),
                    streams
                );
            }

            if tokio::time::Instant::now() >= deadline {
                return;
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    fn request_online_only_via_attrib(path: &Path) -> anyhow::Result<()> {
        let output = std::process::Command::new("attrib")
            .arg("+u")
            .arg(path)
            .output()?;
        if !output.status.success() {
            anyhow::bail!(
                "attrib +u failed for {}: stdout={} stderr={}",
                path.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }

    async fn wait_for_sync_item_in_sync(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(file) = open_sync_item(path)
                && let Ok(info) = placeholder_standard_info_for_file(&file)
                && info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC
                && info.ModifiedDataSize == 0
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        panic!(
            "sync item never returned to in-sync state at {}: {}",
            path.display(),
            sync_item_state_summary(path)
        );
    }

    async fn wait_for_sync_item_not_in_sync(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(file) = open_sync_item(path)
                && let Ok(info) = placeholder_standard_info_for_file(&file)
                && (info.InSyncState != CF_IN_SYNC_STATE_IN_SYNC || info.ModifiedDataSize != 0)
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        panic!(
            "sync item never left in-sync state at {}: {}",
            path.display(),
            sync_item_state_summary(path)
        );
    }

    async fn wait_for_placeholder_in_sync(path: &Path, retries: usize) {
        wait_for_sync_item_in_sync(path, retries).await;
    }

    async fn wait_for_placeholder_present(path: &Path, retries: usize) {
        for _ in 0..retries {
            if let Ok(file) = open_sync_item(path)
                && placeholder_standard_info_for_file(&file).is_ok()
            {
                return;
            }

            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        panic!(
            "file never became a placeholder at {}: {}",
            path.display(),
            sync_item_state_summary(path)
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

    async fn run_cfapi_no_auto_hydration_on_initial_register_case(
        bind: &str,
        key: &str,
        payload: &[u8],
    ) {
        let sync_root = fresh_data_dir("cfapi-no-auto-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-no-auto-hydration")
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
            "ironmesh.systemtest.no.auto.hydration.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test No Auto Hydration Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 220).await;
        wait_for_placeholder_present(&local_file, 220).await;
        wait_for_placeholder_in_sync(&local_file, 220).await;
        wait_for_placeholder_dehydrated(&local_file, 80).await;
        assert_placeholder_stays_dehydrated(
            &local_file,
            Duration::from_secs(7),
            Duration::from_millis(200),
        )
        .await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_concurrent_boundary_read_case(bind: &str, key: &str, payload: &[u8]) {
        let sync_root = fresh_data_dir("cfapi-concurrent-boundary-read-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-boundary-read")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        let path_parts: Vec<&str> = key.split('/').collect();
        let mut current_dir = String::new();
        for dir in path_parts.iter().take(path_parts.len() - 1) {
            if !current_dir.is_empty() {
                current_dir.push('/');
            }
            current_dir.push_str(dir);
            fixture
                .sdk
                .put(format!("{current_dir}/"), Bytes::new())
                .await
                .expect("failed to put folder");
        }
        fixture
            .sdk
            .put_large_aware(key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote object");

        let sync_root_id = format!(
            "ironmesh.systemtest.concurrent.boundary.read.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Concurrent Boundary Read Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 220).await;
        wait_for_placeholder_present(&local_file, 220).await;
        wait_for_placeholder_in_sync(&local_file, 220).await;
        wait_for_placeholder_dehydrated(&local_file, 80).await;

        let base_file = File::open(&local_file).expect("failed to open placeholder");
        for offset in [0_u64, 65_536, 131_072, 196_608, 262_144, 327_680] {
            let chunk = read_exact_at(&base_file, offset, 65_536).unwrap_or_else(|err| {
                panic!("failed to prime boundary chunk at {offset}: {err:#}")
            });
            assert_eq!(
                chunk.as_slice(),
                &payload[offset as usize..offset as usize + 65_536],
                "primed chunk mismatch at offset {offset}"
            );
        }

        let boundary_gap_offset = 393_216_u64;
        let boundary_gap_len = 4_096_usize;
        let boundary_tail_offset = 397_312_u64;
        let boundary_tail_len = 61_440_usize;

        let first_handle = base_file.try_clone().expect("failed to clone first handle");
        let second_handle = base_file
            .try_clone()
            .expect("failed to clone second handle");
        let start_barrier = Arc::new(Barrier::new(3));

        let gap_barrier = start_barrier.clone();
        let gap_worker = thread::spawn(move || {
            gap_barrier.wait();
            read_exact_at(&first_handle, boundary_gap_offset, boundary_gap_len)
        });

        let tail_barrier = start_barrier.clone();
        let tail_worker = thread::spawn(move || {
            tail_barrier.wait();
            read_exact_at(&second_handle, boundary_tail_offset, boundary_tail_len)
        });

        start_barrier.wait();
        let gap_bytes = gap_worker
            .join()
            .expect("gap reader thread should join")
            .expect("gap reader should succeed");
        let tail_bytes = tail_worker
            .join()
            .expect("tail reader thread should join")
            .expect("tail reader should succeed");

        assert_eq!(
            gap_bytes.as_slice(),
            &payload[boundary_gap_offset as usize..boundary_gap_offset as usize + boundary_gap_len]
        );
        assert_eq!(
            tail_bytes.as_slice(),
            &payload
                [boundary_tail_offset as usize..boundary_tail_offset as usize + boundary_tail_len]
        );

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_no_auto_hydration_after_restart_case(bind: &str, key: &str, payload: &[u8]) {
        let sync_root = fresh_data_dir("cfapi-no-auto-hydration-restart-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-no-auto-hydration-restart")
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
            "ironmesh.systemtest.no.auto.hydration.restart.{}",
            bind.replace(['.', ':'], "_")
        );
        let mut adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test No Auto Hydration Restart Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 220).await;
        wait_for_placeholder_present(&local_file, 220).await;
        wait_for_placeholder_in_sync(&local_file, 220).await;
        wait_for_placeholder_dehydrated(&local_file, 80).await;
        assert_placeholder_stays_dehydrated(
            &local_file,
            Duration::from_secs(4),
            Duration::from_millis(200),
        )
        .await;

        stop_server_without_cleanup(&mut adapter).await;

        let mut restarted_adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test No Auto Hydration Restart Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to restart CFAPI adapter");

        wait_for_path(&local_file, 220).await;
        wait_for_placeholder_present(&local_file, 220).await;
        wait_for_placeholder_in_sync(&local_file, 220).await;
        wait_for_placeholder_dehydrated(&local_file, 80).await;
        assert_placeholder_stays_dehydrated(
            &local_file,
            Duration::from_secs(7),
            Duration::from_millis(200),
        )
        .await;

        stop_server(&mut restarted_adapter).await;
        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_hydrating_one_file_keeps_dehydrated_sibling_cold_case(
        bind: &str,
        first_key: &str,
        first_payload: &[u8],
        second_key: &str,
        second_payload: &[u8],
    ) {
        let sync_root = fresh_data_dir("cfapi-sibling-auto-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-sibling-hydration")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        for key in [first_key, second_key] {
            let path_parts: Vec<&str> = key.split('/').collect();
            let mut current_dir = String::new();
            for dir in path_parts.iter().take(path_parts.len() - 1) {
                if !current_dir.is_empty() {
                    current_dir.push('/');
                }
                current_dir.push_str(dir);
                fixture
                    .sdk
                    .put(format!("{current_dir}/"), Bytes::new())
                    .await
                    .expect("failed to put folder");
            }
        }
        fixture
            .sdk
            .put_large_aware(first_key, Bytes::from(first_payload.to_vec()))
            .await
            .expect("failed to seed first remote object");
        fixture
            .sdk
            .put_large_aware(second_key, Bytes::from(second_payload.to_vec()))
            .await
            .expect("failed to seed second remote object");

        let sync_root_id = format!(
            "ironmesh.systemtest.sibling.hydration.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Sibling Hydration Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let first_local = sync_root.join(first_key.replace('/', "\\"));
        let second_local = sync_root.join(second_key.replace('/', "\\"));

        for path in [&first_local, &second_local] {
            wait_for_path(path, 220).await;
            wait_for_placeholder_present(path, 220).await;
            wait_for_placeholder_in_sync(path, 220).await;
            wait_for_placeholder_dehydrated(path, 80).await;
        }

        wait_for_hydrated_payload(&second_local, second_payload, 220).await;
        request_online_only_via_attrib(&second_local)
            .expect("failed to request online-only for second placeholder");
        wait_for_file_attribute_unpinned(&second_local, 120).await;
        wait_for_placeholder_dehydrated(&second_local, 120).await;
        assert_placeholder_stays_dehydrated(
            &second_local,
            Duration::from_secs(3),
            Duration::from_millis(200),
        )
        .await;

        wait_for_hydrated_payload(&first_local, first_payload, 260).await;

        wait_for_placeholder_dehydrated(&second_local, 120).await;
        assert_placeholder_stays_dehydrated(
            &second_local,
            Duration::from_secs(8),
            Duration::from_millis(200),
        )
        .await;

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_restart_keeps_previously_dehydrated_placeholders_cold_case(
        bind: &str,
        keys_and_payloads: &[(&str, &[u8])],
    ) {
        let sync_root = fresh_data_dir("cfapi-restart-cold-placeholders-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-restart-cold-placeholders")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        for (key, payload) in keys_and_payloads {
            let path_parts: Vec<&str> = key.split('/').collect();
            let mut current_dir = String::new();
            for dir in path_parts.iter().take(path_parts.len() - 1) {
                if !current_dir.is_empty() {
                    current_dir.push('/');
                }
                current_dir.push_str(dir);
                fixture
                    .sdk
                    .put(format!("{current_dir}/"), Bytes::new())
                    .await
                    .expect("failed to put folder");
            }
            fixture
                .sdk
                .put_large_aware(*key, Bytes::from(payload.to_vec()))
                .await
                .expect("failed to seed remote object");
        }

        let sync_root_id = format!(
            "ironmesh.systemtest.restart.cold.placeholders.{}",
            bind.replace(['.', ':'], "_")
        );
        let mut adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Restart Cold Placeholders Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_paths = keys_and_payloads
            .iter()
            .map(|(key, _)| sync_root.join(key.replace('/', "\\")))
            .collect::<Vec<_>>();

        for path in &local_paths {
            wait_for_path(path, 220).await;
            wait_for_placeholder_present(path, 220).await;
            wait_for_placeholder_in_sync(path, 220).await;
            wait_for_placeholder_dehydrated(path, 80).await;
        }

        for ((_, payload), path) in keys_and_payloads.iter().zip(local_paths.iter()) {
            wait_for_hydrated_payload(path, payload, 260).await;
            request_online_only_via_attrib(path).unwrap_or_else(|err| {
                panic!(
                    "failed to request online-only for {}: {err:#}",
                    path.display()
                )
            });
            wait_for_file_attribute_unpinned(path, 120).await;
            wait_for_placeholder_dehydrated(path, 120).await;
        }

        stop_server_without_cleanup(&mut adapter).await;

        let mut restarted_adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Restart Cold Placeholders Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to restart CFAPI adapter");

        for path in &local_paths {
            wait_for_path(path, 220).await;
            wait_for_placeholder_present(path, 220).await;
            wait_for_placeholder_in_sync(path, 220).await;
            wait_for_placeholder_dehydrated(path, 120).await;
            assert_placeholder_stays_dehydrated(
                path,
                Duration::from_secs(8),
                Duration::from_millis(200),
            )
            .await;
        }

        stop_server(&mut restarted_adapter).await;
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

    async fn run_cfapi_remote_file_rename_case(
        bind: &str,
        old_key: &str,
        new_key: &str,
        payload: &[u8],
        hydrate_before_rename: bool,
    ) {
        let sync_root = fresh_data_dir("cfapi-remote-file-rename-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture = start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-file-rename")
            .await
            .expect("failed to start authenticated CFAPI fixture");

        fixture
            .sdk
            .put_large_aware(old_key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote file for rename");
        let old_versions = fixture
            .sdk
            .list_versions(old_key)
            .await
            .expect("failed to fetch source version graph before rename")
            .expect("source version graph should exist before rename");
        let old_object_id = old_versions.object_id.clone();

        let sync_root_id = format!(
            "ironmesh.systemtest.remote.file.rename.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Remote File Rename Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let old_path = sync_root.join(old_key.replace('/', "\\"));
        let new_path = sync_root.join(new_key.replace('/', "\\"));
        wait_for_path(&old_path, 220).await;
        wait_for_placeholder_in_sync(&old_path, 220).await;

        if hydrate_before_rename {
            wait_for_hydrated_payload(&old_path, payload, 200).await;
        } else {
            request_online_only_via_attrib(&old_path)
                .expect("failed to request online-only state before rename");
            wait_for_file_attribute_unpinned(&old_path, 220).await;
            wait_for_placeholder_dehydrated(&old_path, 220).await;
        }

        std::fs::rename(&old_path, &new_path).expect("failed to rename cloud-backed file locally");
        wait_for_path(&new_path, 80).await;
        wait_for_remote_payload(&fixture.sdk, new_key, payload, 260).await;
        wait_for_remote_file_absence(&fixture.sdk, old_key, 260).await;

        let new_versions = wait_for_remote_version_graph(&fixture.sdk, new_key, 260).await;
        assert_eq!(
            new_versions.object_id, old_object_id,
            "local rename should preserve remote object identity instead of reuploading"
        );

        if hydrate_before_rename {
            wait_for_hydrated_payload(&new_path, payload, 220).await;
        } else {
            wait_for_placeholder_in_sync(&new_path, 220).await;
            wait_for_placeholder_dehydrated(&new_path, 120).await;
            assert_placeholder_stays_dehydrated(
                &new_path,
                Duration::from_secs(3),
                Duration::from_millis(200),
            )
            .await;
        }

        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
    }

    async fn run_cfapi_remote_delete_restart_case(
        bind: &str,
        key: &str,
        payload: &'static [u8],
        offline_local_payload: Option<&'static [u8]>,
    ) -> anyhow::Result<()> {
        let sync_root = fresh_data_dir("cfapi-remote-delete-restart-sync-root");
        std::fs::create_dir_all(&sync_root).context("failed to create sync root")?;
        let mut fixture =
            start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-remote-delete-restart")
                .await
                .context("failed to start authenticated CFAPI fixture")?;

        let sync_root_id = format!(
            "ironmesh.systemtest.remote.delete.restart.{}",
            bind.replace(['.', ':'], "_")
        );

        fixture
            .sdk
            .put_large_aware(key, Bytes::from_static(payload))
            .await
            .context("failed to seed remote file for restart delete case")?;

        let mut adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Remote Delete Restart Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .context("failed to register and serve CFAPI adapter")?;

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 220).await;
        pin_cfapi_placeholder(&sync_root, key, true)
            .await
            .context("failed to pin placeholder before restart")?;
        wait_for_hydrated_payload(&local_file, payload, 200).await;

        stop_server_without_cleanup(&mut adapter).await;

        fixture
            .sdk
            .delete_path(key)
            .await
            .with_context(|| format!("failed to delete remote file {key} while adapter offline"))?;
        wait_for_remote_file_absence(&fixture.sdk, key, 220).await;
        wait_for_remote_store_index_file_absence(&fixture.sdk, key, 220).await;
        if let Some(offline_local_payload) = offline_local_payload {
            let mut file =
                File::create(&local_file).context("failed to reopen local file while offline")?;
            file.write_all(offline_local_payload)
                .context("failed to write offline local bytes after remote delete")?;
            file.sync_all()
                .context("failed to sync offline local bytes after remote delete")?;
            drop(file);
        }

        let mut restarted_adapter = start_cfapi_adapter_with_bootstrap(
            &sync_root_id,
            "ironmesh System Test Remote Delete Restart Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .context("failed to restart CFAPI adapter after remote delete")?;

        let result = async {
            if let Some(offline_local_payload) = offline_local_payload {
                wait_for_path(&local_file, 220).await;
                wait_for_hydrated_payload(&local_file, offline_local_payload, 220).await;
                wait_for_remote_payload(&fixture.sdk, key, offline_local_payload, 220).await;
            } else {
                wait_for_path_absence(&local_file, 220).await;
                wait_for_remote_file_absence(&fixture.sdk, key, 220).await;
                wait_for_remote_store_index_file_absence(&fixture.sdk, key, 220).await;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut restarted_adapter).await;
        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        result
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
    async fn test_cfapi_placeholder_handles_concurrent_boundary_reads() {
        let payload = (0..(2 * 1024 * 1024 + 17_000))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<u8>>();
        run_cfapi_concurrent_boundary_read_case(
            "127.0.0.1:19117",
            "hydrate/concurrent-boundary.jpg",
            &payload,
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_placeholder_does_not_auto_hydrate_on_initial_register() {
        run_cfapi_no_auto_hydration_on_initial_register_case(
            "127.0.0.1:19113",
            "hydrate/no-auto-hydrate.txt",
            b"remote payload should stay dehydrated until accessed",
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_large_placeholder_does_not_auto_hydrate_on_initial_register() {
        let payload = format!(
            "{}{}",
            "L".repeat(2 * 1024 * 1024),
            "\nlarge-no-auto-hydration-tail"
        );
        run_cfapi_no_auto_hydration_on_initial_register_case(
            "127.0.0.1:19115",
            "hydrate/no-auto-hydrate-large.bin",
            payload.as_bytes(),
        )
        .await;
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
    async fn test_cfapi_placeholder_does_not_auto_hydrate_after_provider_restart() {
        let payload = format!(
            "{}{}",
            "R".repeat(2 * 1024 * 1024),
            "\nrestart-no-auto-hydration-tail"
        );
        run_cfapi_no_auto_hydration_after_restart_case(
            "127.0.0.1:19114",
            "hydrate/no-auto-hydrate-after-restart.bin",
            payload.as_bytes(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_small_placeholder_does_not_auto_hydrate_after_provider_restart() {
        run_cfapi_no_auto_hydration_after_restart_case(
            "127.0.0.1:19116",
            "hydrate/no-auto-hydrate-after-restart-small.txt",
            b"small restart payload should stay dehydrated until accessed",
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_hydrating_one_file_does_not_auto_hydrate_dehydrated_sibling() {
        let first_payload = format!(
            "{}{}",
            "F".repeat(4 * 1024 * 1024),
            "\nfirst-hydrated-payload"
        );
        let second_payload = format!(
            "{}{}",
            "S".repeat(3 * 1024 * 1024),
            "\nsecond-dehydrated-payload"
        );
        run_cfapi_hydrating_one_file_keeps_dehydrated_sibling_cold_case(
            "127.0.0.1:19118",
            "movies/first-hydrated.bin",
            first_payload.as_bytes(),
            "movies/second-should-stay-cold.bin",
            second_payload.as_bytes(),
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_restart_does_not_auto_hydrate_previously_dehydrated_placeholders() {
        let first_payload = format!(
            "{}{}",
            "R".repeat(4 * 1024 * 1024),
            "\nrestart-first-payload"
        );
        let second_payload = format!(
            "{}{}",
            "Q".repeat(3 * 1024 * 1024),
            "\nrestart-second-payload"
        );
        run_cfapi_restart_keeps_previously_dehydrated_placeholders_cold_case(
            "127.0.0.1:19119",
            &[
                ("movies/restart-first.bin", first_payload.as_bytes()),
                ("movies/restart-second.bin", second_payload.as_bytes()),
            ],
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "manual reproduction test for access-hydrated placeholder free-up-space dehydration"]
    async fn manual_cfapi_access_hydrated_placeholder_becomes_online_only_after_attrib_u() {
        let payload = format!(
            "{}{}",
            "D".repeat(2 * 1024 * 1024),
            "\nmanual-free-up-space-tail"
        );
        let sync_root = fresh_data_dir("cfapi-manual-free-up-space-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let mut fixture =
            start_authenticated_cfapi_fixture("127.0.0.1:19111", &sync_root, "cfapi-free-space")
                .await
                .expect("failed to start authenticated CFAPI fixture");

        let key = "free-up-space/access-hydrated.bin";
        fixture
            .sdk
            .put("free-up-space/", Bytes::new())
            .await
            .expect("failed to seed remote folder marker");
        fixture
            .sdk
            .put_large_aware(key, Bytes::from(payload.clone().into_bytes()))
            .await
            .expect("failed to seed remote object");

        let sync_root_id = "ironmesh.systemtest.manual.free_up_space";
        let _adapter = start_cfapi_adapter_with_bootstrap(
            sync_root_id,
            "ironmesh Manual Free Up Space Root",
            &sync_root,
            500,
            &fixture.bootstrap_file,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 220).await;
        wait_for_placeholder_present(&local_file, 220).await;
        wait_for_placeholder_in_sync(&local_file, 220).await;

        let before_access = placeholder_standard_info(&local_file)
            .expect("failed to read placeholder info before access");
        assert_eq!(
            file_attributes(&local_file).expect("failed to read file attributes before access")
                & FILE_ATTRIBUTE_UNPINNED,
            0,
            "expected placeholder to start without the unpinned attribute"
        );

        wait_for_hydrated_payload(&local_file, payload.as_bytes(), 200).await;

        let after_access = placeholder_standard_info(&local_file)
            .expect("failed to read placeholder after access");
        assert!(
            after_access.OnDiskDataSize >= before_access.OnDiskDataSize,
            "expected placeholder to remain or become hydrated before online-only request, got before_on_disk={} after_on_disk={}",
            before_access.OnDiskDataSize,
            after_access.OnDiskDataSize,
        );

        request_online_only_via_attrib(&local_file)
            .expect("failed to request online-only via attrib +u");
        wait_for_file_attribute_unpinned(&local_file, 80).await;
        wait_for_placeholder_dehydrated(&local_file, 120).await;

        drop(_adapter);
        stop_server(&mut fixture.server).await;
        let _ = std::fs::remove_dir_all(&fixture.server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
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
    async fn test_cfapi_dehydrated_in_sync_file_rename_preserves_remote_object_identity() {
        run_cfapi_remote_file_rename_case(
            "127.0.0.1:19113",
            "rename-remote/dehydrated-source.jpg",
            "rename-remote/dehydrated-target.jpg",
            b"dehydrated rename payload",
            false,
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_hydrated_in_sync_file_rename_preserves_remote_object_identity() {
        run_cfapi_remote_file_rename_case(
            "127.0.0.1:19114",
            "rename-remote/hydrated-source.jpg",
            "rename-remote/hydrated-target.jpg",
            b"hydrated rename payload",
            true,
        )
        .await;
    }

    #[tokio::test]
    async fn test_cfapi_remote_delete_while_offline_does_not_resurrect_clean_file_on_restart() {
        run_cfapi_remote_delete_restart_case(
            "127.0.0.1:19115",
            "offline-delete/check.txt",
            b"remote delete restart payload",
            None,
        )
        .await
        .expect("remote delete while offline should not resurrect clean file on restart");
    }

    #[tokio::test]
    async fn test_cfapi_remote_delete_while_offline_preserves_local_only_changes_on_restart() {
        run_cfapi_remote_delete_restart_case(
            "127.0.0.1:19116",
            "offline-delete/local-change.txt",
            b"remote delete restart payload",
            Some(b"offline local-only payload"),
        )
        .await
        .expect("remote delete while offline should preserve local-only file changes on restart");
    }

    #[tokio::test]
    async fn test_cfapi_register_rejects_non_empty_first_time_folder() {
        let sync_root = fresh_data_dir("cfapi-non-empty-register-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        std::fs::write(
            sync_root.join("local-only.txt"),
            b"preexisting local content",
        )
        .expect("failed to seed pre-existing local file");

        let mut fixture = start_authenticated_cfapi_fixture(
            "127.0.0.1:19117",
            &sync_root,
            "cfapi-non-empty-register",
        )
        .await
        .expect("failed to start authenticated CFAPI fixture");
        let bootstrap = ConnectionBootstrap::from_path(&fixture.bootstrap_file)
            .expect("failed to read bootstrap bundle");
        let os_integration_bin = binary_path("os-integration").expect("os-integration binary");

        let output = Command::new(os_integration_bin)
            .arg("register")
            .arg("--sync-root-id")
            .arg("ironmesh.systemtest.reject.nonempty.first.register")
            .arg("--display-name")
            .arg("ironmesh Reject Non-Empty First Register")
            .arg("--root-path")
            .arg(&sync_root)
            .arg("--cluster-id")
            .arg(bootstrap.cluster_id.to_string())
            .output()
            .await
            .expect("failed to execute os-integration register");

        assert!(
            !output.status.success(),
            "register unexpectedly succeeded for non-empty sync root"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("refusing to register non-empty folder"),
            "expected non-empty registration rejection, stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );

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
            let client_config_dir = server_data_dir.join("client-config");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
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

            let client_identity_file = default_client_identity_path(&bootstrap_file);
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
    async fn test_cfapi_adapter_uses_existing_sibling_identity_without_reenrolling() {
        let bind = "127.0.0.1:19112";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-auth-existing-identity-server");
        let sync_root = fresh_data_dir("cfapi-auth-existing-identity-sync-root");
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
            let issued_bootstrap = issue_bootstrap_bundle(
                &http,
                &base_url,
                admin_token,
                Some("cfapi-existing-identity"),
                Some(600),
            )
            .await?;

            let client_config_dir = server_data_dir.join("client-config-existing-identity");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            issued_bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let bootstrap_json = issued_bootstrap.to_json_pretty()?;
            let enrolled = tokio::task::spawn_blocking(move || {
                enroll_connection_input_blocking(
                    &bootstrap_json,
                    None,
                    Some("cfapi-existing-identity"),
                )
            })
            .await
            .expect("bootstrap enrollment task should join")?;

            let persisted_bootstrap_json = enrolled
                .connection_bootstrap_json
                .clone()
                .expect("enrollment response should include persisted bootstrap json");
            let persisted_bootstrap = ConnectionBootstrap::from_json_str(&persisted_bootstrap_json)
                .expect("failed to parse persisted bootstrap json");
            let identity = enrolled
                .client_identity_material()
                .expect("failed to build client identity material from enrollment response");
            let client_identity_file = default_client_identity_path(&bootstrap_file);
            identity
                .write_to_path(&client_identity_file)
                .expect("failed to persist sibling client identity");

            let mut bootstrap_with_invalid_pairing = issued_bootstrap.clone();
            bootstrap_with_invalid_pairing.pairing_token =
                Some("definitely-invalid-pairing-token".to_string());
            bootstrap_with_invalid_pairing
                .write_to_path(&bootstrap_file)
                .expect("failed to overwrite bootstrap with invalid pairing token");

            let sync_root_id = format!(
                "ironmesh.systemtest.authenticated.existing.{}",
                bind.replace(['.', ':'], "_")
            );
            let _adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Existing Identity Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            let persisted_identity = ClientIdentityMaterial::from_path(&client_identity_file)
                .expect("failed to reload sibling client identity");
            let sdk = tokio::task::spawn_blocking(move || {
                persisted_bootstrap.build_client_with_identity(&persisted_identity)
            })
            .await
            .expect("bootstrap client builder task should join")
            .expect("failed to build authenticated SDK client from persisted bootstrap");

            let local_file = sync_root.join("existing-identity-upload.txt");
            std::fs::write(&local_file, b"cfapi existing identity upload")
                .expect("failed to write local file for authenticated upload");
            wait_for_remote_payload(
                &sdk,
                "existing-identity-upload.txt",
                b"cfapi existing identity upload",
                220,
            )
            .await;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);

        result.expect("authenticated CFAPI adapter should reuse existing sibling identity");
    }

    #[tokio::test]
    async fn test_thumbnail_provider_fetches_remote_thumbnail_for_authenticated_placeholder() {
        let bind = "127.0.0.1:19114";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-thumbnail-provider-server");
        let sync_root = fresh_data_dir("cfapi-thumbnail-provider-sync-root");
        let local_appdata_root = actual_local_appdata_root();
        let local_appdata_state_dir =
            local_appdata_sync_root_state_dir(&local_appdata_root, &sync_root);
        let local_appdata_bootstrap =
            local_appdata_connection_bootstrap_path(&local_appdata_root, &sync_root);
        let local_appdata_identity =
            local_appdata_client_identity_path(&local_appdata_root, &sync_root);
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);
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
                Some("cfapi-thumbnail-provider"),
                Some(600),
            )
            .await?;

            let client_config_dir = server_data_dir.join("client-config-thumbnail-provider");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let sync_root_id = format!(
                "ironmesh.systemtest.thumbnail.provider.{}",
                bind.replace(['.', ':'], "_")
            );
            let mut adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Thumbnail Provider Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            wait_for_path(&local_appdata_bootstrap, 120).await;
            wait_for_path(&local_appdata_identity, 120).await;

            let thumbnail_client = {
                let bootstrap_path = local_appdata_bootstrap.clone();
                let identity_path = local_appdata_identity.clone();
                tokio::task::spawn_blocking(move || {
                    let bootstrap = ConnectionBootstrap::from_path(&bootstrap_path)
                        .expect("failed to load persisted LocalAppData bootstrap");
                    let identity = ClientIdentityMaterial::from_path(&identity_path)
                        .expect("failed to load persisted LocalAppData client identity");
                    bootstrap
                        .build_client_with_identity(&identity)
                        .expect("failed to build authenticated thumbnail test client")
                })
                .await
                .expect("thumbnail client builder task should join")
            };

            thumbnail_client
                .put_large_aware("gallery/cat.png", Bytes::from(sample_png_bytes()))
                .await
                .expect("failed to seed remote image");

            let local_file = sync_root.join("gallery").join("cat.png");
            wait_for_path(&local_file, 250).await;
            wait_for_placeholder_present(&local_file, 220).await;
            wait_for_placeholder_in_sync(&local_file, 220).await;
            wait_for_placeholder_dehydrated(&local_file, 120).await;

            let source_path = local_file.to_string_lossy().to_string();
            let thumbnail = tokio::task::spawn_blocking(move || {
                debug_fetch_thumbnail_for_source_path(&source_path, 256)
            })
            .await
            .expect("thumbnail provider debug fetch task should join")?;

            assert_eq!(thumbnail.remote_key, "gallery/cat.png");
            assert_eq!(
                thumbnail.request_path,
                "/media/thumbnail?key=gallery%2Fcat.png"
            );
            assert_eq!(thumbnail.bootstrap_path, local_appdata_bootstrap);
            assert_eq!(
                thumbnail.identity_path.as_deref(),
                Some(local_appdata_identity.as_path())
            );
            assert!(
                thumbnail
                    .candidate_identity_paths
                    .iter()
                    .any(|path| path == &local_appdata_identity),
                "expected LocalAppData client identity path in candidate list"
            );
            assert_eq!(thumbnail.auth_mode, "client-identity");
            assert!(
                thumbnail.payload_len > 0,
                "thumbnail payload should not be empty"
            );
            assert!(
                thumbnail.decoded_width > 0 && thumbnail.decoded_height > 0,
                "thumbnail should decode to non-zero dimensions"
            );

            stop_server(&mut adapter).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);

        result.expect("thumbnail provider should fetch an authenticated remote thumbnail");
    }

    #[tokio::test]
    async fn test_thumbnail_provider_returns_unauthorized_without_persisted_identity() {
        let bind = "127.0.0.1:19115";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-thumbnail-provider-anon-server");
        let sync_root = fresh_data_dir("cfapi-thumbnail-provider-anon-sync-root");
        let local_appdata_root = actual_local_appdata_root();
        let local_appdata_state_dir =
            local_appdata_sync_root_state_dir(&local_appdata_root, &sync_root);
        let local_appdata_bootstrap =
            local_appdata_connection_bootstrap_path(&local_appdata_root, &sync_root);
        let local_appdata_identity =
            local_appdata_client_identity_path(&local_appdata_root, &sync_root);
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);
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
                Some("cfapi-thumbnail-provider-anon"),
                Some(600),
            )
            .await?;

            let client_config_dir = server_data_dir.join("client-config-thumbnail-provider-anon");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let sync_root_id = format!(
                "ironmesh.systemtest.thumbnail.provider.anon.{}",
                bind.replace(['.', ':'], "_")
            );
            let mut adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Thumbnail Provider Anonymous Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            wait_for_path(&local_appdata_bootstrap, 120).await;
            wait_for_path(&local_appdata_identity, 120).await;

            let thumbnail_client = {
                let bootstrap_path = local_appdata_bootstrap.clone();
                let identity_path = local_appdata_identity.clone();
                tokio::task::spawn_blocking(move || {
                    let bootstrap = ConnectionBootstrap::from_path(&bootstrap_path)
                        .expect("failed to load persisted LocalAppData bootstrap");
                    let identity = ClientIdentityMaterial::from_path(&identity_path)
                        .expect("failed to load persisted LocalAppData client identity");
                    bootstrap
                        .build_client_with_identity(&identity)
                        .expect("failed to build authenticated thumbnail test client")
                })
                .await
                .expect("thumbnail client builder task should join")
            };

            thumbnail_client
                .put_large_aware("gallery/no-identity.png", Bytes::from(sample_png_bytes()))
                .await
                .expect("failed to seed remote image");

            let local_file = sync_root.join("gallery").join("no-identity.png");
            wait_for_path(&local_file, 250).await;
            wait_for_placeholder_present(&local_file, 220).await;
            wait_for_placeholder_in_sync(&local_file, 220).await;
            wait_for_placeholder_dehydrated(&local_file, 120).await;

            std::fs::remove_file(&local_appdata_identity)
                .expect("failed to remove persisted LocalAppData client identity");
            wait_for_path_absence(&local_appdata_identity, 80).await;

            let source_path = local_file.to_string_lossy().to_string();
            let error = tokio::task::spawn_blocking(move || {
                debug_fetch_thumbnail_for_source_path(&source_path, 256)
            })
            .await
            .expect("thumbnail provider debug fetch task should join")
            .expect_err("thumbnail provider should fail without a persisted client identity");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("401 Unauthorized"),
                "expected unauthorized thumbnail fetch error, got: {rendered}"
            );

            stop_server(&mut adapter).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);

        result.expect("thumbnail provider should surface unauthorized errors without identity");
    }

    #[tokio::test]
    async fn test_thumbnail_provider_reports_failed_extraction_for_unsupported_placeholder() {
        let bind = "127.0.0.1:19116";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-thumbnail-provider-unsupported-server");
        let sync_root = fresh_data_dir("cfapi-thumbnail-provider-unsupported-sync-root");
        let local_appdata_root = actual_local_appdata_root();
        let local_appdata_state_dir =
            local_appdata_sync_root_state_dir(&local_appdata_root, &sync_root);
        let local_appdata_bootstrap =
            local_appdata_connection_bootstrap_path(&local_appdata_root, &sync_root);
        let local_appdata_identity =
            local_appdata_client_identity_path(&local_appdata_root, &sync_root);
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);
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
                Some("cfapi-thumbnail-provider-unsupported"),
                Some(600),
            )
            .await?;

            let client_config_dir =
                server_data_dir.join("client-config-thumbnail-provider-unsupported");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let sync_root_id = format!(
                "ironmesh.systemtest.thumbnail.provider.unsupported.{}",
                bind.replace(['.', ':'], "_")
            );
            let mut adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Thumbnail Provider Unsupported Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            wait_for_path(&local_appdata_bootstrap, 120).await;
            wait_for_path(&local_appdata_identity, 120).await;

            let thumbnail_client = {
                let bootstrap_path = local_appdata_bootstrap.clone();
                let identity_path = local_appdata_identity.clone();
                tokio::task::spawn_blocking(move || {
                    let bootstrap = ConnectionBootstrap::from_path(&bootstrap_path)
                        .expect("failed to load persisted LocalAppData bootstrap");
                    let identity = ClientIdentityMaterial::from_path(&identity_path)
                        .expect("failed to load persisted LocalAppData client identity");
                    bootstrap
                        .build_client_with_identity(&identity)
                        .expect("failed to build authenticated thumbnail test client")
                })
                .await
                .expect("thumbnail client builder task should join")
            };

            thumbnail_client
                .put_large_aware(
                    "docs/no-thumbnail.txt",
                    Bytes::from_static(b"thumbnail system test unsupported"),
                )
                .await
                .expect("failed to seed remote unsupported file");

            let local_file = sync_root.join("docs").join("no-thumbnail.txt");
            wait_for_path(&local_file, 250).await;
            wait_for_placeholder_present(&local_file, 220).await;
            wait_for_placeholder_in_sync(&local_file, 220).await;
            wait_for_placeholder_dehydrated(&local_file, 120).await;

            let source_path = local_file.to_string_lossy().to_string();
            let outcome = tokio::task::spawn_blocking(move || {
                debug_thumbnail_outcome_for_source_path(&source_path, 256)
            })
            .await
            .expect("thumbnail provider debug outcome task should join");

            match outcome {
                DebugThumbnailOutcome::Failure(failure) => {
                    assert_eq!(failure.error_kind, "failed-extraction");
                    assert_eq!(failure.hresult, WTS_E_FAILEDEXTRACTION);
                    assert!(
                        failure.message.contains("thumbnail not available"),
                        "expected no-thumbnail failure message, got: {}",
                        failure.message
                    );
                }
                DebugThumbnailOutcome::Success(success) => {
                    panic!(
                        "unsupported placeholder should not resolve a thumbnail: {:?}",
                        success
                    );
                }
            }

            stop_server(&mut adapter).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);

        result.expect(
            "thumbnail provider should classify unsupported placeholders as failed extraction",
        );
    }

    #[tokio::test]
    async fn test_thumbnail_provider_reports_extraction_pending_when_server_is_unreachable() {
        let bind = "127.0.0.1:19117";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-thumbnail-provider-pending-server");
        let sync_root = fresh_data_dir("cfapi-thumbnail-provider-pending-sync-root");
        let local_appdata_root = actual_local_appdata_root();
        let local_appdata_state_dir =
            local_appdata_sync_root_state_dir(&local_appdata_root, &sync_root);
        let local_appdata_bootstrap =
            local_appdata_connection_bootstrap_path(&local_appdata_root, &sync_root);
        let local_appdata_identity =
            local_appdata_client_identity_path(&local_appdata_root, &sync_root);
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);
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
                Some("cfapi-thumbnail-provider-pending"),
                Some(600),
            )
            .await?;

            let client_config_dir =
                server_data_dir.join("client-config-thumbnail-provider-pending");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let sync_root_id = format!(
                "ironmesh.systemtest.thumbnail.provider.pending.{}",
                bind.replace(['.', ':'], "_")
            );
            let mut adapter = start_cfapi_adapter_with_bootstrap(
                &sync_root_id,
                "ironmesh System Test Thumbnail Provider Pending Root",
                &sync_root,
                500,
                &bootstrap_file,
            )
            .await?;

            wait_for_path(&local_appdata_bootstrap, 120).await;
            wait_for_path(&local_appdata_identity, 120).await;

            let thumbnail_client = {
                let bootstrap_path = local_appdata_bootstrap.clone();
                let identity_path = local_appdata_identity.clone();
                tokio::task::spawn_blocking(move || {
                    let bootstrap = ConnectionBootstrap::from_path(&bootstrap_path)
                        .expect("failed to load persisted LocalAppData bootstrap");
                    let identity = ClientIdentityMaterial::from_path(&identity_path)
                        .expect("failed to load persisted LocalAppData client identity");
                    bootstrap
                        .build_client_with_identity(&identity)
                        .expect("failed to build authenticated thumbnail test client")
                })
                .await
                .expect("thumbnail client builder task should join")
            };

            thumbnail_client
                .put_large_aware("gallery/retry-later.png", Bytes::from(sample_png_bytes()))
                .await
                .expect("failed to seed remote image");

            let local_file = sync_root.join("gallery").join("retry-later.png");
            wait_for_path(&local_file, 250).await;
            wait_for_placeholder_present(&local_file, 220).await;
            wait_for_placeholder_in_sync(&local_file, 220).await;
            wait_for_placeholder_dehydrated(&local_file, 120).await;

            stop_server(&mut server).await;

            let source_path = local_file.to_string_lossy().to_string();
            let outcome = tokio::task::spawn_blocking(move || {
                debug_thumbnail_outcome_for_source_path(&source_path, 256)
            })
            .await
            .expect("thumbnail provider debug outcome task should join");

            match outcome {
                DebugThumbnailOutcome::Failure(failure) => {
                    assert_eq!(failure.error_kind, "extraction-pending");
                    assert_eq!(failure.hresult, WTS_E_EXTRACTIONPENDING);
                    assert!(
                        failure.message.contains("request failed"),
                        "expected transient request failure message, got: {}",
                        failure.message
                    );
                }
                DebugThumbnailOutcome::Success(success) => {
                    panic!(
                        "unreachable server should not resolve a thumbnail: {:?}",
                        success
                    );
                }
            }

            stop_server(&mut adapter).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        let _ = std::fs::remove_dir_all(&local_appdata_state_dir);

        result.expect(
            "thumbnail provider should classify transient connection failures as extraction pending",
        );
    }

    #[tokio::test]
    async fn test_cfapi_adapter_persists_local_appdata_state_and_restarts_without_bootstrap_argument()
     {
        let bind = "127.0.0.1:19113";
        let base_url = format!("https://{bind}");
        let admin_token = "system-tests-admin-secret";
        let server_data_dir = fresh_data_dir("cfapi-auth-local-appdata-server");
        let sync_root = fresh_data_dir("cfapi-auth-local-appdata-sync-root");
        let local_appdata_dir = fresh_data_dir("cfapi-auth-local-appdata-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        std::fs::create_dir_all(&local_appdata_dir).expect("failed to create local app data root");
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
            let issued_bootstrap = issue_bootstrap_bundle(
                &http,
                &base_url,
                admin_token,
                Some("cfapi-local-appdata"),
                Some(600),
            )
            .await?;

            let client_config_dir = server_data_dir.join("client-config-local-appdata");
            std::fs::create_dir_all(&client_config_dir)
                .expect("failed to create client config dir");
            let bootstrap_file = client_config_dir.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
            issued_bootstrap
                .write_to_path(&bootstrap_file)
                .expect("failed to write bootstrap bundle");

            let local_appdata_state_dir =
                local_appdata_sync_root_state_dir(&local_appdata_dir, &sync_root);
            let local_appdata_bootstrap =
                local_appdata_connection_bootstrap_path(&local_appdata_dir, &sync_root);
            let local_appdata_identity =
                local_appdata_client_identity_path(&local_appdata_dir, &sync_root);

            let sync_root_id = format!(
                "ironmesh.systemtest.authenticated.localappdata.{}",
                bind.replace(['.', ':'], "_")
            );
            let mut adapter = start_cfapi_adapter_with_bootstrap_and_local_appdata(
                &sync_root_id,
                "ironmesh System Test LocalAppData Root",
                &sync_root,
                500,
                &bootstrap_file,
                &local_appdata_dir,
            )
            .await?;

            wait_for_path(&local_appdata_bootstrap, 120).await;
            wait_for_path(&local_appdata_identity, 120).await;
            assert!(
                local_appdata_bootstrap.starts_with(
                    local_appdata_dir
                        .join(LOCAL_STATE_ROOT_DIR)
                        .join(LOCAL_STATE_SYNC_ROOTS_DIR)
                ),
                "bootstrap should be persisted under the LocalAppData sync-root state directory"
            );
            assert_eq!(
                local_appdata_bootstrap.parent(),
                Some(local_appdata_state_dir.as_path())
            );
            assert_eq!(
                local_appdata_identity.parent(),
                Some(local_appdata_state_dir.as_path())
            );
            assert!(
                !sync_root.join(".ironmesh-connection.json").exists(),
                "legacy sync-root bootstrap file should not be created"
            );
            assert!(
                !sync_root.join(".ironmesh-client-identity.json").exists(),
                "legacy sync-root identity file should not be created"
            );

            let persisted_bootstrap = ConnectionBootstrap::from_path(&local_appdata_bootstrap)
                .expect("failed to reload LocalAppData bootstrap");
            assert_eq!(
                persisted_bootstrap.pairing_token, None,
                "persisted LocalAppData bootstrap should not keep the pairing token"
            );
            let persisted_identity = ClientIdentityMaterial::from_path(&local_appdata_identity)
                .expect("failed to reload LocalAppData client identity");
            let sdk = tokio::task::spawn_blocking(move || {
                persisted_bootstrap.build_client_with_identity(&persisted_identity)
            })
            .await
            .expect("bootstrap client builder task should join")
            .expect("failed to build authenticated SDK client from LocalAppData state");

            let first_upload = sync_root.join("localappdata-first-run-upload.txt");
            std::fs::write(&first_upload, b"cfapi local app data first upload")
                .expect("failed to write initial upload file");
            wait_for_remote_payload(
                &sdk,
                "localappdata-first-run-upload.txt",
                b"cfapi local app data first upload",
                220,
            )
            .await;

            stop_server_without_cleanup(&mut adapter).await;
            std::fs::remove_file(&bootstrap_file)
                .expect("failed to remove original bootstrap file before restart");
            wait_for_path_absence(&bootstrap_file, 80).await;

            let mut restarted_adapter = start_cfapi_adapter_with_local_appdata(
                &sync_root_id,
                "ironmesh System Test LocalAppData Root",
                &sync_root,
                500,
                &local_appdata_dir,
            )
            .await?;

            let restarted_upload = sync_root.join("localappdata-restart-upload.txt");
            std::fs::write(&restarted_upload, b"cfapi local app data restart upload")
                .expect("failed to write restart upload file");
            wait_for_remote_payload(
                &sdk,
                "localappdata-restart-upload.txt",
                b"cfapi local app data restart upload",
                220,
            )
            .await;

            stop_server(&mut restarted_adapter).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = std::fs::remove_dir_all(&server_data_dir);
        let _ = std::fs::remove_dir_all(&sync_root);
        let _ = std::fs::remove_dir_all(&local_appdata_dir);

        result.expect(
            "CFAPI adapter should persist LocalAppData state and restart without --bootstrap-file",
        );
    }

    #[tokio::test]
    async fn test_cfapi_cancel_hydration_command_marks_cancel_request_for_active_path() {
        let sync_root = fresh_data_dir("cfapi-cancel-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
        let relative_path = "videos/large.bin";
        let absolute_path = sync_root.join(relative_path.replace('/', "\\"));

        clear_hydration_cancel_request(&sync_root, relative_path)
            .expect("stale cancel marker cleanup should succeed");
        clear_active_hydration(&sync_root, relative_path)
            .expect("stale active marker cleanup should succeed");
        mark_active_hydration(&sync_root, relative_path)
            .expect("active hydration marker should be created");

        cancel_cfapi_placeholder_hydration(&sync_root, &absolute_path.to_string_lossy())
            .await
            .expect("cancel-hydration command should succeed for active hydration");

        assert!(
            has_hydration_cancel_request(&sync_root, relative_path),
            "cancel-hydration command should write the cancel marker for the active path"
        );

        clear_hydration_cancel_request(&sync_root, relative_path)
            .expect("cancel marker cleanup should succeed");
        clear_active_hydration(&sync_root, relative_path)
            .expect("active marker cleanup should succeed");
        let _ = std::fs::remove_dir_all(&sync_root);
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
    async fn test_cfapi_directory_sync_state_tracks_child_upload_activity() {
        let bind = "127.0.0.1:19102";

        let result = async {
            let sync_root = fresh_data_dir("cfapi-directory-sync-state-sync-root");
            std::fs::create_dir_all(&sync_root).expect("failed to create sync root");
            let mut fixture =
                start_authenticated_cfapi_fixture(bind, &sync_root, "cfapi-directory-sync-state")
                    .await?;

            fixture
                .sdk
                .put_large_aware("dir-sync/check.txt", Bytes::from_static(b"remote seed"))
                .await
                .expect("failed to seed remote object");

            let _adapter = start_cfapi_adapter_with_bootstrap(
                "ironmesh.systemtest.directory.sync.state",
                "ironmesh System Test Directory Sync State",
                &sync_root,
                500,
                &fixture.bootstrap_file,
            )
            .await
            .expect("failed to register and serve CFAPI adapter");

            let local_dir = sync_root.join("dir-sync");
            let local_file = local_dir.join("check.txt");
            wait_for_path(&local_dir, 220).await;
            wait_for_path(&local_file, 220).await;
            wait_for_hydrated_payload(&local_file, b"remote seed", 200).await;
            wait_for_sync_item_in_sync(&local_dir, 220).await;

            let modified_payload = format!("{}{}", "D".repeat(6 * 1024 * 1024), "\ndir-sync-tail");
            std::fs::write(&local_file, modified_payload.as_bytes())
                .expect("failed to modify hydrated placeholder");

            wait_for_sync_item_not_in_sync(&local_file, 220).await;
            wait_for_sync_item_not_in_sync(&local_dir, 220).await;
            wait_for_remote_payload(
                &fixture.sdk,
                "dir-sync/check.txt",
                modified_payload.as_bytes(),
                260,
            )
            .await;
            wait_for_sync_item_in_sync(&local_file, 220).await;
            wait_for_sync_item_in_sync(&local_dir, 220).await;

            stop_server(&mut fixture.server).await;
            let _ = std::fs::remove_dir_all(&fixture.server_data_dir);

            Ok::<std::path::PathBuf, anyhow::Error>(sync_root)
        }
        .await;

        match result {
            Ok(sync_root) => {
                let _ = std::fs::remove_dir_all(sync_root);
            }
            Err(err) => panic!("CFAPI directory sync-state flow failed: {err:#}"),
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
