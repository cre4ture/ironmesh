#![cfg(windows)]

#[cfg(test)]
mod tests {
    use crate::framework::{fresh_data_dir, start_server};
    use crate::framework_win::{start_cfapi_adapter, start_cfapi_adapter_with_refresh};
    use bytes::Bytes;
    use client_sdk::IronMeshClient;
    use reqwest::Client;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use std::time::Duration;

    async fn run_cfapi_monitor_case(bind: &str, initial_content: &str, modified_content: &str) {
        let _server = start_server(bind)
            .await
            .expect("Failed to start local server-node");

        let base_url = format!("http://{bind}");
        let sync_root = fresh_data_dir("cfapi-monitor-sync-root-parameterized");
        std::fs::create_dir_all(&sync_root).expect("Failed to create sync root");

        let test_file = sync_root.join("monitor_test.txt");
        let server_url = format!("{}/store/monitor_test.txt", base_url);
        let client = Client::new();

        // Step 1: Create new file
        let mut file = File::create(&test_file).expect("Failed to create file");
        file.write_all(initial_content.as_bytes())
            .expect("Failed to write initial content");
        file.sync_all().expect("Failed to sync file");

        // start CFAPI adapter to monitor the sync root and upload changes to server
        let _adapter = start_cfapi_adapter(
            "ironmesh.systemtest.syncroot",
            "ironmesh System Test Sync Root",
            &sync_root,
            &base_url,
        )
        .await
        .expect("Failed to register and serve CFAPI adapter");

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(20)).await;
        let resp = client
            .get(&server_url)
            .send()
            .await
            .expect("Failed to GET file");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(
            body.contains(initial_content),
            "Initial content not found on server"
        );

        // Step 2: Modify file
        let mut file = File::create(&test_file).expect("Failed to open file for modification");
        file.write_all(modified_content.as_bytes())
            .expect("Failed to write modified content");
        file.sync_all().expect("Failed to sync file");
        file.flush().expect("Failed to flush file");
        drop(file); // close file to ensure changes are flushed

        // Wait for monitor to detect and upload
        tokio::time::sleep(Duration::from_secs(20)).await;
        let resp = client
            .get(&server_url)
            .send()
            .await
            .expect("Failed to GET file after modification");
        let body = resp.text().await.expect("Failed to read response body");
        assert!(
            body.contains(modified_content),
            "Modified content not found on server"
        );
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
        let _server = start_server(bind)
            .await
            .expect("failed to start local server-node");

        let base_url = format!("http://{bind}");
        let sync_root = fresh_data_dir("cfapi-hydration-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");

        let sdk = IronMeshClient::new(&base_url);
        let path_parts: Vec<&str> = key.split('/').collect();
        let mut current_dir = String::new();
        for dir in path_parts.iter().take(path_parts.len() - 1) {
            if !current_dir.is_empty() {
                current_dir.push('/');
            }
            current_dir.push_str(dir);
            let dir_key = format!("{current_dir}/");
            sdk.put(dir_key, Bytes::new())
                .await
                .expect("failed to put folder");
        }
        sdk.put_large_aware(key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote object");

        let sync_root_id = format!(
            "ironmesh.systemtest.hydration.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter(
            &sync_root_id,
            "ironmesh System Test Hydration Root",
            &sync_root,
            &base_url,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let local_file = sync_root.join(key.replace('/', "\\"));
        wait_for_path(&local_file, 200).await;
        wait_for_hydrated_payload(&local_file, payload, 150).await;
    }

    async fn run_cfapi_remote_additions_case(
        bind: &str,
        folder_key: &str,
        file_key: &str,
        payload: &[u8],
    ) {
        let _server = start_server(bind)
            .await
            .expect("failed to start local server-node");

        let base_url = format!("http://{bind}");
        let sync_root = fresh_data_dir("cfapi-remote-additions-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");

        let sync_root_id = format!(
            "ironmesh.systemtest.remote.additions.{}",
            bind.replace(['.', ':'], "_")
        );
        let _adapter = start_cfapi_adapter(
            &sync_root_id,
            "ironmesh System Test Remote Additions Root",
            &sync_root,
            &base_url,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let sdk = IronMeshClient::new(&base_url);
        sdk.put(folder_key, Bytes::new())
            .await
            .expect("failed to seed remote folder marker");
        sdk.put_large_aware(file_key, Bytes::from(payload.to_vec()))
            .await
            .expect("failed to seed remote file");

        let folder_path = sync_root.join(folder_key.trim_end_matches('/').replace('/', "\\"));
        let local_file = sync_root.join(file_key.replace('/', "\\"));
        wait_for_path(&folder_path, 250).await;
        wait_for_path(&local_file, 250).await;
        wait_for_hydrated_payload(&local_file, payload, 200).await;
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
        let _server = start_server("127.0.0.1:19095")
            .await
            .expect("failed to start local server-node");

        let base_url = "http://127.0.0.1:19095";
        let sdk = IronMeshClient::new(base_url);
        let sync_root = fresh_data_dir("cfapi-local-empty-folder-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");

        let _adapter = start_cfapi_adapter_with_refresh(
            "ironmesh.systemtest.local.empty.folder",
            "ironmesh System Test Local Empty Folder",
            &sync_root,
            base_url,
            500,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let empty_dir = sync_root.join("created-empty-folder");
        std::fs::create_dir_all(&empty_dir)
            .expect("failed to create empty folder inside sync root");
        wait_for_path(&empty_dir, 50).await;

        wait_for_remote_directory_marker_shape(&sdk, "created-empty-folder", 220).await;
    }

    #[tokio::test]
    async fn test_cfapi_local_empty_folder_rename_updates_remote_namespace() {
        let _server = start_server("127.0.0.1:19096")
            .await
            .expect("failed to start local server-node");

        let base_url = "http://127.0.0.1:19096";
        let sdk = IronMeshClient::new(base_url);
        sdk.put("rename-empty/from/", Bytes::new())
            .await
            .expect("failed to seed remote empty folder marker");

        let sync_root = fresh_data_dir("cfapi-local-empty-folder-rename-sync-root");
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");

        let _adapter = start_cfapi_adapter_with_refresh(
            "ironmesh.systemtest.local.empty.folder.rename",
            "ironmesh System Test Local Empty Folder Rename",
            &sync_root,
            base_url,
            500,
        )
        .await
        .expect("failed to register and serve CFAPI adapter");

        let old_dir = sync_root.join("rename-empty").join("from");
        let new_dir = sync_root.join("rename-empty").join("to");
        wait_for_path(&old_dir, 220).await;
        std::fs::rename(&old_dir, &new_dir)
            .expect("failed to rename empty folder inside sync root");
        wait_for_path(&new_dir, 50).await;

        wait_for_remote_directory_presence_any_shape(&sdk, "rename-empty/to", 220).await;
        wait_for_remote_directory_absence(&sdk, "rename-empty/from", 220).await;
    }
}
