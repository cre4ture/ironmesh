#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, binary_path, fresh_data_dir, register_node, start_server,
        start_server_with_env, stop_server, wait_for_online_nodes, wait_for_store_index_entry,
    };
    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use client_sdk::IronMeshClient;
    use std::fs;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::process::Command;
    use tokio::time::sleep;

    const LARGE_UPLOAD_BYTES: usize = 10 * 1024 * 1024;

    fn fuse_runtime_available() -> bool {
        Path::new("/dev/fuse").exists()
    }

    async fn start_linux_fuse_adapter(
        server_base_url: &str,
        mountpoint: &Path,
    ) -> Result<ChildGuard> {
        start_linux_fuse_adapter_with_refresh(server_base_url, mountpoint, 500).await
    }

    async fn start_linux_fuse_adapter_with_refresh(
        server_base_url: &str,
        mountpoint: &Path,
        remote_refresh_interval_ms: u64,
    ) -> Result<ChildGuard> {
        let os_integration_bin = binary_path("os-integration")?;
        let mountpoint_arg = mountpoint.to_string_lossy().to_string();

        let child = Command::new(os_integration_bin)
            .arg("--server-base-url")
            .arg(server_base_url)
            .arg("--mountpoint")
            .arg(&mountpoint_arg)
            .arg("--remote-refresh-interval-ms")
            .arg(remote_refresh_interval_ms.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn linux fuse adapter via os-integration")?;

        Ok(ChildGuard::new(child))
    }

    async fn wait_for_file(path: &Path, retries: usize) -> Result<()> {
        for _ in 0..retries {
            if path.is_file() {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!("expected mounted file does not exist: {}", path.display());
    }

    async fn wait_for_file_bytes(path: &Path, expected: &[u8], retries: usize) -> Result<()> {
        for _ in 0..retries {
            if let Ok(bytes) = fs::read(path)
                && bytes.as_slice() == expected
            {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!(
            "expected mounted file {} to match provided bytes",
            path.display()
        );
    }

    async fn wait_for_ls_reported_size(
        dir: &Path,
        file_name: &str,
        expected_size: u64,
        retries: usize,
    ) -> Result<()> {
        let dir_arg = dir.to_string_lossy().to_string();

        for _ in 0..retries {
            let output = Command::new("ls")
                .arg("-ln")
                .arg(&dir_arg)
                .output()
                .await
                .with_context(|| format!("failed to run ls -ln {}", dir.display()))?;

            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let columns: Vec<&str> = line.split_whitespace().collect();
                    if columns.len() < 9 {
                        continue;
                    }
                    if columns[8] != file_name {
                        continue;
                    }

                    if let Ok(size) = columns[4].parse::<u64>()
                        && size == expected_size
                    {
                        return Ok(());
                    }
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!(
            "ls -ln {} did not report size {} for {}",
            dir.display(),
            expected_size,
            file_name
        );
    }

    async fn wait_for_metadata_size(path: &Path, expected_size: u64, retries: usize) -> Result<()> {
        for _ in 0..retries {
            if let Ok(metadata) = fs::metadata(path)
                && metadata.is_file()
                && metadata.len() == expected_size
            {
                return Ok(());
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!(
            "metadata for {} did not report size {}",
            path.display(),
            expected_size
        );
    }

    async fn wait_for_dir(path: &Path, retries: usize) -> Result<()> {
        for _ in 0..retries {
            if path.is_dir() {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!(
            "expected mounted directory does not exist: {}",
            path.display()
        );
    }

    async fn wait_for_absence(path: &Path, retries: usize) -> Result<()> {
        for _ in 0..retries {
            if !path.exists() {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!("expected mounted path to disappear: {}", path.display());
    }

    async fn try_unmount(mountpoint: &Path) -> Result<()> {
        let mountpoint_arg = mountpoint.to_string_lossy().to_string();

        for command in ["fusermount3", "fusermount"] {
            if let Ok(status) = Command::new(command)
                .arg("-u")
                .arg(&mountpoint_arg)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                && status.success()
            {
                return Ok(());
            }
        }

        bail!("failed to unmount {}", mountpoint.display());
    }

    async fn stop_linux_fuse_adapter(adapter: &mut ChildGuard, mountpoint: &Path) {
        let _ = try_unmount(mountpoint).await;
        stop_server(adapter).await;
        let _ = try_unmount(mountpoint).await;
    }

    async fn wait_for_object_bytes(
        sdk: &IronMeshClient,
        key: &str,
        expected: &[u8],
        retries: usize,
    ) -> Result<()> {
        for _ in 0..retries {
            if let Ok(bytes) = sdk.get(key).await
                && bytes.as_ref() == expected
            {
                return Ok(());
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("server did not expose expected payload for key {key}");
    }

    async fn wait_for_remote_directory_existence(
        sdk: &IronMeshClient,
        dir_name: &str,
        retries: usize,
    ) -> Result<()> {
        let expected_with_trailing_slash = format!("{dir_name}/");

        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 1, None).await {
                let found = index.entries.iter().any(|entry| {
                    let path_match =
                        entry.path == dir_name || entry.path == expected_with_trailing_slash;
                    let type_match = entry.entry_type == "prefix"
                        || entry.entry_type == "key"
                        || entry.path.ends_with('/');
                    path_match && type_match
                });

                if found {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("store index did not report remote directory for {expected_with_trailing_slash}");
    }

    async fn wait_for_remote_directory_absence(
        sdk: &IronMeshClient,
        dir_name: &str,
        retries: usize,
    ) -> Result<()> {
        let expected_prefix = format!("{}/", dir_name.trim_end_matches('/'));

        for _ in 0..retries {
            if let Ok(index) = sdk.store_index(None, 64, None).await {
                let found = index.entries.iter().any(|entry| {
                    entry.path == dir_name
                        || entry.path == expected_prefix
                        || entry.path.starts_with(&expected_prefix)
                });

                if !found {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("store index still reports remote directory subtree for {expected_prefix}");
    }

    async fn wait_for_remote_file_absence(
        sdk: &IronMeshClient,
        key: &str,
        retries: usize,
    ) -> Result<()> {
        for _ in 0..retries {
            let get_missing = sdk.get(key).await.is_err();
            if let Ok(index) = sdk.store_index(None, 64, None).await {
                let index_missing = !index.entries.iter().any(|entry| entry.path == key);
                if get_missing && index_missing {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("remote file {key} was expected to be deleted");
    }

    async fn run_server_mode_upload_case(
        bind: &str,
        seed_key: &str,
        seed_payload: Vec<u8>,
        upload_key: &str,
        upload_payload: Vec<u8>,
    ) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-live-mount");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            sdk.put_large_aware(seed_key, Bytes::from(seed_payload.clone()))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let mount_result = async {
                let mounted_file = mountpoint.join(seed_key);
                wait_for_file(&mounted_file, 100).await?;

                let hydrated = fs::read(&mounted_file).with_context(|| {
                    format!("failed to read mounted file {}", mounted_file.display())
                })?;
                assert_eq!(hydrated, seed_payload);

                let upload_path = mountpoint.join(upload_key);
                fs::write(&upload_path, &upload_payload).with_context(|| {
                    format!("failed to write mounted file {}", upload_path.display())
                })?;
                wait_for_object_bytes(&sdk, upload_key, &upload_payload, 150).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            mount_result
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_nested_folder_roundtrip_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-nested-folders");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let nested_steps = vec![
            ("l1", "l1/small-l1.txt", b"upload-l1".to_vec()),
            ("l1/l2", "l1/l2/small-l2.txt", b"upload-l2".to_vec()),
            ("l1/l2/l3", "l1/l2/l3/small-l3.txt", b"upload-l3".to_vec()),
        ];

        let result = async {
            // Provide a stable remote seed so we can reliably detect mount readiness.
            sdk.put_large_aware("seed-nested.txt", Bytes::from_static(b"seed-nested"))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let phase_one = async {
                let seed_path = mountpoint.join("seed-nested.txt");
                wait_for_file(&seed_path, 100).await?;

                for step_index in 0..nested_steps.len() {
                    let (dir, key, payload) = &nested_steps[step_index];
                    let dir_path = mountpoint.join(dir);
                    fs::create_dir(&dir_path).with_context(|| {
                        format!("failed to create mounted directory {}", dir_path.display())
                    })?;
                    assert!(
                        dir_path.is_dir(),
                        "expected mounted directory to exist: {}",
                        dir_path.display()
                    );
                    let mounted_path = mountpoint.join(key);
                    fs::write(&mounted_path, payload).with_context(|| {
                        format!("failed to write mounted file {}", mounted_path.display())
                    })?;
                    wait_for_object_bytes(&sdk, key, payload, 150).await?;

                    for step in nested_steps.iter().take(step_index + 1) {
                        let (verify_dir, verify_key, _) = &step;
                        let verify_dir_prefix = format!("{verify_dir}/");
                        let parent = verify_dir.rsplit_once('/').map(|(parent, _)| parent);
                        wait_for_store_index_entry(
                            &sdk,
                            parent,
                            1,
                            &verify_dir_prefix,
                            "prefix",
                            true,
                            150,
                        )
                        .await?;
                        wait_for_store_index_entry(
                            &sdk,
                            Some(verify_dir),
                            1,
                            verify_key,
                            "key",
                            true,
                            150,
                        )
                        .await?;
                    }
                }

                Ok::<(), anyhow::Error>(())
            }
            .await;
            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            phase_one?;

            // Remount to validate download/hydration from server for each uploaded file.
            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let phase_two = async {
                for (dir, key, payload) in &nested_steps {
                    let mounted_path = mountpoint.join(key);
                    wait_for_file(&mounted_path, 100).await?;
                    let downloaded = fs::read(&mounted_path).with_context(|| {
                        format!("failed to read mounted file {}", mounted_path.display())
                    })?;
                    assert_eq!(downloaded, *payload);

                    let dir_prefix = format!("{dir}/");
                    let parent = dir.rsplit_once('/').map(|(parent, _)| parent);
                    wait_for_store_index_entry(&sdk, parent, 1, &dir_prefix, "prefix", true, 150)
                        .await?;
                    wait_for_store_index_entry(&sdk, Some(dir), 1, key, "key", true, 150).await?;
                }

                for step_index in (0..nested_steps.len()).rev() {
                    let (_, key, _) = nested_steps[step_index];
                    let mounted_path = mountpoint.join(key);
                    fs::remove_file(&mounted_path).with_context(|| {
                        format!("failed to remove mounted file {}", mounted_path.display())
                    })?;
                    wait_for_remote_file_absence(&sdk, key, 180).await?;
                }

                for step_index in (0..nested_steps.len()).rev() {
                    let (dir, _, _) = nested_steps[step_index];
                    let dir_path = mountpoint.join(dir);
                    fs::remove_dir(&dir_path).with_context(|| {
                        format!("failed to remove mounted directory {}", dir_path.display())
                    })?;
                    assert!(
                        !dir_path.exists(),
                        "expected mounted directory to be deleted: {}",
                        dir_path.display()
                    );
                    wait_for_remote_directory_absence(&sdk, dir, 180).await?;
                }

                Ok::<(), anyhow::Error>(())
            }
            .await;
            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            phase_two
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_cluster_delete_propagation_case(bind_a: &str, bind_b: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let mountpoint = fresh_data_dir("linux-fuse-cluster-delete");
        let data_a = fresh_data_dir("linux-fuse-cluster-delete-node-a");
        let data_b = fresh_data_dir("linux-fuse-cluster-delete-node-b");
        let node_id_a = "00000000-0000-0000-0000-00000000f101";
        let node_id_b = "00000000-0000-0000-0000-00000000f102";

        let extra_env = [
            ("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "true"),
            ("IRONMESH_STARTUP_REPAIR_ENABLED", "false"),
            ("IRONMESH_REPLICATION_REPAIR_ENABLED", "false"),
        ];

        let mut node_a = start_server_with_env(bind_a, &data_a, node_id_a, 2, &extra_env).await?;
        let mut node_b = start_server_with_env(bind_b, &data_b, node_id_b, 2, &extra_env).await?;
        let sdk_a = IronMeshClient::new(&base_a);
        let sdk_b = IronMeshClient::new(&base_b);
        let http = reqwest::Client::new();

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&http, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;
            wait_for_online_nodes(&http, &base_a, 2, 120).await?;
            wait_for_online_nodes(&http, &base_b, 2, 120).await?;

            sdk_a
                .put_large_aware(
                    "seed-cluster-delete.txt",
                    Bytes::from_static(b"seed-cluster-delete"),
                )
                .await?;

            let mut adapter = start_linux_fuse_adapter(&base_a, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-cluster-delete.txt");
                wait_for_file(&seed_path, 150).await?;

                let dir_name = "cluster-delete";
                let file_key = "cluster-delete/target.txt";
                let file_payload = b"cluster-delete-payload".to_vec();
                let dir_path = mountpoint.join(dir_name);
                let file_path = mountpoint.join(file_key);

                fs::create_dir(&dir_path).with_context(|| {
                    format!("failed to create mounted directory {}", dir_path.display())
                })?;
                wait_for_remote_directory_existence(&sdk_a, dir_name, 180).await?;
                wait_for_remote_directory_existence(&sdk_b, dir_name, 220).await?;

                fs::write(&file_path, &file_payload).with_context(|| {
                    format!("failed to write mounted file {}", file_path.display())
                })?;
                wait_for_object_bytes(&sdk_a, file_key, &file_payload, 180).await?;
                wait_for_object_bytes(&sdk_b, file_key, &file_payload, 220).await?;

                fs::remove_file(&file_path).with_context(|| {
                    format!("failed to remove mounted file {}", file_path.display())
                })?;
                wait_for_remote_file_absence(&sdk_a, file_key, 220).await?;
                wait_for_remote_file_absence(&sdk_b, file_key, 260).await?;

                fs::remove_dir(&dir_path).with_context(|| {
                    format!("failed to remove mounted directory {}", dir_path.display())
                })?;
                wait_for_remote_directory_absence(&sdk_a, dir_name, 220).await?;
                wait_for_remote_directory_absence(&sdk_b, dir_name, 260).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&mountpoint);
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        result
    }

    async fn run_empty_folder_create_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-empty-folder");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            // Seed one remote file so we have a deterministic mount-readiness probe.
            sdk.put_large_aware(
                "seed-empty-folder.txt",
                Bytes::from_static(b"seed-empty-folder"),
            )
            .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-empty-folder.txt");
                wait_for_file(&seed_path, 120).await?;

                let empty_dir_name = "created-empty-dir";
                let empty_dir_path = mountpoint.join(empty_dir_name);
                fs::create_dir(&empty_dir_path).with_context(|| {
                    format!(
                        "failed to create mounted directory {}",
                        empty_dir_path.display()
                    )
                })?;
                assert!(
                    empty_dir_path.is_dir(),
                    "expected mounted directory to exist: {}",
                    empty_dir_path.display()
                );

                wait_for_remote_directory_existence(&sdk, empty_dir_name, 150).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_additions_refresh_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-refresh");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            sdk.put_large_aware("seed-refresh.txt", Bytes::from_static(b"seed-refresh"))
                .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&base_url, &mountpoint, 500).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-refresh.txt");
                wait_for_file(&seed_path, 120).await?;

                sdk.put_large_aware(
                    "live-refresh/added.txt",
                    Bytes::from_static(b"remote-refresh-content"),
                )
                .await?;
                sdk.put("live-refresh/subdir/", Bytes::new()).await?;

                let folder_path = mountpoint.join("live-refresh");
                let nested_folder_path = mountpoint.join("live-refresh").join("subdir");
                let file_path = mountpoint.join("live-refresh").join("added.txt");

                wait_for_dir(&folder_path, 180).await?;
                wait_for_dir(&nested_folder_path, 180).await?;
                wait_for_file(&file_path, 180).await?;

                let hydrated = fs::read(&file_path).with_context(|| {
                    format!("failed to read mounted file {}", file_path.display())
                })?;
                assert_eq!(hydrated, b"remote-refresh-content");

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_update_refresh_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-update-refresh");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            let remote_key = "live-refresh/updated.txt";
            sdk.put_large_aware(remote_key, Bytes::from_static(b"version-one"))
                .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&base_url, &mountpoint, 250).await?;
            let scenario = async {
                let mounted_file = mountpoint.join(remote_key);
                wait_for_file(&mounted_file, 180).await?;
                wait_for_file_bytes(&mounted_file, b"version-one", 180).await?;

                sdk.put_large_aware(remote_key, Bytes::from_static(b"version-two-extended"))
                    .await?;

                wait_for_file_bytes(&mounted_file, b"version-two-extended", 220).await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_file_size_reporting_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-size-reporting");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            let size_probe_payload = b"size-probe-remote-file".to_vec();
            sdk.put_large_aware("seed-size-reporting.txt", Bytes::from_static(b"seed-size"))
                .await?;
            sdk.put_large_aware("reported-size.txt", Bytes::from(size_probe_payload.clone()))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-size-reporting.txt");
                wait_for_file(&seed_path, 120).await?;

                wait_for_ls_reported_size(
                    &mountpoint,
                    "reported-size.txt",
                    size_probe_payload.len() as u64,
                    180,
                )
                .await?;
                wait_for_metadata_size(
                    &mountpoint.join("reported-size.txt"),
                    size_probe_payload.len() as u64,
                    180,
                )
                .await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_local_rename_move_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-local-rename-move");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            sdk.put_large_aware(
                "seed-local-rename.txt",
                Bytes::from_static(b"seed-local-rename"),
            )
            .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-local-rename.txt");
                wait_for_file(&seed_path, 120).await?;

                let local_file_payload = b"local-file-move-payload".to_vec();
                let file_from_dir = mountpoint.join("local-file-move").join("from");
                let file_to_dir = mountpoint.join("local-file-move").join("to");
                fs::create_dir_all(&file_from_dir).with_context(|| {
                    format!(
                        "failed to create mounted directory {}",
                        file_from_dir.display()
                    )
                })?;
                fs::create_dir_all(&file_to_dir).with_context(|| {
                    format!(
                        "failed to create mounted directory {}",
                        file_to_dir.display()
                    )
                })?;

                let file_from = file_from_dir.join("source.txt");
                let file_to = file_to_dir.join("renamed.txt");
                fs::write(&file_from, &local_file_payload).with_context(|| {
                    format!("failed to write mounted file {}", file_from.display())
                })?;
                wait_for_object_bytes(
                    &sdk,
                    "local-file-move/from/source.txt",
                    &local_file_payload,
                    180,
                )
                .await?;

                fs::rename(&file_from, &file_to).with_context(|| {
                    format!(
                        "failed to rename mounted file {} -> {}",
                        file_from.display(),
                        file_to.display()
                    )
                })?;
                wait_for_file(&file_to, 120).await?;
                wait_for_absence(&file_from, 120).await?;
                wait_for_object_bytes(
                    &sdk,
                    "local-file-move/to/renamed.txt",
                    &local_file_payload,
                    180,
                )
                .await?;
                wait_for_store_index_entry(
                    &sdk,
                    None,
                    64,
                    "local-file-move/from/source.txt",
                    "key",
                    false,
                    180,
                )
                .await?;

                let local_folder_payload = b"local-folder-move-payload".to_vec();
                let folder_from = mountpoint.join("local-folder-move").join("from");
                let folder_from_nested = folder_from.join("nested");
                fs::create_dir_all(&folder_from_nested).with_context(|| {
                    format!(
                        "failed to create mounted directory {}",
                        folder_from_nested.display()
                    )
                })?;
                let folder_from_file = folder_from_nested.join("inside.txt");
                fs::write(&folder_from_file, &local_folder_payload).with_context(|| {
                    format!(
                        "failed to write mounted file {}",
                        folder_from_file.display()
                    )
                })?;
                wait_for_object_bytes(
                    &sdk,
                    "local-folder-move/from/nested/inside.txt",
                    &local_folder_payload,
                    180,
                )
                .await?;

                let folder_to = mountpoint.join("local-folder-move").join("to");
                fs::rename(&folder_from, &folder_to).with_context(|| {
                    format!(
                        "failed to rename mounted directory {} -> {}",
                        folder_from.display(),
                        folder_to.display()
                    )
                })?;
                let folder_to_file = folder_to.join("nested").join("inside.txt");
                wait_for_file(&folder_to_file, 120).await?;
                wait_for_absence(&folder_from, 120).await?;
                wait_for_object_bytes(
                    &sdk,
                    "local-folder-move/to/nested/inside.txt",
                    &local_folder_payload,
                    200,
                )
                .await?;
                wait_for_store_index_entry(
                    &sdk,
                    None,
                    64,
                    "local-folder-move/from/nested/inside.txt",
                    "key",
                    false,
                    200,
                )
                .await?;
                wait_for_store_index_entry(
                    &sdk,
                    Some("local-folder-move"),
                    1,
                    "local-folder-move/to/",
                    "prefix",
                    true,
                    200,
                )
                .await?;
                wait_for_remote_directory_absence(&sdk, "local-folder-move/from", 200).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_rename_move_refresh_case(bind: &str) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-rename-move");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            sdk.put_large_aware(
                "seed-remote-rename.txt",
                Bytes::from_static(b"seed-remote-rename"),
            )
            .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&base_url, &mountpoint, 250).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-remote-rename.txt");
                wait_for_file(&seed_path, 120).await?;

                let remote_file_payload = b"remote-file-move-payload".to_vec();
                let remote_file_from = "remote-file-move/from.txt";
                let remote_file_to = "remote-file-move/sub/renamed.txt";
                sdk.put_large_aware(remote_file_from, Bytes::from(remote_file_payload.clone()))
                    .await?;

                let mounted_remote_file_from = mountpoint.join(remote_file_from);
                wait_for_file(&mounted_remote_file_from, 180).await?;
                sdk.rename_path(remote_file_from, remote_file_to, false)
                    .await?;

                let mounted_remote_file_to = mountpoint.join(remote_file_to);
                wait_for_file(&mounted_remote_file_to, 240).await?;
                wait_for_file_bytes(&mounted_remote_file_to, &remote_file_payload, 240).await?;
                wait_for_absence(&mounted_remote_file_from, 240).await?;

                let remote_folder_payload = b"remote-folder-move-payload".to_vec();
                let old_root = "remote-folder-move/from";
                let old_nested_marker = "remote-folder-move/from/nested/";
                let old_root_marker = "remote-folder-move/from/";
                let old_file = "remote-folder-move/from/nested/inside.txt";
                let new_root_marker = "remote-folder-move/to/";
                let new_nested_marker = "remote-folder-move/to/nested/";
                let new_file = "remote-folder-move/to/nested/inside.txt";

                sdk.put(old_root_marker, Bytes::new()).await?;
                sdk.put(old_nested_marker, Bytes::new()).await?;
                sdk.put_large_aware(old_file, Bytes::from(remote_folder_payload.clone()))
                    .await?;

                let mounted_old_file = mountpoint.join(old_file);
                wait_for_file(&mounted_old_file, 220).await?;

                sdk.rename_path(old_file, new_file, false).await?;
                sdk.rename_path(old_nested_marker, new_nested_marker, false)
                    .await?;
                sdk.rename_path(old_root_marker, new_root_marker, false)
                    .await?;

                let mounted_new_file = mountpoint.join(new_file);
                wait_for_file(&mounted_new_file, 260).await?;
                wait_for_file_bytes(&mounted_new_file, &remote_folder_payload, 260).await?;
                wait_for_absence(&mountpoint.join(old_root), 260).await?;
                wait_for_dir(&mountpoint.join("remote-folder-move/to"), 260).await?;
                wait_for_remote_directory_absence(&sdk, old_root, 220).await?;
                wait_for_store_index_entry(
                    &sdk,
                    Some("remote-folder-move"),
                    1,
                    "remote-folder-move/to/",
                    "prefix",
                    true,
                    220,
                )
                .await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    #[tokio::test]
    async fn linux_fuse_server_mode_uploads_small_payload() -> Result<()> {
        run_server_mode_upload_case(
            "127.0.0.1:19360",
            "seed-small.txt",
            b"hello-from-live-server".to_vec(),
            "upload-small.txt",
            b"uploaded-via-fuse-small".to_vec(),
        )
        .await
    }

    #[tokio::test]
    async fn linux_fuse_server_mode_uploads_large_10mb_payload() -> Result<()> {
        let seed_payload = b"seed-large".to_vec();
        let mut upload_payload = vec![b'Z'; LARGE_UPLOAD_BYTES];
        upload_payload[0..9].copy_from_slice(b"10MBHEAD:");
        upload_payload[LARGE_UPLOAD_BYTES - 8..LARGE_UPLOAD_BYTES].copy_from_slice(b":10MBEND");

        run_server_mode_upload_case(
            "127.0.0.1:19361",
            "seed-large.txt",
            seed_payload,
            "upload-large-10mb.bin",
            upload_payload,
        )
        .await
    }

    #[tokio::test]
    async fn linux_fuse_server_mode_nested_folders_create_delete_and_file_roundtrip() -> Result<()>
    {
        run_nested_folder_roundtrip_case("127.0.0.1:19362").await
    }

    #[tokio::test]
    async fn linux_fuse_creates_empty_folder_and_persists_remote_prefix() -> Result<()> {
        run_empty_folder_create_case("127.0.0.1:19365").await
    }

    #[tokio::test]
    async fn linux_fuse_remote_additions_materialize_without_remount() -> Result<()> {
        run_remote_additions_refresh_case("127.0.0.1:19363").await
    }

    #[tokio::test]
    async fn linux_fuse_remote_file_update_refreshes_without_remount() -> Result<()> {
        run_remote_update_refresh_case("127.0.0.1:19364").await
    }

    #[tokio::test]
    async fn linux_fuse_reports_remote_file_sizes_to_ls() -> Result<()> {
        run_remote_file_size_reporting_case("127.0.0.1:19370").await
    }

    #[tokio::test]
    async fn linux_fuse_local_file_and_folder_renames_moves_sync_to_remote() -> Result<()> {
        run_local_rename_move_case("127.0.0.1:19366").await
    }

    #[tokio::test]
    async fn linux_fuse_remote_file_and_folder_renames_moves_refresh_in_place() -> Result<()> {
        run_remote_rename_move_refresh_case("127.0.0.1:19367").await
    }

    #[tokio::test]
    async fn linux_fuse_local_deletes_propagate_across_cluster() -> Result<()> {
        run_cluster_delete_propagation_case("127.0.0.1:19368", "127.0.0.1:19369").await
    }
}
