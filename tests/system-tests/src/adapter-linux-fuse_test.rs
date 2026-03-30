#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, TEST_ADMIN_TOKEN, binary_path, fresh_data_dir,
        issue_bootstrap_bundle_and_enroll_client, lock_test_resources, path_resource_key,
        register_node, start_authenticated_server, start_open_server_with_env,
        start_rendezvous_service, stop_server, wait_for_online_nodes,
        wait_for_rendezvous_registered_endpoints, wait_for_store_index_entry, wait_for_url_status,
    };
    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use client_sdk::IronMeshClient;
    use reqwest::StatusCode;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::process::Command;
    use tokio::time::sleep;
    use uuid::Uuid;

    const LARGE_UPLOAD_BYTES: usize = 10 * 1024 * 1024;

    #[derive(Debug, Clone)]
    struct LinuxFuseConnection {
        server_base_url: Option<String>,
        bootstrap_path: Option<PathBuf>,
        client_identity_path: Option<PathBuf>,
    }

    impl LinuxFuseConnection {
        fn direct(server_base_url: impl Into<String>) -> Self {
            Self {
                server_base_url: Some(server_base_url.into()),
                bootstrap_path: None,
                client_identity_path: None,
            }
        }

        fn apply_to_command(&self, command: &mut Command) {
            if let Some(server_base_url) = self.server_base_url.as_deref() {
                command.arg("--server-base-url").arg(server_base_url);
            }
            if let Some(bootstrap_path) = self.bootstrap_path.as_deref() {
                command.arg("--bootstrap-file").arg(bootstrap_path);
            }
            if let Some(client_identity_path) = self.client_identity_path.as_deref() {
                command
                    .arg("--client-identity-file")
                    .arg(client_identity_path);
            }
        }
    }

    struct AuthenticatedLinuxFuseFixture {
        server: ChildGuard,
        sdk: IronMeshClient,
        connection: LinuxFuseConnection,
    }

    async fn start_authenticated_linux_fuse_fixture(
        bind: &str,
    ) -> Result<AuthenticatedLinuxFuseFixture> {
        let nonce = bind.replace(['.', ':'], "-");
        let data_dir = fresh_data_dir(&format!("linux-fuse-auth-server-{nonce}"));
        let client_dir = fresh_data_dir(&format!("linux-fuse-auth-client-{nonce}"));
        let node_id = Uuid::new_v4().to_string();
        let server = start_authenticated_server(bind, &data_dir, &node_id, 1).await?;
        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "linux-fuse.bootstrap.json",
            Some("linux-fuse-test"),
            Some(3600),
        )
        .await?;
        let sdk = enrolled.build_client_async().await?;
        let connection = LinuxFuseConnection {
            server_base_url: None,
            bootstrap_path: Some(enrolled.bootstrap_path.clone()),
            client_identity_path: Some(crate::framework::default_client_identity_path(
                &enrolled.bootstrap_path,
            )),
        };
        Ok(AuthenticatedLinuxFuseFixture {
            server,
            sdk,
            connection,
        })
    }

    fn fuse_runtime_available() -> bool {
        Path::new("/dev/fuse").exists()
    }

    async fn start_linux_fuse_adapter(
        connection: &LinuxFuseConnection,
        mountpoint: &Path,
    ) -> Result<ChildGuard> {
        start_linux_fuse_adapter_with_refresh(connection, mountpoint, 500).await
    }

    async fn start_linux_fuse_adapter_with_refresh(
        connection: &LinuxFuseConnection,
        mountpoint: &Path,
        remote_refresh_interval_ms: u64,
    ) -> Result<ChildGuard> {
        let os_integration_bin = binary_path("os-integration")?;
        let mountpoint_arg = mountpoint.to_string_lossy().to_string();
        let resource_guards = lock_test_resources([
            "linux-fuse-adapter".to_string(),
            path_resource_key(mountpoint),
        ])
        .await;

        let mut command = Command::new(os_integration_bin);
        connection.apply_to_command(&mut command);
        let child = command
            .arg("--mountpoint")
            .arg(&mountpoint_arg)
            .arg("--remote-refresh-interval-ms")
            .arg(remote_refresh_interval_ms.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn linux fuse adapter via os-integration")?;

        Ok(ChildGuard::with_resources(child, resource_guards))
    }

    struct LocalEdgeClusterFixture {
        rendezvous: ChildGuard,
        upstream: ChildGuard,
        local_edge: ChildGuard,
        rendezvous_url: String,
        upstream_bind: String,
        upstream_base_url: String,
        upstream_data_dir: PathBuf,
        upstream_node_id: String,
        cluster_id: String,
        local_edge_base_url: String,
    }

    impl LocalEdgeClusterFixture {
        async fn restart_upstream(&mut self) -> Result<()> {
            stop_server(&mut self.upstream).await;
            self.upstream = start_cluster_node(
                &self.upstream_bind,
                &self.upstream_data_dir,
                &self.upstream_node_id,
                &self.cluster_id,
                &self.rendezvous_url,
            )
            .await?;
            self.wait_until_ready(2).await
        }

        async fn stop(&mut self) {
            stop_server(&mut self.local_edge).await;
            stop_server(&mut self.upstream).await;
            stop_server(&mut self.rendezvous).await;
        }

        async fn wait_until_ready(&self, expected_online_nodes: u64) -> Result<()> {
            let http = reqwest::Client::new();
            wait_for_rendezvous_registered_endpoints(
                &self.rendezvous_url,
                expected_online_nodes,
                120,
            )
            .await?;
            wait_for_online_nodes(&http, &self.upstream_base_url, expected_online_nodes, 120)
                .await?;
            wait_for_online_nodes(&http, &self.local_edge_base_url, expected_online_nodes, 120)
                .await
        }
    }

    async fn start_cluster_node(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        cluster_id: &str,
        rendezvous_url: &str,
    ) -> Result<ChildGuard> {
        let cluster_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url),
            ("IRONMESH_RELAY_MODE", "fallback"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
        ];
        start_open_server_with_env(bind, data_dir, node_id, 2, &cluster_env).await
    }

    async fn start_local_edge_node(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        cluster_id: &str,
        rendezvous_url: &str,
    ) -> Result<ChildGuard> {
        let cluster_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url),
            ("IRONMESH_RELAY_MODE", "fallback"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
        ];
        start_open_server_with_env(bind, data_dir, node_id, 2, &cluster_env).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_local_edge_cluster_fixture(
        rendezvous_bind: &str,
        upstream_bind: &str,
        local_edge_bind: &str,
        upstream_data_dir: &Path,
        local_edge_data_dir: &Path,
        cluster_id: &str,
        upstream_node_id: &str,
        local_edge_node_id: &str,
    ) -> Result<LocalEdgeClusterFixture> {
        let rendezvous_url = format!("http://{rendezvous_bind}");
        let upstream_base_url = format!("http://{upstream_bind}");
        let local_edge_base_url = format!("http://{local_edge_bind}");

        let rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        wait_for_url_status(
            &format!("{rendezvous_url}/control/presence"),
            StatusCode::OK,
            40,
        )
        .await?;
        let upstream = start_cluster_node(
            upstream_bind,
            upstream_data_dir,
            upstream_node_id,
            cluster_id,
            &rendezvous_url,
        )
        .await?;
        let local_edge = start_local_edge_node(
            local_edge_bind,
            local_edge_data_dir,
            local_edge_node_id,
            cluster_id,
            &rendezvous_url,
        )
        .await?;

        let fixture = LocalEdgeClusterFixture {
            rendezvous,
            upstream,
            local_edge,
            rendezvous_url,
            upstream_bind: upstream_bind.to_string(),
            upstream_base_url,
            upstream_data_dir: upstream_data_dir.to_path_buf(),
            upstream_node_id: upstream_node_id.to_string(),
            cluster_id: cluster_id.to_string(),
            local_edge_base_url,
        };
        fixture.wait_until_ready(2).await?;
        Ok(fixture)
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

    async fn create_mounted_dir_all(path: &Path, retries: usize) -> Result<()> {
        let mut last_err = None;

        for _ in 0..retries {
            match fs::create_dir_all(path) {
                Ok(()) => return Ok(()),
                Err(err) => last_err = Some(err),
            }
            sleep(Duration::from_millis(100)).await;
        }

        let err = last_err
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("mounted mkdir retries exhausted"));
        Err(err).with_context(|| format!("failed to create mounted directory {}", path.display()))
    }

    async fn wait_for_mount_active(path: &Path, retries: usize) -> Result<()> {
        let mountpoint = path.to_string_lossy().to_string();

        for _ in 0..retries {
            if let Ok(mounts) = fs::read_to_string("/proc/mounts")
                && mounts.lines().any(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .map(|entry| entry == mountpoint)
                        .unwrap_or(false)
                })
            {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!("mountpoint did not become active: {}", path.display());
    }

    fn mounted_path_absent(path: &Path) -> bool {
        if let Some(parent) = path.parent()
            && let Ok(entries) = fs::read_dir(parent)
        {
            let target_name = path.file_name().and_then(|name| name.to_str());
            let mut found = false;
            for entry in entries.flatten() {
                if entry.file_name().to_str() == target_name {
                    found = true;
                    break;
                }
            }
            if !found {
                return true;
            }
        }

        !path.exists()
    }

    async fn wait_for_absence(path: &Path, retries: usize) -> Result<()> {
        for _ in 0..retries {
            if mounted_path_absent(path) {
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

    async fn wait_for_remote_sync_via_local_edge(
        local_edge_base_url: &str,
        sdk: &IronMeshClient,
        key: &str,
        expected: &[u8],
        retries: usize,
    ) -> Result<()> {
        let http = reqwest::Client::new();

        for _ in 0..retries {
            let _ = http
                .post(format!(
                    "{}/cluster/replication/repair",
                    local_edge_base_url.trim_end_matches('/')
                ))
                .send()
                .await;

            if let Ok(bytes) = sdk.get(key).await
                && bytes.as_ref() == expected
            {
                return Ok(());
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("server did not expose expected payload for key {key} after local-edge repair");
    }

    async fn trigger_local_edge_repair(local_edge_base_url: &str) {
        let http = reqwest::Client::new();
        let _ = http
            .post(format!(
                "{}/cluster/replication/repair",
                local_edge_base_url.trim_end_matches('/')
            ))
            .send()
            .await;
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
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-live-mount");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            sdk.put_large_aware(seed_key, Bytes::from(seed_payload.clone()))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_nested_folder_roundtrip_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-nested-folders");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let nested_steps = vec![
            ("l1", "l1/small-l1.txt", b"upload-l1".to_vec()),
            ("l1/l2", "l1/l2/small-l2.txt", b"upload-l2".to_vec()),
            ("l1/l2/l3", "l1/l2/l3/small-l3.txt", b"upload-l3".to_vec()),
        ];

        let result = async {
            // Provide a stable remote seed so we can reliably detect mount readiness.
            sdk.put_large_aware("seed-nested.txt", Bytes::from_static(b"seed-nested"))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
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
            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_cluster_delete_propagation_case(bind_a: &str, bind_b: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
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

        let mut node_a =
            start_open_server_with_env(bind_a, &data_a, node_id_a, 2, &extra_env).await?;
        let mut node_b =
            start_open_server_with_env(bind_b, &data_b, node_id_b, 2, &extra_env).await?;
        let sdk_a = IronMeshClient::from_direct_base_url(&base_a);
        let sdk_b = IronMeshClient::from_direct_base_url(&base_b);
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

            let node_a_connection = LinuxFuseConnection::direct(base_a.clone());
            let mut adapter = start_linux_fuse_adapter(&node_a_connection, &mountpoint).await?;
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
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-empty-folder");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            // Seed one remote file so we have a deterministic mount-readiness probe.
            sdk.put_large_aware(
                "seed-empty-folder.txt",
                Bytes::from_static(b"seed-empty-folder"),
            )
            .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_additions_refresh_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-remote-refresh");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            sdk.put_large_aware("seed-refresh.txt", Bytes::from_static(b"seed-refresh"))
                .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&fixture.connection, &mountpoint, 500)
                    .await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_additions_refresh_local_edge_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let local_edge_bind = "127.0.0.1:19472";
        let rendezvous_bind = "127.0.0.1:19572";
        let cluster_id = "11111111-1111-7111-8111-111111111372";
        let upstream_node_id = "00000000-0000-0000-0000-000000001372";
        let local_edge_node_id = "00000000-0000-0000-0000-000000011372";
        let base_url = format!("http://{bind}");
        let local_edge_base_url = format!("http://{local_edge_bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-refresh-local-edge");
        let upstream_data_dir = fresh_data_dir("linux-fuse-remote-refresh-local-edge-upstream");
        let local_edge_data_dir = fresh_data_dir("linux-fuse-remote-refresh-local-edge-node");
        let mut cluster = start_local_edge_cluster_fixture(
            rendezvous_bind,
            bind,
            local_edge_bind,
            &upstream_data_dir,
            &local_edge_data_dir,
            cluster_id,
            upstream_node_id,
            local_edge_node_id,
        )
        .await?;
        let sdk = IronMeshClient::from_direct_base_url(&base_url);

        let result = async {
            sdk.put_large_aware("seed-refresh.txt", Bytes::from_static(b"seed-refresh"))
                .await?;

            let local_edge_connection = LinuxFuseConnection::direct(local_edge_base_url.clone());
            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&local_edge_connection, &mountpoint, 250)
                    .await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-refresh.txt");
                wait_for_mount_active(&mountpoint, 150).await?;
                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if seed_path.is_file() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&seed_path, 40).await?;

                sdk.put_large_aware(
                    "live-refresh-local-edge/added.txt",
                    Bytes::from_static(b"remote-refresh-content-local-edge"),
                )
                .await?;
                sdk.put("live-refresh-local-edge/subdir/", Bytes::new())
                    .await?;

                let folder_path = mountpoint.join("live-refresh-local-edge");
                let nested_folder_path = mountpoint.join("live-refresh-local-edge").join("subdir");
                let file_path = mountpoint.join("live-refresh-local-edge").join("added.txt");
                let expected_payload = b"remote-refresh-content-local-edge";

                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;

                    if folder_path.is_dir()
                        && nested_folder_path.is_dir()
                        && file_path.is_file()
                        && let Ok(hydrated) = fs::read(&file_path)
                        && hydrated == expected_payload
                    {
                        return Ok::<(), anyhow::Error>(());
                    }

                    sleep(Duration::from_millis(100)).await;
                }

                bail!(
                    "local-edge mounted refresh did not materialize remote additions at {}",
                    file_path.display()
                )
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        cluster.stop().await;
        let _ = fs::remove_dir_all(&mountpoint);
        let _ = fs::remove_dir_all(&upstream_data_dir);
        let _ = fs::remove_dir_all(&local_edge_data_dir);
        result
    }

    async fn run_remote_delete_refresh_local_edge_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let local_edge_bind = "127.0.0.1:19473";
        let rendezvous_bind = "127.0.0.1:19573";
        let cluster_id = "11111111-1111-7111-8111-111111111373";
        let upstream_node_id = "00000000-0000-0000-0000-000000001373";
        let local_edge_node_id = "00000000-0000-0000-0000-000000011373";
        let base_url = format!("http://{bind}");
        let local_edge_base_url = format!("http://{local_edge_bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-delete-local-edge");
        let upstream_data_dir = fresh_data_dir("linux-fuse-remote-delete-local-edge-upstream");
        let local_edge_data_dir = fresh_data_dir("linux-fuse-remote-delete-local-edge-node");
        let mut cluster = start_local_edge_cluster_fixture(
            rendezvous_bind,
            bind,
            local_edge_bind,
            &upstream_data_dir,
            &local_edge_data_dir,
            cluster_id,
            upstream_node_id,
            local_edge_node_id,
        )
        .await?;
        let sdk = IronMeshClient::from_direct_base_url(&base_url);

        let result = async {
            sdk.put_large_aware(
                "seed-remote-delete-local-edge.txt",
                Bytes::from_static(b"seed"),
            )
            .await?;

            let local_edge_connection = LinuxFuseConnection::direct(local_edge_base_url.clone());
            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&local_edge_connection, &mountpoint, 250)
                    .await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-remote-delete-local-edge.txt");
                wait_for_mount_active(&mountpoint, 150).await?;
                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if seed_path.is_file() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&seed_path, 40).await?;

                let unique = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let remote_file_payload = b"remote-file-delete-local-edge-payload".to_vec();
                let remote_file = format!("remote-file-delete-local-edge-{unique}/from.txt");
                sdk.put_large_aware(
                    remote_file.clone(),
                    Bytes::from(remote_file_payload.clone()),
                )
                .await?;

                let mounted_remote_file = mountpoint.join(&remote_file);
                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if mounted_remote_file.is_file() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&mounted_remote_file, 40).await?;
                wait_for_file_bytes(&mounted_remote_file, &remote_file_payload, 40).await?;

                sdk.delete_path(&remote_file).await?;
                let local_edge_sdk = IronMeshClient::from_direct_base_url(&local_edge_base_url);
                wait_for_remote_file_absence(&local_edge_sdk, &remote_file, 80).await?;
                for _ in 0..260 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if mounted_path_absent(&mounted_remote_file) {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_absence(&mounted_remote_file, 40).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        cluster.stop().await;
        let _ = fs::remove_dir_all(&mountpoint);
        let _ = fs::remove_dir_all(&upstream_data_dir);
        let _ = fs::remove_dir_all(&local_edge_data_dir);
        result
    }

    async fn run_remote_update_refresh_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-remote-update-refresh");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            let remote_key = "live-refresh/updated.txt";
            sdk.put_large_aware(remote_key, Bytes::from_static(b"version-one"))
                .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&fixture.connection, &mountpoint, 250)
                    .await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_file_size_reporting_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-size-reporting");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            let size_probe_payload = b"size-probe-remote-file".to_vec();
            sdk.put_large_aware("seed-size-reporting.txt", Bytes::from_static(b"seed-size"))
                .await?;
            sdk.put_large_aware("reported-size.txt", Bytes::from(size_probe_payload.clone()))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_zero_byte_create_persistence_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-zero-byte-persistence");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            sdk.put_large_aware("seed-zero-byte.txt", Bytes::from_static(b"seed"))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-zero-byte.txt");
                wait_for_file(&seed_path, 120).await?;

                let created_empty = mountpoint.join("created-empty.txt");
                fs::File::create(&created_empty).with_context(|| {
                    format!("failed to create mounted file {}", created_empty.display())
                })?;
                wait_for_object_bytes(&sdk, "created-empty.txt", b"", 180).await?;

                let truncated_empty = mountpoint.join("truncated-empty.txt");
                fs::write(&truncated_empty, b"truncate-me").with_context(|| {
                    format!("failed to seed mounted file {}", truncated_empty.display())
                })?;
                let file = fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&truncated_empty)
                    .with_context(|| {
                        format!(
                            "failed to truncate mounted file {}",
                            truncated_empty.display()
                        )
                    })?;
                drop(file);
                wait_for_object_bytes(&sdk, "truncated-empty.txt", b"", 180).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_local_rename_move_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-local-rename-move");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            sdk.put_large_aware(
                "seed-local-rename.txt",
                Bytes::from_static(b"seed-local-rename"),
            )
            .await?;

            let mut adapter = start_linux_fuse_adapter(&fixture.connection, &mountpoint).await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-local-rename.txt");
                wait_for_file(&seed_path, 120).await?;

                let local_file_payload = b"local-file-move-payload".to_vec();
                let file_from_dir = mountpoint.join("local-file-move").join("from");
                let file_to_dir = mountpoint.join("local-file-move").join("to");
                create_mounted_dir_all(&file_from_dir, 60).await?;
                create_mounted_dir_all(&file_to_dir, 60).await?;

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
                create_mounted_dir_all(&folder_from_nested, 60).await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_rename_move_refresh_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let mountpoint = fresh_data_dir("linux-fuse-remote-rename-move");
        let mut fixture = start_authenticated_linux_fuse_fixture(bind).await?;
        let sdk = fixture.sdk.clone();

        let result = async {
            sdk.put_large_aware(
                "seed-remote-rename.txt",
                Bytes::from_static(b"seed-remote-rename"),
            )
            .await?;

            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&fixture.connection, &mountpoint, 250)
                    .await?;
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&mountpoint);
        result
    }

    async fn run_remote_file_rename_refresh_local_edge_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let local_edge_bind = "127.0.0.1:19474";
        let rendezvous_bind = "127.0.0.1:19574";
        let cluster_id = "11111111-1111-7111-8111-111111111374";
        let upstream_node_id = "00000000-0000-0000-0000-000000001374";
        let local_edge_node_id = "00000000-0000-0000-0000-000000011374";
        let base_url = format!("http://{bind}");
        let local_edge_base_url = format!("http://{local_edge_bind}");
        let mountpoint = fresh_data_dir("linux-fuse-remote-rename-move-local-edge");
        let upstream_data_dir = fresh_data_dir("linux-fuse-remote-rename-move-local-edge-upstream");
        let local_edge_data_dir = fresh_data_dir("linux-fuse-remote-rename-move-local-edge-node");
        let mut cluster = start_local_edge_cluster_fixture(
            rendezvous_bind,
            bind,
            local_edge_bind,
            &upstream_data_dir,
            &local_edge_data_dir,
            cluster_id,
            upstream_node_id,
            local_edge_node_id,
        )
        .await?;
        let sdk = IronMeshClient::from_direct_base_url(&base_url);

        let result = async {
            sdk.put_large_aware(
                "seed-remote-rename-local-edge.txt",
                Bytes::from_static(b"seed-remote-rename-local-edge"),
            )
            .await?;

            let local_edge_connection = LinuxFuseConnection::direct(local_edge_base_url.clone());
            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&local_edge_connection, &mountpoint, 250)
                    .await?;
            let scenario = async {
                let seed_path = mountpoint.join("seed-remote-rename-local-edge.txt");
                wait_for_mount_active(&mountpoint, 150).await?;
                let local_edge_sdk = IronMeshClient::from_direct_base_url(&local_edge_base_url);
                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if seed_path.is_file() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&seed_path, 40).await?;

                let remote_file_payload = b"remote-file-move-local-edge-payload".to_vec();
                let remote_file_from = "remote-file-move-local-edge/from.txt";
                let remote_file_to = "remote-file-move-local-edge/sub/renamed.txt";
                sdk.put_large_aware(remote_file_from, Bytes::from(remote_file_payload.clone()))
                    .await?;

                let mounted_remote_file_from = mountpoint.join(remote_file_from);
                for _ in 0..220 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if mounted_remote_file_from.is_file() {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&mounted_remote_file_from, 40).await?;

                sdk.rename_path(remote_file_from, remote_file_to, false)
                    .await?;
                for _ in 0..260 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    let new_ready = local_edge_sdk
                        .get(remote_file_to)
                        .await
                        .map(|bytes| bytes.as_ref() == remote_file_payload.as_slice())
                        .unwrap_or(false);
                    let old_missing = local_edge_sdk.get(remote_file_from).await.is_err();
                    if new_ready && old_missing {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_object_bytes(&local_edge_sdk, remote_file_to, &remote_file_payload, 120)
                    .await?;
                wait_for_remote_file_absence(&local_edge_sdk, remote_file_from, 120).await?;

                let mounted_remote_file_to = mountpoint.join(remote_file_to);
                for _ in 0..360 {
                    trigger_local_edge_repair(&local_edge_base_url).await;
                    if mounted_remote_file_to.is_file()
                        && mounted_path_absent(&mounted_remote_file_from)
                    {
                        break;
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                wait_for_file(&mounted_remote_file_to, 120).await?;
                wait_for_file_bytes(&mounted_remote_file_to, &remote_file_payload, 120).await?;
                wait_for_absence(&mounted_remote_file_from, 120).await?;

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            scenario
        }
        .await;

        cluster.stop().await;
        let _ = fs::remove_dir_all(&mountpoint);
        let _ = fs::remove_dir_all(&upstream_data_dir);
        let _ = fs::remove_dir_all(&local_edge_data_dir);
        result
    }

    async fn run_local_edge_upstream_restart_case(bind: &str) -> Result<()> {
        let _case_guard = lock_test_resources(["linux-fuse-case".to_string()]).await;
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let local_edge_bind = "127.0.0.1:19471";
        let rendezvous_bind = "127.0.0.1:19571";
        let cluster_id = "11111111-1111-7111-8111-111111111371";
        let upstream_data_dir = fresh_data_dir("linux-fuse-local-edge-upstream-node");
        let local_edge_data_dir = fresh_data_dir("linux-fuse-local-edge-node");
        let mountpoint = fresh_data_dir("linux-fuse-local-edge-mount");
        let base_url = format!("http://{bind}");
        let upstream_node_id = "4a764850-f4e2-4bb7-ae22-9fe19e17ba40";
        let local_edge_node_id = "73df8d52-b894-4e95-aaba-905a1fd39371";
        let mut cluster = start_local_edge_cluster_fixture(
            rendezvous_bind,
            bind,
            local_edge_bind,
            &upstream_data_dir,
            &local_edge_data_dir,
            cluster_id,
            upstream_node_id,
            local_edge_node_id,
        )
        .await?;
        let sdk = IronMeshClient::from_direct_base_url(&base_url);

        let result = async {
            let local_edge_connection =
                LinuxFuseConnection::direct(cluster.local_edge_base_url.clone());
            let mut adapter =
                start_linux_fuse_adapter_with_refresh(&local_edge_connection, &mountpoint, 250)
                    .await?;

            wait_for_mount_active(&mountpoint, 150).await?;
            let local_edge_base_url = cluster.local_edge_base_url.clone();

            let online_key = "online-edge-write.txt";
            let online_payload = b"written-while-upstream-online".to_vec();
            let mounted_online = mountpoint.join(online_key);
            fs::write(&mounted_online, &online_payload).with_context(|| {
                format!(
                    "failed to write mounted online file {}",
                    mounted_online.display()
                )
            })?;
            wait_for_remote_sync_via_local_edge(
                &local_edge_base_url,
                &sdk,
                online_key,
                &online_payload,
                300,
            )
            .await?;

            stop_server(&mut cluster.upstream).await;

            let offline_key = "offline-edge-write.txt";
            let offline_payload = b"written-while-upstream-offline".to_vec();
            let mounted_offline = mountpoint.join(offline_key);
            fs::write(&mounted_offline, &offline_payload).with_context(|| {
                format!(
                    "failed to write mounted offline file {}",
                    mounted_offline.display()
                )
            })?;

            cluster.restart_upstream().await?;
            wait_for_remote_sync_via_local_edge(
                &local_edge_base_url,
                &sdk,
                offline_key,
                &offline_payload,
                300,
            )
            .await?;

            stop_linux_fuse_adapter(&mut adapter, &mountpoint).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        cluster.stop().await;
        let _ = fs::remove_dir_all(&mountpoint);
        let _ = fs::remove_dir_all(&upstream_data_dir);
        let _ = fs::remove_dir_all(&local_edge_data_dir);
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
    async fn linux_fuse_remote_additions_materialize_without_remount_in_local_edge_mode()
    -> Result<()> {
        run_remote_additions_refresh_local_edge_case("127.0.0.1:19372").await
    }

    #[tokio::test]
    async fn linux_fuse_remote_deletes_refresh_in_place_in_local_edge_mode() -> Result<()> {
        run_remote_delete_refresh_local_edge_case("127.0.0.1:19373").await
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
    async fn linux_fuse_zero_byte_creates_and_truncate_persist_remotely() -> Result<()> {
        run_zero_byte_create_persistence_case("127.0.0.1:19375").await
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
    async fn linux_fuse_remote_file_rename_refreshes_in_place_in_local_edge_mode() -> Result<()> {
        run_remote_file_rename_refresh_local_edge_case("127.0.0.1:19374").await
    }

    #[tokio::test]
    async fn linux_fuse_local_deletes_propagate_across_cluster() -> Result<()> {
        run_cluster_delete_propagation_case("127.0.0.1:19368", "127.0.0.1:19369").await
    }

    #[tokio::test]
    async fn linux_fuse_local_edge_mount_survives_upstream_restart_and_syncs_offline_write()
    -> Result<()> {
        run_local_edge_upstream_restart_case("127.0.0.1:19371").await
    }
}
