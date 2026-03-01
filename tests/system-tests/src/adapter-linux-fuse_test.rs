#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, binary_path, fresh_data_dir, start_server, stop_server,
        wait_for_store_index_entry,
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
        let os_integration_bin = binary_path("os-integration")?;
        let mountpoint_arg = mountpoint.to_string_lossy().to_string();

        let child = Command::new(os_integration_bin)
            .arg("--server-base-url")
            .arg(server_base_url)
            .arg("--mountpoint")
            .arg(&mountpoint_arg)
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
}
