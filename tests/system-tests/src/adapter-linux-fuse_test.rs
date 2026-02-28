#![cfg(target_os = "linux")]

#[cfg(test)]
mod tests {
    use crate::framework::{ChildGuard, binary_path, fresh_data_dir, start_server, stop_server};
    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use client_sdk::IronMeshClient;
    use std::fs;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::Duration;
    use tokio::process::Command;
    use tokio::time::sleep;

    const LARGE_PAYLOAD_BYTES: usize = 5 * 1024 * 1024 + 1024;

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

    async fn run_server_mode_hydration_case(bind: &str, key: &str, payload: Vec<u8>) -> Result<()> {
        if !fuse_runtime_available() {
            eprintln!("skipping linux fuse system test because /dev/fuse is missing");
            return Ok(());
        }

        let base_url = format!("http://{bind}");
        let mountpoint = fresh_data_dir("linux-fuse-live-mount");
        let mut server = start_server(bind).await?;
        let sdk = IronMeshClient::new(&base_url);

        let result = async {
            sdk.put_large_aware(key, Bytes::from(payload.clone()))
                .await?;

            let mut adapter = start_linux_fuse_adapter(&base_url, &mountpoint).await?;
            let mount_result = async {
                let mounted_file = mountpoint.join(key);
                wait_for_file(&mounted_file, 100).await?;

                let hydrated = fs::read(&mounted_file).with_context(|| {
                    format!("failed to read mounted file {}", mounted_file.display())
                })?;
                assert_eq!(hydrated, payload);

                let write_result = fs::write(&mounted_file, b"must-fail");
                assert!(write_result.is_err(), "linux fuse mount must be read-only");

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

    #[tokio::test]
    async fn linux_fuse_server_mode_hydrates_small_payload() -> Result<()> {
        run_server_mode_hydration_case(
            "127.0.0.1:19360",
            "live-small.txt",
            b"hello-from-live-server".to_vec(),
        )
        .await
    }

    #[tokio::test]
    async fn linux_fuse_server_mode_hydrates_large_payload() -> Result<()> {
        let mut payload = vec![b'Z'; LARGE_PAYLOAD_BYTES];
        payload[0..6].copy_from_slice(b"BEGIN:");
        payload[LARGE_PAYLOAD_BYTES - 4..LARGE_PAYLOAD_BYTES].copy_from_slice(b":END");

        run_server_mode_hydration_case("127.0.0.1:19361", "live-large.bin", payload).await
    }
}
