#[cfg(test)]
mod tests {
    use std::fs;
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::OnceLock;
    use std::time::SystemTime;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use client_sdk::ClientNode;
    use reqwest::StatusCode;
    use tokio::process::{Child, Command};
    use tokio::time::sleep;

    #[tokio::test]
    async fn sdk_roundtrip_against_live_server() -> Result<()> {
        let bind = "127.0.0.1:19080";
        let base_url = format!("http://{bind}");
        let mut server = start_server(bind).await?;

        let client = ClientNode::new(&base_url);
        let key = "sdk-roundtrip";
        let value = Bytes::from_static(b"hello-from-sdk");

        client.put(key, value.clone()).await?;
        let fetched = client.get(key).await?;
        assert_eq!(fetched, value);

        stop_server(&mut server).await;
        Ok(())
    }

    #[tokio::test]
    async fn cli_put_then_get_against_live_server() -> Result<()> {
        let bind = "127.0.0.1:19081";
        let base_url = format!("http://{bind}");
        let mut server = start_server(bind).await?;

        run_cli(&[
            "--server-url",
            &base_url,
            "put",
            "cli-roundtrip",
            "hello-from-cli",
        ])
        .await?;

        let output = run_cli(&["--server-url", &base_url, "get", "cli-roundtrip"]).await?;
        assert!(output.contains("hello-from-cli"));

        stop_server(&mut server).await;
        Ok(())
    }

    #[tokio::test]
    async fn cli_web_interface_ping() -> Result<()> {
        let bind = "127.0.0.1:19082";
        let mut cli_web = start_cli_web(bind).await?;

        let ping_url = format!("http://{bind}/api/ping");
        let body = reqwest::get(&ping_url)
            .await
            .context("failed to call cli web ping endpoint")?
            .error_for_status()
            .context("cli web ping endpoint returned non-success status")?
            .text()
            .await
            .context("failed to read ping response body")?;

        assert!(body.contains("\"ok\":true"));
        assert!(body.contains("cli-client-web"));

        stop_server(&mut cli_web).await;
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_time_travel_read_via_http() -> Result<()> {
        let bind = "127.0.0.1:19083";
        let data_dir = fresh_data_dir("snapshot-time-travel");
        let mut server = start_server_with_data_dir(bind, &data_dir).await?;
        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            client
                .put(format!("{base_url}/store/history-key"))
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let first_snapshot_id = latest_snapshot_id(&client, &base_url).await?;

            client
                .put(format!("{base_url}/store/history-key"))
                .body("v2")
                .send()
                .await?
                .error_for_status()?;

            let latest = client
                .get(format!("{base_url}/store/history-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(latest, "v2");

            let historical = client
                .get(format!(
                    "{base_url}/store/history-key?snapshot={first_snapshot_id}"
                ))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(historical, "v1");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn corrupted_chunk_returns_conflict() -> Result<()> {
        let bind = "127.0.0.1:19084";
        let data_dir = fresh_data_dir("corrupt-detection");
        let mut server = start_server_with_data_dir(bind, &data_dir).await?;
        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            client
                .put(format!("{base_url}/store/corrupt-me"))
                .body("payload-for-corruption-check")
                .send()
                .await?
                .error_for_status()?;

            let chunk_file = first_chunk_file(data_dir.join("chunks"))?;
            let mut bytes = fs::read(&chunk_file)?;
            if bytes.is_empty() {
                bail!("chunk file unexpectedly empty: {}", chunk_file.display());
            }
            bytes[0] ^= 0xFF;
            fs::write(&chunk_file, bytes)?;

            let response = client
                .get(format!("{base_url}/store/corrupt-me"))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::CONFLICT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn version_graph_and_confirm_flow() -> Result<()> {
        let bind = "127.0.0.1:19085";
        let data_dir = fresh_data_dir("version-graph");
        let mut server = start_server_with_data_dir(bind, &data_dir).await?;
        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            client
                .put(format!("{base_url}/store/versioned-key"))
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let first_versions_payload = client
                .get(format!("{base_url}/versions/versioned-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let first_versions: serde_json::Value =
                serde_json::from_str(&first_versions_payload)?;

            let first_version_id = first_versions
                .get("versions")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|entry| entry.get("version_id"))
                .and_then(|v| v.as_str())
                .context("missing first version id")?
                .to_string();

            client
                .put(format!("{base_url}/store/versioned-key?state=provisional"))
                .body("v2")
                .send()
                .await?
                .error_for_status()?;

            let second_versions_payload = client
                .get(format!("{base_url}/versions/versioned-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let second_versions: serde_json::Value =
                serde_json::from_str(&second_versions_payload)?;

            let provisional_entry = second_versions
                .get("versions")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter().find(|entry| {
                        entry
                            .get("state")
                            .and_then(|s| s.as_str())
                            .map(|state| state == "provisional")
                            .unwrap_or(false)
                    })
                })
                .context("missing provisional version entry")?;

            let provisional_version_id = provisional_entry
                .get("version_id")
                .and_then(|v| v.as_str())
                .context("missing provisional version id")?
                .to_string();

            let v1_payload = client
                .get(format!(
                    "{base_url}/store/versioned-key?version={first_version_id}"
                ))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(v1_payload, "v1");

            let confirm_response = client
                .post(format!(
                    "{base_url}/versions/versioned-key/confirm/{provisional_version_id}"
                ))
                .send()
                .await?;
            assert_eq!(confirm_response.status(), StatusCode::NO_CONTENT);

            let third_versions_payload = client
                .get(format!("{base_url}/versions/versioned-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let third_versions: serde_json::Value = serde_json::from_str(&third_versions_payload)?;

            let confirmed_again = third_versions
                .get("versions")
                .and_then(|v| v.as_array())
                .and_then(|arr| {
                    arr.iter().find(|entry| {
                        entry
                            .get("version_id")
                            .and_then(|s| s.as_str())
                            .map(|id| id == provisional_version_id)
                            .unwrap_or(false)
                    })
                })
                .and_then(|entry| entry.get("state"))
                .and_then(|s| s.as_str())
                .context("missing confirmed state after confirm")?;
            assert_eq!(confirmed_again, "confirmed");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    async fn start_server(bind: &str) -> Result<Child> {
        let data_dir = fresh_data_dir("default-server");
        start_server_with_data_dir(bind, &data_dir).await
    }

    async fn start_server_with_data_dir(bind: &str, data_dir: &Path) -> Result<Child> {
        let server_bin = binary_path("server-node")?;

        let child = Command::new(server_bin)
            .env("IRONMESH_SERVER_BIND", bind)
            .env("IRONMESH_DATA_DIR", data_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn server-node")?;

        wait_for_server(bind, 40).await?;
        Ok(child)
    }

    async fn latest_snapshot_id(http: &reqwest::Client, base_url: &str) -> Result<String> {
        let payload = http
            .get(format!("{base_url}/snapshots"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        let parsed: serde_json::Value = serde_json::from_str(&payload)?;
        let first = parsed
            .as_array()
            .and_then(|arr| arr.first())
            .context("snapshots endpoint returned empty list")?;

        first
            .get("id")
            .and_then(|v| v.as_str())
            .map(ToString::to_string)
            .context("snapshot id missing in response")
    }

    async fn run_cli(args: &[&str]) -> Result<String> {
        let cli_bin = binary_path("cli-client")?;
        let output = Command::new(cli_bin)
            .args(args)
            .output()
            .await
            .context("failed to execute cli-client")?;

        if !output.status.success() {
            bail!(
                "cli-client failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    async fn start_cli_web(bind: &str) -> Result<Child> {
        let cli_bin = binary_path("cli-client")?;

        let child = Command::new(cli_bin)
            .arg("serve-web")
            .arg("--bind")
            .arg(bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn cli-client serve-web")?;

        wait_for_url_status(&format!("http://{bind}/api/ping"), StatusCode::OK, 40).await?;
        Ok(child)
    }

    async fn wait_for_server(bind: &str, retries: usize) -> Result<()> {
        let health_url = format!("http://{bind}/health");
        wait_for_url_status(&health_url, StatusCode::OK, retries).await
    }

    async fn wait_for_url_status(url: &str, expected: StatusCode, retries: usize) -> Result<()> {
        let http = reqwest::Client::new();

        for _ in 0..retries {
            if let Ok(resp) = http.get(url).send().await
                && resp.status() == expected
            {
                return Ok(());
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!("service did not return {expected} at {url}");
    }

    async fn stop_server(child: &mut Child) {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    fn binary_path(name: &str) -> Result<PathBuf> {
        let workspace_root = workspace_root()?;
        ensure_binaries_built(&workspace_root)?;
        let mut path = workspace_root.join("target").join("debug").join(name);

        if let Some(suffix) = std::env::consts::EXE_SUFFIX.strip_prefix('.') {
            let mut filename = OsString::from(name);
            filename.push(".");
            filename.push(suffix);
            path = workspace_root.join("target").join("debug").join(filename);
        }

        if !path.exists() {
            bail!("expected binary does not exist: {}", path.display());
        }

        Ok(path)
    }

    fn workspace_root() -> Result<PathBuf> {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .context("failed to resolve workspace root")
    }

    fn build_required_binaries(workspace_root: &PathBuf) -> Result<()> {
        let status = std::process::Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("server-node")
            .arg("-p")
            .arg("cli-client")
            .current_dir(workspace_root)
            .status()
            .context("failed to run cargo build for system test binaries")?;

        if !status.success() {
            bail!("cargo build for system test binaries failed");
        }

        Ok(())
    }

    fn ensure_binaries_built(workspace_root: &PathBuf) -> Result<()> {
        static BUILD_RESULT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

        let result = BUILD_RESULT.get_or_init(|| {
            build_required_binaries(workspace_root).map_err(|err| err.to_string())
        });

        if let Err(message) = result {
            bail!("failed to build required binaries: {message}");
        }

        Ok(())
    }

    fn fresh_data_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("ironmesh-{name}-{unique}"));
        let _ = fs::remove_dir_all(&path);
        let _ = fs::create_dir_all(&path);
        path
    }

    fn first_chunk_file(root: PathBuf) -> Result<PathBuf> {
        let mut dirs = vec![root];

        while let Some(dir) = dirs.pop() {
            for entry in fs::read_dir(&dir)
                .with_context(|| format!("failed to read dir {}", dir.display()))?
            {
                let entry = entry?;
                let path = entry.path();

                if path.is_dir() {
                    dirs.push(path);
                } else {
                    return Ok(path);
                }
            }
        }

        bail!("no chunk files found")
    }
}
