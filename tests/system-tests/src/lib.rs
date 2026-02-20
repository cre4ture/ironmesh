#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Stdio;
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

    async fn start_server(bind: &str) -> Result<Child> {
        let server_bin = binary_path("server-node")?;

        let child = Command::new(server_bin)
            .env("IRONMESH_SERVER_BIND", bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("failed to spawn server-node")?;

        wait_for_server(bind, 40).await?;
        Ok(child)
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
        let mut path = workspace_root.join("target").join("debug").join(name);

        if let Some(suffix) = std::env::consts::EXE_SUFFIX.strip_prefix('.') {
            let mut filename = OsString::from(name);
            filename.push(".");
            filename.push(suffix);
            path = workspace_root.join("target").join("debug").join(filename);
        }

        if !path.exists() {
            build_required_binaries(&workspace_root)?;
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
}
