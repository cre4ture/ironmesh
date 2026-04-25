#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, TEST_ADMIN_TOKEN, binary_path, fresh_data_dir, issue_bootstrap_bundle,
        lock_test_resources, start_authenticated_server, stop_server, tcp_resource_key,
        wait_for_url_status,
    };
    use anyhow::{Context, Result, bail};
    use reqwest::StatusCode;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;
    use uuid::Uuid;

    fn config_app_exe_name() -> &'static str {
        if cfg!(windows) {
            "ironmesh-config-app.exe"
        } else {
            "ironmesh-config-app"
        }
    }

    fn isolated_config_app_binary(package_root: &Path) -> Result<PathBuf> {
        fs::create_dir_all(package_root).with_context(|| {
            format!(
                "failed creating isolated config-app package root {}",
                package_root.display()
            )
        })?;
        let source = binary_path("config-app")?;
        let target = package_root.join(config_app_exe_name());
        fs::copy(&source, &target).with_context(|| {
            format!(
                "failed copying config-app binary {} -> {}",
                source.display(),
                target.display()
            )
        })?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&target)
                .with_context(|| format!("failed reading permissions for {}", target.display()))?
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&target, permissions)
                .with_context(|| format!("failed making {} executable", target.display()))?;
        }

        Ok(target)
    }

    async fn start_config_app(
        bind: &str,
        config_root: &Path,
        package_root: &Path,
    ) -> Result<ChildGuard> {
        let config_app_bin = isolated_config_app_binary(package_root)?;
        let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;
        let mut command = Command::new(config_app_bin);
        command
            .arg("--bind")
            .arg(bind)
            .arg("--no-browser")
            .env("LOCALAPPDATA", config_root)
            .env("XDG_CONFIG_HOME", config_root)
            .env("XDG_STATE_HOME", config_root)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = command.spawn().context("failed to spawn config-app")?;
        if let Err(error) =
            wait_for_url_status(&format!("http://{bind}/api/config"), StatusCode::OK, 40).await
        {
            let mut stderr_output = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut stderr_output).await;
            }
            let _ = child.kill().await;
            return Err(error).with_context(|| {
                format!(
                    "config-app failed to become ready on {bind}; stderr: {}",
                    stderr_output.trim()
                )
            });
        }

        Ok(ChildGuard::with_resources(child, resource_guards))
    }

    #[tokio::test]
    async fn config_app_enrolls_managed_client_identity_from_pasted_bootstrap() -> Result<()> {
        let server_bind = "127.0.0.1:19450";
        let config_bind = "127.0.0.1:19451";
        let server_base = format!("http://{server_bind}");
        let config_base = format!("http://{config_bind}");
        let data_dir = fresh_data_dir("config-app-enroll-server");
        let config_root = fresh_data_dir("config-app-enroll-config");
        let package_root = fresh_data_dir("config-app-isolated-package");
        let node_id = Uuid::new_v4().to_string();
        let http = reqwest::Client::new();

        let mut server = start_authenticated_server(server_bind, &data_dir, &node_id, 1).await?;
        let mut config_app = start_config_app(config_bind, &config_root, &package_root).await?;

        let result = async {
            let bootstrap = issue_bootstrap_bundle(
                &http,
                &server_base,
                TEST_ADMIN_TOKEN,
                Some("config-app-device"),
                Some(3600),
            )
            .await?;
            let bootstrap_content = bootstrap.to_json_pretty()?;
            assert_eq!(bootstrap.device_label.as_deref(), Some("config-app-device"));

            let response = http
                .post(format!("{config_base}/api/client-identities"))
                .json(&serde_json::json!({
                    "bootstrap_content": bootstrap_content,
                    "enroll": true,
                }))
                .send()
                .await
                .context("failed posting pasted bootstrap to config-app")?;
            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed reading config-app enrollment response")?;
            if !status.is_success() {
                bail!("config-app enrollment returned {status}: {body}");
            }

            let payload: serde_json::Value = serde_json::from_str(&body)
                .context("failed decoding config-app enrollment response")?;
            let identities = payload
                .get("config")
                .and_then(|value| value.get("store"))
                .and_then(|value| value.get("client_identities"))
                .and_then(|value| value.as_array())
                .context("config-app response missing client identities")?;
            assert_eq!(identities.len(), 1);
            let identity = &identities[0];
            assert_eq!(
                identity.get("label").and_then(|value| value.as_str()),
                Some("config-app-device")
            );
            assert_eq!(
                identity
                    .get("device_label")
                    .and_then(|value| value.as_str()),
                Some("config-app-device")
            );

            let bootstrap_path = identity
                .get("bootstrap_file")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                .context("managed identity missing bootstrap_file")?;
            let identity_path = identity
                .get("client_identity_file")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                .context("managed identity missing client_identity_file")?;
            assert!(
                bootstrap_path.exists(),
                "expected managed bootstrap file to exist at {}",
                bootstrap_path.display()
            );
            assert!(
                identity_path.exists(),
                "expected enrolled client identity file to exist at {}",
                identity_path.display()
            );

            let persisted_identity: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&identity_path).with_context(|| {
                    format!(
                        "failed reading enrolled identity file {}",
                        identity_path.display()
                    )
                })?)
                .context("failed decoding enrolled identity JSON")?;
            assert_eq!(
                persisted_identity
                    .get("label")
                    .and_then(|value| value.as_str()),
                Some("config-app-device")
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut config_app).await;
        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&config_root);
        let _ = fs::remove_dir_all(&package_root);
        result
    }

    #[tokio::test]
    async fn config_app_launch_report_points_to_service_log_file() -> Result<()> {
        let config_bind = "127.0.0.1:19452";
        let config_base = format!("http://{config_bind}");
        let config_root = fresh_data_dir("config-app-launch-log-config");
        let package_root = fresh_data_dir("config-app-launch-log-package");
        let sync_root = fresh_data_dir("config-app-launch-log-sync-root");
        let http = reqwest::Client::new();

        let mut config_app = start_config_app(config_bind, &config_root, &package_root).await?;

        let result = async {
            let response = http
                .post(format!("{config_base}/api/folder-agent-instances"))
                .json(&serde_json::json!({
                    "id": "folder-log-test",
                    "label": "Folder Log Test",
                    "enabled": true,
                    "root_dir": sync_root.display().to_string(),
                }))
                .send()
                .await
                .context("failed posting folder-agent instance to config-app")?;
            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed reading folder-agent save response")?;
            if !status.is_success() {
                bail!("config-app folder-agent save returned {status}: {body}");
            }

            let response = http
                .post(format!("{config_base}/api/launch-enabled"))
                .send()
                .await
                .context("failed launching enabled services through config-app")?;
            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed reading launch-enabled response")?;
            if !status.is_success() {
                bail!("config-app launch-enabled returned {status}: {body}");
            }

            let report: serde_json::Value =
                serde_json::from_str(&body).context("failed decoding launch report")?;
            let outcome = report
                .get("outcomes")
                .and_then(|value| value.as_array())
                .and_then(|values| values.first())
                .context("launch report missing first outcome")?;
            assert_eq!(
                outcome.get("instance_kind").and_then(|value| value.as_str()),
                Some("folder-agent")
            );
            assert_eq!(
                outcome.get("id").and_then(|value| value.as_str()),
                Some("folder-log-test")
            );
            assert!(
                outcome.get("error").and_then(|value| value.as_str()).is_some(),
                "missing executable should be reported as a launch error"
            );

            let log_file = outcome
                .get("log_file")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                .context("launch outcome missing log_file")?;
            assert!(
                log_file.exists(),
                "expected service log file to exist at {}",
                log_file.display()
            );
            let log = fs::read_to_string(&log_file)
                .with_context(|| format!("failed reading service log {}", log_file.display()))?;
            assert!(log.contains("=== IronMesh service launch ==="));
            assert!(log.contains("instance_kind=folder-agent"));
            assert!(log.contains("id=folder-log-test"));
            assert!(log.contains("spawn attempt failed executable="));

            let config: serde_json::Value = http
                .get(format!("{config_base}/api/config"))
                .send()
                .await
                .context("failed fetching config after launch")?
                .json()
                .await
                .context("failed decoding config after launch")?;
            let service_log_dir = config
                .get("service_log_dir")
                .and_then(|value| value.as_str())
                .context("config response missing service_log_dir")?;
            assert!(
                log_file.starts_with(service_log_dir),
                "log file {} should be under service log dir {}",
                log_file.display(),
                service_log_dir
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut config_app).await;
        let _ = fs::remove_dir_all(&config_root);
        let _ = fs::remove_dir_all(&package_root);
        let _ = fs::remove_dir_all(&sync_root);
        result
    }
}
