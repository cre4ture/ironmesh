#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, TEST_ADMIN_TOKEN, binary_path, fresh_data_dir, issue_bootstrap_bundle,
        lock_test_resources, start_authenticated_server, start_open_server_with_env, stop_server,
        tcp_resource_key, wait_for_url_status,
    };
    use anyhow::{Context, Result, bail};
    use client_sdk::ClientIdentityMaterial;
    use reqwest::StatusCode;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::AsyncReadExt;
    use tokio::process::Command;
    use transport_sdk::{
        rendezvous_client_identity_is_expired_at, rendezvous_client_identity_needs_renewal_at,
    };
    use uuid::Uuid;

    const KNOWN_EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_NOT_AFTER_UNIX: u64 = 1_776_690_574;
    const KNOWN_EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIB3DCCAYKgAwIBAgITK3r0r5jwkdN+susWXewPKMOgPDAKBggqhkjOPQQDAjBA\n",
        "MT4wPAYDVQQDDDVpcm9ubWVzaC1jbHVzdGVyLTAxOWQwMmViLWFiMzktNzIyMC05\n",
        "MTFhLWMwZWFmY2IzODI0OTAeFw0yNjAzMjExMzA5MzRaFw0yNjA0MjAxMzA5MzRa\n",
        "MD8xPTA7BgNVBAMMNGlyb25tZXNoLWRldmljZS0wMTlkMTA4My1lYTIzLTdiZjEt\n",
        "YjVjYi0xZDVmY2ViNTBlOGEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASeG/Cl\n",
        "E3s04e07hBjVXH8/IMPXIiGewwOLPXEcJM4pU0ELoDcfpgZ0evvEiOKFC+R19CI3\n",
        "/dbbU02U0VnXMMXxo1wwWjBDBgNVHREEPDA6hjh1cm46aXJvbm1lc2g6ZGV2aWNl\n",
        "OjAxOWQxMDgzLWVhMjMtN2JmMS1iNWNiLTFkNWZjZWI1MGU4YTATBgNVHSUEDDAK\n",
        "BggrBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiBPOa5XZSZLs8CqhQO9PscDS2Il\n",
        "jkjn2HXRB0g2pB2aeAIhALe+yYYMAqULo8WmhjcudAgQm/1vYSjowEWtUcMCY2J3\n",
        "-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaxQmF3EgQxM8/nYg\n",
        "C4fi+hVjqma6xwFK4pwamjmotA+hRANCAASeG/ClE3s04e07hBjVXH8/IMPXIiGe\n",
        "wwOLPXEcJM4pU0ELoDcfpgZ0evvEiOKFC+R19CI3/dbbU02U0VnXMMXx\n",
        "-----END PRIVATE KEY-----\n"
    );

    fn current_unix_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0)
    }

    fn packaged_binary_file_name(binary_name: &str) -> Result<&'static str> {
        match binary_name {
            "config-app" => Ok(if cfg!(windows) {
                "ironmesh-config-app.exe"
            } else {
                "ironmesh-config-app"
            }),
            "cli-client" => Ok(if cfg!(windows) {
                "ironmesh.exe"
            } else {
                "ironmesh"
            }),
            "ironmesh-folder-agent" => Ok(if cfg!(windows) {
                "ironmesh-folder-agent.exe"
            } else {
                "ironmesh-folder-agent"
            }),
            "os-integration" => Ok(if cfg!(windows) {
                "ironmesh-os-integration.exe"
            } else {
                "ironmesh-os-integration"
            }),
            "server-node" => Ok(if cfg!(windows) {
                "ironmesh-server-node.exe"
            } else {
                "ironmesh-server-node"
            }),
            "rendezvous-service" => Ok(if cfg!(windows) {
                "ironmesh-rendezvous-service.exe"
            } else {
                "ironmesh-rendezvous-service"
            }),
            _ => bail!("unsupported packaged binary mapping for {binary_name}"),
        }
    }

    fn copy_binary_into_package_root(package_root: &Path, binary_name: &str) -> Result<PathBuf> {
        fs::create_dir_all(package_root).with_context(|| {
            format!(
                "failed creating isolated config-app package root {}",
                package_root.display()
            )
        })?;
        let source = binary_path(binary_name)?;
        let target = package_root.join(packaged_binary_file_name(binary_name)?);
        fs::copy(&source, &target).with_context(|| {
            format!(
                "failed copying packaged binary {} -> {}",
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

    fn isolated_config_app_binary(
        package_root: &Path,
        sibling_binaries: &[&str],
    ) -> Result<PathBuf> {
        let config_app_bin = copy_binary_into_package_root(package_root, "config-app")?;
        for binary_name in sibling_binaries {
            let _ = copy_binary_into_package_root(package_root, binary_name)?;
        }
        Ok(config_app_bin)
    }

    async fn start_config_app_with_args(
        bind: &str,
        config_root: &Path,
        package_root: &Path,
        sibling_binaries: &[&str],
        extra_args: &[&str],
    ) -> Result<ChildGuard> {
        let config_app_bin = isolated_config_app_binary(package_root, sibling_binaries)?;
        let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;
        let mut command = Command::new(config_app_bin);
        command.args(extra_args);
        command
            .arg("--bind")
            .arg(bind)
            .arg("--no-browser")
            .arg("--no-desktop-status")
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

    async fn start_config_app(
        bind: &str,
        config_root: &Path,
        package_root: &Path,
    ) -> Result<ChildGuard> {
        start_config_app_with_args(bind, config_root, package_root, &[], &[]).await
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

            let config: serde_json::Value = http
                .get(format!("{config_base}/api/config"))
                .send()
                .await
                .context("failed fetching config before service start")?
                .json()
                .await
                .context("failed decoding config before service start")?;
            let service_status = config
                .get("service_statuses")
                .and_then(|value| value.as_array())
                .and_then(|statuses| {
                    statuses.iter().find(|status| {
                        status.get("instance_kind").and_then(|value| value.as_str())
                            == Some("folder-agent")
                            && status.get("id").and_then(|value| value.as_str())
                                == Some("folder-log-test")
                    })
                })
                .context("config response missing folder-agent service status")?;
            assert_eq!(
                service_status
                    .get("running")
                    .and_then(|value| value.as_bool()),
                Some(false)
            );
            let status_log_file = service_status
                .get("log_file")
                .and_then(|value| value.as_str())
                .context("config response service status missing log_file")?;
            assert!(
                status_log_file.ends_with("folder-agent-folder-log-test.log"),
                "unexpected service status log file path: {status_log_file}"
            );

            let response = http
                .post(format!(
                    "{config_base}/api/services/folder-agent/folder-log-test/start"
                ))
                .send()
                .await
                .context("failed starting folder-agent service through config-app")?;
            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed reading service start response")?;
            if !status.is_success() {
                bail!("config-app service start returned {status}: {body}");
            }

            let action_response: serde_json::Value =
                serde_json::from_str(&body).context("failed decoding service start response")?;
            let outcome = action_response
                .get("launch")
                .context("service start response missing launch outcome")?;
            assert_eq!(
                outcome
                    .get("instance_kind")
                    .and_then(|value| value.as_str()),
                Some("folder-agent")
            );
            assert_eq!(
                outcome.get("id").and_then(|value| value.as_str()),
                Some("folder-log-test")
            );
            assert!(
                outcome
                    .get("error")
                    .and_then(|value| value.as_str())
                    .is_some(),
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

            let stop_response: serde_json::Value = http
                .post(format!(
                    "{config_base}/api/services/folder-agent/folder-log-test/stop"
                ))
                .send()
                .await
                .context("failed stopping folder-agent service through config-app")?
                .json()
                .await
                .context("failed decoding service stop response")?;
            assert_eq!(
                stop_response
                    .get("stop")
                    .and_then(|value| value.get("was_running"))
                    .and_then(|value| value.as_bool()),
                Some(false)
            );

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
            let service_status = config
                .get("service_statuses")
                .and_then(|value| value.as_array())
                .and_then(|statuses| {
                    statuses.iter().find(|status| {
                        status.get("instance_kind").and_then(|value| value.as_str())
                            == Some("folder-agent")
                            && status.get("id").and_then(|value| value.as_str())
                                == Some("folder-log-test")
                    })
                })
                .context("config response missing folder-agent service status after stop")?;
            let log_file_string = log_file.to_string_lossy().to_string();
            assert_eq!(
                service_status
                    .get("log_file")
                    .and_then(|value| value.as_str()),
                Some(log_file_string.as_str())
            );
            assert_eq!(
                service_status
                    .get("running")
                    .and_then(|value| value.as_bool()),
                Some(false)
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

    #[tokio::test]
    async fn config_app_bundle_links_running_client_service_bind_addresses() -> Result<()> {
        let config_bind = "127.0.0.1:19453";
        let config_base = format!("http://{config_bind}");
        let config_root = fresh_data_dir("config-app-client-bind-link-config");
        let package_root = fresh_data_dir("config-app-client-bind-link-package");
        let http = reqwest::Client::new();

        let mut config_app = start_config_app(config_bind, &config_root, &package_root).await?;

        let result = async {
            let response = http
                .get(format!("{config_base}/app.js"))
                .send()
                .await
                .context("failed fetching config-app JS bundle")?;
            let status = response.status();
            let js = response
                .text()
                .await
                .context("failed reading config-app JS bundle")?;
            if !status.is_success() {
                bail!("config-app JS bundle returned {status}: {js}");
            }

            assert!(
                js.contains("kind === 'client' && label === 'Bind Address' && running"),
                "app bundle should only link bind addresses for running client services"
            );
            assert!(
                js.contains("class=\"instance-link\""),
                "app bundle should render a dedicated bind-address link class"
            );
            assert!(
                js.contains("target=\"_blank\" rel=\"noopener noreferrer\""),
                "app bundle should open bind-address links in a separate browser tab"
            );
            assert!(
                js.contains("http://${value}"),
                "app bundle should turn client bind addresses into local http links"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut config_app).await;
        let _ = fs::remove_dir_all(&config_root);
        let _ = fs::remove_dir_all(&package_root);
        result
    }

    #[tokio::test]
    async fn config_app_startup_launch_renews_expired_managed_client_identity() -> Result<()> {
        let server_bind = "127.0.0.1:19454";
        let config_bind = "127.0.0.1:19455";
        let client_bind = "127.0.0.1:19456";
        let server_base = format!("http://{server_bind}");
        let config_base = format!("http://{config_bind}");
        let client_health_url = format!("http://{client_bind}/api/v1/health");
        let data_dir = fresh_data_dir("config-app-auto-renew-server");
        let config_root = fresh_data_dir("config-app-auto-renew-config");
        let package_root = fresh_data_dir("config-app-auto-renew-package");
        let cluster_id = "11111111-1111-7111-8111-111111111154";
        let node_id = "00000000-0000-0000-0000-000000000954";
        let http = reqwest::Client::new();
        let node_env = [
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_ADMIN_TOKEN", TEST_ADMIN_TOKEN),
            ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
            ("IRONMESH_RENDEZVOUS_MTLS_REQUIRED", "true"),
        ];

        assert!(
            current_unix_ts() > KNOWN_EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_NOT_AFTER_UNIX,
            "expired rendezvous identity fixture is no longer expired for the current test clock"
        );

        let mut server =
            start_open_server_with_env(server_bind, &data_dir, node_id, 1, &node_env).await?;
        let mut config_app = start_config_app_with_args(
            config_bind,
            &config_root,
            &package_root,
            &["cli-client"],
            &[],
        )
        .await?;

        let result = async {
            let bootstrap = issue_bootstrap_bundle(
                &http,
                &server_base,
                TEST_ADMIN_TOKEN,
                Some("managed-auto-renew"),
                Some(3600),
            )
            .await?;
            let bootstrap_content = bootstrap.to_json_pretty()?;

            let enrollment_response = http
                .post(format!("{config_base}/api/client-identities"))
                .json(&serde_json::json!({
                    "bootstrap_content": bootstrap_content,
                    "enroll": true,
                }))
                .send()
                .await
                .context("failed posting managed bootstrap to config-app")?;
            let enrollment_status = enrollment_response.status();
            let enrollment_body = enrollment_response
                .text()
                .await
                .context("failed reading managed identity enrollment response")?;
            if !enrollment_status.is_success() {
                bail!(
                    "config-app managed identity enrollment returned {enrollment_status}: {enrollment_body}"
                );
            }

            let enrollment_payload: serde_json::Value = serde_json::from_str(&enrollment_body)
                .context("failed decoding managed identity enrollment response")?;
            let identity = enrollment_payload
                .get("config")
                .and_then(|value| value.get("store"))
                .and_then(|value| value.get("client_identities"))
                .and_then(|value| value.as_array())
                .and_then(|identities| identities.first())
                .context("config-app enrollment response missing managed identity")?;
            let identity_id = identity
                .get("id")
                .and_then(|value| value.as_str())
                .context("managed identity missing id")?;
            let identity_path = identity
                .get("client_identity_file")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                .context("managed identity missing client_identity_file")?;

            let mut persisted_identity = ClientIdentityMaterial::from_path(&identity_path)
                .with_context(|| {
                    format!(
                        "failed reading managed identity file {}",
                        identity_path.display()
                    )
                })?;
            let original_rendezvous_identity = persisted_identity
                .rendezvous_client_identity_pem
                .clone()
                .context("managed identity should include rendezvous client identity material")?;
            persisted_identity.rendezvous_client_identity_pem =
                Some(KNOWN_EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM.to_string());
            persisted_identity
                .write_to_path(&identity_path)
                .with_context(|| {
                    format!(
                        "failed writing expired rendezvous identity fixture to {}",
                        identity_path.display()
                    )
                })?;

            let expired_identity = ClientIdentityMaterial::from_path(&identity_path)
                .with_context(|| {
                    format!(
                        "failed reloading expired managed identity {}",
                        identity_path.display()
                    )
                })?;
            let expired_pem = expired_identity
                .rendezvous_client_identity_pem
                .as_deref()
                .context("expired managed identity should retain rendezvous PEM")?;
            assert!(
                rendezvous_client_identity_is_expired_at(expired_pem.as_bytes(), current_unix_ts()),
                "managed identity fixture should be expired before startup launch renewal"
            );

            let client_response = http
                .post(format!("{config_base}/api/client-cli-instances"))
                .json(&serde_json::json!({
                    "id": "managed-auto-renew-client",
                    "label": "Managed Auto Renew Client",
                    "enabled": true,
                    "bind": client_bind,
                    "client_identity_id": identity_id,
                }))
                .send()
                .await
                .context("failed posting managed client-cli instance to config-app")?;
            let client_status = client_response.status();
            let client_body = client_response
                .text()
                .await
                .context("failed reading managed client-cli save response")?;
            if !client_status.is_success() {
                bail!("config-app managed client-cli save returned {client_status}: {client_body}");
            }

            stop_server(&mut config_app).await;
            config_app = start_config_app_with_args(
                config_bind,
                &config_root,
                &package_root,
                &["cli-client"],
                &["--background"],
            )
            .await?;

            let config: serde_json::Value = http
                .get(format!("{config_base}/api/config"))
                .send()
                .await
                .context("failed fetching config after startup launch renewal")?
                .json()
                .await
                .context("failed decoding config after startup launch renewal")?;
            let service_status = config
                .get("service_statuses")
                .and_then(|value| value.as_array())
                .and_then(|statuses| {
                    statuses.iter().find(|status| {
                        status.get("instance_kind").and_then(|value| value.as_str())
                            == Some("client-cli")
                            && status.get("id").and_then(|value| value.as_str())
                                == Some("managed-auto-renew-client")
                    })
                })
                .context("config response missing managed client-cli service status")?;
            let log_file = service_status
                .get("log_file")
                .and_then(|value| value.as_str())
                .map(PathBuf::from)
                .context("managed client-cli service status missing log_file")?;
            if service_status
                .get("running")
                .and_then(|value| value.as_bool())
                != Some(true)
            {
                let service_log = fs::read_to_string(&log_file).unwrap_or_default();
                bail!(
                    "managed client-cli did not stay running after startup launch; status={service_status}; service log:\n{service_log}"
                );
            }

            if let Err(error) = wait_for_url_status(&client_health_url, StatusCode::OK, 120).await {
                let health_probe = match http.get(&client_health_url).send().await {
                    Ok(response) => {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        format!("HTTP {status}: {body}")
                    }
                    Err(probe_error) => format!("request failed: {probe_error}"),
                };
                let service_log = fs::read_to_string(&log_file).unwrap_or_default();
                bail!(
                    "managed client-cli health never became ready: {error:#}; health probe={health_probe}; service log:\n{service_log}"
                );
            }

            let renewed_identity = ClientIdentityMaterial::from_path(&identity_path)
                .with_context(|| {
                    format!(
                        "failed loading renewed managed identity {}",
                        identity_path.display()
                    )
                })?;
            let renewed_pem = renewed_identity
                .rendezvous_client_identity_pem
                .as_deref()
                .context("renewed managed identity should include rendezvous PEM")?;

            assert_ne!(
                renewed_pem,
                KNOWN_EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM,
                "managed identity should not keep the injected expired rendezvous cert"
            );
            assert_ne!(
                renewed_pem,
                original_rendezvous_identity.as_str(),
                "managed identity should receive fresh rendezvous material during renewal"
            );
            assert!(
                !rendezvous_client_identity_is_expired_at(
                    renewed_pem.as_bytes(),
                    current_unix_ts()
                ),
                "renewed managed identity should no longer be expired"
            );
            assert!(
                !rendezvous_client_identity_needs_renewal_at(
                    renewed_pem.as_bytes(),
                    current_unix_ts()
                ),
                "renewed managed identity should not need immediate renewal"
            );

            let stop_response: serde_json::Value = http
                .post(format!(
                    "{config_base}/api/services/client-cli/managed-auto-renew-client/stop"
                ))
                .send()
                .await
                .context("failed stopping managed client-cli through config-app")?
                .json()
                .await
                .context("failed decoding managed client-cli stop response")?;
            assert_eq!(
                stop_response
                    .get("stop")
                    .and_then(|value| value.get("was_running"))
                    .and_then(|value| value.as_bool()),
                Some(true)
            );
            assert_eq!(
                stop_response
                    .get("stop")
                    .and_then(|value| value.get("stopped"))
                    .and_then(|value| value.as_bool()),
                Some(true)
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
}
