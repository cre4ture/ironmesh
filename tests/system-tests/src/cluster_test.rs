#[cfg(test)]
mod tests {
    const CHUNK_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;
    const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;

    use std::collections::HashSet;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use std::time::Instant;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::framework::*;
    use anyhow::{Context, Result, bail};
    use bytes::Bytes;
    use client_sdk::{ClientIdentityMaterial, IronMeshClient, build_signed_request_headers};
    use reqwest::{Method, RequestBuilder, StatusCode};
    use tokio::time::sleep;
    use uuid::Uuid;

    #[derive(Clone)]
    struct AuthenticatedTestHttp {
        base_url: String,
        http: reqwest::Client,
        identity: ClientIdentityMaterial,
    }

    impl AuthenticatedTestHttp {
        fn new(base_url: String, identity: ClientIdentityMaterial) -> Self {
            Self {
                base_url,
                http: reqwest::Client::new(),
                identity,
            }
        }

        fn request(&self, method: Method, path_and_query: &str) -> Result<RequestBuilder> {
            let normalized = if path_and_query.starts_with('/') {
                path_and_query.to_string()
            } else {
                format!("/{path_and_query}")
            };
            let headers = build_signed_request_headers(
                &self.identity,
                method.as_str(),
                &normalized,
                unix_ts(),
                None,
            )?;
            let url = format!("{}{}", self.base_url.trim_end_matches('/'), normalized);
            Ok(headers.apply_to_reqwest(self.http.request(method, url)))
        }
    }

    struct AuthenticatedClusterFixture {
        server: ChildGuard,
        data_dir: PathBuf,
        client_dir: PathBuf,
        sdk: IronMeshClient,
        http: AuthenticatedTestHttp,
    }

    struct EnrolledHttpClient {
        client_dir: PathBuf,
        http: AuthenticatedTestHttp,
    }

    async fn start_authenticated_cluster_test_client(
        bind: &str,
        server_name: &str,
        client_name: &str,
    ) -> Result<(crate::framework::ChildGuard, EnrolledTestClient)> {
        let data_dir = fresh_data_dir(server_name);
        let client_dir = fresh_data_dir(client_name);
        let node_id = Uuid::new_v4().to_string();
        let server = start_authenticated_server(bind, &data_dir, &node_id, 1).await?;
        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "cluster.bootstrap.json",
            Some(client_name),
            Some(3600),
        )
        .await?;
        Ok((server, enrolled))
    }

    async fn start_authenticated_cluster_fixture(
        bind: &str,
        server_name: &str,
        client_name: &str,
    ) -> Result<AuthenticatedClusterFixture> {
        start_authenticated_cluster_fixture_with_options(
            bind,
            server_name,
            client_name,
            Uuid::new_v4().to_string(),
            1,
            None,
            None,
            &[],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn start_authenticated_cluster_fixture_with_options(
        bind: &str,
        server_name: &str,
        client_name: &str,
        node_id: String,
        replication_factor: usize,
        metadata_commit_mode: Option<&str>,
        heartbeat_timeout_secs: Option<u64>,
        extra_env: &[(&str, &str)],
    ) -> Result<AuthenticatedClusterFixture> {
        let data_dir = fresh_data_dir(server_name);
        let client_dir = fresh_data_dir(client_name);
        let server = start_authenticated_server_with_env_options(
            bind,
            &data_dir,
            &node_id,
            replication_factor,
            metadata_commit_mode,
            heartbeat_timeout_secs,
            extra_env,
        )
        .await?;
        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "cluster-http.bootstrap.json",
            Some(client_name),
            Some(3600),
        )
        .await?;
        let sdk = enrolled.build_client_async().await?;
        let http = AuthenticatedTestHttp::new(base_url, enrolled.identity.clone());
        Ok(AuthenticatedClusterFixture {
            server,
            data_dir,
            client_dir,
            sdk,
            http,
        })
    }

    fn unix_ts() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    async fn enroll_authenticated_http_client(
        base_url: &str,
        client_name: &str,
    ) -> Result<EnrolledHttpClient> {
        let client_dir = fresh_data_dir(client_name);
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "cluster-http.bootstrap.json",
            Some(client_name),
            Some(3600),
        )
        .await?;
        Ok(EnrolledHttpClient {
            client_dir,
            http: AuthenticatedTestHttp::new(base_url.to_string(), enrolled.identity),
        })
    }

    async fn wait_for_object_payload_authenticated(
        client: &AuthenticatedTestHttp,
        key: &str,
        expected: &str,
        attempts: usize,
    ) -> Result<()> {
        for _ in 0..attempts {
            let response = client
                .request(Method::GET, &format!("/store/{key}"))?
                .send()
                .await?;
            if response.status() == StatusCode::OK {
                let body = response.text().await?;
                if body == expected {
                    return Ok(());
                }
            }
            sleep(Duration::from_millis(100)).await;
        }

        bail!("timed out waiting for object '{key}' to match expected payload")
    }

    #[tokio::test]
    async fn cli_put_then_get_against_live_server() -> Result<()> {
        let bind = "127.0.0.1:19081";
        let (mut server, enrolled) = start_authenticated_cluster_test_client(
            bind,
            "cluster-cli-roundtrip-server",
            "cluster-cli-roundtrip-client",
        )
        .await?;
        let bootstrap_path = enrolled.bootstrap_path.to_string_lossy().to_string();

        run_cli(&[
            "--bootstrap-file",
            &bootstrap_path,
            "put",
            "cli-roundtrip",
            "hello-from-cli",
        ])
        .await?;

        let output =
            run_cli(&["--bootstrap-file", &bootstrap_path, "get", "cli-roundtrip"]).await?;
        assert!(output.contains("hello-from-cli"));

        stop_server(&mut server).await;
        Ok(())
    }

    async fn run_server_store_put_get_payload_case(
        bind: &str,
        data_dir_suffix: &str,
        payload_len: usize,
    ) -> Result<()> {
        let mut fixture = start_authenticated_cluster_fixture(
            bind,
            data_dir_suffix,
            &format!("{data_dir_suffix}-client"),
        )
        .await?;

        let result = async {
            let key = "large-payload.bin";

            let mut payload = vec![b'X'; payload_len];
            payload[0..6].copy_from_slice(b"BEGIN:");
            payload[payload_len - 4..payload_len].copy_from_slice(b":END");
            let payload = Bytes::from(payload);

            if payload_len > CHUNK_UPLOAD_THRESHOLD_BYTES {
                put_store_chunked(&fixture.http, key, &payload).await?;
            } else {
                fixture
                    .http
                    .request(Method::PUT, &format!("/store/{key}"))?
                    .body(payload.clone())
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let fetched = fixture
                .http
                .request(Method::GET, &format!("/store/{key}"))?
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;

            assert_eq!(fetched.len(), payload.len());
            assert_eq!(fetched, payload);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    async fn put_store_chunked(
        client: &AuthenticatedTestHttp,
        key: &str,
        payload: &[u8],
    ) -> Result<()> {
        let mut uploaded_chunks = Vec::new();

        for chunk in payload.chunks(CHUNK_UPLOAD_SIZE_BYTES) {
            let response: serde_json::Value = client
                .request(Method::POST, "/store-chunks/upload")?
                .body(chunk.to_vec())
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let hash = response
                .get("hash")
                .and_then(|v| v.as_str())
                .context("chunk upload response missing hash")?;
            let size_bytes = response
                .get("size_bytes")
                .and_then(|v| v.as_u64())
                .context("chunk upload response missing size_bytes")?;

            uploaded_chunks.push(serde_json::json!({
                "hash": hash,
                "size_bytes": size_bytes,
            }));
        }

        let complete_payload = serde_json::json!({
            "total_size_bytes": payload.len(),
            "chunks": uploaded_chunks,
        });

        client
            .request(Method::POST, &format!("/store/{key}?complete"))?
            .json(&complete_payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    fn parse_session_cookie(response: &reqwest::Response) -> Result<String> {
        let raw = response
            .headers()
            .get(reqwest::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .context("admin login response missing Set-Cookie header")?;
        raw.split(';')
            .next()
            .map(ToString::to_string)
            .context("failed to parse admin session cookie")
    }

    async fn setup_start_cluster(
        http: &reqwest::Client,
        bind: &str,
        admin_password: &str,
    ) -> Result<serde_json::Value> {
        http.post(format!("https://{bind}/setup/start-cluster"))
            .json(&serde_json::json!({
                "admin_password": admin_password,
                "public_origin": format!("https://{bind}"),
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("failed decoding setup start-cluster response")
    }

    async fn setup_generate_join_request(
        http: &reqwest::Client,
        bind: &str,
    ) -> Result<serde_json::Value> {
        http.post(format!("https://{bind}/setup/join/request"))
            .json(&serde_json::json!({
                "public_origin": format!("https://{bind}"),
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("failed decoding setup join request response")
    }

    async fn setup_import_node_enrollment(
        http: &reqwest::Client,
        bind: &str,
        admin_password: &str,
        package: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        http.post(format!("https://{bind}/setup/join/import"))
            .json(&serde_json::json!({
                "admin_password": admin_password,
                "package_json": serde_json::to_string(package)?,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("failed decoding setup join import response")
    }

    async fn wait_for_runtime_admin_surface(http: &reqwest::Client, bind: &str) -> Result<()> {
        for _ in 0..120 {
            if let Ok(response) = http
                .get(format!("https://{bind}/auth/admin/session"))
                .send()
                .await
                && response.status() == StatusCode::OK
            {
                return Ok(());
            }
            sleep(Duration::from_millis(250)).await;
        }
        bail!("runtime admin surface did not become ready on https://{bind}");
    }

    async fn admin_login_cookie(
        http: &reqwest::Client,
        bind: &str,
        admin_password: &str,
    ) -> Result<String> {
        let response = http
            .post(format!("https://{bind}/auth/admin/login"))
            .json(&serde_json::json!({
                "password": admin_password,
            }))
            .send()
            .await?
            .error_for_status()?;
        parse_session_cookie(&response)
    }

    async fn issue_node_enrollment_from_join_request_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        join_request: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        http.post(format!(
            "https://{bind}/auth/node-join-requests/issue-enrollment"
        ))
        .header(reqwest::header::COOKIE, session_cookie)
        .json(&serde_json::json!({
            "join_request": join_request,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed decoding node enrollment from join request response")
    }

    async fn issue_bootstrap_bundle_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        label: Option<&str>,
        expires_in_secs: Option<u64>,
    ) -> Result<client_sdk::ConnectionBootstrap> {
        http.post(format!("https://{bind}/auth/bootstrap-bundles/issue"))
            .header(reqwest::header::COOKIE, session_cookie)
            .json(&serde_json::json!({
                "label": label,
                "expires_in_secs": expires_in_secs,
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<client_sdk::ConnectionBootstrap>()
            .await
            .context("failed decoding bootstrap bundle response")
    }

    async fn issue_bootstrap_claim_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        label: Option<&str>,
        expires_in_secs: Option<u64>,
        preferred_rendezvous_url: Option<&str>,
    ) -> Result<client_sdk::ClientBootstrapClaimIssueResponse> {
        http.post(format!("https://{bind}/auth/bootstrap-claims/issue"))
            .header(reqwest::header::COOKIE, session_cookie)
            .json(&serde_json::json!({
                "label": label,
                "expires_in_secs": expires_in_secs,
                "preferred_rendezvous_url": preferred_rendezvous_url,
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<client_sdk::ClientBootstrapClaimIssueResponse>()
            .await
            .context("failed decoding bootstrap claim response")
    }

    async fn update_rendezvous_config_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        editable_urls: &[&str],
    ) -> Result<serde_json::Value> {
        http.put(format!("https://{bind}/auth/rendezvous-config"))
            .header(reqwest::header::COOKIE, session_cookie)
            .json(&serde_json::json!({
                "editable_urls": editable_urls,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .context("failed decoding rendezvous config response")
    }

    async fn export_managed_control_plane_promotion_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        passphrase: &str,
        target_node_id: &str,
        public_url: &str,
    ) -> Result<serde_json::Value> {
        http.post(format!(
            "https://{bind}/auth/managed-control-plane/promotion/export"
        ))
        .header(reqwest::header::COOKIE, session_cookie)
        .json(&serde_json::json!({
            "passphrase": passphrase,
            "target_node_id": target_node_id,
            "public_url": public_url,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed decoding managed control-plane promotion export response")
    }

    async fn import_managed_control_plane_promotion_with_cookie(
        http: &reqwest::Client,
        bind: &str,
        session_cookie: &str,
        passphrase: &str,
        package: &serde_json::Value,
        bind_addr: &str,
    ) -> Result<serde_json::Value> {
        http.post(format!(
            "https://{bind}/auth/managed-control-plane/promotion/import"
        ))
        .header(reqwest::header::COOKIE, session_cookie)
        .json(&serde_json::json!({
            "passphrase": passphrase,
            "package": package,
            "bind_addr": bind_addr,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed decoding managed control-plane promotion import response")
    }

    #[tokio::test]
    async fn server_store_put_get_payload_small() -> Result<()> {
        run_server_store_put_get_payload_case("127.0.0.1:19123", "server-small-payload", 1024).await
    }

    #[tokio::test]
    async fn server_store_put_get_payload_large_over_5mb() -> Result<()> {
        run_server_store_put_get_payload_case(
            "127.0.0.1:19124",
            "server-large-payload",
            5 * 1024 * 1024 + 1024,
        )
        .await
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
        let mut fixture = start_authenticated_cluster_fixture(
            bind,
            "snapshot-time-travel",
            "snapshot-time-travel-client",
        )
        .await?;

        let result = async {
            fixture
                .http
                .request(Method::PUT, "/store/history-key")?
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let first_snapshot_id = latest_snapshot_id_for_client(&fixture.sdk).await?;

            fixture
                .http
                .request(Method::PUT, "/store/history-key")?
                .body("v2")
                .send()
                .await?
                .error_for_status()?;

            let latest = fixture
                .http
                .request(Method::GET, "/store/history-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(latest, "v2");

            let historical = fixture
                .http
                .request(
                    Method::GET,
                    &format!("/store/history-key?snapshot={first_snapshot_id}"),
                )?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(historical, "v1");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn store_index_lists_keys_by_prefix_and_depth() -> Result<()> {
        let bind = "127.0.0.1:19122";
        let mut fixture =
            start_authenticated_cluster_fixture(bind, "store-index", "store-index-client").await?;

        let result = async {
            for (key, payload) in [
                ("docs/guide/intro.md", "intro"),
                ("docs/guide/setup.md", "setup"),
                ("docs/api/v1.json", "api"),
            ] {
                let encoded = key.replace('/', "%2F");
                fixture
                    .http
                    .request(Method::PUT, &format!("/store/{encoded}"))?
                    .body(payload)
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let index: serde_json::Value = fixture
                .http
                .request(Method::GET, "/store/index?prefix=docs&depth=1")?
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let paths = index
                .get("entries")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.get("path").and_then(|v| v.as_str()))
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .context("missing entries in store index response")?;

            assert!(paths.contains(&"docs/api/".to_string()));
            assert!(paths.contains(&"docs/guide/".to_string()));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn corrupted_chunk_returns_conflict() -> Result<()> {
        let bind = "127.0.0.1:19084";
        let mut fixture = start_authenticated_cluster_fixture(
            bind,
            "corrupt-detection",
            "corrupt-detection-client",
        )
        .await?;

        let result = async {
            fixture
                .http
                .request(Method::PUT, "/store/corrupt-me")?
                .body("payload-for-corruption-check")
                .send()
                .await?
                .error_for_status()?;

            let chunk_file = first_chunk_file(fixture.data_dir.join("chunks"))?;
            let mut bytes = fs::read(&chunk_file)?;
            if bytes.is_empty() {
                bail!("chunk file unexpectedly empty: {}", chunk_file.display());
            }
            bytes[0] ^= 0xFF;
            fs::write(&chunk_file, bytes)?;

            let response = fixture
                .http
                .request(Method::GET, "/store/corrupt-me")?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::CONFLICT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn version_graph_and_confirm_flow() -> Result<()> {
        let bind = "127.0.0.1:19085";
        let mut fixture =
            start_authenticated_cluster_fixture(bind, "version-graph", "version-graph-client")
                .await?;

        let result = async {
            fixture
                .http
                .request(Method::PUT, "/store/versioned-key")?
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let first_versions_payload = fixture
                .http
                .request(Method::GET, "/versions/versioned-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let first_versions: serde_json::Value = serde_json::from_str(&first_versions_payload)?;

            let first_version_id = first_versions
                .get("versions")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|entry| entry.get("version_id"))
                .and_then(|v| v.as_str())
                .context("missing first version id")?
                .to_string();

            fixture
                .http
                .request(Method::PUT, "/store/versioned-key?state=provisional")?
                .body("v2")
                .send()
                .await?
                .error_for_status()?;

            let second_versions_payload = fixture
                .http
                .request(Method::GET, "/versions/versioned-key")?
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

            let v1_payload = fixture
                .http
                .request(
                    Method::GET,
                    &format!("/store/versioned-key?version={first_version_id}"),
                )?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(v1_payload, "v1");

            let confirm_response = fixture
                .http
                .request(
                    Method::POST,
                    &format!("/versions/versioned-key/confirm/{provisional_version_id}"),
                )?
                .send()
                .await?;
            assert_eq!(confirm_response.status(), StatusCode::NO_CONTENT);

            let third_versions_payload = fixture
                .http
                .request(Method::GET, "/versions/versioned-key")?
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

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn read_modes_respect_preferred_and_confirmed_visibility() -> Result<()> {
        let bind = "127.0.0.1:19087";
        let mut fixture =
            start_authenticated_cluster_fixture(bind, "read-modes", "read-modes-client").await?;

        let result = async {
            fixture
                .http
                .request(Method::PUT, "/store/read-mode-key")?
                .body("confirmed-v1")
                .send()
                .await?
                .error_for_status()?;

            fixture
                .http
                .request(Method::PUT, "/store/read-mode-key?state=provisional")?
                .body("provisional-v2")
                .send()
                .await?
                .error_for_status()?;

            let versions_payload = fixture
                .http
                .request(Method::GET, "/versions/read-mode-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let versions: serde_json::Value = serde_json::from_str(&versions_payload)?;

            let reason = versions
                .get("preferred_head_reason")
                .and_then(|v| v.as_str())
                .context("missing preferred_head_reason")?;
            assert_eq!(reason, "provisional_fallback_no_confirmed");

            let preferred_default = fixture
                .http
                .request(Method::GET, "/store/read-mode-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(preferred_default, "provisional-v2");

            let preferred_explicit = fixture
                .http
                .request(Method::GET, "/store/read-mode-key?read_mode=preferred")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(preferred_explicit, "provisional-v2");

            let provisional_allowed = fixture
                .http
                .request(
                    Method::GET,
                    "/store/read-mode-key?read_mode=provisional_allowed",
                )?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(provisional_allowed, "provisional-v2");

            let confirmed_only = fixture
                .http
                .request(Method::GET, "/store/read-mode-key?read_mode=confirmed_only")?
                .send()
                .await?;
            assert_eq!(confirmed_only.status(), StatusCode::NOT_FOUND);

            fixture
                .http
                .request(Method::PUT, "/store/confirmed-head-key?state=confirmed")?
                .body("confirmed-head")
                .send()
                .await?
                .error_for_status()?;

            let confirmed_head = fixture
                .http
                .request(
                    Method::GET,
                    "/store/confirmed-head-key?read_mode=confirmed_only",
                )?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(confirmed_head, "confirmed-head");

            fixture
                .http
                .request(Method::PUT, "/store/provisional-only-key?state=provisional")?
                .body("only-provisional")
                .send()
                .await?
                .error_for_status()?;

            let provisional_only_confirmed = fixture
                .http
                .request(
                    Method::GET,
                    "/store/provisional-only-key?read_mode=confirmed_only",
                )?
                .send()
                .await?;
            assert_eq!(provisional_only_confirmed.status(), StatusCode::NOT_FOUND);

            let bad_mode = fixture
                .http
                .request(Method::GET, "/store/read-mode-key?read_mode=unknown")?
                .send()
                .await?;
            assert_eq!(bad_mode.status(), StatusCode::BAD_REQUEST);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn commit_endpoint_enforces_quorum_mode() -> Result<()> {
        let bind = "127.0.0.1:19086";
        let mut fixture = start_authenticated_cluster_fixture_with_options(
            bind,
            "version-commit-quorum",
            "version-commit-quorum-client",
            "00000000-0000-0000-0000-0000000000a1".to_string(),
            3,
            Some("quorum"),
            Some(1),
            &[],
        )
        .await?;

        let internal_base_url = internal_base_url_from_public_bind(bind)?;
        let client = reqwest::Client::new();

        let result = async {
            register_node(
                &client,
                &fixture.http.base_url,
                "00000000-0000-0000-0000-0000000000b2",
                "http://127.0.0.1:29091",
                "dc-b",
                "rack-2",
            )
            .await?;
            register_node(
                &client,
                &fixture.http.base_url,
                "00000000-0000-0000-0000-0000000000c3",
                "http://127.0.0.1:29092",
                "dc-c",
                "rack-3",
            )
            .await?;

            fixture
                .http
                .request(Method::PUT, "/store/quorum-key?state=provisional")?
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let versions_payload = fixture
                .http
                .request(Method::GET, "/versions/quorum-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            let versions: serde_json::Value = serde_json::from_str(&versions_payload)?;

            let provisional_version_id = versions
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
                .and_then(|entry| entry.get("version_id"))
                .and_then(|v| v.as_str())
                .context("missing provisional version id")?
                .to_string();

            sleep(Duration::from_millis(2_300)).await;
            client
                .get(format!("{}/cluster/status", fixture.http.base_url))
                .send()
                .await?
                .error_for_status()?;

            let rejected = fixture
                .http
                .request(
                    Method::POST,
                    &format!("/versions/quorum-key/commit/{provisional_version_id}"),
                )?
                .send()
                .await?;
            assert_eq!(rejected.status(), StatusCode::CONFLICT);

            let heartbeat_payload = serde_json::json!({
                "free_bytes": 700_000,
                "capacity_bytes": 1_000_000,
                "labels": {
                    "region": "local",
                    "dc": "dc-b",
                    "rack": "rack-2"
                }
            });

            let mtls_b = mtls_client_for_node_id("00000000-0000-0000-0000-0000000000b2")?;
            mtls_b
                .post(format!(
                    "{internal_base_url}/cluster/nodes/00000000-0000-0000-0000-0000000000b2/heartbeat"
                ))
                .json(&heartbeat_payload)
                .send()
                .await?
                .error_for_status()?;

            let accepted = fixture
                .http
                .request(
                    Method::POST,
                    &format!("/versions/quorum-key/commit/{provisional_version_id}"),
                )?
                .send()
                .await?;
            assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }

    #[tokio::test]
    async fn autonomous_peer_heartbeat_keeps_peers_online() -> Result<()> {
        let bind_a = "127.0.0.1:19144";
        let bind_b = "127.0.0.1:19145";
        let node_id_a = "00000000-0000-0000-0000-0000000007c1";
        let node_id_b = "00000000-0000-0000-0000-0000000007d2";

        let data_a = fresh_data_dir("autonomous-heartbeat-a");
        let data_b = fresh_data_dir("autonomous-heartbeat-b");

        let heartbeat_env = [
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "true"),
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS", "1"),
        ];

        let mut node_a = start_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let mut node_b = start_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let client = reqwest::Client::new();

        let result = async {
            register_node(&client, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&client, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&client, &base_a, 2, 120).await?;
            wait_for_online_nodes(&client, &base_b, 2, 80).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);

        result
    }

    #[tokio::test]
    async fn autonomous_peer_heartbeat_recovers_after_peer_restart() -> Result<()> {
        let bind_a = "127.0.0.1:19125";
        let bind_b = "127.0.0.1:19126";
        let node_id_a = "00000000-0000-0000-0000-0000000007e3";
        let node_id_b = "00000000-0000-0000-0000-0000000007f4";

        let data_a = fresh_data_dir("autonomous-heartbeat-recovery-a");
        let data_b = fresh_data_dir("autonomous-heartbeat-recovery-b");

        let heartbeat_env = [
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "true"),
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS", "1"),
        ];

        let mut node_a = start_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let mut node_b = start_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let client = reqwest::Client::new();

        let result = async {
            register_node(&client, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&client, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&client, &base_a, 2, 80).await?;

            stop_server(&mut node_b).await;
            wait_for_online_nodes(&client, &base_a, 1, 80).await?;

            node_b = start_server_with_env_options(
                bind_b,
                &data_b,
                node_id_b,
                2,
                None,
                Some(2),
                &heartbeat_env,
            )
            .await?;

            register_node(&client, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&client, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&client, &base_a, 2, 80).await?;
            wait_for_online_nodes(&client, &base_b, 2, 80).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);

        result
    }

    #[tokio::test]
    async fn autonomous_peer_heartbeat_recovers_after_repeated_peer_flaps() -> Result<()> {
        let bind_a = "127.0.0.1:19127";
        let bind_b = "127.0.0.1:19128";
        let node_id_a = "00000000-0000-0000-0000-000000000801";
        let node_id_b = "00000000-0000-0000-0000-000000000802";

        let data_a = fresh_data_dir("autonomous-heartbeat-flap-a");
        let data_b = fresh_data_dir("autonomous-heartbeat-flap-b");

        let heartbeat_env = [
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "true"),
            ("IRONMESH_AUTONOMOUS_HEARTBEAT_INTERVAL_SECS", "1"),
        ];

        let mut node_a = start_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let mut node_b = start_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            Some(2),
            &heartbeat_env,
        )
        .await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let client = reqwest::Client::new();

        let result = async {
            register_node(&client, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&client, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&client, &base_a, 2, 80).await?;

            for _ in 0..2 {
                stop_server(&mut node_b).await;
                wait_for_online_nodes(&client, &base_a, 1, 120).await?;

                node_b = start_server_with_env_options(
                    bind_b,
                    &data_b,
                    node_id_b,
                    2,
                    None,
                    Some(2),
                    &heartbeat_env,
                )
                .await?;

                register_node(&client, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
                register_node(&client, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

                wait_for_online_nodes(&client, &base_a, 2, 120).await?;
                wait_for_online_nodes(&client, &base_b, 2, 120).await?;
            }

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);

        result
    }

    #[tokio::test]
    async fn multi_node_replication_plan_detects_missing_replicas() -> Result<()> {
        let bind_a = "127.0.0.1:19090";
        let bind_b = "127.0.0.1:19091";
        let bind_c = "127.0.0.1:19092";

        let node_id_a = "00000000-0000-0000-0000-0000000000a1";
        let node_id_b = "00000000-0000-0000-0000-0000000000b2";
        let node_id_c = "00000000-0000-0000-0000-0000000000c3";

        let data_a = fresh_data_dir("multi-node-a");
        let data_b = fresh_data_dir("multi-node-b");
        let data_c = fresh_data_dir("multi-node-c");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_authenticated_server(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "multi-node-a-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            client_a
                .http
                .request(Method::PUT, "/store/multi-key")?
                .body("multi-node-payload")
                .send()
                .await?
                .error_for_status()?;

            let plan_body = http
                .get(format!("{base_a}/cluster/replication/plan"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            let plan: serde_json::Value = serde_json::from_str(&plan_body)?;
            let items = plan
                .get("items")
                .and_then(|v| v.as_array())
                .context("missing replication plan items")?;

            let item = items
                .iter()
                .find(|entry| {
                    entry
                        .get("key")
                        .and_then(|v| v.as_str())
                        .map(|k| k == "multi-key")
                        .unwrap_or(false)
                })
                .context("replication plan did not include multi-key")?;

            let missing = item
                .get("missing_nodes")
                .and_then(|v| v.as_array())
                .context("missing_nodes absent in plan item")?;
            assert!(
                !missing.is_empty(),
                "expected missing replicas in multi-node plan"
            );

            let has_version_subject = items.iter().any(|entry| {
                entry
                    .get("key")
                    .and_then(|v| v.as_str())
                    .map(|k| k.starts_with("multi-key@"))
                    .unwrap_or(false)
            });
            assert!(
                has_version_subject,
                "expected branch-aware replication subject key (multi-key@<version>)"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        stop_server(&mut node_c).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&data_c);
        let _ = fs::remove_dir_all(&client_a.client_dir);

        result
    }

    #[tokio::test]
    async fn cluster_node_decommission_removes_member_and_validates_errors() -> Result<()> {
        let bind = "127.0.0.1:19093";
        let local_node_id = "00000000-0000-0000-0000-0000000000d1";
        let remove_node_id = "00000000-0000-0000-0000-0000000000e2";

        let data_dir = fresh_data_dir("node-decommission");
        let mut server = start_server_with_config(bind, &data_dir, local_node_id, 2).await?;

        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(
                &http,
                &base_url,
                remove_node_id,
                "http://127.0.0.1:29093",
                "dc-x",
                "rack-x",
            )
            .await?;

            let before_nodes: serde_json::Value = http
                .get(format!("{base_url}/cluster/nodes"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let before_len = before_nodes
                .as_array()
                .map(Vec::len)
                .context("cluster nodes response is not an array")?;
            assert!(before_len >= 2);

            let remove_response = http
                .delete(format!("{base_url}/cluster/nodes/{remove_node_id}"))
                .send()
                .await?;
            assert_eq!(remove_response.status(), StatusCode::NO_CONTENT);

            let after_nodes: serde_json::Value = http
                .get(format!("{base_url}/cluster/nodes"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let after_array = after_nodes
                .as_array()
                .context("cluster nodes response is not an array")?;
            assert_eq!(after_array.len() + 1, before_len);

            let removed_absent = after_array.iter().all(|entry| {
                entry
                    .get("node_id")
                    .and_then(|v| v.as_str())
                    .map(|id| id != remove_node_id)
                    .unwrap_or(true)
            });
            assert!(removed_absent, "decommissioned node should be absent");

            let not_found = http
                .delete(format!("{base_url}/cluster/nodes/{remove_node_id}"))
                .send()
                .await?;
            assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

            let local_conflict = http
                .delete(format!("{base_url}/cluster/nodes/{local_node_id}"))
                .send()
                .await?;
            assert_eq!(local_conflict.status(), StatusCode::CONFLICT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn manual_replication_repair_reduces_missing_plan_items() -> Result<()> {
        let bind_a = "127.0.0.1:19105";
        let bind_b = "127.0.0.1:19106";
        let bind_c = "127.0.0.1:19107";

        let node_id_a = "00000000-0000-0000-0000-0000000003a1";
        let node_id_b = "00000000-0000-0000-0000-0000000003b2";
        let node_id_c = "00000000-0000-0000-0000-0000000003c3";

        let data_a = fresh_data_dir("repair-a");
        let data_b = fresh_data_dir("repair-b");
        let data_c = fresh_data_dir("repair-c");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_authenticated_server(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "repair-a-client").await?;
        let client_b = enroll_authenticated_http_client(&base_b, "repair-b-client").await?;
        let client_c = enroll_authenticated_http_client(&base_c, "repair-c-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            client_a
                .http
                .request(Method::PUT, "/store/repair-key")?
                .body("repair-payload")
                .send()
                .await?
                .error_for_status()?;

            let before_plan: serde_json::Value = http
                .get(format!("{base_a}/cluster/replication/plan"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let before_under = before_plan
                .get("under_replicated")
                .and_then(|v| v.as_u64())
                .context("missing under_replicated before repair")?;
            assert!(before_under >= 1, "expected missing replicas before repair");

            let repair_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let successful = repair_report
                .get("successful_transfers")
                .and_then(|v| v.as_u64())
                .context("missing successful_transfers")?;
            assert!(
                successful >= 1,
                "expected at least one successful transfer, report={repair_report:?}"
            );

            let after_plan: serde_json::Value = http
                .get(format!("{base_a}/cluster/replication/plan"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let after_under = after_plan
                .get("under_replicated")
                .and_then(|v| v.as_u64())
                .context("missing under_replicated after repair")?;

            assert!(
                after_under <= before_under,
                "repair should not increase under-replication"
            );

            let b_read = client_b
                .http
                .request(Method::GET, "/store/repair-key")?
                .send()
                .await?;
            let c_read = client_c
                .http
                .request(Method::GET, "/store/repair-key")?
                .send()
                .await?;
            assert!(
                b_read.status() == StatusCode::OK || c_read.status() == StatusCode::OK,
                "expected at least one remote node to have replicated payload"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        stop_server(&mut node_c).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&data_c);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);
        let _ = fs::remove_dir_all(&client_c.client_dir);

        result
    }

    #[tokio::test]
    async fn autonomous_replication_after_put_populates_peer_without_manual_repair() -> Result<()> {
        let bind_a = "127.0.0.1:19131";
        let bind_b = "127.0.0.1:19132";

        let node_id_a = "00000000-0000-0000-0000-0000000007a1";
        let node_id_b = "00000000-0000-0000-0000-0000000007b2";

        let data_a = fresh_data_dir("auto-repair-a");
        let data_b = fresh_data_dir("auto-repair-b");

        let mut node_a = start_authenticated_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            None,
            &[("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "true")],
        )
        .await?;
        let mut node_b = start_authenticated_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            None,
            &[("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "true")],
        )
        .await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "auto-repair-a-client").await?;
        let client_b = enroll_authenticated_http_client(&base_b, "auto-repair-b-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;

            let payload = "autonomous-replication-payload";
            client_a
                .http
                .request(Method::PUT, "/store/autonomous-repair-key")?
                .body(payload)
                .send()
                .await?
                .error_for_status()?;

            wait_for_object_payload_authenticated(
                &client_b.http,
                "autonomous-repair-key",
                payload,
                120,
            )
            .await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);

        result
    }

    #[tokio::test]
    async fn manual_replication_repair_respects_batch_size_limit() -> Result<()> {
        let bind_a = "127.0.0.1:19108";
        let bind_b = "127.0.0.1:19109";
        let bind_c = "127.0.0.1:19110";

        let node_id_a = "00000000-0000-0000-0000-0000000004a1";
        let node_id_b = "00000000-0000-0000-0000-0000000004b2";
        let node_id_c = "00000000-0000-0000-0000-0000000004c3";

        let data_a = fresh_data_dir("repair-batch-a");
        let data_b = fresh_data_dir("repair-batch-b");
        let data_c = fresh_data_dir("repair-batch-c");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_authenticated_server(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "repair-batch-a-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            client_a
                .http
                .request(Method::PUT, "/store/repair-batch-key-a")?
                .body("payload-a")
                .send()
                .await?
                .error_for_status()?;

            client_a
                .http
                .request(Method::PUT, "/store/repair-batch-key-b")?
                .body("payload-b")
                .send()
                .await?
                .error_for_status()?;

            let report: serde_json::Value = http
                .post(format!("{base_a}/cluster/replication/repair?batch_size=1"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let attempted = report
                .get("attempted_transfers")
                .and_then(|v| v.as_u64())
                .context("missing attempted_transfers")?;
            assert_eq!(attempted, 1, "expected one transfer due to batch_size=1");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        stop_server(&mut node_c).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&data_c);
        let _ = fs::remove_dir_all(&client_a.client_dir);

        result
    }

    #[tokio::test]
    async fn manual_replication_repair_preserves_version_id_on_target() -> Result<()> {
        let bind_a = "127.0.0.1:19111";
        let bind_b = "127.0.0.1:19112";

        let node_id_a = "00000000-0000-0000-0000-0000000005a1";
        let node_id_b = "00000000-0000-0000-0000-0000000005b2";

        let data_a = fresh_data_dir("repair-version-a");
        let data_b = fresh_data_dir("repair-version-b");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "repair-version-a-client").await?;
        let client_b = enroll_authenticated_http_client(&base_b, "repair-version-b-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;

            client_a
                .http
                .request(Method::PUT, "/store/repair-version-key")?
                .body("repair-version-payload")
                .send()
                .await?
                .error_for_status()?;

            let versions_a: serde_json::Value = client_a
                .http
                .request(Method::GET, "/versions/repair-version-key")?
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let source_version_id = versions_a
                .get("preferred_head_version_id")
                .and_then(|v| v.as_str())
                .context("missing preferred_head_version_id on source")?
                .to_string();

            let repair_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let successful = repair_report
                .get("successful_transfers")
                .and_then(|v| v.as_u64())
                .context("missing successful_transfers")?;
            assert!(
                successful >= 1,
                "expected at least one successful transfer, report={repair_report:?}"
            );

            let versions_b: serde_json::Value = client_b
                .http
                .request(Method::GET, "/versions/repair-version-key")?
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let contains_source_version = versions_b
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries.iter().any(|entry| {
                        entry
                            .get("version_id")
                            .and_then(|v| v.as_str())
                            .map(|id| id == source_version_id)
                            .unwrap_or(false)
                    })
                })
                .unwrap_or(false);

            assert!(
                contains_source_version,
                "expected target node to contain replicated source version id"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);

        result
    }

    #[tokio::test]
    async fn manual_replication_repair_propagates_remote_rename_as_old_path_removal() -> Result<()>
    {
        let bind_a = "127.0.0.1:19144";
        let bind_b = "127.0.0.1:19145";

        let node_id_a = "00000000-0000-0000-0000-0000000009a1";
        let node_id_b = "00000000-0000-0000-0000-0000000009b2";

        let data_a = fresh_data_dir("repair-rename-a");
        let data_b = fresh_data_dir("repair-rename-b");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "repair-rename-a-client").await?;
        let client_b = enroll_authenticated_http_client(&base_b, "repair-rename-b-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_b, node_id_a, &base_a, "dc-a", "rack-1").await?;
            wait_for_online_nodes(&http, &base_a, 2, 120).await?;
            wait_for_online_nodes(&http, &base_b, 2, 120).await?;

            let from_path = "rename-gap-from.txt";
            let to_path = "rename-gap-to.txt";
            let payload = "rename-gap-payload";

            client_a
                .http
                .request(Method::PUT, &format!("/store/{from_path}"))?
                .body(payload)
                .send()
                .await?
                .error_for_status()?;

            http.post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?;

            wait_for_object_payload_authenticated(&client_b.http, from_path, payload, 120).await?;

            client_a
                .http
                .request(Method::POST, "/store/rename")?
                .json(&serde_json::json!({
                    "from_path": from_path,
                    "to_path": to_path,
                    "overwrite": false,
                }))
                .send()
                .await?
                .error_for_status()?;

            http.post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?;

            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                let new_resp = client_b
                    .http
                    .request(Method::GET, &format!("/store/{to_path}"))?
                    .send()
                    .await?;
                let old_resp = client_b
                    .http
                    .request(Method::GET, &format!("/store/{from_path}"))?
                    .send()
                    .await?;

                if new_resp.status() == StatusCode::OK && old_resp.status() == StatusCode::NOT_FOUND
                {
                    let new_body = new_resp.text().await?;
                    assert_eq!(new_body, payload);
                    return Ok::<(), anyhow::Error>(());
                }

                sleep(Duration::from_millis(100)).await;
            }

            bail!(
                "peer did not converge rename semantics: expected {} to disappear and {} to appear",
                from_path,
                to_path
            )
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);

        result
    }

    #[tokio::test]
    async fn recursive_directory_delete_query_removes_remote_subtree() -> Result<()> {
        let bind = "127.0.0.1:19146";
        let (mut server, enrolled) = start_authenticated_cluster_test_client(
            bind,
            "cluster-recursive-delete-server",
            "cluster-recursive-delete-client",
        )
        .await?;
        let sdk = enrolled.build_client_async().await?;

        let result = async {
            for (key, payload) in [
                ("docs/", Bytes::new()),
                ("docs/a.txt", Bytes::from_static(b"a")),
                ("docs/nested/", Bytes::new()),
                ("docs/nested/b.txt", Bytes::from_static(b"b")),
                ("keep.txt", Bytes::from_static(b"keep")),
            ] {
                sdk.put_large_aware(key, payload).await?;
            }

            sdk.delete_path("docs/").await?;

            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(5) {
                let index = sdk.store_index(None, 64, None).await?;
                let docs_present = index.entries.iter().any(|entry| {
                    entry.path == "docs" || entry.path == "docs/" || entry.path.starts_with("docs/")
                });
                let keep_present = index.entries.iter().any(|entry| entry.path == "keep.txt");
                let docs_file_missing = sdk.get("docs/a.txt").await.is_err();
                let nested_file_missing = sdk.get("docs/nested/b.txt").await.is_err();

                if !docs_present && keep_present && docs_file_missing && nested_file_missing {
                    let keep_bytes = sdk.get("keep.txt").await?;
                    assert_eq!(keep_bytes.as_ref(), b"keep");
                    return Ok::<(), anyhow::Error>(());
                }

                sleep(Duration::from_millis(100)).await;
            }

            bail!("recursive directory delete did not remove remote subtree")
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    #[ignore = "performance measurement test; run manually"]
    async fn manual_replication_repair_reports_small_payload_throughput() -> Result<()> {
        let bind_a = "127.0.0.1:19141";
        let bind_b = "127.0.0.1:19142";
        let bind_c = "127.0.0.1:19143";

        let node_id_a = "00000000-0000-0000-0000-0000000008a1";
        let node_id_b = "00000000-0000-0000-0000-0000000008b2";
        let node_id_c = "00000000-0000-0000-0000-0000000008c3";

        let data_a = fresh_data_dir("repair-perf-a");
        let data_b = fresh_data_dir("repair-perf-b");
        let data_c = fresh_data_dir("repair-perf-c");

        let env = [
            ("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "false"),
            ("IRONMESH_STARTUP_REPAIR_ENABLED", "false"),
            ("IRONMESH_REPLICATION_REPAIR_ENABLED", "false"),
        ];

        let mut node_a = start_authenticated_server_with_env_options(
            bind_a, &data_a, node_id_a, 3, None, None, &env,
        )
        .await?;
        let mut node_b = start_authenticated_server_with_env_options(
            bind_b, &data_b, node_id_b, 3, None, None, &env,
        )
        .await?;
        let mut node_c = start_authenticated_server_with_env_options(
            bind_c, &data_c, node_id_c, 3, None, None, &env,
        )
        .await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "repair-perf-a-client").await?;

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            let object_count = 12u64;
            for idx in 0..object_count {
                client_a
                    .http
                    .request(Method::PUT, &format!("/store/repair-perf-key-{idx}"))?
                    .body("x")
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let before_plan: serde_json::Value = http
                .get(format!("{base_a}/cluster/replication/plan"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let before_under = before_plan
                .get("under_replicated")
                .and_then(|v| v.as_u64())
                .context("missing under_replicated before perf repair")?;
            assert!(before_under > 0, "expected under-replicated items before repair");

            let start = Instant::now();
            let repair_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let elapsed = start.elapsed();

            let attempted = repair_report
                .get("attempted_transfers")
                .and_then(|v| v.as_u64())
                .context("missing attempted_transfers in perf repair report")?;
            let successful = repair_report
                .get("successful_transfers")
                .and_then(|v| v.as_u64())
                .context("missing successful_transfers in perf repair report")?;

            assert!(attempted > 0, "expected attempted transfers in perf test");
            assert!(
                successful > 0,
                "expected successful transfers in perf test, report={repair_report:?}"
            );

            let elapsed_secs = elapsed.as_secs_f64().max(0.001);
            let transfers_per_sec = attempted as f64 / elapsed_secs;

            eprintln!(
                "repair perf: attempted={attempted} successful={successful} elapsed_ms={} throughput={:.2} transfers/s",
                elapsed.as_millis(),
                transfers_per_sec
            );

            let after_plan: serde_json::Value = http
                .get(format!("{base_a}/cluster/replication/plan"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let after_under = after_plan
                .get("under_replicated")
                .and_then(|v| v.as_u64())
                .context("missing under_replicated after perf repair")?;
            assert!(
                after_under <= before_under,
                "repair should not increase under-replication in perf test"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        stop_server(&mut node_c).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&data_c);
        let _ = fs::remove_dir_all(&client_a.client_dir);

        result
    }

    #[tokio::test]
    async fn internal_listener_requires_client_certificate() -> Result<()> {
        let bind = "127.0.0.1:19113";
        let node_id = "00000000-0000-0000-0000-0000000006a1";
        let data_dir = fresh_data_dir("internal-mtls-requires-client-cert");

        let mut server = start_server_with_config(bind, &data_dir, node_id, 1).await?;
        let internal_base = internal_base_url_from_public_bind(bind)?;

        let https_only = https_client_with_root_from_data_dir(&data_dir)?;
        assert!(
            https_only
                .get(format!("{internal_base}/health"))
                .send()
                .await
                .is_err(),
            "expected internal listener to reject missing client certificate"
        );

        let mtls = mtls_client_from_data_dir(&data_dir)?;
        let ok = mtls
            .get(format!("{internal_base}/health"))
            .send()
            .await?
            .error_for_status()?;
        assert_eq!(ok.status(), StatusCode::OK);

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        Ok(())
    }

    #[tokio::test]
    async fn internal_listener_enforces_self_only_heartbeat() -> Result<()> {
        let bind_a = "127.0.0.1:19114";
        let bind_b = "127.0.0.1:19115";

        let node_id_a = "00000000-0000-0000-0000-0000000006b2";
        let node_id_b = "00000000-0000-0000-0000-0000000006c3";

        let data_a = fresh_data_dir("internal-mtls-heartbeat-a");
        let data_b = fresh_data_dir("internal-mtls-heartbeat-b");

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let internal_b = internal_base_url_from_public_bind(bind_b)?;

        let http = reqwest::Client::new();

        // Register membership in both directions so B recognizes A's identity.
        register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
        register_node(&http, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

        let mtls_a = mtls_client_from_data_dir(&data_a)?;
        let payload = serde_json::json!({
            "free_bytes": 800_000,
            "capacity_bytes": 1_000_000,
            "labels": { "region": "local", "dc": "dc-a", "rack": "rack-a" }
        });

        let ok = mtls_a
            .post(format!("{internal_b}/cluster/nodes/{node_id_a}/heartbeat"))
            .json(&payload)
            .send()
            .await?;
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);

        let forbidden = mtls_a
            .post(format!("{internal_b}/cluster/nodes/{node_id_b}/heartbeat"))
            .json(&payload)
            .send()
            .await?;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        Ok(())
    }
    #[tokio::test]
    async fn rejoin_reconciliation_preserves_provisional_branches() -> Result<()> {
        let bind_a = "127.0.0.1:19100";
        let bind_b = "127.0.0.1:19101";

        let node_id_a = "00000000-0000-0000-0000-0000000001a1";
        let node_id_b = "00000000-0000-0000-0000-0000000001b2";

        let data_a = fresh_data_dir("rejoin-a");
        let data_b = fresh_data_dir("rejoin-b");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();
        let client_a = enroll_authenticated_http_client(&base_a, "rejoin-a-client").await?;
        let client_b = enroll_authenticated_http_client(&base_b, "rejoin-b-client").await?;

        let result = async {
            client_a
                .http
                .request(Method::PUT, "/store/rejoin-key")?
                .body("a-confirmed")
                .send()
                .await?
                .error_for_status()?;

            client_a
                .http
                .request(Method::PUT, "/store/rejoin-key?state=provisional")?
                .body("a-branch")
                .send()
                .await?
                .error_for_status()?;

            client_b
                .http
                .request(Method::PUT, "/store/rejoin-key?state=provisional")?
                .body("b-branch")
                .send()
                .await?
                .error_for_status()?;

            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;

            let reconcile = http
                .post(format!("{base_a}/cluster/reconcile/{node_id_b}"))
                .send()
                .await?
                .error_for_status()?;
            let reconcile_body: serde_json::Value = reconcile.json().await?;
            let imported = reconcile_body
                .get("imported")
                .and_then(|v| v.as_u64())
                .context("missing imported count")?;
            assert!(
                imported >= 1,
                "expected at least one imported provisional commit"
            );

            let versions_payload = client_a
                .http
                .request(Method::GET, "/versions/rejoin-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            let versions: serde_json::Value = serde_json::from_str(&versions_payload)?;
            let entries = versions
                .get("versions")
                .and_then(|v| v.as_array())
                .context("missing versions array")?;

            let provisional_count = entries
                .iter()
                .filter(|entry| {
                    entry
                        .get("state")
                        .and_then(|v| v.as_str())
                        .map(|state| state == "provisional")
                        .unwrap_or(false)
                })
                .count();
            assert!(
                provisional_count >= 2,
                "expected at least two provisional branches after reconciliation"
            );

            let mut payloads = HashSet::new();
            for entry in entries {
                let version_id = entry
                    .get("version_id")
                    .and_then(|v| v.as_str())
                    .context("missing version_id")?;

                let payload = client_a
                    .http
                    .request(
                        Method::GET,
                        &format!("/store/rejoin-key?version={version_id}"),
                    )?
                    .send()
                    .await?
                    .error_for_status()?
                    .text()
                    .await?;
                payloads.insert(payload);
            }

            assert!(payloads.contains("a-confirmed"));
            assert!(payloads.contains("a-branch"));
            assert!(payloads.contains("b-branch"));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);

        result
    }

    #[tokio::test]
    async fn reconcile_replay_is_idempotent() -> Result<()> {
        let bind_a = "127.0.0.1:19103";
        let bind_b = "127.0.0.1:19104";

        let node_id_a = "00000000-0000-0000-0000-0000000002a1";
        let node_id_b = "00000000-0000-0000-0000-0000000002b2";

        let data_a = fresh_data_dir("reconcile-idempotent-a");
        let data_b = fresh_data_dir("reconcile-idempotent-b");

        let mut node_a = start_authenticated_server(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_authenticated_server(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();
        let client_a =
            enroll_authenticated_http_client(&base_a, "reconcile-idempotent-a-client").await?;
        let client_b =
            enroll_authenticated_http_client(&base_b, "reconcile-idempotent-b-client").await?;

        let result = async {
            client_b
                .http
                .request(Method::PUT, "/store/replay-key?state=provisional")?
                .body("remote-branch")
                .send()
                .await?
                .error_for_status()?;

            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;

            let first_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/reconcile/{node_id_b}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let first_imported = first_report
                .get("imported")
                .and_then(|v| v.as_u64())
                .context("missing first imported count")?;
            assert!(first_imported >= 1, "expected first reconcile to import");

            let versions_after_first: serde_json::Value = client_a
                .http
                .request(Method::GET, "/versions/replay-key")?
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let count_after_first = versions_after_first
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .context("missing versions after first reconcile")?;

            let second_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/reconcile/{node_id_b}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let second_imported = second_report
                .get("imported")
                .and_then(|v| v.as_u64())
                .context("missing second imported count")?;
            let second_skipped_replayed = second_report
                .get("skipped_replayed")
                .and_then(|v| v.as_u64())
                .context("missing second skipped_replayed count")?;

            assert_eq!(second_imported, 0);
            assert!(
                second_skipped_replayed >= 1,
                "expected replay skips on second reconcile"
            );

            let versions_after_second: serde_json::Value = client_a
                .http
                .request(Method::GET, "/versions/replay-key")?
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let count_after_second = versions_after_second
                .get("versions")
                .and_then(|v| v.as_array())
                .map(|arr| arr.len())
                .context("missing versions after second reconcile")?;

            assert_eq!(count_after_first, count_after_second);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);
        let _ = fs::remove_dir_all(&client_b.client_dir);

        result
    }

    #[tokio::test]
    async fn relay_required_rendezvous_cluster_supports_bootstrap_enrollment_and_replication()
    -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19147";
        let bind_a = "127.0.0.1:19148";
        let bind_b = "127.0.0.1:19149";
        let cluster_id = "11111111-1111-7111-8111-111111111111";
        let node_id_a = "00000000-0000-0000-0000-0000000007a1";
        let node_id_b = "00000000-0000-0000-0000-0000000007b2";
        let admin_token = "admin-secret";

        let rendezvous_url = format!("http://{rendezvous_bind}");
        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");

        let data_a = fresh_data_dir("relay-rendezvous-node-a");
        let data_b = fresh_data_dir("relay-rendezvous-node-b");
        let client_dir = fresh_data_dir("relay-rendezvous-client");

        let node_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "required"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
            ("IRONMESH_ADMIN_TOKEN", admin_token),
            ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
        ];

        let mut rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        let mut node_a = start_server_with_env(bind_a, &data_a, node_id_a, 2, &node_env).await?;
        let mut node_b = start_server_with_env(bind_b, &data_b, node_id_b, 2, &node_env).await?;
        let http = reqwest::Client::new();

        let result = async {
            let wait_for_known_nodes = |base_url: String, expected_nodes: usize| {
                let http = http.clone();
                async move {
                    for _ in 0..120 {
                        if let Ok(response) =
                            http.get(format!("{base_url}/cluster/nodes")).send().await
                            && let Ok(response) = response.error_for_status()
                            && let Ok(nodes) = response.json::<serde_json::Value>().await
                            && let Some(entries) = nodes.as_array()
                            && entries.len() == expected_nodes
                        {
                            return Ok::<(), anyhow::Error>(());
                        }
                        sleep(Duration::from_millis(250)).await;
                    }
                    bail!("cluster did not converge to {expected_nodes} known nodes at {base_url}");
                }
            };

            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 2, 120).await?;
            wait_for_known_nodes(base_a.clone(), 2).await?;
            wait_for_known_nodes(base_b.clone(), 2).await?;

            let bootstrap_a =
                issue_bootstrap_bundle(&http, &base_a, admin_token, Some("relay-cli"), Some(3600))
                    .await?;
            let bootstrap_a_path = client_dir.join("node-a.bootstrap.json");
            bootstrap_a.write_to_path(&bootstrap_a_path)?;

            let client_identity_path = client_dir.join("client-identity.json");
            let bootstrap_a_arg = bootstrap_a_path.to_string_lossy().into_owned();
            let client_identity_arg = client_identity_path.to_string_lossy().into_owned();

            let enroll_output = run_cli(&[
                "--bootstrap-file",
                bootstrap_a_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "enroll",
                "--label",
                "relay-cli",
            ])
            .await?;
            assert!(
                enroll_output.contains("enrolled device"),
                "unexpected enroll output: {enroll_output}"
            );
            assert!(
                client_identity_path.exists(),
                "expected client identity file to be written"
            );

            let put_output = run_cli(&[
                "--bootstrap-file",
                bootstrap_a_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "put",
                "relay-key",
                "payload-over-rendezvous-relay",
            ])
            .await?;
            assert!(
                put_output.contains("stored 'relay-key'"),
                "unexpected put output: {put_output}"
            );

            for _ in 0..120 {
                if let Ok(output) = run_cli(&[
                    "--bootstrap-file",
                    bootstrap_a_arg.as_str(),
                    "--client-identity-file",
                    client_identity_arg.as_str(),
                    "get",
                    "relay-key",
                ])
                .await
                    && output.contains("payload-over-rendezvous-relay")
                {
                    break;
                }

                sleep(Duration::from_millis(250)).await;
            }

            let bootstrap_b =
                issue_bootstrap_bundle(&http, &base_b, admin_token, Some("relay-cli"), Some(3600))
                    .await?;
            let bootstrap_b_path = client_dir.join("node-b.bootstrap.json");
            bootstrap_b.write_to_path(&bootstrap_b_path)?;
            let bootstrap_b_arg = bootstrap_b_path.to_string_lossy().into_owned();

            for _ in 0..120 {
                http.post(format!("{base_a}/cluster/replication/repair"))
                    .send()
                    .await?
                    .error_for_status()?;

                if let Ok(output) = run_cli(&[
                    "--bootstrap-file",
                    bootstrap_b_arg.as_str(),
                    "--client-identity-file",
                    client_identity_arg.as_str(),
                    "get",
                    "relay-key",
                ])
                .await
                    && output.contains("payload-over-rendezvous-relay")
                {
                    return Ok::<(), anyhow::Error>(());
                }

                sleep(Duration::from_millis(250)).await;
            }

            bail!("replicated payload was not readable through node B via bootstrap-aware client");
        }
        .await;

        stop_server(&mut rendezvous).await;
        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_dir);

        result
    }

    #[tokio::test]
    async fn bootstrap_claim_redeems_through_selected_rendezvous_when_multiple_are_configured()
    -> Result<()> {
        let dedicated_rendezvous_bind = "127.0.0.1:19165";
        let bind_a = "127.0.0.1:19166";
        let admin_password = "selected-rendezvous-password";
        let dedicated_rendezvous_url = format!("http://{dedicated_rendezvous_bind}");
        let data_a = fresh_data_dir("bootstrap-claim-selected-rendezvous-node-a");
        let client_dir = fresh_data_dir("bootstrap-claim-selected-rendezvous-client");

        let mut dedicated_rendezvous = start_rendezvous_service(dedicated_rendezvous_bind).await?;
        let mut node_a = start_zero_touch_server(bind_a, &data_a).await?;
        let insecure_http = insecure_https_client()?;

        let result = async {
            setup_start_cluster(&insecure_http, bind_a, admin_password).await?;
            wait_for_runtime_admin_surface(&insecure_http, bind_a).await?;
            let admin_cookie = admin_login_cookie(&insecure_http, bind_a, admin_password).await?;

            let rendezvous_config = update_rendezvous_config_with_cookie(
                &insecure_http,
                bind_a,
                &admin_cookie,
                &[dedicated_rendezvous_url.as_str()],
            )
            .await?;
            let effective_urls = rendezvous_config
                .get("effective_urls")
                .and_then(|value| value.as_array())
                .context("missing effective_urls in rendezvous config response")?;
            assert_eq!(effective_urls.len(), 2);
            assert!(
                effective_urls
                    .iter()
                    .filter_map(|value| value.as_str())
                    .any(|value| value == format!("{dedicated_rendezvous_url}/")),
                "expected dedicated rendezvous URL in effective config: {rendezvous_config}"
            );

            wait_for_rendezvous_registered_endpoints(&dedicated_rendezvous_url, 1, 120).await?;

            let issued = issue_bootstrap_claim_with_cookie(
                &insecure_http,
                bind_a,
                &admin_cookie,
                Some("selected-rendezvous-cli"),
                Some(3600),
                Some(dedicated_rendezvous_url.as_str()),
            )
            .await?;
            issued.validate()?;
            assert_eq!(
                issued.bootstrap_claim.rendezvous_url,
                format!("{dedicated_rendezvous_url}/")
            );

            let claim_path = client_dir.join("selected-rendezvous.claim.json");
            fs::write(&claim_path, issued.bootstrap_claim.to_json_pretty()?)
                .context("failed writing bootstrap claim json")?;
            let claim_arg = claim_path.to_string_lossy().into_owned();

            let client_identity_path = client_dir.join("selected-rendezvous.identity.json");
            let client_identity_arg = client_identity_path.to_string_lossy().into_owned();

            let enroll_output = run_cli(&[
                "--bootstrap-file",
                claim_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "enroll",
                "--label",
                "selected-rendezvous-cli",
            ])
            .await?;
            assert!(
                enroll_output.contains("enrolled device"),
                "unexpected enroll output: {enroll_output}"
            );
            assert!(
                client_identity_path.exists(),
                "expected client identity file to be written"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut dedicated_rendezvous).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&client_dir);

        result
    }

    #[tokio::test]
    async fn bootstrap_client_uses_relay_when_direct_endpoint_is_unreachable() -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19135";
        let bind = "127.0.0.1:19136";
        let cluster_id = "11111111-1111-7111-8111-111111111112";
        let node_id = "00000000-0000-0000-0000-0000000008a1";
        let admin_token = "admin-secret";

        let rendezvous_url = format!("http://{rendezvous_bind}");
        let base_url = format!("http://{bind}");
        let data_dir = fresh_data_dir("relay-client-unreachable-direct-node");
        let client_dir = fresh_data_dir("relay-client-unreachable-direct-client");

        let node_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "fallback"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
            ("IRONMESH_ADMIN_TOKEN", admin_token),
            ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
        ];

        let mut rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        let mut node = start_server_with_env(bind, &data_dir, node_id, 1, &node_env).await?;
        let http = reqwest::Client::new();

        let result = async {
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let bootstrap = issue_bootstrap_bundle(
                &http,
                &base_url,
                admin_token,
                Some("relay-cli"),
                Some(3600),
            )
            .await?;
            let bootstrap_path = client_dir.join("bootstrap.json");
            bootstrap.write_to_path(&bootstrap_path)?;

            let client_identity_path = client_dir.join("client-identity.json");
            let bootstrap_arg = bootstrap_path.to_string_lossy().into_owned();
            let client_identity_arg = client_identity_path.to_string_lossy().into_owned();

            run_cli(&[
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "enroll",
                "--label",
                "relay-cli",
            ])
            .await?;

            let mut relay_only_bootstrap = bootstrap.clone();
            for endpoint in &mut relay_only_bootstrap.direct_endpoints {
                if endpoint.usage == Some(client_sdk::BootstrapEndpointUse::PublicApi) {
                    endpoint.url = "http://127.0.0.1:9".to_string();
                }
            }
            let relay_only_bootstrap_path = client_dir.join("relay-only.bootstrap.json");
            relay_only_bootstrap.write_to_path(&relay_only_bootstrap_path)?;
            let relay_only_bootstrap_arg = relay_only_bootstrap_path.to_string_lossy().into_owned();

            let put_output = run_cli(&[
                "--bootstrap-file",
                relay_only_bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "put",
                "relay-only-key",
                "payload-via-relay-only-client",
            ])
            .await?;
            assert!(
                put_output.contains("stored 'relay-only-key'"),
                "unexpected put output: {put_output}"
            );

            let get_output = run_cli(&[
                "--bootstrap-file",
                relay_only_bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "get",
                "relay-only-key",
            ])
            .await?;
            assert_eq!(get_output.trim(), "payload-via-relay-only-client");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut rendezvous).await;
        stop_server(&mut node).await;
        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&client_dir);

        result
    }

    #[tokio::test]
    async fn bootstrap_client_prefers_direct_and_uses_relay_after_rendezvous_restart_and_forced_direct_failure()
    -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19137";
        let bind = "127.0.0.1:19138";
        let cluster_id = "11111111-1111-7111-8111-111111111113";
        let node_id = "00000000-0000-0000-0000-0000000008b2";
        let admin_token = "admin-secret";

        let rendezvous_url = format!("http://{rendezvous_bind}");
        let base_url = format!("http://{bind}");
        let data_dir = fresh_data_dir("relay-client-direct-then-relay-node");
        let client_dir = fresh_data_dir("relay-client-direct-then-relay-client");

        let node_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "fallback"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
            ("IRONMESH_ADMIN_TOKEN", admin_token),
            ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
        ];

        let mut rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        let mut node = start_server_with_env(bind, &data_dir, node_id, 1, &node_env).await?;
        let http = reqwest::Client::new();

        let result = async {
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let bootstrap = issue_bootstrap_bundle(
                &http,
                &base_url,
                admin_token,
                Some("relay-cli"),
                Some(3600),
            )
            .await?;
            let bootstrap_path = client_dir.join("bootstrap.json");
            bootstrap.write_to_path(&bootstrap_path)?;

            let client_identity_path = client_dir.join("client-identity.json");
            let bootstrap_arg = bootstrap_path.to_string_lossy().into_owned();
            let client_identity_arg = client_identity_path.to_string_lossy().into_owned();

            run_cli(&[
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "enroll",
                "--label",
                "relay-cli",
            ])
            .await?;

            stop_server(&mut rendezvous).await;

            let direct_output = run_cli(&[
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "put",
                "direct-first-key",
                "payload-written-while-rendezvous-down",
            ])
            .await?;
            assert!(
                direct_output.contains("stored 'direct-first-key'"),
                "unexpected direct-path put output: {direct_output}"
            );

            rendezvous = start_rendezvous_service(rendezvous_bind).await?;
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let mut relay_fallback_bootstrap = bootstrap.clone();
            for endpoint in &mut relay_fallback_bootstrap.direct_endpoints {
                if endpoint.usage == Some(client_sdk::BootstrapEndpointUse::PublicApi) {
                    endpoint.url = "http://127.0.0.1:9".to_string();
                }
            }
            let relay_fallback_bootstrap_path = client_dir.join("relay-fallback.bootstrap.json");
            relay_fallback_bootstrap.write_to_path(&relay_fallback_bootstrap_path)?;
            let relay_fallback_bootstrap_arg =
                relay_fallback_bootstrap_path.to_string_lossy().into_owned();

            let relay_output = run_cli(&[
                "--bootstrap-file",
                relay_fallback_bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "get",
                "direct-first-key",
            ])
            .await?;
            assert_eq!(relay_output.trim(), "payload-written-while-rendezvous-down");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut rendezvous).await;
        stop_server(&mut node).await;
        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&client_dir);

        result
    }

    #[tokio::test]
    async fn relay_required_nodes_reconnect_after_rendezvous_restart_and_replicate() -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19139";
        let bind_a = "127.0.0.1:19140";
        let bind_b = "127.0.0.1:19141";
        let cluster_id = "11111111-1111-7111-8111-111111111114";
        let node_id_a = "00000000-0000-0000-0000-0000000008c1";
        let node_id_b = "00000000-0000-0000-0000-0000000008c2";
        let rendezvous_url = format!("http://{rendezvous_bind}");
        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");

        let data_a = fresh_data_dir("relay-restart-repl-node-a");
        let data_b = fresh_data_dir("relay-restart-repl-node-b");

        let node_env = [
            ("IRONMESH_NODE_MODE", "local-edge"),
            ("IRONMESH_CLUSTER_ID", cluster_id),
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "required"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
            ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
            ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
            ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
        ];

        let mut rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        let mut node_a = start_authenticated_server_with_env_options(
            bind_a, &data_a, node_id_a, 2, None, None, &node_env,
        )
        .await?;
        let mut node_b = start_authenticated_server_with_env_options(
            bind_b, &data_b, node_id_b, 2, None, None, &node_env,
        )
        .await?;
        let http = reqwest::Client::new();
        let client_a =
            enroll_authenticated_http_client(&base_a, "relay-restart-repl-a-client").await?;

        let result = async {
            let wait_for_known_nodes = |base_url: String, expected_nodes: usize| {
                let http = http.clone();
                async move {
                    for _ in 0..120 {
                        if let Ok(response) =
                            http.get(format!("{base_url}/cluster/nodes")).send().await
                            && let Ok(response) = response.error_for_status()
                            && let Ok(nodes) = response.json::<serde_json::Value>().await
                            && let Some(entries) = nodes.as_array()
                            && entries.len() == expected_nodes
                        {
                            return Ok::<(), anyhow::Error>(());
                        }
                        sleep(Duration::from_millis(250)).await;
                    }
                    bail!("cluster did not converge to {expected_nodes} known nodes at {base_url}");
                }
            };

            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 2, 120).await?;
            wait_for_known_nodes(base_a.clone(), 2).await?;
            wait_for_known_nodes(base_b.clone(), 2).await?;

            stop_server(&mut rendezvous).await;
            rendezvous = start_rendezvous_service(rendezvous_bind).await?;

            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 2, 120).await?;
            wait_for_known_nodes(base_a.clone(), 2).await?;
            wait_for_known_nodes(base_b.clone(), 2).await?;

            client_a
                .http
                .request(Method::PUT, "/store/restart-relay-key")?
                .body("payload-after-rendezvous-restart")
                .send()
                .await?
                .error_for_status()?;

            let repair_report: serde_json::Value = http
                .post(format!("{base_a}/cluster/replication/repair"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let successful = repair_report
                .get("successful_transfers")
                .and_then(|v| v.as_u64())
                .context("missing successful_transfers after relay-required repair")?;
            assert!(
                successful >= 1,
                "expected at least one successful relay-required transfer, report={repair_report:?}"
            );

            let bootstrap_b = issue_bootstrap_bundle(
                &http,
                &base_b,
                TEST_ADMIN_TOKEN,
                Some("relay-restart-repl-b"),
                Some(3600),
            )
            .await?;
            let identity = client_a.http.identity.clone();
            let client_b_sdk = tokio::task::spawn_blocking(move || {
                bootstrap_b.build_client_with_identity(&identity)
            })
            .await
            .context("relay-required node B client construction task panicked")??;

            for _ in 0..120 {
                if let Ok(bytes) = client_b_sdk.get("restart-relay-key").await
                    && bytes.as_ref() == b"payload-after-rendezvous-restart"
                {
                    return Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(250)).await;
            }

            bail!("replicated relay-required payload was not readable through node B bootstrap-aware client");

        }
        .await;

        stop_server(&mut rendezvous).await;
        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_a.client_dir);

        result
    }

    #[tokio::test]
    async fn zero_touch_managed_rendezvous_failover_promotes_second_node_and_keeps_relay_clients_working()
    -> Result<()> {
        let bind_a = "127.0.0.1:19150";
        let bind_b = "127.0.0.1:19151";
        let rendezvous_bind = "127.0.0.1:20150";
        let rendezvous_url = format!("https://{rendezvous_bind}");
        let admin_password = "correct horse battery staple";
        let failover_passphrase = "managed rendezvous failover secret";

        let data_a = fresh_data_dir("zero-touch-rendezvous-failover-a");
        let data_b = fresh_data_dir("zero-touch-rendezvous-failover-b");
        let client_dir = fresh_data_dir("zero-touch-rendezvous-failover-client");

        let insecure_http = insecure_https_client()?;
        let mut node_a = start_zero_touch_server(bind_a, &data_a).await?;
        let mut node_b = start_zero_touch_server(bind_b, &data_b).await?;

        let result = async {
            setup_start_cluster(&insecure_http, bind_a, admin_password).await?;
            wait_for_runtime_admin_surface(&insecure_http, bind_a).await?;
            let admin_cookie_a = admin_login_cookie(&insecure_http, bind_a, admin_password).await?;

            let join_request = setup_generate_join_request(&insecure_http, bind_b).await?;
            let target_node_id = join_request
                .get("node_id")
                .and_then(|value| value.as_str())
                .context("join request missing node_id")?
                .to_string();

            let enrollment_package = issue_node_enrollment_from_join_request_with_cookie(
                &insecure_http,
                bind_a,
                &admin_cookie_a,
                &join_request,
            )
            .await?;
            setup_import_node_enrollment(
                &insecure_http,
                bind_b,
                admin_password,
                &enrollment_package,
            )
            .await?;
            wait_for_runtime_admin_surface(&insecure_http, bind_b).await?;
            let admin_cookie_b = admin_login_cookie(&insecure_http, bind_b, admin_password).await?;

            let promotion_package = export_managed_control_plane_promotion_with_cookie(
                &insecure_http,
                bind_a,
                &admin_cookie_a,
                failover_passphrase,
                &target_node_id,
                &rendezvous_url,
            )
            .await?;
            let import_report = import_managed_control_plane_promotion_with_cookie(
                &insecure_http,
                bind_b,
                &admin_cookie_b,
                failover_passphrase,
                &promotion_package,
                rendezvous_bind,
            )
            .await?;
            assert_eq!(
                import_report
                    .get("restart_required")
                    .and_then(|value| value.as_bool()),
                Some(true)
            );

            stop_server(&mut node_a).await;
            stop_server(&mut node_b).await;
            node_b = start_zero_touch_server(bind_b, &data_b).await?;

            wait_for_runtime_admin_surface(&insecure_http, bind_b).await?;
            let managed_rendezvous_http = managed_runtime_mtls_client_from_data_dir(&data_b)?;
            wait_for_url_status_with_client(
                &managed_rendezvous_http,
                &format!("{rendezvous_url}/health"),
                StatusCode::OK,
                120,
            )
            .await?;
            let admin_cookie_b = admin_login_cookie(&insecure_http, bind_b, admin_password).await?;

            let bootstrap = issue_bootstrap_bundle_with_cookie(
                &insecure_http,
                bind_b,
                &admin_cookie_b,
                Some("relay-after-failover"),
                Some(3600),
            )
            .await?;
            let bootstrap_path = client_dir.join("relay-after-failover.bootstrap.json");
            bootstrap.write_to_path(&bootstrap_path)?;
            let bootstrap_arg = bootstrap_path.to_string_lossy().into_owned();

            let client_identity_path = client_dir.join("relay-after-failover.identity.json");
            let client_identity_arg = client_identity_path.to_string_lossy().into_owned();

            let enroll_output = run_cli(&[
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "enroll",
                "--label",
                "relay-after-failover",
            ])
            .await?;
            assert!(
                enroll_output.contains("enrolled device"),
                "unexpected enroll output: {enroll_output}"
            );

            let mut relay_only_bootstrap = bootstrap.clone();
            for endpoint in &mut relay_only_bootstrap.direct_endpoints {
                if endpoint.usage == Some(client_sdk::BootstrapEndpointUse::PublicApi) {
                    endpoint.url = "http://127.0.0.1:9".to_string();
                }
            }
            let relay_only_bootstrap_path =
                client_dir.join("relay-only-after-failover.bootstrap.json");
            relay_only_bootstrap.write_to_path(&relay_only_bootstrap_path)?;
            let relay_only_bootstrap_arg = relay_only_bootstrap_path.to_string_lossy().into_owned();

            let put_output = run_cli(&[
                "--bootstrap-file",
                relay_only_bootstrap_arg.as_str(),
                "--client-identity-file",
                client_identity_arg.as_str(),
                "put",
                "relay-failover-key",
                "payload-via-promoted-rendezvous",
            ])
            .await?;
            assert!(
                put_output.contains("stored 'relay-failover-key'"),
                "unexpected put output after failover: {put_output}"
            );

            for _ in 0..120 {
                if let Ok(output) = run_cli(&[
                    "--bootstrap-file",
                    relay_only_bootstrap_arg.as_str(),
                    "--client-identity-file",
                    client_identity_arg.as_str(),
                    "get",
                    "relay-failover-key",
                ])
                .await
                    && output.trim() == "payload-via-promoted-rendezvous"
                {
                    return Ok::<(), anyhow::Error>(());
                }
                sleep(Duration::from_millis(250)).await;
            }

            bail!("relay-only client did not recover through the promoted managed rendezvous host");
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        let _ = fs::remove_dir_all(&data_a);
        let _ = fs::remove_dir_all(&data_b);
        let _ = fs::remove_dir_all(&client_dir);

        result
    }

    #[tokio::test]
    async fn maintenance_cleanup_removes_orphans_and_keeps_live_data() -> Result<()> {
        let bind = "127.0.0.1:19102";
        let mut fixture = start_authenticated_cluster_fixture(
            bind,
            "maintenance-cleanup",
            "maintenance-cleanup-client",
        )
        .await?;
        let client = reqwest::Client::new();

        let result = async {
            fixture
                .http
                .request(Method::PUT, "/store/live-key")?
                .body("live-payload")
                .send()
                .await?
                .error_for_status()?;

            let orphan_chunk_bytes = b"orphan-chunk-payload";
            let orphan_chunk_hash =
                "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff".to_string();
            let orphan_chunk_dir = fixture
                .data_dir
                .join("chunks")
                .join(&orphan_chunk_hash[0..2]);
            fs::create_dir_all(&orphan_chunk_dir)?;
            fs::write(
                orphan_chunk_dir.join(&orphan_chunk_hash),
                orphan_chunk_bytes,
            )?;

            let orphan_manifest = serde_json::json!({
                "key": "orphan-key",
                "total_size_bytes": orphan_chunk_bytes.len(),
                "created_at_unix": 0,
                "chunks": [
                    {
                        "hash": orphan_chunk_hash,
                        "size_bytes": orphan_chunk_bytes.len()
                    }
                ]
            });

            let orphan_manifest_bytes = serde_json::to_vec_pretty(&orphan_manifest)?;
            let orphan_manifest_hash =
                "bb11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff".to_string();
            fs::write(
                fixture
                    .data_dir
                    .join("manifests")
                    .join(format!("{orphan_manifest_hash}.json")),
                orphan_manifest_bytes,
            )?;

            let cleanup_response = client
                .post(format!(
                    "{}/maintenance/cleanup?retention_secs=0&dry_run=false&approve=true",
                    fixture.http.base_url
                ))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .send()
                .await?
                .error_for_status()?;

            let cleanup_report: serde_json::Value = cleanup_response.json().await?;
            assert!(
                cleanup_report
                    .get("deleted_manifests")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    >= 1,
                "expected at least one orphan manifest to be deleted"
            );
            assert!(
                cleanup_report
                    .get("deleted_chunks")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
                    >= 1,
                "expected at least one orphan chunk to be deleted"
            );

            let live_payload = fixture
                .http
                .request(Method::GET, "/store/live-key")?
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(live_payload, "live-payload");

            let orphan_manifest_still_exists = fixture
                .data_dir
                .join("manifests")
                .join(format!("{orphan_manifest_hash}.json"))
                .exists();
            assert!(
                !orphan_manifest_still_exists,
                "orphan manifest should be removed"
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut fixture.server).await;
        let _ = fs::remove_dir_all(&fixture.data_dir);
        let _ = fs::remove_dir_all(&fixture.client_dir);
        result
    }
}
