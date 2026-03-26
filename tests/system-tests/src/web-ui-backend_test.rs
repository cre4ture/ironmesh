#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, EnrolledTestClient, TEST_ADMIN_TOKEN, binary_path, fresh_data_dir,
        issue_bootstrap_bundle, issue_bootstrap_bundle_and_enroll_client, lock_test_resources,
        run_cli, start_authenticated_server, start_open_server_with_env, start_rendezvous_service,
        stop_server, tcp_resource_key, wait_for_rendezvous_registered_endpoints,
        wait_for_url_status,
    };
    use anyhow::{Context, Result};
    use client_sdk::BootstrapEndpointUse;
    use reqwest::StatusCode;
    use std::fs;
    use std::process::Stdio;
    use tokio::process::Command;
    use uuid::Uuid;

    const CHUNK_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;

    fn sample_png_bytes() -> Vec<u8> {
        let image = image::DynamicImage::new_rgba8(4, 3);
        let mut cursor = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut cursor, image::ImageFormat::Png)
            .expect("sample PNG encode should succeed");
        cursor.into_inner()
    }

    fn sample_split_manifest_json(
        manifest_key: &str,
        logical_key: &str,
        parts: &[(&str, &str, &[u8])],
    ) -> serde_json::Value {
        let mut offset_bytes = 0_u64;
        let entries = parts
            .iter()
            .map(|(part_id, key, payload)| {
                let size_bytes = payload.len() as u64;
                let entry = serde_json::json!({
                    "part_id": part_id,
                    "key": *key,
                    "offset_bytes": offset_bytes,
                    "size_bytes": size_bytes
                });
                offset_bytes += size_bytes;
                entry
            })
            .collect::<Vec<_>>();

        serde_json::json!({
            "manifest_version": 1,
            "type": "split_file_manifest",
            "logical_format": "mbtiles",
            "logical_key": logical_key,
            "manifest_key": manifest_key,
            "logical_size_bytes": offset_bytes,
            "parts_count": entries.len(),
            "parts": entries
        })
    }

    async fn start_web_backend_with_args(bind: &str, cli_args: &[&str]) -> Result<ChildGuard> {
        let cli_bin = binary_path("cli-client")?;
        let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;
        let child = Command::new(cli_bin)
            .args(cli_args)
            .arg("serve-web")
            .arg("--bind")
            .arg(bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn cli-client serve-web")?;

        wait_for_url_status(&format!("http://{bind}/api/ping"), StatusCode::OK, 40).await?;
        Ok(ChildGuard::with_resources(child, resource_guards))
    }

    async fn start_authenticated_web_backend(
        server_bind: &str,
        web_bind: &str,
        server_name: &str,
        client_name: &str,
    ) -> Result<(ChildGuard, ChildGuard, EnrolledTestClient)> {
        let data_dir = fresh_data_dir(server_name);
        let client_dir = fresh_data_dir(client_name);
        let node_id = Uuid::new_v4().to_string();
        let server = start_authenticated_server(server_bind, &data_dir, &node_id, 1).await?;
        let base_url = format!("http://{server_bind}");
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "web-ui.bootstrap.json",
            Some(client_name),
            Some(3600),
        )
        .await?;
        let bootstrap_arg = enrolled.bootstrap_path.to_string_lossy().into_owned();
        let web =
            start_web_backend_with_args(web_bind, &["--bootstrap-file", bootstrap_arg.as_str()])
                .await?;
        Ok((server, web, enrolled))
    }

    #[tokio::test]
    async fn web_ui_backend_serves_react_client_ui_assets() -> Result<()> {
        let server_bind = "127.0.0.1:19378";
        let web_bind = "127.0.0.1:19379";
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let (mut server, mut web, _enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-assets-server",
            "web-ui-assets-client",
        )
        .await?;

        let result = async {
            let html = client
                .get(format!("{web_base}/"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(html.contains("Client UI"));
            assert!(html.contains("/app.js"));
            assert!(html.contains("/app.css"));

            let js = client
                .get(format!("{web_base}/app.js"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(js.contains("Transport-aware"));

            let css = client
                .get(format!("{web_base}/app.css"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(css.contains("radial-gradient"));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_text_store_roundtrip() -> Result<()> {
        let server_bind = "127.0.0.1:19380";
        let web_bind = "127.0.0.1:19381";
        let web_base = format!("http://{web_bind}");
        let key = "ui-text.txt";
        let value = "hello-from-web-ui-backend";
        let client = reqwest::Client::new();

        let (mut server, mut web, enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-text-server",
            "web-ui-text-client",
        )
        .await?;
        let upstream_client = enrolled.build_client_async().await?;

        let result = async {
            let put_payload = serde_json::json!({
                "key": key,
                "value": value
            });

            let put_resp: serde_json::Value = client
                .post(format!("{web_base}/api/store/put"))
                .json(&put_payload)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(put_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(
                put_resp.get("size_bytes").and_then(|v| v.as_u64()),
                Some(value.len() as u64)
            );

            let get_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/get"))
                .query(&[("key", key)])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(get_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(get_resp.get("value").and_then(|v| v.as_str()), Some(value));

            let upstream = upstream_client.get(key).await?;
            assert_eq!(upstream, bytes::Bytes::from(value.to_string()));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_store_get_preview_truncates_large_payload() -> Result<()> {
        let server_bind = "127.0.0.1:19390";
        let web_bind = "127.0.0.1:19391";
        let web_base = format!("http://{web_bind}");
        let key = "ui-preview.txt";
        let value = "A".repeat(4096);
        let client = reqwest::Client::new();

        let (mut server, mut web, _enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-preview-server",
            "web-ui-preview-client",
        )
        .await?;

        let result = async {
            let put_payload = serde_json::json!({
                "key": key,
                "value": value,
            });

            client
                .post(format!("{web_base}/api/store/put"))
                .json(&put_payload)
                .send()
                .await?
                .error_for_status()?;

            let get_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/get"))
                .query(&[("key", key), ("preview_bytes", "1024")])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            assert_eq!(get_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(
                get_resp.get("truncated").and_then(|v| v.as_bool()),
                Some(true)
            );
            assert_eq!(
                get_resp.get("total_size_bytes").and_then(|v| v.as_u64()),
                Some(4096)
            );
            assert_eq!(
                get_resp.get("preview_size_bytes").and_then(|v| v.as_u64()),
                Some(1024)
            );
            assert_eq!(
                get_resp
                    .get("value")
                    .and_then(|v| v.as_str())
                    .map(|value| value.len()),
                Some(1024)
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_binary_chunked_roundtrip() -> Result<()> {
        let server_bind = "127.0.0.1:19382";
        let web_bind = "127.0.0.1:19383";
        let web_base = format!("http://{web_bind}");
        let key = "ui-large.bin";
        let mut payload = vec![b'B'; CHUNK_UPLOAD_THRESHOLD_BYTES + 128];
        payload[0..6].copy_from_slice(b"BEGIN:");
        let payload_len = payload.len();
        let client = reqwest::Client::new();

        let (mut server, mut web, _enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-binary-server",
            "web-ui-binary-client",
        )
        .await?;

        let result = async {
            let put_resp: serde_json::Value = client
                .post(format!("{web_base}/api/store/put-binary"))
                .query(&[("key", key)])
                .body(payload.clone())
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(put_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(
                put_resp.get("size_bytes").and_then(|v| v.as_u64()),
                Some(payload_len as u64)
            );
            assert_eq!(
                put_resp.get("upload_mode").and_then(|v| v.as_str()),
                Some("chunked")
            );

            let response = client
                .get(format!("{web_base}/api/store/get-binary"))
                .query(&[("key", key)])
                .send()
                .await?
                .error_for_status()?;

            assert_eq!(
                response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/octet-stream")
            );

            let disposition = response
                .headers()
                .get(reqwest::header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(disposition.contains("attachment;"));
            assert!(disposition.contains("filename=\"ui-large.bin\""));

            let body = response.bytes().await?;
            assert_eq!(body.as_ref(), payload.as_slice());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_store_list_and_delete_flow() -> Result<()> {
        let server_bind = "127.0.0.1:19384";
        let web_bind = "127.0.0.1:19385";
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let (mut server, mut web, enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-list-delete-server",
            "web-ui-list-delete-client",
        )
        .await?;
        let upstream_client = enrolled.build_client_async().await?;

        let result = async {
            for (key, value) in [
                ("docs/guide/intro.md", "intro"),
                ("docs/guide/setup.md", "setup"),
                ("docs/api/v1.json", "api"),
            ] {
                let payload = serde_json::json!({
                    "key": key,
                    "value": value,
                });
                client
                    .post(format!("{web_base}/api/store/put"))
                    .json(&payload)
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let list_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/list"))
                .query(&[("prefix", "docs"), ("depth", "1")])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let paths = list_resp
                .get("entries")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.get("path").and_then(|v| v.as_str()))
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .context("missing entries in /api/store/list response")?;
            assert!(paths.contains(&"docs/api/".to_string()));
            assert!(paths.contains(&"docs/guide/".to_string()));

            for (key, value) in [("cameras/", ""), ("cameras/front.jpg", "jpeg")] {
                let payload = serde_json::json!({
                    "key": key,
                    "value": value,
                });
                client
                    .post(format!("{web_base}/api/store/put"))
                    .json(&payload)
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let tree_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/list"))
                .query(&[("depth", "1"), ("view", "tree")])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let tree_entries = tree_resp
                .get("entries")
                .and_then(|v| v.as_array())
                .context("missing entries in tree /api/store/list response")?;
            let cameras_entries = tree_entries
                .iter()
                .filter(|entry| entry.get("path").and_then(|v| v.as_str()) == Some("cameras/"))
                .collect::<Vec<_>>();
            assert_eq!(cameras_entries.len(), 1);
            assert_eq!(
                cameras_entries[0]
                    .get("entry_type")
                    .and_then(|v| v.as_str()),
                Some("prefix")
            );

            let delete_key = "web-delete.txt";
            let delete_payload = serde_json::json!({
                "key": delete_key,
                "value": "to-delete",
            });
            client
                .post(format!("{web_base}/api/store/put"))
                .json(&delete_payload)
                .send()
                .await?
                .error_for_status()?;

            let delete_resp: serde_json::Value = client
                .delete(format!("{web_base}/api/store/delete"))
                .query(&[("key", delete_key)])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(
                delete_resp.get("deleted").and_then(|v| v.as_bool()),
                Some(true)
            );
            assert_eq!(
                delete_resp.get("key").and_then(|v| v.as_str()),
                Some(delete_key)
            );

            let get_deleted = client
                .get(format!("{web_base}/api/store/get"))
                .query(&[("key", delete_key)])
                .send()
                .await?;
            assert_eq!(get_deleted.status(), StatusCode::BAD_GATEWAY);

            assert!(upstream_client.get(delete_key).await.is_err());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_proxies_media_thumbnail_requests() -> Result<()> {
        let server_bind = "127.0.0.1:19386";
        let web_bind = "127.0.0.1:19387";
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let (mut server, mut web, _enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-thumb-server",
            "web-ui-thumb-client",
        )
        .await?;

        let result = async {
            client
                .post(format!("{web_base}/api/store/put-binary"))
                .query(&[("key", "gallery/cat.png")])
                .body(sample_png_bytes())
                .send()
                .await?
                .error_for_status()?;

            let response = client
                .get(format!("{web_base}/media/thumbnail"))
                .query(&[("key", "gallery/cat.png")])
                .send()
                .await?
                .error_for_status()?;

            assert_eq!(
                response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("image/jpeg")
            );
            assert_eq!(
                response
                    .headers()
                    .get(reqwest::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("public, max-age=31536000, immutable")
            );

            let body = response.bytes().await?;
            assert!(!body.is_empty(), "thumbnail body should not be empty");

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_serves_split_logical_file_ranges() -> Result<()> {
        let server_bind = "127.0.0.1:19388";
        let web_bind = "127.0.0.1:19389";
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let (mut server, mut web, _enrolled) = start_authenticated_web_backend(
            server_bind,
            web_bind,
            "web-ui-map-logical-server",
            "web-ui-map-logical-client",
        )
        .await?;

        let manifest_key = "sys/maps/test-map.mbtiles.manifest.json";
        let logical_key = "sys/maps/test-map.mbtiles";
        let part_aa_key = "sys/maps/test-map.mbtiles-part-aa";
        let part_ab_key = "sys/maps/test-map.mbtiles-part-ab";
        let part_ac_key = "sys/maps/test-map.mbtiles-part-ac";
        let part_aa = b"hello ".to_vec();
        let part_ab = b"world".to_vec();
        let part_ac = b" !!!".to_vec();
        let expected = [part_aa.clone(), part_ab.clone(), part_ac.clone()].concat();

        let result = async {
            let expected_content_length = expected.len().to_string();
            let expected_content_range = format!("bytes 3-10/{}", expected.len());
            for (key, payload) in [
                (part_aa_key, part_aa.clone()),
                (part_ab_key, part_ab.clone()),
                (part_ac_key, part_ac.clone()),
            ] {
                client
                    .post(format!("{web_base}/api/store/put-binary"))
                    .query(&[("key", key)])
                    .body(payload)
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let manifest_payload = sample_split_manifest_json(
                manifest_key,
                logical_key,
                &[
                    ("aa", part_aa_key, part_aa.as_slice()),
                    ("ab", part_ab_key, part_ab.as_slice()),
                    ("ac", part_ac_key, part_ac.as_slice()),
                ],
            );
            client
                .post(format!("{web_base}/api/store/put"))
                .json(&serde_json::json!({
                    "key": manifest_key,
                    "value": serde_json::to_string(&manifest_payload)?,
                }))
                .send()
                .await?
                .error_for_status()?;

            let head_response = client
                .head(format!("{web_base}/api/maps/logical-file"))
                .query(&[("manifest_key", manifest_key)])
                .send()
                .await?
                .error_for_status()?;
            assert_eq!(
                head_response
                    .headers()
                    .get(reqwest::header::ACCEPT_RANGES)
                    .and_then(|value| value.to_str().ok()),
                Some("bytes")
            );
            assert_eq!(
                head_response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_content_length.as_str())
            );

            let full_response = client
                .get(format!("{web_base}/api/maps/logical-file"))
                .query(&[("manifest_key", manifest_key)])
                .send()
                .await?
                .error_for_status()?;
            assert_eq!(
                full_response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/vnd.sqlite3")
            );
            let full_body = full_response.bytes().await?;
            assert_eq!(full_body.as_ref(), expected.as_slice());

            let range_response = client
                .get(format!("{web_base}/api/maps/logical-file"))
                .query(&[("manifest_key", manifest_key)])
                .header(reqwest::header::RANGE, "bytes=3-10")
                .send()
                .await?
                .error_for_status()?;
            assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                range_response
                    .headers()
                    .get(reqwest::header::CONTENT_RANGE)
                    .and_then(|value| value.to_str().ok()),
                Some(expected_content_range.as_str())
            );
            let range_body = range_response.bytes().await?;
            assert_eq!(range_body.as_ref(), &expected[3..11]);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_bootstrap_enroll_default_identity_supports_relay_only_serve_web()
    -> Result<()> {
        let rendezvous_bind = "127.0.0.1:19390";
        let server_bind = "127.0.0.1:19391";
        let web_bind = "127.0.0.1:19392";
        let cluster_id = "11111111-1111-7111-8111-111111119390";
        let node_id = "00000000-0000-0000-0000-000000009390";
        let admin_token = "admin-secret";
        let rendezvous_url = format!("http://{rendezvous_bind}");
        let server_base = format!("http://{server_bind}");
        let web_base = format!("http://{web_bind}");
        let data_dir = fresh_data_dir("web-ui-relay-only-node");
        let client_dir = fresh_data_dir("web-ui-relay-only-client");

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
        let mut server =
            start_open_server_with_env(server_bind, &data_dir, node_id, 1, &node_env).await?;
        let http = reqwest::Client::new();

        let result = async {
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let mut bootstrap = issue_bootstrap_bundle(
                &http,
                &server_base,
                admin_token,
                Some("relay-web-ui"),
                Some(3600),
            )
            .await?;
            let bootstrap_path = client_dir.join("relay-web.bootstrap.json");
            bootstrap.write_to_path(&bootstrap_path)?;
            let bootstrap_arg = bootstrap_path.to_string_lossy().into_owned();

            let enroll_output = run_cli(&[
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "enroll",
                "--label",
                "relay-web-ui",
            ])
            .await?;
            assert!(
                enroll_output.contains("enrolled device"),
                "unexpected enroll output: {enroll_output}"
            );

            let default_identity_path = client_dir.join("relay-web.bootstrap.client-identity.json");
            assert!(
                default_identity_path.exists(),
                "expected default client identity file to be written at {}",
                default_identity_path.display()
            );

            for endpoint in &mut bootstrap.direct_endpoints {
                if endpoint.usage == Some(BootstrapEndpointUse::PublicApi) {
                    endpoint.url = "http://127.0.0.1:9".to_string();
                }
            }
            bootstrap.write_to_path(&bootstrap_path)?;

            let mut web = start_web_backend_with_args(
                web_bind,
                &["--bootstrap-file", bootstrap_arg.as_str()],
            )
            .await?;

            let result = async {
                let rendezvous_refresh: serde_json::Value = http
                    .post(format!("{web_base}/api/rendezvous/refresh"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                let transport_mode = rendezvous_refresh
                    .get("transport_mode")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                assert_eq!(transport_mode, "relay");

                let cluster_status: serde_json::Value = http
                    .get(format!("{web_base}/api/cluster/status"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                assert_eq!(
                    cluster_status
                        .get("total_nodes")
                        .and_then(|value| value.as_u64()),
                    Some(1)
                );

                let cluster_nodes: serde_json::Value = http
                    .get(format!("{web_base}/api/cluster/nodes"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                assert_eq!(
                    cluster_nodes.as_array().map(|entries| entries.len()),
                    Some(1)
                );

                let replication_plan: serde_json::Value = http
                    .get(format!("{web_base}/api/cluster/replication/plan"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                assert_eq!(
                    replication_plan
                        .get("under_replicated")
                        .and_then(|value| value.as_u64()),
                    Some(0)
                );

                let put_payload = serde_json::json!({
                    "key": "relay-web-ui.txt",
                    "value": "payload-via-relay-web-ui",
                });
                let put_response: serde_json::Value = http
                    .post(format!("{web_base}/api/store/put"))
                    .json(&put_payload)
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                assert_eq!(
                    put_response.get("key").and_then(|value| value.as_str()),
                    Some("relay-web-ui.txt")
                );

                let get_response: serde_json::Value = http
                    .get(format!("{web_base}/api/store/get"))
                    .query(&[("key", "relay-web-ui.txt")])
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?;
                assert_eq!(
                    get_response.get("value").and_then(|value| value.as_str()),
                    Some("payload-via-relay-web-ui")
                );

                Ok::<(), anyhow::Error>(())
            }
            .await;

            stop_server(&mut web).await;
            result
        }
        .await;

        stop_server(&mut server).await;
        stop_server(&mut rendezvous).await;
        let _ = fs::remove_dir_all(&data_dir);
        let _ = fs::remove_dir_all(&client_dir);
        result
    }
}
