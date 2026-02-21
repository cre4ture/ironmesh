#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::OnceLock;
    use std::time::Duration;
    use std::time::SystemTime;

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
            let first_versions: serde_json::Value = serde_json::from_str(&first_versions_payload)?;

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

    #[tokio::test]
    async fn read_modes_respect_preferred_and_confirmed_visibility() -> Result<()> {
        let bind = "127.0.0.1:19087";
        let data_dir = fresh_data_dir("read-modes");
        let mut server = start_server_with_data_dir(bind, &data_dir).await?;
        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            client
                .put(format!("{base_url}/store/read-mode-key"))
                .body("confirmed-v1")
                .send()
                .await?
                .error_for_status()?;

            client
                .put(format!("{base_url}/store/read-mode-key?state=provisional"))
                .body("provisional-v2")
                .send()
                .await?
                .error_for_status()?;

            let versions_payload = client
                .get(format!("{base_url}/versions/read-mode-key"))
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

            let preferred_default = client
                .get(format!("{base_url}/store/read-mode-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(preferred_default, "provisional-v2");

            let preferred_explicit = client
                .get(format!(
                    "{base_url}/store/read-mode-key?read_mode=preferred"
                ))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(preferred_explicit, "provisional-v2");

            let provisional_allowed = client
                .get(format!(
                    "{base_url}/store/read-mode-key?read_mode=provisional_allowed"
                ))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(provisional_allowed, "provisional-v2");

            let confirmed_only = client
                .get(format!(
                    "{base_url}/store/read-mode-key?read_mode=confirmed_only"
                ))
                .send()
                .await?;
            assert_eq!(confirmed_only.status(), StatusCode::NOT_FOUND);

            client
                .put(format!(
                    "{base_url}/store/confirmed-head-key?state=confirmed"
                ))
                .body("confirmed-head")
                .send()
                .await?
                .error_for_status()?;

            let confirmed_head = client
                .get(format!(
                    "{base_url}/store/confirmed-head-key?read_mode=confirmed_only"
                ))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(confirmed_head, "confirmed-head");

            client
                .put(format!(
                    "{base_url}/store/provisional-only-key?state=provisional"
                ))
                .body("only-provisional")
                .send()
                .await?
                .error_for_status()?;

            let provisional_only_confirmed = client
                .get(format!(
                    "{base_url}/store/provisional-only-key?read_mode=confirmed_only"
                ))
                .send()
                .await?;
            assert_eq!(provisional_only_confirmed.status(), StatusCode::NOT_FOUND);

            let bad_mode = client
                .get(format!("{base_url}/store/read-mode-key?read_mode=unknown"))
                .send()
                .await?;
            assert_eq!(bad_mode.status(), StatusCode::BAD_REQUEST);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn commit_endpoint_enforces_quorum_mode() -> Result<()> {
        let bind = "127.0.0.1:19086";
        let data_dir = fresh_data_dir("version-commit-quorum");
        let mut server = start_server_with_options(
            bind,
            &data_dir,
            "00000000-0000-0000-0000-0000000000a1",
            3,
            Some("quorum"),
            Some(1),
        )
        .await?;

        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            register_node(
                &client,
                &base_url,
                "00000000-0000-0000-0000-0000000000b2",
                "http://127.0.0.1:29091",
                "dc-b",
                "rack-2",
            )
            .await?;
            register_node(
                &client,
                &base_url,
                "00000000-0000-0000-0000-0000000000c3",
                "http://127.0.0.1:29092",
                "dc-c",
                "rack-3",
            )
            .await?;

            client
                .put(format!("{base_url}/store/quorum-key?state=provisional"))
                .body("v1")
                .send()
                .await?
                .error_for_status()?;

            let versions_payload = client
                .get(format!("{base_url}/versions/quorum-key"))
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
                .get(format!("{base_url}/cluster/status"))
                .send()
                .await?
                .error_for_status()?;

            let rejected = client
                .post(format!(
                    "{base_url}/versions/quorum-key/commit/{provisional_version_id}"
                ))
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

            client
                .post(format!(
                    "{base_url}/cluster/nodes/00000000-0000-0000-0000-0000000000a1/heartbeat"
                ))
                .json(&heartbeat_payload)
                .send()
                .await?
                .error_for_status()?;

            client
                .post(format!(
                    "{base_url}/cluster/nodes/00000000-0000-0000-0000-0000000000b2/heartbeat"
                ))
                .json(&heartbeat_payload)
                .send()
                .await?
                .error_for_status()?;

            let accepted = client
                .post(format!(
                    "{base_url}/versions/quorum-key/commit/{provisional_version_id}"
                ))
                .send()
                .await?;
            assert_eq!(accepted.status(), StatusCode::NO_CONTENT);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
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

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_server_with_config(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            http.put(format!("{base_a}/store/multi-key"))
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

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_server_with_config(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            http.put(format!("{base_a}/store/repair-key"))
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

            let b_read = http
                .get(format!("{base_b}/store/repair-key"))
                .send()
                .await?;
            let c_read = http
                .get(format!("{base_c}/store/repair-key"))
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

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;
        let mut node_c = start_server_with_config(bind_c, &data_c, node_id_c, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let base_c = format!("http://{bind_c}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;
            register_node(&http, &base_a, node_id_c, &base_c, "dc-c", "rack-3").await?;

            http.put(format!("{base_a}/store/repair-batch-key-a"))
                .body("payload-a")
                .send()
                .await?
                .error_for_status()?;

            http.put(format!("{base_a}/store/repair-batch-key-b"))
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

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-2").await?;

            http.put(format!("{base_a}/store/repair-version-key"))
                .body("repair-version-payload")
                .send()
                .await?
                .error_for_status()?;

            let versions_a: serde_json::Value = http
                .get(format!("{base_a}/versions/repair-version-key"))
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

            let versions_b: serde_json::Value = http
                .get(format!("{base_b}/versions/repair-version-key"))
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

        result
    }

    #[tokio::test]
    async fn internal_replication_push_chunk_rejects_missing_token() -> Result<()> {
        let bind = "127.0.0.1:19113";
        let node_id = "00000000-0000-0000-0000-0000000006a1";
        let data_dir = fresh_data_dir("internal-auth-missing-token");

        let mut server = start_server_with_env(
            bind,
            &data_dir,
            node_id,
            1,
            &[("IRONMESH_INTERNAL_API_TOKEN", "secret-1")],
        )
        .await?;

        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let result = async {
            let response = http
                .post(format!(
                    "{base_url}/cluster/replication/push/chunk/deadbeef"
                ))
                .header("x-ironmesh-node-id", node_id)
                .body("chunk")
                .send()
                .await?;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn internal_replication_push_chunk_rejects_wrong_token() -> Result<()> {
        let bind = "127.0.0.1:19114";
        let node_id = "00000000-0000-0000-0000-0000000006b2";
        let data_dir = fresh_data_dir("internal-auth-wrong-token");

        let mut server = start_server_with_env(
            bind,
            &data_dir,
            node_id,
            1,
            &[("IRONMESH_INTERNAL_API_TOKEN", "secret-2")],
        )
        .await?;

        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let result = async {
            let response = http
                .post(format!(
                    "{base_url}/cluster/replication/push/chunk/deadbeef"
                ))
                .header("x-ironmesh-node-id", node_id)
                .header("x-ironmesh-internal-token", "wrong-secret")
                .body("chunk")
                .send()
                .await?;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn internal_replication_push_chunk_rejects_token_node_mismatch() -> Result<()> {
        let bind = "127.0.0.1:19115";
        let controller_node_id = "00000000-0000-0000-0000-0000000006c3";
        let caller_node_id = "00000000-0000-0000-0000-0000000006d4";
        let data_dir = fresh_data_dir("internal-auth-node-mismatch");

        let per_node_tokens =
            format!("{controller_node_id}=token-controller,{caller_node_id}=token-caller");

        let mut server = start_server_with_env(
            bind,
            &data_dir,
            controller_node_id,
            1,
            &[("IRONMESH_INTERNAL_NODE_TOKENS", per_node_tokens.as_str())],
        )
        .await?;

        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let result = async {
            register_node(
                &http,
                &base_url,
                caller_node_id,
                "http://127.0.0.1:29999",
                "dc-caller",
                "rack-caller",
            )
            .await?;

            let response = http
                .post(format!(
                    "{base_url}/cluster/replication/push/chunk/deadbeef"
                ))
                .header("x-ironmesh-node-id", caller_node_id)
                .header("x-ironmesh-internal-token", "token-controller")
                .body("chunk")
                .send()
                .await?;

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn internal_replication_drop_accepts_valid_token_and_node_id() -> Result<()> {
        let bind = "127.0.0.1:19116";
        let node_id = "00000000-0000-0000-0000-0000000006e5";
        let data_dir = fresh_data_dir("internal-auth-valid-token");

        let mut server = start_server_with_env(
            bind,
            &data_dir,
            node_id,
            1,
            &[("IRONMESH_INTERNAL_API_TOKEN", "secret-3")],
        )
        .await?;

        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let result = async {
            let response = http
                .post(format!("{base_url}/cluster/replication/drop"))
                .query(&[("key", "missing-key")])
                .header("x-ironmesh-node-id", node_id)
                .header("x-ironmesh-internal-token", "secret-3")
                .send()
                .await?;

            assert_eq!(response.status(), StatusCode::OK);

            let report: serde_json::Value = response.json().await?;
            assert_eq!(report.get("dropped").and_then(|v| v.as_bool()), Some(false));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    #[tokio::test]
    async fn rejoin_reconciliation_preserves_provisional_branches() -> Result<()> {
        let bind_a = "127.0.0.1:19100";
        let bind_b = "127.0.0.1:19101";

        let node_id_a = "00000000-0000-0000-0000-0000000001a1";
        let node_id_b = "00000000-0000-0000-0000-0000000001b2";

        let data_a = fresh_data_dir("rejoin-a");
        let data_b = fresh_data_dir("rejoin-b");

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();

        let result = async {
            http.put(format!("{base_a}/store/rejoin-key"))
                .body("a-confirmed")
                .send()
                .await?
                .error_for_status()?;

            http.put(format!("{base_a}/store/rejoin-key?state=provisional"))
                .body("a-branch")
                .send()
                .await?
                .error_for_status()?;

            http.put(format!("{base_b}/store/rejoin-key?state=provisional"))
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

            let versions_payload = http
                .get(format!("{base_a}/versions/rejoin-key"))
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

                let payload = http
                    .get(format!("{base_a}/store/rejoin-key?version={version_id}"))
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

        let mut node_a = start_server_with_config(bind_a, &data_a, node_id_a, 2).await?;
        let mut node_b = start_server_with_config(bind_b, &data_b, node_id_b, 2).await?;

        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let http = reqwest::Client::new();

        let result = async {
            http.put(format!("{base_b}/store/replay-key?state=provisional"))
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

            let versions_after_first: serde_json::Value = http
                .get(format!("{base_a}/versions/replay-key"))
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

            let versions_after_second: serde_json::Value = http
                .get(format!("{base_a}/versions/replay-key"))
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

        result
    }

    #[tokio::test]
    async fn maintenance_cleanup_removes_orphans_and_keeps_live_data() -> Result<()> {
        let bind = "127.0.0.1:19102";
        let data_dir = fresh_data_dir("maintenance-cleanup");
        let mut server = start_server_with_data_dir(bind, &data_dir).await?;
        let base_url = format!("http://{bind}");
        let client = reqwest::Client::new();

        let result = async {
            client
                .put(format!("{base_url}/store/live-key"))
                .body("live-payload")
                .send()
                .await?
                .error_for_status()?;

            let orphan_chunk_bytes = b"orphan-chunk-payload";
            let orphan_chunk_hash =
                "aa11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff".to_string();
            let orphan_chunk_dir = data_dir.join("chunks").join(&orphan_chunk_hash[0..2]);
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
                data_dir
                    .join("manifests")
                    .join(format!("{orphan_manifest_hash}.json")),
                orphan_manifest_bytes,
            )?;

            let cleanup_response = client
                .post(format!(
                    "{base_url}/maintenance/cleanup?retention_secs=0&dry_run=false"
                ))
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

            let live_payload = client
                .get(format!("{base_url}/store/live-key"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(live_payload, "live-payload");

            let orphan_manifest_still_exists = data_dir
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

        stop_server(&mut server).await;
        let _ = fs::remove_dir_all(&data_dir);
        result
    }

    async fn start_server(bind: &str) -> Result<Child> {
        let data_dir = fresh_data_dir("default-server");
        start_server_with_data_dir(bind, &data_dir).await
    }

    async fn start_server_with_data_dir(bind: &str, data_dir: &Path) -> Result<Child> {
        start_server_with_config(bind, data_dir, "", 3).await
    }

    async fn start_server_with_config(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        replication_factor: usize,
    ) -> Result<Child> {
        start_server_with_options(bind, data_dir, node_id, replication_factor, None, None).await
    }

    async fn start_server_with_options(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        replication_factor: usize,
        metadata_commit_mode: Option<&str>,
        heartbeat_timeout_secs: Option<u64>,
    ) -> Result<Child> {
        start_server_with_env_options(
            bind,
            data_dir,
            node_id,
            replication_factor,
            metadata_commit_mode,
            heartbeat_timeout_secs,
            &[],
        )
        .await
    }

    async fn start_server_with_env(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        replication_factor: usize,
        extra_env: &[(&str, &str)],
    ) -> Result<Child> {
        start_server_with_env_options(
            bind,
            data_dir,
            node_id,
            replication_factor,
            None,
            None,
            extra_env,
        )
        .await
    }

    async fn start_server_with_env_options(
        bind: &str,
        data_dir: &Path,
        node_id: &str,
        replication_factor: usize,
        metadata_commit_mode: Option<&str>,
        heartbeat_timeout_secs: Option<u64>,
        extra_env: &[(&str, &str)],
    ) -> Result<Child> {
        let server_bin = binary_path("server-node")?;

        let mut command = Command::new(server_bin);
        let command = command
            .env("IRONMESH_SERVER_BIND", bind)
            .env("IRONMESH_DATA_DIR", data_dir)
            .env(
                "IRONMESH_REPLICATION_FACTOR",
                replication_factor.to_string(),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if let Some(mode) = metadata_commit_mode {
            command.env("IRONMESH_METADATA_COMMIT_MODE", mode);
        }

        if let Some(timeout) = heartbeat_timeout_secs {
            command.env("IRONMESH_HEARTBEAT_TIMEOUT_SECS", timeout.to_string());
        }

        if !node_id.is_empty() {
            command.env("IRONMESH_NODE_ID", node_id);
        }

        for (key, value) in extra_env {
            command.env(key, value);
        }

        let child = command.spawn().context("failed to spawn server-node")?;

        wait_for_server(bind, 40).await?;
        Ok(child)
    }

    async fn register_node(
        http: &reqwest::Client,
        controller_base: &str,
        node_id: &str,
        public_url: &str,
        dc: &str,
        rack: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "public_url": public_url,
            "labels": {
                "region": "local",
                "dc": dc,
                "rack": rack
            },
            "capacity_bytes": 1_000_000,
            "free_bytes": 800_000
        });

        http.put(format!("{controller_base}/cluster/nodes/{node_id}"))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
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

        let result = BUILD_RESULT
            .get_or_init(|| build_required_binaries(workspace_root).map_err(|err| err.to_string()));

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
