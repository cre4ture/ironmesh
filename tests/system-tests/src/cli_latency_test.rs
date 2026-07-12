#![cfg(test)]

use crate::framework::{
    TEST_ADMIN_TOKEN, default_client_identity_path, fresh_data_dir,
    issue_bootstrap_bundle_and_enroll_client, run_latency_cli, run_latency_cli_allow_failure,
    run_latency_cli_with_retry, start_open_server_with_env, start_rendezvous_service, stop_server,
    wait_for_online_nodes, wait_for_rendezvous_registered_endpoints,
};
use anyhow::{Context, Result};
use client_sdk::{BootstrapEndpoint, BootstrapEndpointUse};
use std::fs;

const RENDEZVOUS_BIND: &str = "127.0.0.1:19470";
const NODE_A_BIND: &str = "127.0.0.1:19471";
const NODE_B_BIND: &str = "127.0.0.1:19472";
const CLUSTER_ID: &str = "11111111-1111-7111-8111-111111119470";
const NODE_ID_A: &str = "00000000-0000-0000-0000-000000009471";
const NODE_ID_B: &str = "00000000-0000-0000-0000-000000009472";

#[tokio::test]
async fn cli_latency_test_supports_list_targets_and_explicit_node_and_relay_selection() -> Result<()>
{
    let rendezvous_url = format!("http://{RENDEZVOUS_BIND}");
    let base_a = format!("http://{NODE_A_BIND}");
    let base_b = format!("http://{NODE_B_BIND}");
    let data_a = fresh_data_dir("cli-latency-node-a");
    let data_b = fresh_data_dir("cli-latency-node-b");
    let client_dir = fresh_data_dir("cli-latency-client");

    // relay_mode "fallback" keeps both direct and relay connectivity usable.
    // IRONMESH_REQUIRE_CLIENT_AUTH=true matches every other cluster test in this suite: the
    // direct multiplexed transport used by latency diagnostics (/transport/ws) requires an
    // authenticated client identity to be attached to the request, which the server only does
    // when client auth is required. In that mode a single node's issued bootstrap only lists its
    // own direct endpoint (client credentials still need to replicate to other nodes before those
    // nodes will trust them), so this test manually merges node B's endpoint into the enrolled
    // bootstrap below rather than relying on bootstrap-bundle issuance to discover it.
    let node_env = [
        ("IRONMESH_CLUSTER_ID", CLUSTER_ID),
        ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
        ("IRONMESH_RELAY_MODE", "fallback"),
        ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
        ("IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS", "2"),
        ("IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS", "2"),
        ("IRONMESH_STARTUP_REPAIR_DELAY_SECS", "1"),
        ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
    ];

    let mut rendezvous = start_rendezvous_service(RENDEZVOUS_BIND).await?;
    let mut node_a =
        start_open_server_with_env(NODE_A_BIND, &data_a, NODE_ID_A, 2, &node_env).await?;
    let mut node_b =
        start_open_server_with_env(NODE_B_BIND, &data_b, NODE_ID_B, 2, &node_env).await?;
    let http = reqwest::Client::new();

    let result = async {
        wait_for_rendezvous_registered_endpoints(&rendezvous_url, 2, 120).await?;
        wait_for_online_nodes(&http, &base_a, 2, 120).await?;
        wait_for_online_nodes(&http, &base_b, 2, 120).await?;

        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_a,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "cli-latency.bootstrap.json",
            Some("cli-latency-test"),
            Some(3600),
        )
        .await?;

        assert_eq!(
            enrolled.bootstrap.direct_endpoints.len(),
            1,
            "expected a single-node client bootstrap under required client auth, got {:?}",
            enrolled.bootstrap.direct_endpoints
        );

        let mut merged_bootstrap = enrolled.bootstrap.clone();
        merged_bootstrap.direct_endpoints.push(BootstrapEndpoint {
            url: base_b.clone(),
            usage: Some(BootstrapEndpointUse::PublicApi),
            node_id: Some(
                NODE_ID_B
                    .parse()
                    .context("NODE_ID_B should be a valid uuid")?,
            ),
        });
        let merged_bootstrap_path = client_dir.join("cli-latency-merged.bootstrap.json");
        merged_bootstrap.write_to_path(&merged_bootstrap_path)?;

        let bootstrap_arg = merged_bootstrap_path.to_string_lossy().into_owned();
        // The identity file lives next to the *originally issued* bootstrap file; the merged
        // bootstrap above reuses that same enrolled identity.
        let identity_path = default_client_identity_path(&enrolled.bootstrap_path);
        let identity_arg = identity_path.to_string_lossy().into_owned();

        // --list-targets: both nodes and the rendezvous URL should be discoverable up front.
        let list_output =
            run_latency_cli(&bootstrap_arg, &identity_arg, &["--list-targets"]).await?;
        assert!(
            list_output.contains(NODE_ID_A) && list_output.contains(NODE_A_BIND),
            "expected node A in --list-targets output, got: {list_output}"
        );
        assert!(
            list_output.contains(NODE_ID_B) && list_output.contains(NODE_B_BIND),
            "expected node B in --list-targets output, got: {list_output}"
        );
        assert!(
            list_output.contains(RENDEZVOUS_BIND),
            "expected the rendezvous URL in --list-targets output, got: {list_output}"
        );

        // --path direct --node-id <A>: must reach node A specifically, even though the CLI's
        // already-established "current" connection also happens to be direct (the case the
        // force_diagnostic_target fix addresses).
        let direct_a_json = run_latency_cli(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "direct",
                "--node-id",
                NODE_ID_A,
                "--samples",
                "2",
                "--warmup",
                "1",
                "--pause-ms",
                "0",
                "--json",
            ],
        )
        .await?;
        let direct_a: serde_json::Value =
            serde_json::from_str(&direct_a_json).context("direct/node-a output should be JSON")?;
        assert_direct_probe_succeeded(&direct_a, NODE_A_BIND);

        // --path direct --node-id <B>: must reach node B, not node A. Node B only trusts the
        // client's credential once it has synced from node A, so retry for a while.
        let direct_b_json = run_latency_cli_with_retry(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "direct",
                "--node-id",
                NODE_ID_B,
                "--samples",
                "2",
                "--warmup",
                "1",
                "--pause-ms",
                "0",
                "--json",
            ],
            120,
        )
        .await?;
        let direct_b: serde_json::Value =
            serde_json::from_str(&direct_b_json).context("direct/node-b output should be JSON")?;
        assert_direct_probe_succeeded(&direct_b, NODE_B_BIND);

        // Unknown --node-id must fail with a helpful error listing the known node ids.
        let (success, _stdout, stderr) = run_latency_cli_allow_failure(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "direct",
                "--node-id",
                "99999999-9999-9999-9999-999999999999",
            ],
        )
        .await?;
        assert!(!success, "unknown --node-id should fail, stderr: {stderr}");
        assert!(
            stderr.contains(NODE_ID_A) && stderr.contains(NODE_ID_B),
            "expected known node ids in error message, got: {stderr}"
        );

        // --path relay --relay-url <rendezvous>: pins the relay probe to the one configured
        // rendezvous URL.
        let relay_json = run_latency_cli(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "relay",
                "--relay-url",
                &rendezvous_url,
                "--samples",
                "2",
                "--warmup",
                "1",
                "--pause-ms",
                "0",
                "--json",
            ],
        )
        .await?;
        let relay: serde_json::Value =
            serde_json::from_str(&relay_json).context("relay output should be JSON")?;
        let relay_targets = relay
            .get("targets")
            .and_then(|value| value.as_array())
            .context("relay output missing targets array")?;
        assert_eq!(
            relay_targets.len(),
            1,
            "expected exactly one pinned relay target, got {relay}"
        );
        for target in relay_targets {
            assert_eq!(
                target.get("transport_mode").and_then(|v| v.as_str()),
                Some("relay"),
                "expected relay target, got {relay}"
            );
            assert!(
                target.get("error").is_none_or(serde_json::Value::is_null),
                "expected relay probe to succeed, got {relay}"
            );
            assert!(
                target
                    .get("target")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.contains(&rendezvous_url)),
                "expected pinned relay target to use {rendezvous_url}, got {relay}"
            );
        }

        // Unknown --relay-url must fail with a helpful error listing the known rendezvous URLs.
        let (success, _stdout, stderr) = run_latency_cli_allow_failure(
            &bootstrap_arg,
            &identity_arg,
            &["--path", "relay", "--relay-url", "http://127.0.0.1:1"],
        )
        .await?;
        assert!(
            !success,
            "unknown --relay-url should fail, stderr: {stderr}"
        );
        assert!(
            stderr.contains(RENDEZVOUS_BIND),
            "expected the known rendezvous URL in error message, got: {stderr}"
        );

        // --node-id and --relay-url combine to pin the relay probe to one specific node via one
        // specific rendezvous URL. This also relays through node B, so tolerate the same
        // credential-sync delay as the direct probe above.
        let combined_json = run_latency_cli_with_retry(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "relay",
                "--node-id",
                NODE_ID_B,
                "--relay-url",
                &rendezvous_url,
                "--samples",
                "2",
                "--warmup",
                "1",
                "--pause-ms",
                "0",
                "--json",
            ],
            120,
        )
        .await?;
        let combined: serde_json::Value =
            serde_json::from_str(&combined_json).context("combined output should be JSON")?;
        let combined_targets = combined
            .get("targets")
            .and_then(|value| value.as_array())
            .context("combined output missing targets array")?;
        assert_eq!(
            combined_targets.len(),
            1,
            "expected exactly one combined relay target, got {combined}"
        );
        assert!(
            combined_targets.iter().any(|target| {
                target
                    .get("target")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.contains(NODE_ID_B) && value.contains(&rendezvous_url))
            }),
            "expected a relay target addressing node B, got {combined}"
        );

        // --node-id/--relay-url are meaningless with --path current and must be rejected.
        let (success, _stdout, stderr) = run_latency_cli_allow_failure(
            &bootstrap_arg,
            &identity_arg,
            &["--path", "current", "--node-id", NODE_ID_A],
        )
        .await?;
        assert!(
            !success,
            "--node-id with --path current should be rejected, stderr: {stderr}"
        );
        assert!(
            stderr.contains("--path current"),
            "expected an explanatory error, got: {stderr}"
        );

        // Baseline: unfiltered --path all still works end to end (feature parity with the web UI).
        let all_json = run_latency_cli(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "all",
                "--samples",
                "2",
                "--warmup",
                "1",
                "--pause-ms",
                "0",
                "--json",
            ],
        )
        .await?;
        let all: serde_json::Value =
            serde_json::from_str(&all_json).context("--path all output should be JSON")?;
        assert!(
            all.get("targets")
                .and_then(|value| value.as_array())
                .is_some_and(|targets| !targets.is_empty()),
            "expected --path all to produce at least one target, got {all}"
        );

        Ok::<(), anyhow::Error>(())
    }
    .await;

    stop_server(&mut node_a).await;
    stop_server(&mut node_b).await;
    stop_server(&mut rendezvous).await;
    let _ = fs::remove_dir_all(&data_a);
    let _ = fs::remove_dir_all(&data_b);
    let _ = fs::remove_dir_all(&client_dir);

    result
}

fn assert_direct_probe_succeeded(response: &serde_json::Value, expected_bind: &str) {
    let targets = response
        .get("targets")
        .and_then(|value| value.as_array())
        .expect("direct probe response should have a targets array");
    let direct_target = targets
        .iter()
        .find(|target| target.get("path_id").and_then(|v| v.as_str()) == Some("direct"))
        .unwrap_or_else(|| panic!("missing direct target in {response}"));
    assert!(
        direct_target
            .get("target")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.contains(expected_bind)),
        "expected direct target to address {expected_bind}, got {response}"
    );
    assert!(
        direct_target
            .get("error")
            .is_none_or(serde_json::Value::is_null),
        "expected direct probe to succeed, got {response}"
    );
    assert_eq!(
        direct_target
            .get("result")
            .and_then(|value| value.get("summary"))
            .and_then(|value| value.get("success_count"))
            .and_then(|value| value.as_u64()),
        Some(2),
        "expected two successful direct samples, got {response}"
    );
}
