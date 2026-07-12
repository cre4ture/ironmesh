#![cfg(test)]

use crate::framework::{
    default_client_identity_path, fresh_data_dir, insecure_https_client, run_cli, run_latency_cli,
    run_latency_cli_allow_failure, run_latency_cli_with_retry, start_rendezvous_service,
    start_zero_touch_server, stop_server, wait_for_rendezvous_registered_endpoints,
};
use anyhow::{Context, Result, bail};
use client_sdk::{BootstrapEndpoint, BootstrapEndpointUse, ConnectionBootstrap};
use std::fs;
use std::time::Duration;
use tokio::time::sleep;

const DEDICATED_RENDEZVOUS_BIND: &str = "127.0.0.1:19480";
const NODE_A_BIND: &str = "127.0.0.1:19481";
const NODE_B_BIND: &str = "127.0.0.1:19482";
const ADMIN_PASSWORD: &str = "cli-managed-rendezvous-password";

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
            && response.status() == reqwest::StatusCode::OK
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    bail!("runtime admin surface did not become ready on https://{bind}");
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

async fn admin_login_cookie(
    http: &reqwest::Client,
    bind: &str,
    admin_password: &str,
) -> Result<String> {
    let response = http
        .post(format!("https://{bind}/auth/admin/login"))
        .json(&serde_json::json!({ "password": admin_password }))
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
        "tls_validity_secs": null,
        "tls_renewal_window_secs": null,
    }))
    .send()
    .await?
    .error_for_status()?
    .json()
    .await
    .context("failed decoding node enrollment from join request response")
}

async fn update_rendezvous_config_with_cookie(
    http: &reqwest::Client,
    bind: &str,
    session_cookie: &str,
    editable_urls: &[&str],
) -> Result<serde_json::Value> {
    http.put(format!("https://{bind}/auth/rendezvous-config"))
        .header(reqwest::header::COOKIE, session_cookie)
        .json(&serde_json::json!({ "editable_urls": editable_urls }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("failed decoding rendezvous config response")
}

async fn issue_bootstrap_bundle_with_cookie(
    http: &reqwest::Client,
    bind: &str,
    session_cookie: &str,
    label: Option<&str>,
    expires_in_secs: Option<u64>,
) -> Result<ConnectionBootstrap> {
    http.post(format!("https://{bind}/auth/bootstrap-bundles/issue"))
        .header(reqwest::header::COOKIE, session_cookie)
        .json(&serde_json::json!({
            "label": label,
            "expires_in_secs": expires_in_secs,
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<ConnectionBootstrap>()
        .await
        .context("failed decoding bootstrap bundle response")
}

async fn wait_for_cluster_nodes_with_cookie(
    http: &reqwest::Client,
    bind: &str,
    session_cookie: &str,
    expected_count: usize,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(response) = http
            .get(format!("https://{bind}/cluster/nodes"))
            .header(reqwest::header::COOKIE, session_cookie)
            .send()
            .await
            && let Ok(ok_response) = response.error_for_status()
            && let Ok(nodes) = ok_response.json::<serde_json::Value>().await
            && let Some(entries) = nodes.as_array()
            && entries.len() == expected_count
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
    bail!(
        "cluster did not converge to {expected_count} known nodes at https://{bind}/cluster/nodes"
    );
}

/// Node A hosts the cluster's managed/embedded rendezvous service (auto-started the moment
/// /setup/start-cluster runs); a second, fully standalone `rendezvous-service` process is then
/// added to the cluster's rendezvous config so both are simultaneously usable. Node B joins the
/// same cluster as a plain runtime member (it does not get its own embedded rendezvous). This
/// mirrors the zero-touch appliance flow real deployments use, not the classic IRONMESH_*
/// env-var startup the other cluster tests use.
#[tokio::test]
async fn cli_latency_test_covers_embedded_and_standalone_rendezvous_in_managed_cluster()
-> Result<()> {
    let dedicated_rendezvous_url = format!("http://{DEDICATED_RENDEZVOUS_BIND}");
    let data_a = fresh_data_dir("cli-managed-rendezvous-node-a");
    let data_b = fresh_data_dir("cli-managed-rendezvous-node-b");
    let client_dir = fresh_data_dir("cli-managed-rendezvous-client");

    let insecure_http = insecure_https_client()?;
    let mut dedicated_rendezvous = start_rendezvous_service(DEDICATED_RENDEZVOUS_BIND).await?;
    let mut node_a = start_zero_touch_server(NODE_A_BIND, &data_a).await?;
    let mut node_b = start_zero_touch_server(NODE_B_BIND, &data_b).await?;

    let result = async {
        let start_cluster_response =
            setup_start_cluster(&insecure_http, NODE_A_BIND, ADMIN_PASSWORD).await?;
        let node_id_a = start_cluster_response
            .get("node_id")
            .and_then(|value| value.as_str())
            .context("start-cluster response missing node_id")?
            .to_string();
        wait_for_runtime_admin_surface(&insecure_http, NODE_A_BIND).await?;
        let admin_cookie_a =
            admin_login_cookie(&insecure_http, NODE_A_BIND, ADMIN_PASSWORD).await?;

        // Add the standalone rendezvous alongside node A's auto-started embedded one.
        let rendezvous_config = update_rendezvous_config_with_cookie(
            &insecure_http,
            NODE_A_BIND,
            &admin_cookie_a,
            &[dedicated_rendezvous_url.as_str()],
        )
        .await?;
        let effective_urls = rendezvous_config
            .get("effective_urls")
            .and_then(|value| value.as_array())
            .and_then(|values| {
                values
                    .iter()
                    .map(|value| value.as_str().map(ToString::to_string))
                    .collect::<Option<Vec<_>>>()
            })
            .context("missing effective_urls in rendezvous config response")?;
        assert_eq!(
            effective_urls.len(),
            2,
            "expected both the embedded and standalone rendezvous URLs, got {effective_urls:?}"
        );
        let dedicated_url_normalized = format!("{dedicated_rendezvous_url}/");
        assert!(
            effective_urls.contains(&dedicated_url_normalized),
            "expected the standalone rendezvous URL in effective config: {effective_urls:?}"
        );
        let embedded_rendezvous_url = effective_urls
            .iter()
            .find(|url| *url != &dedicated_url_normalized)
            .cloned()
            .context("expected an embedded rendezvous URL distinct from the standalone one")?;

        wait_for_rendezvous_registered_endpoints(&dedicated_rendezvous_url, 1, 120).await?;

        // Join node B as a plain runtime member of the same cluster.
        let join_request = setup_generate_join_request(&insecure_http, NODE_B_BIND).await?;
        let node_id_b = join_request
            .get("node_id")
            .and_then(|value| value.as_str())
            .context("join request missing node_id")?
            .to_string();
        let enrollment_package = issue_node_enrollment_from_join_request_with_cookie(
            &insecure_http,
            NODE_A_BIND,
            &admin_cookie_a,
            &join_request,
        )
        .await?;
        setup_import_node_enrollment(
            &insecure_http,
            NODE_B_BIND,
            ADMIN_PASSWORD,
            &enrollment_package,
        )
        .await?;
        wait_for_runtime_admin_surface(&insecure_http, NODE_B_BIND).await?;

        wait_for_cluster_nodes_with_cookie(&insecure_http, NODE_A_BIND, &admin_cookie_a, 2, 120)
            .await?;

        // Client bootstrap issued by a managed/appliance node still only lists the issuing node's
        // own direct endpoint (client credentials need to propagate to other nodes before those
        // nodes will trust them, same restriction as the classic runtime), so node B's endpoint
        // is merged in manually below. All configured rendezvous URLs are listed regardless.
        let bootstrap = issue_bootstrap_bundle_with_cookie(
            &insecure_http,
            NODE_A_BIND,
            &admin_cookie_a,
            Some("cli-managed-latency"),
            Some(3600),
        )
        .await?;
        assert_eq!(
            bootstrap.direct_endpoints.len(),
            1,
            "expected a single-node client bootstrap under required client auth, got {:?}",
            bootstrap.direct_endpoints
        );
        assert_eq!(
            bootstrap.rendezvous_urls.len(),
            2,
            "expected both rendezvous URLs in the managed bootstrap, got {:?}",
            bootstrap.rendezvous_urls
        );

        let mut merged_bootstrap = bootstrap.clone();
        merged_bootstrap.direct_endpoints.push(BootstrapEndpoint {
            url: format!("https://{NODE_B_BIND}"),
            usage: Some(BootstrapEndpointUse::PublicApi),
            node_id: Some(
                node_id_b
                    .parse()
                    .context("node_id_b should be a valid uuid")?,
            ),
        });
        let bootstrap_path = client_dir.join("cli-managed-latency.bootstrap.json");
        bootstrap.write_to_path(&bootstrap_path)?;
        let merged_bootstrap_path = client_dir.join("cli-managed-latency-merged.bootstrap.json");
        merged_bootstrap.write_to_path(&merged_bootstrap_path)?;
        let mut relay_only_bootstrap = merged_bootstrap.clone();
        relay_only_bootstrap.direct_endpoints.clear();
        let relay_only_bootstrap_path =
            client_dir.join("cli-managed-latency-relay-only.bootstrap.json");
        relay_only_bootstrap.write_to_path(&relay_only_bootstrap_path)?;

        let bootstrap_arg = merged_bootstrap_path.to_string_lossy().into_owned();
        let relay_only_bootstrap_arg = relay_only_bootstrap_path.to_string_lossy().into_owned();
        // The identity file lives next to the *originally issued* bootstrap file; the merged
        // bootstrap above reuses that same enrolled identity.
        let identity_path = default_client_identity_path(&bootstrap_path);
        let identity_arg = identity_path.to_string_lossy().into_owned();

        let enroll_output = run_cli(&[
            "--bootstrap-file",
            bootstrap_arg.as_str(),
            "--client-identity-file",
            identity_arg.as_str(),
            "enroll",
            "--label",
            "cli-managed-latency",
        ])
        .await?;
        assert!(
            enroll_output.contains("enrolled device"),
            "unexpected enroll output: {enroll_output}"
        );

        // --list-targets: both nodes and both rendezvous URLs should be discoverable up front.
        let list_output =
            run_latency_cli(&bootstrap_arg, &identity_arg, &["--list-targets"]).await?;
        assert!(
            list_output.contains(&node_id_a) && list_output.contains(NODE_A_BIND),
            "expected node A in --list-targets output, got: {list_output}"
        );
        assert!(
            list_output.contains(&node_id_b) && list_output.contains(NODE_B_BIND),
            "expected node B in --list-targets output, got: {list_output}"
        );
        assert!(
            list_output.contains(DEDICATED_RENDEZVOUS_BIND),
            "expected the standalone rendezvous URL in --list-targets output, got: {list_output}"
        );
        assert!(
            list_output.contains(embedded_rendezvous_url.trim_end_matches('/')),
            "expected the embedded rendezvous URL in --list-targets output, got: {list_output}"
        );

        // --path direct --node-id <A> / <B>: reach each node directly, tolerating the same
        // credential-propagation delay the classic-runtime test also needs.
        let direct_a_json = run_latency_cli_with_retry(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "direct",
                "--node-id",
                &node_id_a,
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
        let direct_a: serde_json::Value =
            serde_json::from_str(&direct_a_json).context("direct/node-a output should be JSON")?;
        assert_direct_probe_succeeded(&direct_a, NODE_A_BIND);

        let direct_b_json = run_latency_cli_with_retry(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "direct",
                "--node-id",
                &node_id_b,
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
            stderr.contains(&node_id_a) && stderr.contains(&node_id_b),
            "expected known node ids in error message, got: {stderr}"
        );

        // --path relay --relay-url <standalone>: relay through the dedicated rendezvous service.
        let relay_standalone_json = run_latency_cli_with_retry(
            &relay_only_bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "relay",
                "--relay-url",
                &dedicated_rendezvous_url,
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
        assert_filtered_relay_probe_pinned(
            &serde_json::from_str(&relay_standalone_json)?,
            dedicated_rendezvous_url.trim_end_matches('/'),
        );

        // --path relay --relay-url <embedded>: relay through node A's own embedded rendezvous.
        let relay_embedded_json = run_latency_cli_with_retry(
            &relay_only_bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "relay",
                "--relay-url",
                embedded_rendezvous_url.trim_end_matches('/'),
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
        assert_filtered_relay_probe_pinned(
            &serde_json::from_str(&relay_embedded_json)?,
            embedded_rendezvous_url.trim_end_matches('/'),
        );

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
            stderr.contains(DEDICATED_RENDEZVOUS_BIND),
            "expected the known standalone rendezvous URL in error message, got: {stderr}"
        );

        // --node-id + --relay-url combine: relay to node B specifically, via the standalone
        // rendezvous specifically.
        let combined_json = run_latency_cli_with_retry(
            &bootstrap_arg,
            &identity_arg,
            &[
                "--path",
                "relay",
                "--node-id",
                &node_id_b,
                "--relay-url",
                &dedicated_rendezvous_url,
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
        assert_relay_probe_succeeded(&combined);
        let combined_targets = combined
            .get("targets")
            .and_then(|value| value.as_array())
            .context("combined output missing targets array")?;
        assert!(
            combined_targets.iter().any(|target| {
                target
                    .get("target")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.contains(&node_id_b))
            }),
            "expected a relay target addressing node B, got {combined}"
        );

        // Baseline: unfiltered --path all still works end to end.
        let all_json = run_latency_cli_with_retry(
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
            120,
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
    stop_server(&mut dedicated_rendezvous).await;
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

fn assert_relay_probe_succeeded(response: &serde_json::Value) {
    let targets = response
        .get("targets")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("relay probe response should have a targets array: {response}"));
    assert!(
        !targets.is_empty(),
        "expected at least one relay target, got {response}"
    );
    for target in targets {
        assert_eq!(
            target.get("transport_mode").and_then(|v| v.as_str()),
            Some("relay"),
            "expected relay target, got {response}"
        );
        assert!(
            target.get("error").is_none_or(serde_json::Value::is_null),
            "expected relay probe to succeed, got {response}"
        );
    }
}

fn assert_filtered_relay_probe_pinned(
    response: &serde_json::Value,
    rendezvous_hint: &str,
) {
    let targets = response
        .get("targets")
        .and_then(|value| value.as_array())
        .unwrap_or_else(|| panic!("filtered relay probe response should have a targets array: {response}"));
    assert_eq!(
        targets.len(),
        1,
        "expected a single filtered relay target, got {response}"
    );
    let target = &targets[0];
    assert_eq!(
        target.get("transport_mode").and_then(|value| value.as_str()),
        Some("relay"),
        "expected relay transport mode, got {response}"
    );
    assert_eq!(
        target
            .get("uses_current_runtime")
            .and_then(|value| value.as_bool()),
        Some(false),
        "filtered relay probes should not fall back to the current runtime, got {response}"
    );
    assert!(
        target
            .get("target")
            .and_then(|value| value.as_str())
            .is_some_and(|value| value.contains(rendezvous_hint)),
        "expected pinned rendezvous hint {rendezvous_hint} in target description, got {response}"
    );
    assert!(
        target.get("error").is_none_or(serde_json::Value::is_null),
        "expected filtered relay probe to succeed, got {response}"
    );
}
