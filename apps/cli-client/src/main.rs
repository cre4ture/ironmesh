use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand, ValueEnum};
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, ConnectionBootstrapDiagnosticTargets,
    IronMeshClient, LatencyProbeComparison, LatencyProbeConfig, LatencyProbeResult,
    build_client_with_optional_identity_from_planned_target, build_http_client_from_pem,
    build_http_client_with_identity_from_pem, compare_direct_and_relay_latency,
    enroll_connection_input_blocking, normalize_server_base_url,
};
use serde::Serialize;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing_subscriber::filter::Directive;
use web_ui_backend::{WebUiBootstrapPersistence, WebUiConfig};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LatencyTestPathSelection {
    Current,
    Direct,
    Relay,
    All,
}

#[derive(Debug, Clone, Serialize)]
struct LatencyTestPathResult {
    path_id: String,
    label: String,
    transport_mode: String,
    uses_current_runtime: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<LatencyProbeResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct LatencyTestSuiteResult {
    generated_at_unix_ms: u64,
    config: LatencyProbeConfig,
    targets: Vec<LatencyTestPathResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comparison: Option<LatencyProbeComparison>,
}
#[derive(Debug, Clone, Parser)]
#[command(name = "ironmesh")]
#[command(about = "CLI client for ironmesh distributed storage")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Cli {
    #[arg(long)]
    server_url: Option<String>,
    #[arg(long)]
    bootstrap_file: Option<PathBuf>,
    #[arg(long)]
    server_ca_pem_file: Option<PathBuf>,
    #[arg(long)]
    client_identity_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    Enroll {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        device_id: Option<String>,
        #[arg(long)]
        label: Option<String>,
    },
    Put {
        key: String,
        value: String,
    },
    Get {
        key: String,
    },
    List {
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long, default_value_t = 1)]
        depth: usize,
    },
    Health,
    ClusterStatus,
    Nodes,
    ReplicationPlan,
    CacheList,
    LatencyTest {
        #[arg(long, value_enum, default_value_t = LatencyTestPathSelection::All)]
        path: LatencyTestPathSelection,
        #[arg(long, default_value_t = 6)]
        samples: usize,
        #[arg(long, default_value_t = 1)]
        warmup: usize,
        #[arg(long, default_value_t = 1024)]
        response_bytes: usize,
        #[arg(long, default_value_t = 125)]
        pause_ms: u64,
        #[arg(long, default_value_t = 0)]
        server_delay_ms: u64,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        max_average_ms: Option<f64>,
        #[arg(long)]
        max_p95_ms: Option<f64>,
    },
    ServeWeb {
        #[arg(long, default_value = "127.0.0.1:8081")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    init_cli_tracing();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Enroll {
            output,
            device_id,
            label,
        } => {
            enroll_from_bootstrap(
                &cli,
                output.as_ref(),
                device_id.as_deref(),
                label.as_deref(),
            )
            .await
        }
        Commands::CacheList => {
            let client = build_client_node_from_cli(&cli).await?;
            for entry in client.cache_entries().await {
                println!("{} ({} bytes)", entry.key, entry.size_bytes);
            }
            Ok(())
        }
        Commands::Put { key, value } => {
            let client = build_client_node_from_cli(&cli).await?;
            let object = client.put(key.clone(), Bytes::from(value.clone())).await?;
            println!("stored '{}' ({} bytes)", object.key, object.size_bytes);
            Ok(())
        }
        Commands::Get { key } => {
            let client = build_client_node_from_cli(&cli).await?;
            let payload = client.get_cached_or_fetch(key).await?;
            println!("{}", String::from_utf8_lossy(&payload));
            Ok(())
        }
        Commands::List { prefix, depth } => {
            let sdk = build_authenticated_sdk_from_cli(&cli).await?;
            let value = sdk
                .store_index(prefix.as_deref(), (*depth).max(1), None)
                .await?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Commands::Health => {
            let client = build_authenticated_sdk_from_cli(&cli).await?;
            print_json_endpoint(&client, "/health").await
        }
        Commands::ClusterStatus => {
            let client = build_authenticated_sdk_from_cli(&cli).await?;
            print_json_endpoint(&client, "/cluster/status").await
        }
        Commands::Nodes => {
            let client = build_authenticated_sdk_from_cli(&cli).await?;
            print_json_endpoint(&client, "/cluster/nodes").await
        }
        Commands::ReplicationPlan => {
            let client = build_authenticated_sdk_from_cli(&cli).await?;
            print_json_endpoint(&client, "/cluster/replication/plan").await
        }
        Commands::LatencyTest {
            path,
            samples,
            warmup,
            response_bytes,
            pause_ms,
            server_delay_ms,
            json,
            max_average_ms,
            max_p95_ms,
        } => {
            let suite = run_latency_test(
                &cli,
                *path,
                LatencyProbeConfig {
                    sample_count: *samples,
                    warmup_count: *warmup,
                    response_bytes: *response_bytes,
                    server_delay_ms: *server_delay_ms,
                    pause_between_samples_ms: *pause_ms,
                },
            )
            .await?;
            if *json {
                println!("{}", serde_json::to_string_pretty(&suite)?);
            } else {
                print_latency_test_suite(&suite);
            }
            validate_latency_test_thresholds(&suite, *max_average_ms, *max_p95_ms)
        }
        Commands::ServeWeb { bind } => {
            let bind_addr: SocketAddr = bind.parse()?;
            let web_ui_config = if cli.server_url.is_some() || cli.bootstrap_file.is_some() {
                let client = build_authenticated_sdk_from_cli(&cli).await?;
                let mut web_ui_config = WebUiConfig::from_client(client);
                if let Some(bootstrap_path) = cli.bootstrap_file.as_deref() {
                    let server_ca_override = read_server_ca_override_from_cli(&cli)?;
                    let bootstrap =
                        load_bootstrap_from_path(bootstrap_path, server_ca_override.as_deref())?;
                    let persistence_path = bootstrap_path.to_path_buf();
                    web_ui_config = web_ui_config
                        .with_connection_bootstrap(bootstrap)
                        .with_connection_bootstrap_persistence(WebUiBootstrapPersistence::new(
                            "bootstrap_file",
                            move |bootstrap| bootstrap.write_to_path(&persistence_path),
                        ));
                }
                if let Some(identity) = read_client_identity_from_cli(&cli)? {
                    web_ui_config = web_ui_config.with_client_identity(identity);
                }
                web_ui_config
            } else {
                WebUiConfig::new("http://127.0.0.1:9")
            }
            .with_service_name("cli-client-web");
            let app = web_ui_backend::router(web_ui_config);

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

fn init_cli_tracing() {
    let perf_logging_enabled = env_flag_is_truthy("IRONMESH_MAP_PERF_LOG");
    let mut env_filter = common::logging::env_filter_from_default_env("warn");
    if perf_logging_enabled {
        env_filter = env_filter.add_directive(
            "info"
                .parse::<Directive>()
                .expect("valid info tracing directive"),
        );
    }
    common::logging::init_compact_tracing(env_filter);
}

fn env_flag_is_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

async fn enroll_from_bootstrap(
    cli: &Cli,
    output: Option<&PathBuf>,
    device_id: Option<&str>,
    label: Option<&str>,
) -> Result<()> {
    if cli.server_url.is_some() {
        bail!("enroll requires --bootstrap-file and does not accept --server-url");
    }

    let bootstrap_path = cli
        .bootstrap_file
        .clone()
        .ok_or_else(|| anyhow::anyhow!("enroll requires --bootstrap-file"))?;
    let output_path = output
        .cloned()
        .or_else(|| cli.client_identity_file.clone())
        .unwrap_or_else(|| default_client_identity_path(&bootstrap_path));
    let output_path_for_print = output_path.clone();
    let device_id = device_id.map(ToString::to_string);
    let label = label.map(ToString::to_string);

    let enrolled = tokio::task::spawn_blocking(
        move || -> Result<(ClientIdentityMaterial, Option<String>)> {
            let connection_input = fs::read_to_string(&bootstrap_path).with_context(|| {
                format!(
                    "failed to read bootstrap input {}",
                    bootstrap_path.display()
                )
            })?;
            let enrolled = enroll_connection_input_blocking(
                &connection_input,
                device_id.as_deref(),
                label.as_deref(),
            )?;
            let identity = enrolled.client_identity_material()?;
            identity.write_to_path(&output_path)?;
            Ok((identity, enrolled.server_base_url))
        },
    )
    .await
    .context("enroll task panicked")??;

    println!("enrolled device {}", enrolled.0.device_id);
    println!("cluster {}", enrolled.0.cluster_id);
    if let Some(server_base_url) = enrolled.1.as_deref() {
        println!("server {server_base_url}");
    } else {
        println!("server relay-only");
    }
    println!("identity {}", output_path_for_print.display());
    Ok(())
}

fn build_authenticated_sdk_from_cli_blocking(cli: &Cli) -> Result<IronMeshClient> {
    let client_identity = read_client_identity_from_cli(cli)?;
    let server_ca_override = read_server_ca_override_from_cli(cli)?;

    if let Some(bootstrap_path) = cli.bootstrap_file.as_deref() {
        let bootstrap = load_bootstrap_from_path(bootstrap_path, server_ca_override.as_deref())?;
        return match client_identity.as_ref() {
            Some(identity) => bootstrap.build_client_with_identity(identity),
            None => bootstrap.build_client(),
        };
    }

    let server_url = cli
        .server_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("set either --bootstrap-file or --server-url"))?;
    let base_url = normalize_server_base_url(server_url)?;
    match client_identity.as_ref() {
        Some(identity) => build_http_client_with_identity_from_pem(
            server_ca_override.as_deref(),
            base_url.as_str(),
            identity,
        ),
        None => build_http_client_from_pem(server_ca_override.as_deref(), base_url.as_str()),
    }
}

async fn build_authenticated_sdk_from_cli(cli: &Cli) -> Result<IronMeshClient> {
    let cli = cli.clone();
    tokio::task::spawn_blocking(move || build_authenticated_sdk_from_cli_blocking(&cli))
        .await
        .context("client construction task panicked")?
}

async fn build_client_node_from_cli(cli: &Cli) -> Result<ClientNode> {
    Ok(ClientNode::with_client(
        build_authenticated_sdk_from_cli(cli).await?,
    ))
}

async fn print_json_endpoint(client: &IronMeshClient, path: &str) -> Result<()> {
    let value = client.get_json_path(path).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn run_latency_test(
    cli: &Cli,
    path_selection: LatencyTestPathSelection,
    config: LatencyProbeConfig,
) -> Result<LatencyTestSuiteResult> {
    config.validate()?;

    let current_client = build_authenticated_sdk_from_cli(cli).await?;
    let bootstrap = load_bootstrap_from_cli(cli)?;
    let identity = read_client_identity_from_cli(cli)?;
    let diagnostic_targets = bootstrap
        .as_ref()
        .map(ConnectionBootstrap::diagnostic_targets)
        .transpose()?
        .unwrap_or_default();

    let mut targets = match path_selection {
        LatencyTestPathSelection::Current => {
            vec![probe_current_latency_target(&current_client, &config).await]
        }
        LatencyTestPathSelection::Direct => {
            vec![
                probe_direct_latency_target(
                    &current_client,
                    &diagnostic_targets,
                    identity.as_ref(),
                    &config,
                )
                .await,
            ]
        }
        LatencyTestPathSelection::Relay => {
            probe_relay_latency_targets(
                &current_client,
                &diagnostic_targets,
                identity.as_ref(),
                &config,
                true,
            )
            .await
        }
        LatencyTestPathSelection::All => {
            let mut targets = vec![probe_current_latency_target(&current_client, &config).await];
            if current_client.uses_relay_transport() && diagnostic_targets.direct.is_some() {
                targets.push(
                    probe_direct_latency_target(
                        &current_client,
                        &diagnostic_targets,
                        identity.as_ref(),
                        &config,
                    )
                    .await,
                );
            }
            targets.extend(
                probe_relay_latency_targets(
                    &current_client,
                    &diagnostic_targets,
                    identity.as_ref(),
                    &config,
                    true,
                )
                .await,
            );
            targets
        }
    };

    dedup_latency_targets(&mut targets);

    let comparison = select_direct_and_relay_results(&targets)
        .map(|(direct, relay)| compare_direct_and_relay_latency(Some(direct), Some(relay)))
        .flatten();

    Ok(LatencyTestSuiteResult {
        generated_at_unix_ms: unix_ts_ms(),
        config,
        targets,
        comparison,
    })
}

async fn probe_current_latency_target(
    client: &IronMeshClient,
    config: &LatencyProbeConfig,
) -> LatencyTestPathResult {
    probe_latency_client(
        "current",
        "Current runtime path".to_string(),
        current_transport_mode(client).to_string(),
        true,
        describe_current_target(client),
        client,
        config,
    )
    .await
}

async fn probe_direct_latency_target(
    current_client: &IronMeshClient,
    diagnostic_targets: &ConnectionBootstrapDiagnosticTargets,
    identity: Option<&ClientIdentityMaterial>,
    config: &LatencyProbeConfig,
) -> LatencyTestPathResult {
    if !current_client.uses_relay_transport() {
        return probe_latency_client(
            "direct",
            "Direct path (current runtime)".to_string(),
            "direct".to_string(),
            true,
            describe_current_target(current_client),
            current_client,
            config,
        )
        .await;
    }

    let Some(target) = diagnostic_targets.direct.as_ref() else {
        return LatencyTestPathResult {
            path_id: "direct".to_string(),
            label: "Direct path".to_string(),
            transport_mode: "direct".to_string(),
            uses_current_runtime: false,
            target: None,
            result: None,
            error: Some("no direct bootstrap target is available for diagnostics".to_string()),
        };
    };

    match build_client_with_optional_identity_from_planned_target(target, identity) {
        Ok(client) => {
            probe_latency_client(
                "direct",
                "Direct bootstrap path".to_string(),
                "direct".to_string(),
                false,
                target.server_base_url.clone(),
                &client,
                config,
            )
            .await
        }
        Err(error) => LatencyTestPathResult {
            path_id: "direct".to_string(),
            label: "Direct path".to_string(),
            transport_mode: "direct".to_string(),
            uses_current_runtime: false,
            target: target.server_base_url.clone(),
            result: None,
            error: Some(error.to_string()),
        },
    }
}

async fn probe_relay_latency_targets(
    current_client: &IronMeshClient,
    diagnostic_targets: &ConnectionBootstrapDiagnosticTargets,
    identity: Option<&ClientIdentityMaterial>,
    config: &LatencyProbeConfig,
    include_current_runtime_if_relay: bool,
) -> Vec<LatencyTestPathResult> {
    let mut results = Vec::new();

    if include_current_runtime_if_relay && current_client.uses_relay_transport() {
        results.push(
            probe_latency_client(
                "relay-current",
                "Relay path (current runtime)".to_string(),
                "relay".to_string(),
                true,
                describe_current_target(current_client),
                current_client,
                config,
            )
            .await,
        );
    }

    if diagnostic_targets.relay.is_empty() {
        if results.is_empty() {
            results.push(LatencyTestPathResult {
                path_id: "relay".to_string(),
                label: "Relay path".to_string(),
                transport_mode: "relay".to_string(),
                uses_current_runtime: false,
                target: None,
                result: None,
                error: Some("no relay bootstrap target is available for diagnostics".to_string()),
            });
        }
        return results;
    }

    for (index, target) in diagnostic_targets.relay.iter().enumerate() {
        let rendezvous_hint = target
            .rendezvous_urls
            .first()
            .map(|url| url.trim_end_matches('/').to_string())
            .unwrap_or_else(|| "rendezvous".to_string());
        let target_description = target
            .target_node_id
            .map(|node_id| format!("relay://{node_id}@{rendezvous_hint}"));
        let path_id = format!("relay-{}", index + 1);
        let label = format!("Relay via {rendezvous_hint}");

        match build_client_with_optional_identity_from_planned_target(target, identity) {
            Ok(client) => {
                results.push(
                    probe_latency_client(
                        &path_id,
                        label,
                        "relay".to_string(),
                        false,
                        target_description,
                        &client,
                        config,
                    )
                    .await,
                );
            }
            Err(error) => {
                results.push(LatencyTestPathResult {
                    path_id,
                    label,
                    transport_mode: "relay".to_string(),
                    uses_current_runtime: false,
                    target: target_description
                        .or_else(|| target.target_node_id.map(|node_id| node_id.to_string())),
                    result: None,
                    error: Some(error.to_string()),
                });
            }
        }
    }

    results
}

async fn probe_latency_client(
    path_id: &str,
    label: String,
    transport_mode: String,
    uses_current_runtime: bool,
    target: Option<String>,
    client: &IronMeshClient,
    config: &LatencyProbeConfig,
) -> LatencyTestPathResult {
    match client.run_latency_probe(config.clone()).await {
        Ok(result) => LatencyTestPathResult {
            path_id: path_id.to_string(),
            label,
            transport_mode,
            uses_current_runtime,
            target,
            result: Some(result),
            error: None,
        },
        Err(error) => LatencyTestPathResult {
            path_id: path_id.to_string(),
            label,
            transport_mode,
            uses_current_runtime,
            target,
            result: None,
            error: Some(error.to_string()),
        },
    }
}

fn dedup_latency_targets(targets: &mut Vec<LatencyTestPathResult>) {
    let mut seen = std::collections::HashSet::new();
    targets.retain(|target| {
        let key = format!(
            "{}:{}",
            target.transport_mode,
            target.target.as_deref().unwrap_or_default()
        );
        seen.insert(key)
    });
}

fn select_direct_and_relay_results(
    targets: &[LatencyTestPathResult],
) -> Option<(&LatencyProbeResult, &LatencyProbeResult)> {
    let direct = targets.iter().find_map(|target| {
        (target.path_id == "direct" || target.transport_mode == "direct")
            .then(|| target.result.as_ref())
            .flatten()
    })?;
    let relay = targets.iter().find_map(|target| {
        (target.path_id == "relay" || target.transport_mode == "relay")
            .then(|| target.result.as_ref())
            .flatten()
    })?;
    Some((direct, relay))
}

fn current_transport_mode(client: &IronMeshClient) -> &'static str {
    if client.uses_relay_transport() {
        "relay"
    } else {
        "direct"
    }
}

fn describe_current_target(client: &IronMeshClient) -> Option<String> {
    if client.uses_relay_transport() {
        let rendezvous_hint = client
            .rendezvous_client()
            .and_then(|rendezvous| rendezvous.config().rendezvous_urls.first().cloned())
            .unwrap_or_else(|| "rendezvous".to_string());
        return client.relay_target_node_id().map(|node_id| {
            format!(
                "relay://{node_id}@{}",
                rendezvous_hint.trim_end_matches('/')
            )
        });
    }

    client
        .direct_server_base_url()
        .map(|url| url.trim_end_matches('/').to_string())
}

fn print_latency_test_suite(suite: &LatencyTestSuiteResult) {
    println!(
        "latency probe: {} samples, {} warmup, {} bytes",
        suite.config.sample_count, suite.config.warmup_count, suite.config.response_bytes
    );
    for target in &suite.targets {
        if let Some(result) = target.result.as_ref() {
            let summary = &result.summary;
            println!(
                "{} [{}] avg={} p95={} cold={} overhead={} sessions={}/{}/{} assessment={:?}",
                target.label,
                target.transport_mode,
                format_duration_ms(summary.avg_total_duration_ms),
                format_duration_ms(summary.p95_total_duration_ms),
                format_duration_ms(result.cold_connect_duration_ms),
                format_duration_ms(summary.avg_transport_overhead_ms),
                result.transport_session_pool.connect_count,
                result.transport_session_pool.reuse_count,
                result.transport_session_pool.reset_count,
                summary.assessment
            );
            if let Some(target_description) = target.target.as_deref() {
                println!("  target: {target_description}");
            }
            if result.transport_session_pool.connect_count > 0 {
                println!(
                    "  session reuse: {} connect(s), {} reuse(s), {} reset(s)",
                    result.transport_session_pool.connect_count,
                    result.transport_session_pool.reuse_count,
                    result.transport_session_pool.reset_count
                );
            }
            for observation in &summary.observations {
                println!("  note: {observation}");
            }
        } else {
            println!(
                "{} [{}] failed{}",
                target.label,
                target.transport_mode,
                target
                    .error
                    .as_deref()
                    .map(|error| format!(": {error}"))
                    .unwrap_or_default()
            );
        }
    }

    if let Some(comparison) = suite.comparison.as_ref() {
        println!(
            "direct-vs-relay assessment={:?} delta={} ratio={}",
            comparison.assessment,
            format_duration_ms(comparison.relay_avg_total_delta_ms),
            comparison
                .relay_avg_total_ratio
                .map(|value| format!("{value:.2}x"))
                .unwrap_or_else(|| "n/a".to_string())
        );
        for observation in &comparison.observations {
            println!("  note: {observation}");
        }
    }
}

fn validate_latency_test_thresholds(
    suite: &LatencyTestSuiteResult,
    max_average_ms: Option<f64>,
    max_p95_ms: Option<f64>,
) -> Result<()> {
    for target in &suite.targets {
        let Some(result) = target.result.as_ref() else {
            continue;
        };
        if let Some(max_average_ms) = max_average_ms
            && let Some(avg_ms) = result.summary.avg_total_duration_ms
            && avg_ms > max_average_ms
        {
            bail!(
                "{} average latency {:.1} ms exceeded threshold {:.1} ms",
                target.label,
                avg_ms,
                max_average_ms
            );
        }
        if let Some(max_p95_ms) = max_p95_ms
            && let Some(p95_ms) = result.summary.p95_total_duration_ms
            && p95_ms > max_p95_ms
        {
            bail!(
                "{} p95 latency {:.1} ms exceeded threshold {:.1} ms",
                target.label,
                p95_ms,
                max_p95_ms
            );
        }
    }
    Ok(())
}

fn format_duration_ms(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.1} ms"))
        .unwrap_or_else(|| "n/a".to_string())
}

fn read_optional_utf8_file(path: Option<&Path>) -> Result<Option<String>> {
    path.map(|path| {
        std::fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context(format!("failed to read UTF-8 file {}", path.display())))
    })
    .transpose()
    .map(|value| value.filter(|value| !value.is_empty()))
}

fn read_client_identity_from_cli(cli: &Cli) -> Result<Option<ClientIdentityMaterial>> {
    if let Some(path) = cli.client_identity_file.as_deref() {
        return ClientIdentityMaterial::from_path(path).map(Some);
    }

    if let Some(bootstrap_path) = cli.bootstrap_file.as_deref() {
        let default_path = default_client_identity_path(bootstrap_path);
        if default_path.exists() {
            return ClientIdentityMaterial::from_path(&default_path).map(Some);
        }
    }

    Ok(None)
}

fn read_server_ca_override_from_cli(cli: &Cli) -> Result<Option<String>> {
    read_optional_utf8_file(cli.server_ca_pem_file.as_deref())
}

fn load_bootstrap_from_cli(cli: &Cli) -> Result<Option<ConnectionBootstrap>> {
    let Some(bootstrap_path) = cli.bootstrap_file.as_deref() else {
        return Ok(None);
    };
    let server_ca_override = read_server_ca_override_from_cli(cli)?;
    load_bootstrap_from_path(bootstrap_path, server_ca_override.as_deref()).map(Some)
}

fn load_bootstrap_from_path(
    bootstrap_path: &Path,
    server_ca_override: Option<&str>,
) -> Result<ConnectionBootstrap> {
    let mut bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
    if let Some(server_ca_override) = server_ca_override {
        bootstrap.trust_roots.public_api_ca_pem = Some(server_ca_override.to_string());
    }
    Ok(bootstrap)
}

fn default_client_identity_path(bootstrap_path: &Path) -> PathBuf {
    if let Some(stem) = bootstrap_path.file_stem() {
        let mut file_name = stem.to_os_string();
        file_name.push(".client-identity.json");
        return bootstrap_path.with_file_name(file_name);
    }
    bootstrap_path.with_file_name("ironmesh-client-identity.json")
}

fn unix_ts_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
