use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, IronMeshClient,
    build_http_client_from_pem, build_http_client_with_identity_from_pem,
    build_reqwest_client_from_pem, build_signed_request_headers, normalize_server_base_url,
};
use reqwest::{Method, RequestBuilder, Url};
use web_ui_backend::WebUiConfig;

#[derive(Debug, Parser)]
#[command(name = "ironmesh")]
#[command(about = "CLI client for ironmesh distributed storage")]
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

#[derive(Debug, Subcommand)]
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
    ServeWeb {
        #[arg(long, default_value = "127.0.0.1:8081")]
        bind: String,
    },
}

#[derive(Clone)]
struct ResolvedCliTarget {
    base_url: Url,
    server_ca_pem: Option<String>,
    client_identity: Option<ClientIdentityMaterial>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Enroll {
            output,
            device_id,
            label,
        } => enroll_from_bootstrap(
            &cli,
            output.as_ref(),
            device_id.as_deref(),
            label.as_deref(),
        ),
        Commands::CacheList => {
            let target = resolve_target(&cli)?;
            let client = build_client_node(&target)?;
            for entry in client.cache_entries().await {
                println!("{} ({} bytes)", entry.key, entry.size_bytes);
            }
            Ok(())
        }
        Commands::Put { key, value } => {
            let target = resolve_target(&cli)?;
            let client = build_client_node(&target)?;
            let object = client.put(key.clone(), Bytes::from(value.clone())).await?;
            println!("stored '{}' ({} bytes)", object.key, object.size_bytes);
            Ok(())
        }
        Commands::Get { key } => {
            let target = resolve_target(&cli)?;
            let client = build_client_node(&target)?;
            let payload = client.get_cached_or_fetch(key).await?;
            println!("{}", String::from_utf8_lossy(&payload));
            Ok(())
        }
        Commands::List { prefix, depth } => {
            let target = resolve_target(&cli)?;
            let sdk = build_authenticated_sdk(&target)?;
            let value = sdk.store_index_blocking(prefix.as_deref(), (*depth).max(1), None)?;
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(())
        }
        Commands::Health => {
            let target = resolve_target(&cli)?;
            print_json_endpoint(&target, "/health").await
        }
        Commands::ClusterStatus => {
            let target = resolve_target(&cli)?;
            print_json_endpoint(&target, "/cluster/status").await
        }
        Commands::Nodes => {
            let target = resolve_target(&cli)?;
            print_json_endpoint(&target, "/cluster/nodes").await
        }
        Commands::ReplicationPlan => {
            let target = resolve_target(&cli)?;
            print_json_endpoint(&target, "/cluster/replication/plan").await
        }
        Commands::ServeWeb { bind } => {
            let target = resolve_target(&cli)?;
            let bind_addr: SocketAddr = bind.parse()?;
            let mut web_ui_config = WebUiConfig::new(target.base_url.as_str().to_string())
                .with_service_name("cli-client-web");
            if let Some(server_ca_pem) = target.server_ca_pem.as_ref() {
                web_ui_config = web_ui_config.with_server_ca_pem(server_ca_pem.clone());
            }
            if let Some(client_identity) = target.client_identity.clone() {
                web_ui_config = web_ui_config.with_client_identity(client_identity);
            }
            let app = web_ui_backend::router(web_ui_config);

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
}

fn enroll_from_bootstrap(
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
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("enroll requires --bootstrap-file"))?;
    let bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
    let enrolled = bootstrap.enroll_blocking(device_id, label)?;
    let identity = enrolled.client_identity_material()?;
    let output_path = output
        .cloned()
        .or_else(|| cli.client_identity_file.clone())
        .unwrap_or_else(|| default_client_identity_path(bootstrap_path));
    identity.write_to_path(&output_path)?;

    println!("enrolled device {}", identity.device_id);
    println!("cluster {}", identity.cluster_id);
    println!("server {}", enrolled.server_base_url);
    println!("identity {}", output_path.display());
    Ok(())
}

fn resolve_target(cli: &Cli) -> Result<ResolvedCliTarget> {
    if cli.bootstrap_file.is_some() && cli.server_url.is_some() {
        bail!("use either --bootstrap-file or --server-url, not both");
    }

    let server_ca_override = read_optional_utf8_file(cli.server_ca_pem_file.as_deref())?;
    let client_identity = cli
        .client_identity_file
        .as_deref()
        .map(ClientIdentityMaterial::from_path)
        .transpose()?;

    if let Some(bootstrap_path) = cli.bootstrap_file.as_deref() {
        let bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
        let resolved = bootstrap.resolve_blocking()?;
        let base_url = Url::parse(&resolved.server_base_url)
            .with_context(|| format!("invalid resolved server URL {}", resolved.server_base_url))?;
        let server_ca_pem = server_ca_override
            .or(resolved.server_ca_pem)
            .or(resolved.cluster_ca_pem);
        return Ok(ResolvedCliTarget {
            base_url,
            server_ca_pem,
            client_identity,
        });
    }

    let server_url = cli
        .server_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("set either --bootstrap-file or --server-url"))?;
    Ok(ResolvedCliTarget {
        base_url: normalize_server_base_url(server_url)?,
        server_ca_pem: server_ca_override,
        client_identity,
    })
}

fn build_authenticated_sdk(target: &ResolvedCliTarget) -> Result<IronMeshClient> {
    match target.client_identity.as_ref() {
        Some(identity) => build_http_client_with_identity_from_pem(
            target.server_ca_pem.as_deref(),
            target.base_url.as_str(),
            identity,
        ),
        None => build_http_client_from_pem(
            target.server_ca_pem.as_deref(),
            target.base_url.as_str(),
            &None,
        ),
    }
}

fn build_client_node(target: &ResolvedCliTarget) -> Result<ClientNode> {
    Ok(ClientNode::with_client(build_authenticated_sdk(target)?))
}

async fn print_json_endpoint(target: &ResolvedCliTarget, path: &str) -> Result<()> {
    let value = fetch_server_json(target, path).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn fetch_server_json(target: &ResolvedCliTarget, path: &str) -> Result<serde_json::Value> {
    let client = build_reqwest_client_from_pem(target.server_ca_pem.as_deref())?;
    let url = endpoint_url(&target.base_url, path)?;
    let response = apply_optional_request_auth(
        client.get(url.clone()),
        Method::GET,
        &url,
        target.client_identity.as_ref(),
    )?
    .send()
    .await
    .context("failed to contact server")?
    .error_for_status()
    .context("server returned error status")?;

    response
        .json::<serde_json::Value>()
        .await
        .context("failed to decode server response")
}

fn apply_optional_request_auth(
    request: RequestBuilder,
    method: Method,
    url: &Url,
    client_identity: Option<&ClientIdentityMaterial>,
) -> Result<RequestBuilder> {
    let Some(client_identity) = client_identity else {
        return Ok(request);
    };

    let headers = build_signed_request_headers(
        client_identity,
        method.as_str(),
        &url_path_and_query(url),
        unix_ts(),
        None,
    )?;
    Ok(headers.apply_to_reqwest(request))
}

fn endpoint_url(base_url: &Url, path: &str) -> Result<Url> {
    base_url
        .join(path.trim_start_matches('/'))
        .with_context(|| format!("failed to build endpoint URL from {base_url} and {path}"))
}

fn url_path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn default_client_identity_path(bootstrap_path: &Path) -> PathBuf {
    if let Some(stem) = bootstrap_path.file_stem() {
        let mut file_name = stem.to_os_string();
        file_name.push(".client-identity.json");
        return bootstrap_path.with_file_name(file_name);
    }
    bootstrap_path.with_file_name("ironmesh-client-identity.json")
}
