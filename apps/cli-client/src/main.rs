use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use client_sdk::{
    ClientIdentityMaterial, ClientNode, ConnectionBootstrap, IronMeshClient,
    build_http_client_from_pem, build_http_client_with_identity_from_pem,
    normalize_server_base_url,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use web_ui_backend::WebUiConfig;

#[derive(Debug, Clone, Parser)]
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
    ServeWeb {
        #[arg(long, default_value = "127.0.0.1:8081")]
        bind: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
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
            let value = sdk.store_index_blocking(prefix.as_deref(), (*depth).max(1), None)?;
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
        Commands::ServeWeb { bind } => {
            let client = build_authenticated_sdk_from_cli(&cli).await?;
            let bind_addr: SocketAddr = bind.parse()?;
            let web_ui_config =
                WebUiConfig::from_client(client).with_service_name("cli-client-web");
            let app = web_ui_backend::router(web_ui_config);

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
            Ok(())
        }
    }
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

    let enrolled =
        tokio::task::spawn_blocking(move || -> Result<(ClientIdentityMaterial, String)> {
            let bootstrap = ConnectionBootstrap::from_path(&bootstrap_path)?;
            let enrolled = bootstrap.enroll_blocking(device_id.as_deref(), label.as_deref())?;
            let identity = enrolled.client_identity_material()?;
            identity.write_to_path(&output_path)?;
            Ok((identity, enrolled.server_base_url))
        })
        .await
        .context("enroll task panicked")??;

    println!("enrolled device {}", enrolled.0.device_id);
    println!("cluster {}", enrolled.0.cluster_id);
    println!("server {}", enrolled.1);
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
    cli.client_identity_file
        .as_deref()
        .map(ClientIdentityMaterial::from_path)
        .transpose()
}

fn read_server_ca_override_from_cli(cli: &Cli) -> Result<Option<String>> {
    read_optional_utf8_file(cli.server_ca_pem_file.as_deref())
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
