use std::net::SocketAddr;

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use client_sdk::ClientNode;
use reqwest::Client;
use web_ui_backend::WebUiConfig;

#[derive(Debug, Parser)]
#[command(name = "ironmesh")]
#[command(about = "CLI client for ironmesh distributed storage")]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_url: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
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
    let client = ClientNode::new(&cli.server_url);
    let http = Client::new();

    match cli.command {
        Commands::Put { key, value } => {
            let object = client.put(key, Bytes::from(value)).await?;
            println!("stored '{}' ({} bytes)", object.key, object.size_bytes);
        }
        Commands::Get { key } => {
            let payload = client.get_cached_or_fetch(&key).await?;
            println!("{}", String::from_utf8_lossy(&payload));
        }
        Commands::List { prefix, depth } => {
            let value = http
                .get(format!(
                    "{}/store/index",
                    cli.server_url.trim_end_matches('/')
                ))
                .query(&[("depth", depth.to_string())])
                .query(&prefix.as_ref().map(|value| ("prefix", value.as_str())))
                .send()
                .await
                .context("failed to request store index")?
                .error_for_status()
                .context("store index request failed")?
                .json::<serde_json::Value>()
                .await
                .context("failed to decode store index response")?;
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Commands::Health => {
            print_json_endpoint(&http, &cli.server_url, "/health").await?;
        }
        Commands::ClusterStatus => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/status").await?;
        }
        Commands::Nodes => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/nodes").await?;
        }
        Commands::ReplicationPlan => {
            print_json_endpoint(&http, &cli.server_url, "/cluster/replication/plan").await?;
        }
        Commands::CacheList => {
            for entry in client.cache_entries().await {
                println!("{} ({} bytes)", entry.key, entry.size_bytes);
            }
        }
        Commands::ServeWeb { bind } => {
            let bind_addr: SocketAddr = bind.parse()?;
            let app = web_ui_backend::router(
                WebUiConfig::new(cli.server_url.clone()).with_service_name("cli-client-web"),
            );

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}

async fn print_json_endpoint(http: &Client, server_url: &str, path: &str) -> Result<()> {
    let value = fetch_server_json(http, server_url, path).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn fetch_server_json(
    http: &Client,
    server_url: &str,
    path: &str,
) -> Result<serde_json::Value> {
    let url = format!("{}{}", server_url.trim_end_matches('/'), path);
    let value = http
        .get(url)
        .send()
        .await
        .context("failed to contact server")?
        .error_for_status()
        .context("server returned error status")?
        .json::<serde_json::Value>()
        .await
        .context("failed to decode server response")?;
    Ok(value)
}
