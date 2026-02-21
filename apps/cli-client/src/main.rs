use std::net::SocketAddr;

use anyhow::Result;
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use client_sdk::ClientNode;

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

    match cli.command {
        Commands::Put { key, value } => {
            let object = client.put(key, Bytes::from(value)).await?;
            println!("stored '{}' ({} bytes)", object.key, object.size_bytes);
        }
        Commands::Get { key } => {
            let payload = client.get_cached_or_fetch(&key).await?;
            println!("{}", String::from_utf8_lossy(&payload));
        }
        Commands::CacheList => {
            for entry in client.cache_entries().await {
                println!("{} ({} bytes)", entry.key, entry.size_bytes);
            }
        }
        Commands::ServeWeb { bind } => {
            let bind_addr: SocketAddr = bind.parse()?;
            let app = Router::new()
                .route("/", get(|| async { Html(web_ui::app_html()) }))
                .route(
                    "/api/ping",
                    get(|| async {
                        Json(serde_json::json!({
                            "ok": true,
                            "service": "cli-client-web"
                        }))
                    }),
                );

            println!("web interface at http://{bind_addr}");
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
