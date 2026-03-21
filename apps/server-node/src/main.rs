use anyhow::Result;
use clap::Parser;

const GIT_VERSION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[derive(Debug, Parser)]
#[command(name = "server-node")]
#[command(about = "Ironmesh server node")]
#[command(version = GIT_VERSION)]
struct Cli {}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();
    server_node_sdk::run_from_env().await
}
