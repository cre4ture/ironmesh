use anyhow::Result;
use clap::Parser;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

#[derive(Debug, Parser)]
#[command(name = "ironmesh-server-node")]
#[command(about = "Ironmesh server node")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Cli {}

#[tokio::main]
async fn main() -> Result<()> {
    Cli::parse();
    server_node_sdk::run_from_env().await
}
