use anyhow::Result;
use clap::Parser;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    fallback = "Build revision: unknown",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    fallback = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: unknown"),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

#[derive(Debug, Parser)]
#[command(name = "ironmesh-server-node")]
#[command(about = "BerryKeep server node")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Cli {}

fn main() -> Result<()> {
    Cli::parse();

    let use_current_thread =
        std::env::var_os("IRONMESH_TOKIO_CURRENT_THREAD").is_some_and(|v| v != "0");

    let runtime = if use_current_thread {
        eprintln!(
            "ironmesh-server-node: using Tokio current-thread runtime because \
IRONMESH_TOKIO_CURRENT_THREAD is set; this avoids worker-pool overhead on \
single-core hosts"
        );
        tokio::runtime::Builder::new_current_thread()
    } else {
        tokio::runtime::Builder::new_multi_thread()
    }
    .enable_all()
    .build()?;

    runtime.block_on(server_node_sdk::run_from_env())
}
