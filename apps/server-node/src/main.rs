use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    server_node_sdk::run_from_env().await
}
