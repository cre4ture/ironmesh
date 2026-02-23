#[cfg(feature = "cfapi-runtime")]
use adapter_windows_cfapi::runtime::{SyncRootRegistration, register_sync_root};
#[cfg(feature = "cfapi-runtime")]
use clap::Parser;

#[cfg(feature = "cfapi-runtime")]
#[derive(Debug, Parser)]
#[command(name = "adapter-windows-cfapi-register")]
#[command(about = "Register a Windows sync root")]
struct Args {
    #[arg(long)]
    sync_root_id: String,
    #[arg(long)]
    display_name: String,
    #[arg(long)]
    root_path: String,
}

#[cfg(feature = "cfapi-runtime")]
fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let registration =
        SyncRootRegistration::new(args.sync_root_id, args.display_name, args.root_path);
    register_sync_root(&registration)
}

#[cfg(not(feature = "cfapi-runtime"))]
fn main() {
    eprintln!("binary requires the `cfapi-runtime` feature");
    std::process::exit(1);
}
