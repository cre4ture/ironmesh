mod gnome;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use client_sdk::{ClientIdentityMaterial, ConnectionBootstrap, normalize_server_base_url};
use serde_json::json;
use std::path::PathBuf;
use sync_agent_core::{
    ConflictResolutionStrategy, FolderAgentRuntimeOptions, PathScope, StartupStateStore,
    cleanup_ironmesh_part_files, delete_conflict_copies, resolve_conflict_action, run_folder_agent,
};

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
#[command(name = "ironmesh-folder-agent")]
#[command(about = "OS-independent folder synchronization agent for Ironmesh")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long)]
    root_dir: PathBuf,
    #[arg(long, global = true)]
    state_root_dir: Option<PathBuf>,
    #[arg(long, global = true)]
    server_base_url: Option<String>,
    #[arg(long, global = true)]
    bootstrap_file: Option<PathBuf>,
    #[arg(long, global = true)]
    server_ca_pem_file: Option<PathBuf>,
    #[arg(long, global = true)]
    client_identity_file: Option<PathBuf>,
    #[arg(long, global = true)]
    prefix: Option<String>,
    #[arg(long, default_value_t = 64, global = true)]
    depth: usize,
    #[arg(long, default_value_t = 3000, global = true)]
    remote_refresh_interval_ms: u64,
    #[arg(long, default_value_t = 2000, global = true)]
    local_scan_interval_ms: u64,
    #[arg(long, default_value_t = false, global = true)]
    no_watch_local: bool,
    #[arg(long, default_value_t = false, global = true)]
    run_once: bool,
    /// Start a local web UI (example: `--ui-bind 127.0.0.1:3030`).
    #[arg(long, global = true)]
    ui_bind: Option<String>,
    /// Publish status for the GNOME Shell extension to the default runtime JSON file.
    #[arg(long, default_value_t = false, global = true)]
    publish_gnome_status: bool,
    /// Override the JSON path used by the GNOME Shell extension.
    #[arg(long, global = true)]
    gnome_status_file: Option<PathBuf>,
    /// How often to poll authenticated server endpoints for connection and replication status.
    #[arg(
        long,
        default_value_t = gnome::default_remote_status_poll_interval_ms(),
        global = true
    )]
    remote_status_poll_interval_ms: u64,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Inspect or resolve startup conflicts persisted in the local SQLite state store.
    Conflicts {
        #[command(subcommand)]
        command: ConflictCommand,
    },
    /// Remove partial download artifacts (`.ironmesh-part-*`) left behind by crashes/power loss.
    Cleanup {
        /// Only print the number of files that would be removed.
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// Install or inspect the native GNOME Shell indicator integration.
    Gnome {
        #[command(subcommand)]
        command: GnomeCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ConflictCommand {
    /// Print all currently persisted startup conflicts.
    List {
        #[arg(long, value_enum, default_value_t = ConflictListFormat::Json)]
        format: ConflictListFormat,
    },
    /// Clear a single conflict row (optionally also deleting related local conflict-copy files).
    Resolve {
        /// Relative path within the agent root directory.
        path: String,
        #[arg(long, value_enum, default_value_t = ConflictResolutionStrategy::KeepLocal)]
        strategy: ConflictResolutionStrategy,
        #[arg(long, default_value_t = false)]
        delete_conflict_copies: bool,
    },
    /// Clear all persisted conflict rows.
    Clear {
        #[arg(long, default_value_t = false)]
        delete_conflict_copies: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GnomeCommand {
    /// Copy the GNOME Shell extension into ~/.local/share/gnome-shell/extensions and try to enable it.
    InstallExtension,
    /// Print the JSON path consumed by the GNOME Shell extension.
    PrintStatusPath,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConflictListFormat {
    Json,
    Table,
}

struct ResolvedStartupTarget {
    connection_target: String,
    server_base_url: Option<String>,
    client_bootstrap_json: Option<String>,
    server_ca_pem: Option<String>,
}

fn main() -> Result<()> {
    common::logging::init_compact_tracing_default("info");
    let args = Args::parse();

    if let Some(command) = args.command.as_ref() {
        return run_command(&args, command);
    }

    run_agent(&args)
}

fn run_command(args: &Args, command: &Command) -> Result<()> {
    match command {
        Command::Cleanup { dry_run } => {
            let removed = cleanup_ironmesh_part_files(&args.root_dir, *dry_run)?;
            if *dry_run {
                println!("cleanup: would remove {removed} partial download artifacts");
            } else {
                println!("cleanup: removed {removed} partial download artifacts");
            }
            Ok(())
        }
        Command::Conflicts { command } => run_conflict_command(args, command),
        Command::Gnome { command } => run_gnome_command(args, command),
    }
}

fn run_gnome_command(args: &Args, command: &GnomeCommand) -> Result<()> {
    match command {
        GnomeCommand::InstallExtension => {
            let outcome = gnome::install_extension(true)?;
            println!(
                "gnome: installed extension {} to {}",
                gnome::GNOME_EXTENSION_UUID,
                outcome.install_dir.display()
            );
            if let Some(note) = outcome.enable_note {
                println!("gnome: {note}");
            }
            Ok(())
        }
        GnomeCommand::PrintStatusPath => {
            let path = match args.gnome_status_file.as_ref() {
                Some(path) => path.clone(),
                None => gnome::default_status_file_path()?,
            };
            println!("{}", path.display());
            Ok(())
        }
    }
}

fn run_conflict_command(args: &Args, command: &ConflictCommand) -> Result<()> {
    let scope = PathScope::new(args.prefix.clone());
    let target = resolve_startup_target(args)?;
    let state_store = match args.state_root_dir.as_deref() {
        Some(state_root_dir) => StartupStateStore::new_with_state_root(
            &args.root_dir,
            &scope,
            &target.connection_target,
            state_root_dir,
        ),
        None => StartupStateStore::new(&args.root_dir, &scope, &target.connection_target),
    };
    let client_identity_json =
        read_optional_client_identity_json(args.client_identity_file.as_deref())?;

    match command {
        ConflictCommand::List { format } => {
            let conflicts = state_store.load_conflicts()?;
            match format {
                ConflictListFormat::Json => {
                    for conflict in conflicts {
                        let parsed_details = serde_json::from_str::<serde_json::Value>(
                            conflict.details_json.as_str(),
                        )
                        .unwrap_or(serde_json::Value::String(conflict.details_json));
                        let line = json!({
                            "path": conflict.path,
                            "reason": conflict.reason,
                            "created_unix_ms": conflict.created_unix_ms,
                            "details": parsed_details,
                        });
                        println!("{}", line);
                    }
                }
                ConflictListFormat::Table => {
                    println!("{:<48}  {:<28}  created_unix_ms", "path", "reason");
                    for conflict in conflicts {
                        println!(
                            "{:<48}  {:<28}  {}",
                            conflict.path, conflict.reason, conflict.created_unix_ms
                        );
                    }
                }
            }

            Ok(())
        }
        ConflictCommand::Clear {
            delete_conflict_copies: delete_copies,
        } => {
            let conflicts = state_store.load_conflicts()?;
            let removed_rows = state_store.clear_conflicts()?;

            if *delete_copies {
                for conflict in &conflicts {
                    let _ = delete_conflict_copies(&args.root_dir, conflict.path.as_str());
                }
            }

            println!("conflicts: cleared {removed_rows} rows");
            Ok(())
        }
        ConflictCommand::Resolve {
            path,
            strategy,
            delete_conflict_copies: delete_copies,
        } => {
            let result = resolve_conflict_action(
                &args.root_dir,
                target.server_base_url.as_deref(),
                target.client_bootstrap_json.as_deref(),
                target.server_ca_pem.as_deref(),
                client_identity_json.as_deref(),
                &scope,
                &state_store,
                path.as_str(),
                *strategy,
                *delete_copies,
            )?;

            let path = result.path.as_str();
            let removed_rows = result.removed_conflict_rows;
            let removed_files = result.removed_conflict_copy_files;

            match result.strategy {
                ConflictResolutionStrategy::KeepLocal => {
                    if *delete_copies {
                        println!(
                            "conflicts: resolved {path} (keep-local), removed {removed_rows} rows, removed {removed_files} conflict copy files"
                        );
                    } else {
                        println!(
                            "conflicts: resolved {path} (keep-local), removed {removed_rows} rows"
                        );
                    }
                }
                ConflictResolutionStrategy::KeepRemote => {
                    if *delete_copies {
                        println!(
                            "conflicts: resolved {path} (keep-remote), removed {removed_rows} rows, removed {removed_files} conflict copy files"
                        );
                    } else {
                        println!(
                            "conflicts: resolved {path} (keep-remote), removed {removed_rows} rows"
                        );
                    }
                }
            }
            Ok(())
        }
    }
}

fn run_agent(args: &Args) -> Result<()> {
    let target = resolve_startup_target(args)?;
    let client_identity_json =
        read_optional_client_identity_json(args.client_identity_file.as_deref())?;
    let runtime_options = FolderAgentRuntimeOptions {
        root_dir: args.root_dir.clone(),
        state_root_dir: args.state_root_dir.clone(),
        local_tree_uri: None,
        server_base_url: target.server_base_url.clone(),
        client_bootstrap_json: target.client_bootstrap_json.clone(),
        server_ca_pem: target.server_ca_pem.clone(),
        client_identity_json: client_identity_json.clone(),
        prefix: args.prefix.clone(),
        depth: args.depth,
        remote_refresh_interval_ms: args.remote_refresh_interval_ms,
        local_scan_interval_ms: args.local_scan_interval_ms,
        no_watch_local: args.no_watch_local,
        run_once: args.run_once,
        ui_bind: args.ui_bind.clone(),
    };

    if args.publish_gnome_status {
        let status_file = match args.gnome_status_file.as_ref() {
            Some(path) => path.clone(),
            None => gnome::default_status_file_path()?,
        };
        let gnome_options = gnome::GnomeRunOptions {
            profile_label: gnome::derive_profile_label(args.prefix.as_deref(), &args.root_dir),
            root_dir: args.root_dir.clone(),
            connection_target: target.connection_target,
            server_base_url: target.server_base_url,
            client_bootstrap_json: target.client_bootstrap_json,
            server_ca_pem: target.server_ca_pem,
            client_identity_json,
            status_file,
            remote_status_poll_interval_ms: args.remote_status_poll_interval_ms,
        };
        return gnome::run_with_gnome_status(&runtime_options, &gnome_options);
    }

    run_folder_agent(&runtime_options)
}

fn resolve_startup_target(args: &Args) -> Result<ResolvedStartupTarget> {
    if args.server_base_url.is_some() && args.bootstrap_file.is_some() {
        bail!("use either --server-base-url or --bootstrap-file, not both");
    }

    let server_ca_override = read_optional_utf8_file(args.server_ca_pem_file.as_deref())?;
    if let Some(bootstrap_path) = args.bootstrap_file.as_deref() {
        let bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
        return Ok(ResolvedStartupTarget {
            connection_target: bootstrap.connection_target_label()?,
            server_base_url: None,
            client_bootstrap_json: Some(bootstrap.to_json_pretty()?),
            server_ca_pem: server_ca_override,
        });
    }

    let server_base_url = args
        .server_base_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("set either --server-base-url or --bootstrap-file"))?;
    let base_url = normalize_server_base_url(server_base_url)?;
    Ok(ResolvedStartupTarget {
        connection_target: base_url.to_string(),
        server_base_url: Some(base_url.to_string()),
        client_bootstrap_json: None,
        server_ca_pem: server_ca_override,
    })
}

fn read_optional_utf8_file(path: Option<&std::path::Path>) -> Result<Option<String>> {
    path.map(|path| {
        std::fs::read_to_string(path)
            .map(|value| value.trim().to_string())
            .map_err(anyhow::Error::from)
            .map_err(|error| error.context(format!("failed to read UTF-8 file {}", path.display())))
    })
    .transpose()
    .map(|value| value.filter(|value| !value.is_empty()))
}

fn read_optional_client_identity_json(path: Option<&std::path::Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let identity = ClientIdentityMaterial::from_path(path)?;
    Ok(Some(identity.to_json_pretty()?))
}
