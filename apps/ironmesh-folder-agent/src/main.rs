use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use client_sdk::{ClientIdentityMaterial, ConnectionBootstrap, normalize_server_base_url};
use reqwest::Url;
use serde_json::json;
use std::path::PathBuf;
use sync_agent_core::{
    ConflictResolutionStrategy, FolderAgentRuntimeOptions, PathScope, StartupStateStore,
    cleanup_ironmesh_part_files, delete_conflict_copies, resolve_conflict_action, run_folder_agent,
};

#[derive(Debug, Parser)]
#[command(name = "ironmesh-folder-agent")]
#[command(about = "OS-independent folder synchronization agent for Ironmesh")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long)]
    root_dir: PathBuf,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ConflictListFormat {
    Json,
    Table,
}

struct ResolvedStartupTarget {
    base_url: Url,
    server_ca_pem: Option<String>,
}

fn main() -> Result<()> {
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
    }
}

fn run_conflict_command(args: &Args, command: &ConflictCommand) -> Result<()> {
    let scope = PathScope::new(args.prefix.clone());
    let target = resolve_startup_target(args)?;
    let base_url = target.base_url;
    let state_store = StartupStateStore::new(&args.root_dir, &scope, base_url.as_str());
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
                base_url.as_str(),
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
    run_folder_agent(&FolderAgentRuntimeOptions {
        root_dir: args.root_dir.clone(),
        local_tree_uri: None,
        server_base_url: target.base_url.to_string(),
        server_ca_pem: target.server_ca_pem,
        client_identity_json: read_optional_client_identity_json(
            args.client_identity_file.as_deref(),
        )?,
        prefix: args.prefix.clone(),
        depth: args.depth,
        remote_refresh_interval_ms: args.remote_refresh_interval_ms,
        local_scan_interval_ms: args.local_scan_interval_ms,
        no_watch_local: args.no_watch_local,
        run_once: args.run_once,
        ui_bind: args.ui_bind.clone(),
    })
}

fn resolve_startup_target(args: &Args) -> Result<ResolvedStartupTarget> {
    if args.server_base_url.is_some() && args.bootstrap_file.is_some() {
        bail!("use either --server-base-url or --bootstrap-file, not both");
    }

    let server_ca_override = read_optional_utf8_file(args.server_ca_pem_file.as_deref())?;
    if let Some(bootstrap_path) = args.bootstrap_file.as_deref() {
        let bootstrap = ConnectionBootstrap::from_path(bootstrap_path)?;
        let resolved = bootstrap.resolve_blocking()?;
        return Ok(ResolvedStartupTarget {
            base_url: normalize_server_base_url(&resolved.server_base_url)?,
            server_ca_pem: server_ca_override
                .or(resolved.server_ca_pem)
                .or(resolved.cluster_ca_pem),
        });
    }

    let server_base_url = args
        .server_base_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("set either --server-base-url or --bootstrap-file"))?;
    Ok(ResolvedStartupTarget {
        base_url: normalize_server_base_url(server_base_url)?,
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
