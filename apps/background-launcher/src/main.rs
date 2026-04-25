#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{Context, Result};
use desktop_client_config::{
    CONFIG_APP_EXE, ManagedInstanceStore, default_instance_store_path, default_launch_report_path,
    launch_enabled_instances, migrate_legacy_state_paths, package_root_from_current_exe,
    save_launch_report,
};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    let package_root = package_root_from_current_exe()?;
    migrate_legacy_state_paths()?;
    let instance_store_path = default_instance_store_path();
    let launch_report_path = default_launch_report_path();

    match spawn_config_app_background(&package_root) {
        Ok(()) => return Ok(()),
        Err(error) => {
            eprintln!(
                "background-launcher: failed to start config app, launching services directly: {error:#}"
            );
        }
    }

    let store = ManagedInstanceStore::load_or_default(&instance_store_path).with_context(|| {
        format!(
            "failed loading managed background instances from {}",
            instance_store_path.display()
        )
    })?;

    let report = launch_enabled_instances(&store, &package_root);
    save_launch_report(&launch_report_path, &report).with_context(|| {
        format!(
            "failed writing background launch report to {}",
            launch_report_path.display()
        )
    })?;

    Ok(())
}

fn spawn_config_app_background(package_root: &std::path::Path) -> Result<()> {
    let mut spawn_errors = Vec::new();
    for config_app_path in config_app_candidates(package_root) {
        let mut command = Command::new(&config_app_path);
        command
            .arg("--background")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_background_command(&mut command);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                spawn_errors.push(format!("{}: {error}", config_app_path.display()));
                continue;
            }
        };
        thread::sleep(Duration::from_millis(500));
        if let Some(status) = child.try_wait().with_context(|| {
            format!(
                "failed checking config app background process {}",
                config_app_path.display()
            )
        })? {
            spawn_errors.push(format!(
                "{}: exited immediately with {status}",
                config_app_path.display()
            ));
            continue;
        }
        return Ok(());
    }

    anyhow::bail!(
        "failed spawning config app background process: {}",
        spawn_errors.join("; ")
    )
}

fn config_app_candidates(package_root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let direct = package_root.join(CONFIG_APP_EXE);
    #[cfg(windows)]
    {
        if is_windows_apps_package_root(package_root)
            && let Some(alias_path) = windows_app_execution_alias_path(CONFIG_APP_EXE)
            && alias_path != direct
        {
            return vec![alias_path, direct];
        }
    }
    vec![direct]
}

#[cfg(windows)]
fn is_windows_apps_package_root(path: &std::path::Path) -> bool {
    path.components().any(|component| {
        component
            .as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case("WindowsApps")
    })
}

#[cfg(windows)]
fn windows_app_execution_alias_path(executable_name: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .map(|path| {
            path.join("Microsoft")
                .join("WindowsApps")
                .join(executable_name)
        })
}

#[cfg(windows)]
fn configure_background_command(command: &mut Command) {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;
    command.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn configure_background_command(_command: &mut Command) {}
