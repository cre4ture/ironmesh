#![cfg_attr(windows, windows_subsystem = "windows")]

use anyhow::{Context, Result};
use desktop_client_config::{
    ManagedInstanceStore, default_instance_store_path, default_launch_report_path,
    launch_enabled_instances, migrate_legacy_state_paths, package_root_from_current_exe,
    save_launch_report,
};

fn main() -> Result<()> {
    let package_root = package_root_from_current_exe()?;
    migrate_legacy_state_paths()?;
    let instance_store_path = default_instance_store_path();
    let launch_report_path = default_launch_report_path();

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