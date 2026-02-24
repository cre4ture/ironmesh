#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    adapter_windows_cfapi::cli::cli_main()
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    adapter_linux_fuse::mount_main::mount_main()
}
