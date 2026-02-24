#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    adapter_windows_cfapi::serve::serve_main()
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    adapter_linux_fuse::mount_main::mount_main()
}
