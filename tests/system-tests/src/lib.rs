#![cfg(test)]

mod client_sdk_test;
mod framework;
mod generic_test;

#[cfg(windows)]
mod framework_win;

#[cfg(windows)]
mod cfapi_monitor_test;

#[cfg(target_os = "linux")]
#[path = "adapter-linux-fuse_test.rs"]
mod adapter_linux_fuse_test;
