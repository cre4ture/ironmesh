#![cfg(test)]

mod client_sdk_test;
mod framework;
mod cluster_test;
#[path = "web-ui-backend_test.rs"]
mod web_ui_backend_test;

#[cfg(windows)]
mod framework_win;

#[cfg(windows)]
mod cfapi_monitor_test;

#[cfg(target_os = "linux")]
#[path = "adapter-linux-fuse_test.rs"]
mod adapter_linux_fuse_test;

#[path = "folder_agent_test.rs"]
mod folder_agent_test;
