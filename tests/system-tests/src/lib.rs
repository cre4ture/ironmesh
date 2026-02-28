#![cfg(test)]

mod client_sdk_test;
mod framework;
mod generic_test;

#[cfg(windows)]
mod framework_win;

#[cfg(windows)]
mod cfapi_monitor_test;
