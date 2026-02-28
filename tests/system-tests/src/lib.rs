#![cfg(test)]

mod framework;

#[cfg(windows)]
mod framework_win;

#[cfg(windows)]
mod cfapi_monitor_test;

mod generic_test;
