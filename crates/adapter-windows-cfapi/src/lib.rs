#![cfg(windows)]

pub mod adapter;
pub mod auth;
pub mod cfapi;
pub(crate) mod cfapi_safe_wrap;
pub mod cli;
pub(crate) mod close_upload;
pub mod connection_config;
pub mod helpers;
pub mod live;
pub mod monitor;
pub mod register;
pub mod runtime;
pub mod snapshot_cache;
pub mod serve;
