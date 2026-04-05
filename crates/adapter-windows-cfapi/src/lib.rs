#![cfg(windows)]

pub mod adapter;
pub mod auth;
pub mod cfapi;
pub(crate) mod cfapi_safe_wrap;
pub mod cli;
pub(crate) mod close_upload;
pub mod connection_config;
pub(crate) mod content_fingerprint;
pub mod helpers;
pub mod live;
pub(crate) mod local_state;
pub mod monitor;
pub mod placeholder_metadata;
pub mod register;
pub mod runtime;
pub mod snapshot_cache;
pub mod sync_root_identity;
