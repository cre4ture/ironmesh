use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod content_fingerprint;
pub mod logging;
pub mod traced_mutex;
pub mod traced_rwlock;

pub type NodeId = Uuid;
pub type ClusterId = Uuid;
pub type DeviceId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageObjectMeta {
    pub key: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CacheEntry {
    pub key: String,
    pub size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthStatus {
    pub node_id: NodeId,
    pub role: String,
    pub online: bool,
    pub version: String,
    pub revision: String,
}
