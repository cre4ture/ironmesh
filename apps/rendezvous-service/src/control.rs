use serde::{Deserialize, Serialize};

use crate::presence::PresenceEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterPresenceResponse {
    pub accepted: bool,
    pub updated_at_unix: u64,
    pub entry: PresenceEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceListResponse {
    pub registered_endpoints: usize,
    pub entries: Vec<PresenceEntry>,
}
