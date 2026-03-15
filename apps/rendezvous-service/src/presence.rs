use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use transport_sdk::rendezvous::{PresenceEntry, PresenceRegistration};

use crate::auth::peer_identity_key;

#[derive(Clone, Default)]
pub struct PresenceRegistry {
    entries: Arc<Mutex<HashMap<String, PresenceEntry>>>,
}

impl PresenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, registration: PresenceRegistration) -> PresenceEntry {
        let entry = PresenceEntry {
            updated_at_unix: registration.connected_at_unix,
            registration,
        };
        let key = peer_identity_key(&entry.registration.identity);
        let mut entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.insert(key, entry.clone());
        entry
    }

    pub fn list(&self) -> Vec<PresenceEntry> {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        let mut values = entries.values().cloned().collect::<Vec<_>>();
        values.sort_by(|left, right| {
            peer_identity_key(&left.registration.identity)
                .cmp(&peer_identity_key(&right.registration.identity))
        });
        values
    }

    pub fn len(&self) -> usize {
        let entries = self
            .entries
            .lock()
            .expect("presence registry lock poisoned");
        entries.len()
    }
}
