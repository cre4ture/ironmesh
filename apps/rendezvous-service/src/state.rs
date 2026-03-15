use crate::config::RendezvousServiceConfig;
use crate::presence::PresenceRegistry;

#[derive(Clone)]
pub struct AppState {
    pub config: RendezvousServiceConfig,
    pub presence: PresenceRegistry,
}

impl AppState {
    pub fn new(config: RendezvousServiceConfig) -> Self {
        Self {
            config,
            presence: PresenceRegistry::new(),
        }
    }
}
