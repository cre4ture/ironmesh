use crate::bootstrap_claims::BootstrapClaimBroker;
use crate::config::RendezvousServiceConfig;
use crate::presence::PresenceRegistry;
use crate::relay::RelayBroker;

#[derive(Clone)]
pub struct AppState {
    pub config: RendezvousServiceConfig,
    pub presence: PresenceRegistry,
    pub relay: RelayBroker,
    pub bootstrap_claims: BootstrapClaimBroker,
}

impl AppState {
    pub fn new(config: RendezvousServiceConfig) -> Self {
        Self {
            config,
            presence: PresenceRegistry::new(),
            relay: RelayBroker::new(),
            bootstrap_claims: BootstrapClaimBroker::new(),
        }
    }
}
