use crate::bootstrap_claims::BootstrapClaimBroker;
use crate::config::RendezvousServiceConfig;
use crate::presence::PresenceRegistry;
use crate::relay::RelayBroker;
use transport_sdk::RelayTunnelBroker;

#[derive(Clone)]
pub struct AppState {
    pub config: RendezvousServiceConfig,
    pub presence: PresenceRegistry,
    pub relay: RelayBroker,
    pub relay_tunnel: RelayTunnelBroker,
    pub bootstrap_claims: BootstrapClaimBroker,
}

impl AppState {
    pub fn new(config: RendezvousServiceConfig) -> Self {
        Self {
            config,
            presence: PresenceRegistry::new(),
            relay: RelayBroker::new(),
            relay_tunnel: RelayTunnelBroker::new(),
            bootstrap_claims: BootstrapClaimBroker::new(),
        }
    }
}
