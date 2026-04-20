use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use rendezvous_server::{
    RendezvousAppState, RendezvousClientCa, RendezvousMtlsConfig, RendezvousServerConfig,
    RendezvousServerTlsIdentity, serve as serve_rendezvous,
};

#[derive(Debug, Clone)]
pub(crate) struct EmbeddedRendezvousConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub client_ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl EmbeddedRendezvousConfig {
    fn server_config(&self) -> RendezvousServerConfig {
        RendezvousServerConfig {
            bind_addr: self.bind_addr,
            public_url: self.public_url.clone(),
            relay_public_urls: vec![self.public_url.clone()],
            mtls: Some(RendezvousMtlsConfig {
                client_ca: RendezvousClientCa::File {
                    cert_path: self.client_ca_cert_path.clone(),
                },
                server_identity: RendezvousServerTlsIdentity::Files {
                    cert_path: self.cert_path.clone(),
                    key_path: self.key_path.clone(),
                },
            }),
        }
    }
}

pub(crate) async fn run_listener(config: EmbeddedRendezvousConfig) -> Result<()> {
    serve_rendezvous(RendezvousAppState::new(config.server_config())).await
}
