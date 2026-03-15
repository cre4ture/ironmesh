use transport_sdk::peer::PeerIdentity;

pub fn peer_identity_key(identity: &PeerIdentity) -> String {
    match identity {
        PeerIdentity::Node(node_id) => format!("node:{node_id}"),
        PeerIdentity::Device(device_id) => format!("device:{device_id}"),
    }
}
