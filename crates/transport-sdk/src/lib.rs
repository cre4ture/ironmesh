pub mod bootstrap;
pub mod candidates;
pub mod http_connector;
pub mod identity;
pub mod peer;
pub mod relay;
pub mod rendezvous;
pub mod request_auth;
pub mod session;

pub use bootstrap::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, CLIENT_BOOTSTRAP_VERSION,
    ClientBootstrap, NodeBootstrap, RelayMode,
};
pub use candidates::{CandidateKind, ConnectionCandidate, rank_candidates};
pub use http_connector::{HttpRouteKind, TransportHttpClientConfig, TransportHttpRequestTarget};
pub use identity::{
    ClientEnrollmentRequest, ClientIdentityMaterial, IssuedClientIdentity, next_device_id,
};
pub use peer::{PeerIdentity, PeerTransportClient, PeerTransportClientConfig};
pub use relay::{
    PendingRelayHttpRequest, RelayHttpHeader, RelayHttpPollRequest, RelayHttpPollResponse,
    RelayHttpRequest, RelayHttpResponse, RelayTicket, RelayTicketRequest,
    encode_optional_body_base64,
};
pub use rendezvous::{
    PresenceEntry, PresenceListResponse, PresenceRegistration, RegisterPresenceResponse,
    RendezvousClientConfig, RendezvousControlClient, TransportCapability,
};
pub use request_auth::{
    HEADER_AUTH_NONCE, HEADER_AUTH_SIGNATURE, HEADER_AUTH_TIMESTAMP, HEADER_CLUSTER_ID,
    HEADER_CREDENTIAL_FINGERPRINT, HEADER_DEVICE_ID, SignedRequestHeaders,
    build_signed_request_headers, credential_fingerprint, next_auth_nonce,
    verify_signed_request_headers,
};
pub use session::{
    SessionPreference, TransportPathKind, TransportSessionPlan, TransportSessionRequest,
    select_session_plan,
};
