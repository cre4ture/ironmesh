export type AdminSessionStatus = {
  login_required: boolean;
  authenticated: boolean;
  session_expires_at_unix: number | null;
  token_override_enabled: boolean;
};

export type ControlPlanePromotionImportResponse = {
  status: string;
  cluster_id: string;
  source_node_id: string;
  target_node_id: string;
  public_url: string;
  restart_required: boolean;
  signer_ca_cert_path: string;
  rendezvous_cert_path: string;
  rendezvous_key_path: string;
};
