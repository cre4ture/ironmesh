import type { VersionGraphResponse } from "../client-ui/types";
import type { StoreIndexEntry, StoreIndexResponse, StoreListView } from "../shared/store-index";

export type AdminSessionStatus = {
  login_required: boolean;
  authenticated: boolean;
  session_expires_at_unix: number | null;
  token_override_enabled: boolean;
};

export type AdminSnapshotSummary = {
  id: string;
} & Record<string, unknown>;

export type AdminStoreEntry = StoreIndexEntry;

export type AdminStoreListResponse = StoreIndexResponse;

export type AdminStoreGetResponse = {
  key: string;
  snapshot?: string | null;
  version?: string | null;
  value: string;
  truncated?: boolean;
  total_size_bytes?: number;
  preview_size_bytes?: number | null;
};

export type AdminVersionGraphResponse = VersionGraphResponse;

export type { StoreListView };

export type ClusterSummary = {
  local_node_id: string;
  total_nodes: number;
  online_nodes: number;
  offline_nodes: number;
  policy: {
    replication_factor: number;
    min_distinct_labels: Record<string, number>;
    accepted_over_replication_items: number;
  };
};

export type NodeDescriptor = {
  node_id: string;
  reachability: {
    public_api_url?: string | null;
    peer_api_url?: string | null;
    relay_required: boolean;
  };
  capabilities: {
    public_api: boolean;
    peer_api: boolean;
    relay_tunnel: boolean;
  };
  labels: Record<string, string>;
  capacity_bytes: number;
  free_bytes: number;
  storage_stats?: StorageStatsSample | null;
  last_heartbeat_unix: number;
  status: "online" | "offline";
};

export type ReplicationPlan = {
  generated_at_unix: number;
  under_replicated: number;
  over_replicated: number;
  cleanup_deferred_items: number;
  cleanup_deferred_extra_nodes: number;
  items: Array<{
    key: string;
    desired_nodes: string[];
    current_nodes: string[];
    missing_nodes: string[];
    extra_nodes: string[];
    cleanup_option: "none" | "deferred_within_tolerance" | "recommended";
    deferred_extra_nodes: number;
  }>;
};

export type ReplicationRepairScope = "local" | "cluster";

export type RepairRunTrigger =
  | "manual_request"
  | "startup_repair"
  | "background_audit"
  | "autonomous_post_write"
  | "peer_cluster_request";

export type RepairRunStatus = "completed" | "skipped_no_gaps";

export type RepairActivityState = "idle" | "scheduled" | "running";

export type StartupRepairStatus =
  | "disabled"
  | "scheduled"
  | "running"
  | "skipped_no_gaps"
  | "completed";

export type RepairPlanSummary = {
  generated_at_unix: number;
  under_replicated: number;
  over_replicated: number;
  cleanup_deferred_items: number;
  cleanup_deferred_extra_nodes: number;
  item_count: number;
};

export type RepairRunSummary = {
  attempted_transfers: number;
  successful_transfers: number;
  failed_transfers: number;
  skipped_items: number;
  skipped_backoff: number;
  skipped_max_retries: number;
  skipped_detail_count: number;
  last_error?: string | null;
  nodes_contacted?: number | null;
  failed_nodes?: number | null;
};

export type RepairRunRecord = {
  run_id: string;
  reporting_node_id: string;
  scope: ReplicationRepairScope;
  trigger: RepairRunTrigger;
  status: RepairRunStatus;
  started_at_unix: number;
  finished_at_unix: number;
  duration_ms: number;
  plan_summary: RepairPlanSummary;
  summary?: RepairRunSummary | null;
  report?: Record<string, unknown> | null;
};

export type RepairActiveRun = {
  run_id: string;
  scope: ReplicationRepairScope;
  trigger: RepairRunTrigger;
  started_at_unix: number;
};

export type RepairHistoryResponse = {
  retention_secs: number;
  runs: RepairRunRecord[];
};

export type RepairActivityStatusResponse = {
  state: RepairActivityState;
  startup_status: StartupRepairStatus;
  active_runs: RepairActiveRun[];
  latest_run?: RepairRunRecord | null;
};

export type DataScrubScope = "local" | "cluster";

export type DataScrubRunTrigger =
  | "manual_request"
  | "scheduled"
  | "peer_cluster_request";

export type DataScrubRunStatus = "clean" | "issues_detected" | "failed";

export type DataScrubActivityState = "idle" | "running";

export type DataScrubIssueKind =
  | "manifest_missing"
  | "manifest_unreadable"
  | "manifest_invalid"
  | "manifest_hash_mismatch"
  | "manifest_key_mismatch"
  | "manifest_size_mismatch"
  | "chunk_missing"
  | "chunk_unreadable"
  | "chunk_size_mismatch"
  | "chunk_hash_mismatch";

export type DataScrubIssue = {
  kind: DataScrubIssueKind;
  key?: string | null;
  object_id?: string | null;
  version_id?: string | null;
  manifest_hash?: string | null;
  chunk_hash?: string | null;
  detail: string;
};

export type DataScrubReport = {
  current_keys_scanned: number;
  version_indexes_scanned: number;
  version_records_scanned: number;
  manifests_scanned: number;
  chunks_scanned: number;
  bytes_scanned: number;
  issue_count: number;
  sampled_issue_count: number;
  issue_sample_truncated: boolean;
  issues: DataScrubIssue[];
};

export type DataScrubActiveRun = {
  run_id: string;
  trigger: DataScrubRunTrigger;
  started_at_unix: number;
};

export type DataScrubRunRecord = {
  run_id: string;
  reporting_node_id: string;
  trigger: DataScrubRunTrigger;
  status: DataScrubRunStatus;
  started_at_unix: number;
  finished_at_unix: number;
  duration_ms: number;
  summary: DataScrubReport;
  last_error?: string | null;
};

export type DataScrubHistoryResponse = {
  retention_secs: number;
  runs: DataScrubRunRecord[];
};

export type DataScrubActivityStatusResponse = {
  state: DataScrubActivityState;
  enabled: boolean;
  interval_secs: number;
  retention_secs: number;
  active_runs: DataScrubActiveRun[];
  latest_run?: DataScrubRunRecord | null;
};

export type DataScrubClusterNodeStatus = {
  node_id: string;
  state: DataScrubActivityState;
  enabled: boolean;
  interval_secs: number;
  retention_secs: number;
  active_runs: DataScrubActiveRun[];
  latest_run?: DataScrubRunRecord | null;
};

export type DataScrubClusterSkippedNode = {
  node_id: string;
  error: string;
};

export type DataScrubClusterStatusResponse = {
  nodes: DataScrubClusterNodeStatus[];
  skipped_nodes: DataScrubClusterSkippedNode[];
  runs: DataScrubRunRecord[];
};

export type DataScrubTriggerNodeResult = {
  node_id: string;
  started: boolean;
  active_run?: DataScrubActiveRun | null;
  error?: string | null;
};

export type DataScrubTriggerResponse = {
  scope: DataScrubScope;
  nodes_contacted: number;
  failed_nodes: number;
  node_results: DataScrubTriggerNodeResult[];
};

export type LogsResponse = {
  entries: string[];
};

export type ServerHealthResponse = {
  node_id?: string;
  role?: string;
  online?: boolean;
  mode?: string;
  state?: string;
  data_dir?: string;
  version?: string;
  revision?: string;
};

export type StorageStatsSample = {
  collected_at_unix: number;
  latest_snapshot_id?: string | null;
  latest_snapshot_created_at_unix?: number | null;
  latest_snapshot_object_count: number;
  chunk_store_bytes: number;
  manifest_store_bytes: number;
  metadata_db_bytes: number;
  media_cache_bytes: number;
  latest_snapshot_logical_bytes: number;
  latest_snapshot_unique_chunk_bytes: number;
};

export type StorageStatsCurrentResponse = {
  sample?: StorageStatsSample | null;
  collecting: boolean;
  last_attempt_unix?: number | null;
  last_success_unix?: number | null;
  last_error?: string | null;
};

export type AdminMediaCacheClearResponse = {
  deleted_metadata_records: number;
  deleted_thumbnail_files: number;
  deleted_thumbnail_bytes: number;
  cleared_at_unix: number;
};

export type SetupStatus = {
  state: "uninitialized" | "pending_join" | "online";
  data_dir: string;
  bind_addr: string;
  bootstrap_tls_cert_path: string;
  bootstrap_tls_fingerprint: string | null;
  cluster_id: string | null;
  node_id: string | null;
  pending_join_request: Record<string, unknown> | null;
};

export type SetupTransitionResponse = {
  status: string;
  cluster_id: string;
  node_id: string;
  public_url: string | null;
  restart_required: boolean;
};

export type BootstrapBundle = Record<string, unknown> & {
  cluster_id?: string;
  relay_mode?: string;
  rendezvous_mtls_required?: boolean;
  rendezvous_urls?: string[];
  direct_endpoints?: Array<{
    url: string;
    usage?: string | null;
    node_id?: string | null;
  }>;
  trust_roots?: {
    cluster_ca_pem?: string | null;
    public_api_ca_pem?: string | null;
    rendezvous_ca_pem?: string | null;
  };
};

export type BootstrapClaimTrust = {
  ca_der_b64u?: string | null;
  ca_pem?: string | null;
  mode?: "rendezvous_ca_der_b64u" | "rendezvous_ca_pem";
};

export type BootstrapClaim = Record<string, unknown> & {
  v?: number;
  c?: string;
  n?: string;
  r?: string[];
  t?: string;
  k?: string;
  version?: number;
  kind?: string;
  cluster_id?: string;
  target_node_id?: string;
  rendezvous_url?: string;
  rendezvous_urls?: string[];
  trust?: BootstrapClaimTrust;
  claim_token?: string;
  expires_at_unix?: number;
};

export type BootstrapClaimIssueResponse = {
  bootstrap_bundle: BootstrapBundle;
  bootstrap_claim: BootstrapClaim;
};

export type NodeEnrollmentPackage = Record<string, unknown> & {
  bootstrap?: Record<string, unknown>;
  public_tls_material?: Record<string, unknown> | null;
  internal_tls_material?: Record<string, unknown> | null;
};

export type ClientCredentialView = {
  device_id: string;
  label: string | null;
  public_key_fingerprint: string | null;
  credential_fingerprint: string | null;
  created_at_unix: number;
  revocation_reason: string | null;
  revoked_by_actor: string | null;
  revoked_by_source_node: string | null;
  revoked_at_unix: number | null;
};

export type NodeCertificateStatus = {
  name: string;
  configured: boolean;
  cert_path: string | null;
  metadata_path: string | null;
  issued_at_unix: number | null;
  renew_after_unix: number | null;
  expires_at_unix: number | null;
  seconds_until_expiry: number | null;
  certificate_fingerprint: string | null;
  metadata_matches_certificate: boolean | null;
  state: string;
};

export type NodeCertificateStatusResponse = {
  public_tls: NodeCertificateStatus;
  internal_tls: NodeCertificateStatus;
  auto_renew: {
    enabled: boolean;
    enrollment_path: string | null;
    issuer_url: string | null;
    check_interval_secs: number | null;
    last_attempt_unix: number | null;
    last_success_unix: number | null;
    last_error: string | null;
    restart_required: boolean;
  };
};

export type RendezvousConfigView = {
  effective_urls: string[];
  editable_urls: string[];
  managed_embedded_url: string | null;
  registration_enabled: boolean;
  registration_interval_secs: number;
  disconnected_retry_interval_secs: number;
  endpoint_registrations: {
    url: string;
    status: "pending" | "connected" | "disconnected";
    last_attempt_unix: number | null;
    last_success_unix: number | null;
    consecutive_failures: number;
    last_error: string | null;
  }[];
  mtls_required: boolean;
  persistence_source: "node_enrollment" | "runtime_only";
  persisted: boolean;
};

export type ManagedControlPlanePromotionPackage = {
  signer_backup: Record<string, unknown>;
  rendezvous_failover: Record<string, unknown>;
};

export type ManagedRendezvousFailoverPackage = Record<string, unknown> & {
  cluster_id?: string;
  source_node_id?: string;
  target_node_id?: string;
  public_url?: string;
};

export type ManagedRendezvousFailoverImportResponse = {
  status: string;
  cluster_id: string;
  source_node_id: string;
  target_node_id: string;
  public_url: string;
  restart_required: boolean;
  cert_path: string;
  key_path: string;
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
