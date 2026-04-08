import type { StoreIndexEntry, StoreIndexResponse, StoreListView } from "../shared/store-index";

export type JsonObject = Record<string, unknown>;

export type ClientUiPingResponse = {
  ok: boolean;
  service: string;
  backend_version?: string;
  backend_revision?: string;
};

export type ClientUiRuntimeInfo = {
  app_name: string;
  transport_mode: "direct" | "relay-capable";
  service_name?: string;
};

export type LatencyProbeAssessment = "healthy" | "warn" | "degraded";

export type LatencyProbeSample = {
  index: number;
  started_unix_ms: number;
  successful: boolean;
  status_code?: number | null;
  total_duration_ms: number;
  server_duration_ms?: number | null;
  transport_overhead_ms?: number | null;
  response_bytes: number;
  throughput_bytes_per_sec?: number | null;
  node_id?: string | null;
  error?: string | null;
};

export type LatencyProbeSummary = {
  requested_samples: number;
  success_count: number;
  failure_count: number;
  min_total_duration_ms?: number | null;
  avg_total_duration_ms?: number | null;
  p50_total_duration_ms?: number | null;
  p95_total_duration_ms?: number | null;
  max_total_duration_ms?: number | null;
  avg_server_duration_ms?: number | null;
  avg_transport_overhead_ms?: number | null;
  p95_transport_overhead_ms?: number | null;
  avg_throughput_bytes_per_sec?: number | null;
  assessment: LatencyProbeAssessment;
  observations: string[];
};

export type TransportSessionPoolSnapshot = {
  connect_count: number;
  reuse_count: number;
  reset_count: number;
};

export type LatencyProbeResult = {
  config: {
    sample_count: number;
    warmup_count: number;
    response_bytes: number;
    server_delay_ms: number;
    pause_between_samples_ms: number;
  };
  route: string;
  generated_at_unix_ms: number;
  cold_connect_duration_ms?: number | null;
  transport_session_pool: TransportSessionPoolSnapshot;
  samples: LatencyProbeSample[];
  summary: LatencyProbeSummary;
};

export type LatencyProbeComparison = {
  assessment: LatencyProbeAssessment;
  relay_avg_total_delta_ms?: number | null;
  relay_avg_total_ratio?: number | null;
  relay_avg_transport_overhead_delta_ms?: number | null;
  observations: string[];
};

export type ClientLatencyProbeTargetResult = {
  path_id: string;
  label: string;
  transport_mode: "direct" | "relay" | string;
  uses_current_runtime: boolean;
  target?: string | null;
  result?: LatencyProbeResult | null;
  error?: string | null;
};

export type ClientLatencyTestResponse = {
  generated_at_unix_ms: number;
  config: LatencyProbeResult["config"];
  targets: ClientLatencyProbeTargetResult[];
  comparison?: LatencyProbeComparison | null;
};

export type ClientRendezvousEndpointStatus = {
  url: string;
  status: "unknown" | "connected" | "disconnected";
  last_attempt_unix: number | null;
  last_success_unix: number | null;
  consecutive_failures: number;
  last_error: string | null;
  active: boolean;
};

export type ClientRendezvousView = {
  available: boolean;
  editable: boolean;
  transport_mode: "direct" | "relay";
  relay_mode: "disabled" | "fallback" | "preferred" | "required" | null;
  configured_urls: string[];
  direct_url: string | null;
  direct_target_node_id: string | null;
  active_url: string | null;
  active_target_node_id: string | null;
  mtls_required: boolean;
  persistence_source: "runtime_only" | "bootstrap_file" | "android_preferences" | "unavailable";
  last_probe_error: string | null;
  endpoint_statuses: ClientRendezvousEndpointStatus[];
};

export type StorePutResponse = {
  key: string;
  size_bytes: number;
  upload_mode?: "direct" | "chunked";
  chunk_size_bytes?: number;
  chunk_count?: number;
};

export type StoreUploadSessionStartResponse = {
  upload_id: string;
  key: string;
  total_size_bytes: number;
  chunk_size_bytes: number;
  chunk_count: number;
  received_indexes: number[];
  completed: boolean;
};

export type StoreUploadSessionChunkResponse = {
  stored: boolean;
  received_index: number;
};

export type StoreUploadSessionCompleteResponse = {
  snapshot_id: string;
  version_id: string;
  manifest_hash: string;
  state: string;
  new_chunks: number;
  dedup_reused_chunks: number;
  created_new_version: boolean;
  total_size_bytes: number;
};

export type StoreGetResponse = {
  key: string;
  snapshot?: string | null;
  version?: string | null;
  value: string;
  truncated?: boolean;
  total_size_bytes?: number;
  preview_size_bytes?: number | null;
};

export type StoreEntry = StoreIndexEntry;

export type StoreListResponse = StoreIndexResponse;

export type { StoreListView };

export type SnapshotSummary = {
  id: string;
} & JsonObject;

export type VersionSummary = {
  version_id: string;
} & JsonObject;

export type VersionGraphResponse = {
  key?: string;
  versions: VersionSummary[];
} & JsonObject;
