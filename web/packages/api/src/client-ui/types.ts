import type { StoreIndexEntry, StoreIndexResponse, StoreListView } from "../shared/store-index";

export type JsonObject = Record<string, unknown>;

export type ClientUiPingResponse = {
  ok: boolean;
  service: string;
};

export type ClientUiRuntimeInfo = {
  app_name: string;
  transport_mode: "direct" | "relay-capable";
  service_name?: string;
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
