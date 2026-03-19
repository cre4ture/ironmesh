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
};

export type StoreEntry = {
  path: string;
  entry_type: string;
  meta?: JsonObject;
};

export type StoreListResponse = {
  entries: StoreEntry[];
};

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
