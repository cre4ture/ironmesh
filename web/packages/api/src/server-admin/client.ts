import { fetchJson } from "../shared/http";
import type {
  AdminMediaCacheClearResponse,
  AdminStoreGetResponse,
  AdminSnapshotSummary,
  AdminStoreListResponse,
  AdminVersionGraphResponse,
  AdminSessionStatus,
  BootstrapClaimIssueResponse,
  BootstrapBundle,
  ClientCredentialView,
  ClusterSummary,
  ControlPlanePromotionImportResponse,
  DataScrubActivityStatusResponse,
  DataScrubClusterStatusResponse,
  DataScrubHistoryResponse,
  DataScrubScope,
  DataScrubTriggerResponse,
  LogsResponse,
  ManagedControlPlanePromotionPackage,
  ManagedRendezvousFailoverImportResponse,
  ManagedRendezvousFailoverPackage,
  NodeCertificateStatusResponse,
  NodeDescriptor,
  NodeEnrollmentPackage,
  RepairActivityStatusResponse,
  RepairHistoryResponse,
  RendezvousConfigView,
  ReplicationPlan,
  ServerHealthResponse,
  StorageStatsCurrentResponse,
  StorageStatsSample,
  StoreListView,
  SetupStatus,
  SetupTransitionResponse
} from "./types";

type AdminRequestOptions = {
  adminTokenOverride?: string;
};

const API_V1_PREFIX = "/api/v1";

function apiV1(path: string): string {
  return `${API_V1_PREFIX}${path}`;
}

function buildAdminHeaders(adminTokenOverride?: string, extraHeaders?: HeadersInit): HeadersInit {
  const headers = new Headers(extraHeaders);
  if (adminTokenOverride?.trim()) {
    headers.set("x-ironmesh-admin-token", adminTokenOverride.trim());
  }
  return headers;
}

async function fetchAdminJson<T>(
  path: string,
  options?: AdminRequestOptions & {
    method?: string;
    body?: unknown;
  }
): Promise<T> {
  return fetchJson<T>(path, {
    method: options?.method,
    credentials: "same-origin",
    cache: "no-store",
    headers: buildAdminHeaders(
      options?.adminTokenOverride,
      options?.body === undefined ? undefined : { "content-type": "application/json" }
    ),
    body: options?.body === undefined ? undefined : JSON.stringify(options.body)
  });
}

export async function getAdminSessionStatus(
  adminTokenOverride?: string
): Promise<AdminSessionStatus> {
  return fetchAdminJson<AdminSessionStatus>(apiV1("/auth/admin/session"), { adminTokenOverride });
}

export async function loginAdmin(password: string): Promise<{ status: string }> {
  return fetchAdminJson<{ status: string }>(apiV1("/auth/admin/login"), {
    method: "POST",
    body: { password }
  });
}

export async function logoutAdmin(adminTokenOverride?: string): Promise<{ status: string }> {
  return fetchAdminJson<{ status: string }>(apiV1("/auth/admin/logout"), {
    method: "POST",
    adminTokenOverride
  });
}

export async function listAdminSnapshots(
  adminTokenOverride?: string
): Promise<AdminSnapshotSummary[]> {
  return fetchAdminJson<AdminSnapshotSummary[]>(apiV1("/auth/store/snapshots"), {
    adminTokenOverride
  });
}

export async function listAdminStoreEntries(
  prefix?: string,
  depth = 1,
  snapshot?: string | null,
  adminTokenOverride?: string,
  view: StoreListView = "tree"
): Promise<AdminStoreListResponse> {
  const query = new URLSearchParams({
    depth: String(Math.max(1, depth))
  });
  if (prefix?.trim()) {
    query.set("prefix", prefix.trim());
  }
  if (snapshot?.trim()) {
    query.set("snapshot", snapshot.trim());
  }
  query.set("view", view);
  return fetchAdminJson<AdminStoreListResponse>(`${apiV1("/auth/store/index")}?${query.toString()}`, {
    adminTokenOverride
  });
}

export function getAdminStoreDownloadUrl(
  key: string,
  snapshot?: string | null,
  version?: string | null
): string {
  const query = new URLSearchParams();
  if (snapshot?.trim()) {
    query.set("snapshot", snapshot.trim());
  }
  if (version?.trim()) {
    query.set("version", version.trim());
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return `${apiV1("/auth/store")}/${encodeURIComponent(key)}${suffix}`;
}

export async function getAdminStoreValue(
  key: string,
  snapshot?: string | null,
  version?: string | null,
  previewBytes?: number | null,
  adminTokenOverride?: string
): Promise<AdminStoreGetResponse> {
  const headers = new Headers(buildAdminHeaders(adminTokenOverride));
  const previewLimit =
    typeof previewBytes === "number" && Number.isFinite(previewBytes) && previewBytes > 0
      ? Math.max(1, Math.floor(previewBytes))
      : null;
  if (previewLimit !== null) {
    headers.set("range", `bytes=0-${previewLimit - 1}`);
  }

  const response = await fetch(getAdminStoreDownloadUrl(key, snapshot, version), {
    credentials: "same-origin",
    cache: "no-store",
    headers
  });
  if (!response.ok) {
    throw new Error(await readAdminErrorMessage(response));
  }

  const buffer = await response.arrayBuffer();
  const payloadBytes = new Uint8Array(buffer);
  const totalSizeBytes =
    parseAdminTotalSizeBytes(response.headers.get("content-range")) ??
    parseAdminHeaderInteger(response.headers.get("content-length")) ??
    payloadBytes.byteLength;

  return {
    key,
    snapshot: snapshot ?? null,
    version: version ?? null,
    value: new TextDecoder().decode(payloadBytes),
    truncated: previewLimit !== null ? totalSizeBytes > payloadBytes.byteLength : false,
    total_size_bytes: totalSizeBytes,
    preview_size_bytes: previewLimit !== null ? payloadBytes.byteLength : null
  };
}

export async function getAdminVersionGraph(
  key: string,
  adminTokenOverride?: string
): Promise<AdminVersionGraphResponse> {
  return fetchAdminJson<AdminVersionGraphResponse>(
    `${apiV1("/auth/versions")}/${encodeURIComponent(key)}`,
    {
      adminTokenOverride
    }
  );
}

export async function deleteAdminStorePath(
  path: string,
  adminTokenOverride?: string
): Promise<Record<string, unknown> | null> {
  const query = new URLSearchParams({ key: path });
  return fetchAdminJson<Record<string, unknown> | null>(
    `${apiV1("/auth/store/delete")}?${query.toString()}`,
    {
      method: "POST",
      adminTokenOverride
    }
  );
}

export async function renameAdminStorePath(
  fromPath: string,
  toPath: string,
  overwrite = false,
  adminTokenOverride?: string
): Promise<Record<string, unknown> | null> {
  return fetchAdminJson<Record<string, unknown> | null>(apiV1("/auth/store/rename"), {
    method: "POST",
    adminTokenOverride,
    body: {
      from_path: fromPath,
      to_path: toPath,
      overwrite
    }
  });
}

export async function getClusterSummary(
  adminTokenOverride?: string
): Promise<ClusterSummary> {
  return fetchAdminJson<ClusterSummary>(apiV1("/cluster/status"), {
    adminTokenOverride
  });
}

export async function getClusterNodes(
  adminTokenOverride?: string
): Promise<NodeDescriptor[]> {
  return fetchAdminJson<NodeDescriptor[]>(apiV1("/cluster/nodes"), {
    adminTokenOverride
  });
}

export async function getReplicationPlan(
  adminTokenOverride?: string
): Promise<ReplicationPlan> {
  return fetchAdminJson<ReplicationPlan>(apiV1("/cluster/replication/plan"), {
    adminTokenOverride
  });
}

export async function getRepairActivityStatus(
  adminTokenOverride?: string
): Promise<RepairActivityStatusResponse> {
  return fetchAdminJson<RepairActivityStatusResponse>(apiV1("/auth/repair/activity"), {
    adminTokenOverride
  });
}

export async function getRepairHistory(
  options?: {
    limit?: number;
    sinceUnix?: number;
  },
  adminTokenOverride?: string
): Promise<RepairHistoryResponse> {
  const query = new URLSearchParams();
  if (typeof options?.limit === "number" && Number.isFinite(options.limit)) {
    query.set("limit", String(Math.max(1, Math.trunc(options.limit))));
  }
  if (typeof options?.sinceUnix === "number" && Number.isFinite(options.sinceUnix)) {
    query.set("since_unix", String(Math.max(0, Math.trunc(options.sinceUnix))));
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return fetchAdminJson<RepairHistoryResponse>(`${apiV1("/auth/repair/history")}${suffix}`, {
    adminTokenOverride
  });
}

export async function getDataScrubActivityStatus(
  adminTokenOverride?: string
): Promise<DataScrubActivityStatusResponse> {
  return fetchAdminJson<DataScrubActivityStatusResponse>(apiV1("/auth/scrub/activity"), {
    adminTokenOverride
  });
}

export async function getDataScrubHistory(
  options?: {
    limit?: number;
    sinceUnix?: number;
  },
  adminTokenOverride?: string
): Promise<DataScrubHistoryResponse> {
  const query = new URLSearchParams();
  if (typeof options?.limit === "number" && Number.isFinite(options.limit)) {
    query.set("limit", String(Math.max(1, Math.trunc(options.limit))));
  }
  if (typeof options?.sinceUnix === "number" && Number.isFinite(options.sinceUnix)) {
    query.set("since_unix", String(Math.max(0, Math.trunc(options.sinceUnix))));
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return fetchAdminJson<DataScrubHistoryResponse>(`${apiV1("/auth/scrub/history")}${suffix}`, {
    adminTokenOverride
  });
}

export async function getDataScrubClusterStatus(
  options?: {
    limit?: number;
    sinceUnix?: number;
  },
  adminTokenOverride?: string
): Promise<DataScrubClusterStatusResponse> {
  const query = new URLSearchParams();
  if (typeof options?.limit === "number" && Number.isFinite(options.limit)) {
    query.set("limit", String(Math.max(1, Math.trunc(options.limit))));
  }
  if (typeof options?.sinceUnix === "number" && Number.isFinite(options.sinceUnix)) {
    query.set("since_unix", String(Math.max(0, Math.trunc(options.sinceUnix))));
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  return fetchAdminJson<DataScrubClusterStatusResponse>(`${apiV1("/auth/scrub/cluster")}${suffix}`, {
    adminTokenOverride
  });
}

export async function triggerDataScrub(
  scope: DataScrubScope = "cluster",
  adminTokenOverride?: string
): Promise<DataScrubTriggerResponse> {
  return fetchAdminJson<DataScrubTriggerResponse>(`${apiV1("/auth/scrub/run")}?scope=${scope}`, {
    method: "POST",
    adminTokenOverride
  });
}

export async function triggerReplicationRepair(
  adminTokenOverride?: string
): Promise<Record<string, unknown>> {
  return fetchAdminJson<Record<string, unknown>>(`${apiV1("/cluster/replication/repair")}?scope=cluster`, {
    method: "POST",
    adminTokenOverride
  });
}

function parseAdminHeaderInteger(value: string | null): number | null {
  if (!value) {
    return null;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function parseAdminTotalSizeBytes(contentRange: string | null): number | null {
  if (!contentRange) {
    return null;
  }
  const match = contentRange.match(/\/(\d+)$/);
  if (!match) {
    return null;
  }
  const parsed = Number.parseInt(match[1], 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

async function readAdminErrorMessage(response: Response): Promise<string> {
  const payload = await response.text().catch(() => "");
  const normalizedPayload = payload.trim();
  if (normalizedPayload) {
    return normalizedPayload;
  }
  return `HTTP ${response.status} ${response.statusText}`;
}

export async function clearAdminMediaCache(
  adminTokenOverride?: string
): Promise<AdminMediaCacheClearResponse> {
  return fetchAdminJson<AdminMediaCacheClearResponse>(`${apiV1("/auth/media/cache/clear")}?approve=true`, {
    method: "POST",
    adminTokenOverride
  });
}

export async function getRecentLogs(
  limit = 200,
  adminTokenOverride?: string
): Promise<LogsResponse> {
  return fetchAdminJson<LogsResponse>(`/logs?limit=${limit}`, {
    adminTokenOverride
  });
}

export async function getServerHealth(): Promise<ServerHealthResponse> {
  return fetchJson<ServerHealthResponse>(apiV1("/health"), {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getStorageStatsCurrent(): Promise<StorageStatsCurrentResponse> {
  return fetchJson<StorageStatsCurrentResponse>(apiV1("/storage/stats/current"), {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getStorageStatsHistory(options?: {
  limit?: number;
  sinceUnix?: number;
  maxPoints?: number;
}): Promise<StorageStatsSample[]> {
  const query = new URLSearchParams();
  if (typeof options?.limit === "number" && Number.isFinite(options.limit)) {
    query.set("limit", String(Math.max(1, Math.trunc(options.limit))));
  }
  if (typeof options?.sinceUnix === "number" && Number.isFinite(options.sinceUnix)) {
    query.set("since_unix", String(Math.max(0, Math.trunc(options.sinceUnix))));
  }
  if (typeof options?.maxPoints === "number" && Number.isFinite(options.maxPoints)) {
    query.set("max_points", String(Math.max(2, Math.trunc(options.maxPoints))));
  }
  if (!query.has("limit") && !query.has("since_unix") && !query.has("max_points")) {
    query.set("limit", "120");
  }

  return fetchJson<StorageStatsSample[]>(`${apiV1("/storage/stats/history")}?${query.toString()}`, {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getSetupStatus(): Promise<SetupStatus> {
  return fetchJson<SetupStatus>("/setup/status", {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function startSetupCluster(request: {
  admin_password: string;
  public_origin: string;
}): Promise<SetupTransitionResponse> {
  return fetchJson<SetupTransitionResponse>("/setup/start-cluster", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  });
}

export async function generateSetupJoinRequest(request: {
  public_origin: string;
}): Promise<Record<string, unknown>> {
  return fetchJson<Record<string, unknown>>("/setup/join/request", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  });
}

export async function importSetupEnrollmentPackage(request: {
  admin_password: string;
  package_json: string;
}): Promise<SetupTransitionResponse> {
  return fetchJson<SetupTransitionResponse>("/setup/join/import", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request)
  });
}

export async function issueBootstrapBundle(
  request: { label?: string | null; expires_in_secs?: number | null },
  adminTokenOverride?: string
): Promise<BootstrapBundle> {
  return fetchAdminJson<BootstrapBundle>(apiV1("/auth/bootstrap-bundles/issue"), {
    method: "POST",
    adminTokenOverride,
    body: request
  });
}

export async function issueBootstrapClaim(
  request: {
    label?: string | null;
    expires_in_secs?: number | null;
    preferred_rendezvous_url?: string | null;
  },
  adminTokenOverride?: string
): Promise<BootstrapClaimIssueResponse> {
  return fetchAdminJson<BootstrapClaimIssueResponse>(apiV1("/auth/bootstrap-claims/issue"), {
    method: "POST",
    adminTokenOverride,
    body: request
  });
}

export async function issueNodeEnrollmentFromJoinRequest(
  request: {
    join_request: Record<string, unknown>;
    tls_validity_secs?: number | null;
    tls_renewal_window_secs?: number | null;
  },
  adminTokenOverride?: string
): Promise<NodeEnrollmentPackage> {
  return fetchAdminJson<NodeEnrollmentPackage>(apiV1("/auth/node-join-requests/issue-enrollment"), {
    method: "POST",
    adminTokenOverride,
    body: request
  });
}

export async function listClientCredentials(
  adminTokenOverride?: string
): Promise<ClientCredentialView[]> {
  return fetchAdminJson<ClientCredentialView[]>(apiV1("/auth/client-credentials"), {
    adminTokenOverride
  });
}

export async function revokeClientCredential(
  deviceId: string,
  reason: string | null,
  adminTokenOverride?: string
): Promise<void> {
  const query = reason?.trim() ? `?reason=${encodeURIComponent(reason.trim())}` : "";
  await fetchAdminJson(`${apiV1("/auth/client-credentials")}/${encodeURIComponent(deviceId)}${query}`, {
    method: "DELETE",
    adminTokenOverride
  });
}

export async function getNodeCertificateStatus(
  adminTokenOverride?: string
): Promise<NodeCertificateStatusResponse> {
  return fetchAdminJson<NodeCertificateStatusResponse>(apiV1("/auth/node-certificates/status"), {
    adminTokenOverride
  });
}

export async function getRendezvousConfig(
  adminTokenOverride?: string
): Promise<RendezvousConfigView> {
  return fetchAdminJson<RendezvousConfigView>(apiV1("/auth/rendezvous-config"), {
    adminTokenOverride
  });
}

export async function updateRendezvousConfig(
  request: { editable_urls: string[] },
  adminTokenOverride?: string
): Promise<RendezvousConfigView> {
  return fetchAdminJson<RendezvousConfigView>(apiV1("/auth/rendezvous-config"), {
    method: "PUT",
    adminTokenOverride,
    body: request
  });
}

export async function exportManagedRendezvousFailover(
  request: {
    passphrase: string;
    target_node_id: string;
    public_url?: string | null;
  },
  adminTokenOverride?: string
): Promise<ManagedRendezvousFailoverPackage> {
  return fetchAdminJson<ManagedRendezvousFailoverPackage>(
    apiV1("/auth/managed-rendezvous/failover/export"),
    {
      method: "POST",
      adminTokenOverride,
      body: request
    }
  );
}

export async function importManagedRendezvousFailover(
  request: {
    passphrase: string;
    package: ManagedRendezvousFailoverPackage;
    bind_addr?: string | null;
  },
  adminTokenOverride?: string
): Promise<ManagedRendezvousFailoverImportResponse> {
  return fetchAdminJson<ManagedRendezvousFailoverImportResponse>(
    apiV1("/auth/managed-rendezvous/failover/import"),
    {
      method: "POST",
      adminTokenOverride,
      body: request
    }
  );
}

export async function exportManagedControlPlanePromotion(
  request: {
    passphrase: string;
    target_node_id: string;
    public_url?: string | null;
  },
  adminTokenOverride?: string
): Promise<ManagedControlPlanePromotionPackage> {
  return fetchAdminJson<ManagedControlPlanePromotionPackage>(
    apiV1("/auth/managed-control-plane/promotion/export"),
    {
      method: "POST",
      adminTokenOverride,
      body: request
    }
  );
}

export async function importManagedControlPlanePromotion(
  request: {
    passphrase: string;
    package: ManagedControlPlanePromotionPackage;
    bind_addr?: string | null;
  },
  adminTokenOverride?: string
): Promise<ControlPlanePromotionImportResponse> {
  return fetchAdminJson<ControlPlanePromotionImportResponse>(
    apiV1("/auth/managed-control-plane/promotion/import"),
    {
      method: "POST",
      adminTokenOverride,
      body: request
    }
  );
}
