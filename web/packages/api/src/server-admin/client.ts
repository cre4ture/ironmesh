import { fetchJson } from "../shared/http";
import type {
  AdminSnapshotSummary,
  AdminStoreListResponse,
  AdminSessionStatus,
  BootstrapClaimIssueResponse,
  BootstrapBundle,
  ClientCredentialView,
  ClusterSummary,
  ControlPlanePromotionImportResponse,
  LogsResponse,
  ManagedControlPlanePromotionPackage,
  ManagedRendezvousFailoverImportResponse,
  ManagedRendezvousFailoverPackage,
  NodeCertificateStatusResponse,
  NodeDescriptor,
  NodeEnrollmentPackage,
  RendezvousConfigView,
  ReplicationPlan,
  StoreListView,
  SetupStatus,
  SetupTransitionResponse
} from "./types";

type AdminRequestOptions = {
  adminTokenOverride?: string;
};

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
  return fetchAdminJson<AdminSessionStatus>("/auth/admin/session", { adminTokenOverride });
}

export async function loginAdmin(password: string): Promise<{ status: string }> {
  return fetchAdminJson<{ status: string }>("/auth/admin/login", {
    method: "POST",
    body: { password }
  });
}

export async function logoutAdmin(adminTokenOverride?: string): Promise<{ status: string }> {
  return fetchAdminJson<{ status: string }>("/auth/admin/logout", {
    method: "POST",
    adminTokenOverride
  });
}

export async function listAdminSnapshots(
  adminTokenOverride?: string
): Promise<AdminSnapshotSummary[]> {
  return fetchAdminJson<AdminSnapshotSummary[]>("/auth/store/snapshots", {
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
  return fetchAdminJson<AdminStoreListResponse>(`/auth/store/index?${query.toString()}`, {
    adminTokenOverride
  });
}

export async function getClusterSummary(): Promise<ClusterSummary> {
  return fetchJson<ClusterSummary>("/cluster/status", {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getClusterNodes(): Promise<NodeDescriptor[]> {
  return fetchJson<NodeDescriptor[]>("/cluster/nodes", {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getReplicationPlan(): Promise<ReplicationPlan> {
  return fetchJson<ReplicationPlan>("/cluster/replication/plan", {
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function triggerReplicationRepair(): Promise<Record<string, unknown>> {
  return fetchJson<Record<string, unknown>>("/cluster/replication/repair", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store"
  });
}

export async function getRecentLogs(limit = 200): Promise<LogsResponse> {
  return fetchJson<LogsResponse>(`/logs?limit=${limit}`, {
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
  return fetchAdminJson<BootstrapBundle>("/auth/bootstrap-bundles/issue", {
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
  return fetchAdminJson<BootstrapClaimIssueResponse>("/auth/bootstrap-claims/issue", {
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
  return fetchAdminJson<NodeEnrollmentPackage>("/auth/node-join-requests/issue-enrollment", {
    method: "POST",
    adminTokenOverride,
    body: request
  });
}

export async function listClientCredentials(
  adminTokenOverride?: string
): Promise<ClientCredentialView[]> {
  return fetchAdminJson<ClientCredentialView[]>("/auth/client-credentials", {
    adminTokenOverride
  });
}

export async function revokeClientCredential(
  deviceId: string,
  reason: string | null,
  adminTokenOverride?: string
): Promise<void> {
  const query = reason?.trim() ? `?reason=${encodeURIComponent(reason.trim())}` : "";
  await fetchAdminJson(`/auth/client-credentials/${encodeURIComponent(deviceId)}${query}`, {
    method: "DELETE",
    adminTokenOverride
  });
}

export async function getNodeCertificateStatus(
  adminTokenOverride?: string
): Promise<NodeCertificateStatusResponse> {
  return fetchAdminJson<NodeCertificateStatusResponse>("/auth/node-certificates/status", {
    adminTokenOverride
  });
}

export async function getRendezvousConfig(
  adminTokenOverride?: string
): Promise<RendezvousConfigView> {
  return fetchAdminJson<RendezvousConfigView>("/auth/rendezvous-config", {
    adminTokenOverride
  });
}

export async function updateRendezvousConfig(
  request: { editable_urls: string[] },
  adminTokenOverride?: string
): Promise<RendezvousConfigView> {
  return fetchAdminJson<RendezvousConfigView>("/auth/rendezvous-config", {
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
    "/auth/managed-rendezvous/failover/export",
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
    "/auth/managed-rendezvous/failover/import",
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
    "/auth/managed-control-plane/promotion/export",
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
    "/auth/managed-control-plane/promotion/import",
    {
      method: "POST",
      adminTokenOverride,
      body: request
    }
  );
}
