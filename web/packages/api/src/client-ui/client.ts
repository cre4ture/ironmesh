import { fetchJson } from "../shared/http";
import type {
  ClientRendezvousView,
  ClientUiPingResponse,
  JsonObject,
  SnapshotSummary,
  StoreGetResponse,
  StoreListResponse,
  StoreListView,
  StorePutResponse,
  VersionGraphResponse
} from "./types";

export type BinaryDownloadResult = {
  blob: Blob;
  filename: string;
  contentType: string;
};

export async function getClientPing(): Promise<ClientUiPingResponse> {
  return fetchJson<ClientUiPingResponse>("/api/ping");
}

export async function getClientHealth(): Promise<JsonObject> {
  return fetchJson<JsonObject>("/api/health");
}

export async function getClientClusterStatus(): Promise<JsonObject> {
  return fetchJson<JsonObject>("/api/cluster/status");
}

export async function getClientRendezvous(): Promise<ClientRendezvousView> {
  return fetchJson<ClientRendezvousView>("/api/rendezvous");
}

export async function refreshClientRendezvous(): Promise<ClientRendezvousView> {
  return fetchJson<ClientRendezvousView>("/api/rendezvous/refresh", {
    method: "POST"
  });
}

export async function updateClientRendezvous(request: {
  rendezvous_urls: string[];
}): Promise<ClientRendezvousView> {
  return fetchJson<ClientRendezvousView>("/api/rendezvous", {
    method: "PUT",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify(request)
  });
}

export async function getClientClusterNodes(): Promise<unknown[]> {
  return fetchJson<unknown[]>("/api/cluster/nodes");
}

export async function getClientReplicationPlan(): Promise<JsonObject> {
  return fetchJson<JsonObject>("/api/cluster/replication/plan");
}

export async function listSnapshots(): Promise<SnapshotSummary[]> {
  return fetchJson<SnapshotSummary[]>("/api/snapshots");
}

export async function listStoreEntries(
  prefix?: string,
  depth = 1,
  snapshot?: string | null,
  view: StoreListView = "tree"
): Promise<StoreListResponse> {
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
  return fetchJson<StoreListResponse>(`/api/store/list?${query.toString()}`);
}

export async function getStoreValue(
  key: string,
  snapshot?: string | null,
  version?: string | null
): Promise<StoreGetResponse> {
  const query = new URLSearchParams({ key });
  if (snapshot?.trim()) {
    query.set("snapshot", snapshot.trim());
  }
  if (version?.trim()) {
    query.set("version", version.trim());
  }
  return fetchJson<StoreGetResponse>(`/api/store/get?${query.toString()}`);
}

export async function putStoreValue(key: string, value: string): Promise<StorePutResponse> {
  return fetchJson<StorePutResponse>("/api/store/put", {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({ key, value })
  });
}

export async function deleteStoreValue(key: string): Promise<JsonObject> {
  const query = new URLSearchParams({ key });
  return fetchJson<JsonObject>(`/api/store/delete?${query.toString()}`, {
    method: "DELETE"
  });
}

export async function putBinaryObject(key: string, file: File): Promise<StorePutResponse> {
  const response = await fetch(`/api/store/put-binary?key=${encodeURIComponent(key)}`, {
    method: "POST",
    body: file,
    headers: {
      "content-type": file.type || "application/octet-stream"
    }
  });
  return readJsonResponse<StorePutResponse>(response);
}

export function getBinaryObjectDownloadUrl(
  key: string,
  snapshot?: string | null,
  version?: string | null
): string {
  const query = new URLSearchParams({ key });
  if (snapshot?.trim()) {
    query.set("snapshot", snapshot.trim());
  }
  if (version?.trim()) {
    query.set("version", version.trim());
  }
  return `/api/store/get-binary?${query.toString()}`;
}

export async function downloadBinaryObject(
  key: string,
  snapshot?: string | null,
  version?: string | null
): Promise<BinaryDownloadResult> {
  const response = await fetch(getBinaryObjectDownloadUrl(key, snapshot, version));
  if (!response.ok) {
    throw new Error(await readErrorMessage(response));
  }

  const contentDisposition = response.headers.get("content-disposition") || "";
  const filenameMatch = contentDisposition.match(/filename="([^"]+)"/i);
  return {
    blob: await response.blob(),
    filename: filenameMatch?.[1] || key.split("/").pop() || "download.bin",
    contentType: response.headers.get("content-type") || "application/octet-stream"
  };
}

export async function getVersionGraph(key: string): Promise<VersionGraphResponse> {
  return fetchJson<VersionGraphResponse>(`/api/versions?key=${encodeURIComponent(key)}`);
}

async function readJsonResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(await readErrorMessage(response));
  }
  return (await response.json()) as T;
}

async function readErrorMessage(response: Response): Promise<string> {
  const payload = await response.json().catch(() => null);
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string") {
    return payload.error;
  }
  return `HTTP ${response.status}`;
}
