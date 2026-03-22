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
  StoreUploadSessionChunkResponse,
  StoreUploadSessionCompleteResponse,
  StoreUploadSessionStartResponse,
  VersionGraphResponse
} from "./types";

export type BinaryDownloadResult = {
  blob: Blob;
  filename: string;
  contentType: string;
};

export type BinaryUploadProgress = {
  uploadedBytes: number;
  totalBytes: number;
  uploadedChunks: number;
  totalChunks: number;
  percent: number;
  phase: "starting" | "uploading" | "finalizing" | "complete";
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
  version?: string | null,
  previewBytes?: number | null
): Promise<StoreGetResponse> {
  const query = new URLSearchParams({ key });
  if (snapshot?.trim()) {
    query.set("snapshot", snapshot.trim());
  }
  if (version?.trim()) {
    query.set("version", version.trim());
  }
  if (previewBytes && previewBytes > 0) {
    query.set("preview_bytes", String(Math.floor(previewBytes)));
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

export async function putBinaryObject(
  key: string,
  file: File,
  onProgress?: (progress: BinaryUploadProgress) => void
): Promise<StorePutResponse> {
  const session = await startStoreUploadSession(key, file.size);
  const receivedIndexes = new Set(session.received_indexes);
  let uploadedBytes = byteCountForReceivedIndexes(
    receivedIndexes,
    session.chunk_size_bytes,
    file.size
  );
  let uploadedChunks = receivedIndexes.size;

  onProgress?.(
    buildBinaryUploadProgress(
      uploadedBytes,
      file.size,
      uploadedChunks,
      session.chunk_count,
      uploadedChunks === 0 ? "starting" : "uploading"
    )
  );

  for (let index = 0; index < session.chunk_count; index += 1) {
    if (receivedIndexes.has(index)) {
      continue;
    }

    const start = index * session.chunk_size_bytes;
    const end = Math.min(start + session.chunk_size_bytes, file.size);
    const chunk = file.slice(start, end);
    const response = await fetch(`/api/store/uploads/${encodeURIComponent(session.upload_id)}/chunk/${index}`, {
      method: "PUT",
      body: chunk,
      headers: {
        "content-type": file.type || "application/octet-stream"
      }
    });
    const ack = await readJsonResponse<StoreUploadSessionChunkResponse>(response);
    if (ack.received_index !== index) {
      throw new Error(`Chunk upload desynchronized at index ${index}`);
    }
    uploadedBytes += end - start;
    uploadedChunks += 1;
    onProgress?.(
      buildBinaryUploadProgress(
        uploadedBytes,
        file.size,
        uploadedChunks,
        session.chunk_count,
        "uploading"
      )
    );
  }

  onProgress?.(
    buildBinaryUploadProgress(
      file.size,
      file.size,
      session.chunk_count,
      session.chunk_count,
      "finalizing"
    )
  );
  const completed = await completeStoreUploadSession(session.upload_id);
  onProgress?.(
    buildBinaryUploadProgress(
      completed.total_size_bytes,
      completed.total_size_bytes,
      session.chunk_count,
      session.chunk_count,
      "complete"
    )
  );
  return {
    key: session.key,
    size_bytes: completed.total_size_bytes,
    upload_mode: "chunked",
    chunk_size_bytes: session.chunk_size_bytes,
    chunk_count: session.chunk_count
  };
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

async function startStoreUploadSession(
  key: string,
  totalSizeBytes: number
): Promise<StoreUploadSessionStartResponse> {
  return fetchJson<StoreUploadSessionStartResponse>("/api/store/uploads/start", {
    method: "POST",
    headers: {
      "content-type": "application/json"
    },
    body: JSON.stringify({
      key,
      total_size_bytes: totalSizeBytes
    })
  });
}

async function completeStoreUploadSession(
  uploadId: string
): Promise<StoreUploadSessionCompleteResponse> {
  return fetchJson<StoreUploadSessionCompleteResponse>(
    `/api/store/uploads/${encodeURIComponent(uploadId)}/complete`,
    {
      method: "POST"
    }
  );
}

function byteCountForReceivedIndexes(
  receivedIndexes: Set<number>,
  chunkSizeBytes: number,
  totalSizeBytes: number
): number {
  let uploadedBytes = 0;
  for (const index of receivedIndexes) {
    const start = index * chunkSizeBytes;
    const end = Math.min(start + chunkSizeBytes, totalSizeBytes);
    uploadedBytes += Math.max(0, end - start);
  }
  return uploadedBytes;
}

function buildBinaryUploadProgress(
  uploadedBytes: number,
  totalBytes: number,
  uploadedChunks: number,
  totalChunks: number,
  phase: BinaryUploadProgress["phase"]
): BinaryUploadProgress {
  const safeTotalBytes = Math.max(0, totalBytes);
  const safeUploadedBytes = Math.min(Math.max(0, uploadedBytes), safeTotalBytes);
  const percent =
    safeTotalBytes === 0 ? 100 : Math.round((safeUploadedBytes / safeTotalBytes) * 100);
  return {
    uploadedBytes: safeUploadedBytes,
    totalBytes: safeTotalBytes,
    uploadedChunks,
    totalChunks,
    percent,
    phase
  };
}

async function readErrorMessage(response: Response): Promise<string> {
  const payload = await response.json().catch(() => null);
  if (payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string") {
    return payload.error;
  }
  return `HTTP ${response.status}`;
}
