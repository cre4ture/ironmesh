export type StoreIndexGps = {
  latitude: number;
  longitude: number;
};

export type StoreIndexThumbnail = {
  url: string;
  profile: string;
  width: number;
  height: number;
  format: string;
  size_bytes: number;
};

export type StoreIndexMedia = {
  status: string;
  content_fingerprint: string;
  media_type?: string | null;
  mime_type?: string | null;
  width?: number | null;
  height?: number | null;
  orientation?: number | null;
  taken_at_unix?: number | null;
  gps?: StoreIndexGps | null;
  thumbnail?: StoreIndexThumbnail | null;
  error?: string | null;
};

export type StoreIndexEntry = {
  path: string;
  entry_type: string;
  version?: string | null;
  content_hash?: string | null;
  size_bytes?: number | null;
  modified_at_unix?: number | null;
  content_fingerprint?: string | null;
  media?: StoreIndexMedia | null;
};

export type StoreIndexResponse = {
  prefix: string;
  depth: number;
  entry_count: number;
  entries: StoreIndexEntry[];
};

export type StoreListView = "raw" | "tree";
