export type GalleryMapVariantKind = "raster" | "vector" | "hybrid";
export type GalleryMapVariantStyle = "raster" | "openmaptiles" | "natural_earth";
export type GalleryMapVariantAsset = "raster" | "vector";

export type GalleryMapVariant = {
  id: string;
  label: string;
  mode_label: string;
  description: string;
  attribution: string;
  kind: GalleryMapVariantKind;
  style: GalleryMapVariantStyle;
  enabled: boolean;
  raster_manifest_key?: string | null;
  vector_manifest_key?: string | null;
};

export type GalleryMapConfiguration = {
  version: number;
  active_variant_id: string;
  variants: GalleryMapVariant[];
};

export type GalleryMapConfigurationResponse = {
  configuration: GalleryMapConfiguration;
  stored: boolean;
};
