import type { GalleryBasemapConfig } from "./GalleryBasemapMap";

export type GalleryMapVariantDefinition = {
  id: string;
  label: string;
  mode_label: string;
  description: string;
  attribution: string;
  kind: "raster" | "vector" | "hybrid";
  style: "raster" | "openmaptiles" | "natural_earth";
  enabled: boolean;
  raster_manifest_key?: string | null;
  vector_manifest_key?: string | null;
};

/** Converts the cluster-stored map variant document into Gallery map sources. */
export function galleryBasemapsFromConfiguration(
  variants: GalleryMapVariantDefinition[]
): GalleryBasemapConfig[] {
  const basemaps: GalleryBasemapConfig[] = [];
  for (const variant of variants) {
    if (!variant.enabled) {
      continue;
    }
    const shared = {
      id: variant.id,
      modeLabel: variant.mode_label,
      label: variant.label,
      attribution: variant.attribution
    };
    if (variant.kind === "raster" && variant.raster_manifest_key) {
      basemaps.push({
        ...shared,
        kind: "raster",
        logicalFileUrl: logicalMapFileUrl(variant.raster_manifest_key),
        metadataUrl: logicalMapMetadataUrl(variant.raster_manifest_key),
        tileUrlTemplate: logicalMapTileUrlTemplate(variant.raster_manifest_key)
      });
      continue;
    }
    if (variant.kind === "vector" && variant.vector_manifest_key) {
      basemaps.push({
        ...shared,
        kind: "vector",
        vectorStyle: vectorStyle(variant.style),
        metadataUrl: logicalMapMetadataUrl(variant.vector_manifest_key),
        vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(variant.vector_manifest_key),
        glyphsUrlTemplate: logicalMapGlyphUrlTemplate()
      });
      continue;
    }
    if (
      variant.kind === "hybrid" &&
      variant.raster_manifest_key &&
      variant.vector_manifest_key
    ) {
      basemaps.push({
        ...shared,
        kind: "hybrid",
        vectorStyle: vectorStyle(variant.style),
        rasterMetadataUrl: logicalMapMetadataUrl(variant.raster_manifest_key),
        rasterTileUrlTemplate: logicalMapTileUrlTemplate(variant.raster_manifest_key),
        vectorMetadataUrl: logicalMapMetadataUrl(variant.vector_manifest_key),
        vectorTileUrlTemplate: logicalMapVectorTileUrlTemplate(variant.vector_manifest_key),
        glyphsUrlTemplate: logicalMapGlyphUrlTemplate()
      });
    }
  }
  return basemaps;
}

function vectorStyle(style: GalleryMapVariantDefinition["style"]): "openmaptiles" | "natural_earth" {
  return style === "natural_earth" ? "natural_earth" : "openmaptiles";
}

function logicalMapFileUrl(manifestKey: string): string {
  return `/api/v1/maps/logical-file?${new URLSearchParams({ manifest_key: manifestKey }).toString()}`;
}

function logicalMapMetadataUrl(manifestKey: string): string {
  return `/api/v1/maps/mbtiles-metadata?${new URLSearchParams({ manifest_key: manifestKey }).toString()}`;
}

function logicalMapTileUrlTemplate(manifestKey: string): string {
  return `/api/v1/maps/tiles/{z}/{x}/{y}?${new URLSearchParams({ manifest_key: manifestKey }).toString()}`;
}

function logicalMapVectorTileUrlTemplate(manifestKey: string): string {
  return `/api/v1/maps/vector-tiles/{z}/{x}/{y}?${new URLSearchParams({ manifest_key: manifestKey }).toString()}`;
}

function logicalMapGlyphUrlTemplate(): string {
  return "/api/v1/maps/fonts/{fontstack}/{range}.pbf";
}
