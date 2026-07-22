import type { GalleryMapConfiguration } from "@ironmesh/api";
import { expect, test, type Page } from "@playwright/test";

export type GalleryMapContractSetup = {
  mapConfiguration?: GalleryMapConfiguration;
  mapConfigurationStatus?: number;
};

export type GalleryMapContractTarget = {
  name: string;
  setup: (page: Page, setup: GalleryMapContractSetup) => Promise<void>;
  openGallery: (page: Page) => Promise<void>;
};

const configuredMapVariants: GalleryMapConfiguration = {
  version: 1,
  active_variant_id: "natural-earth-globe",
  variants: [
    {
      id: "natural-earth-globe",
      label: "Natural Earth Globe",
      mode_label: "Globe",
      description: "Small global overview map.",
      attribution: "Made with Natural Earth.",
      kind: "raster",
      style: "raster",
      enabled: true,
      raster_manifest_key: "sys/maps/natural-earth-globe.mbtiles.manifest.json"
    },
    {
      id: "natural-earth-labels",
      label: "Natural Earth Globe + labels",
      mode_label: "Labels",
      description: "Natural Earth base map with country, city, and border labels.",
      attribution: "Made with Natural Earth.",
      kind: "hybrid",
      style: "natural_earth",
      enabled: true,
      raster_manifest_key: "sys/maps/natural-earth-globe.mbtiles.manifest.json",
      vector_manifest_key: "sys/maps/natural-earth-labels.mbtiles.manifest.json"
    },
    {
      id: "natural-earth-vector",
      label: "Natural Earth Vector",
      mode_label: "Vector",
      description: "Natural Earth physical world map rendered from vector tiles.",
      attribution: "Made with Natural Earth.",
      kind: "vector",
      style: "natural_earth",
      enabled: true,
      vector_manifest_key: "sys/maps/natural-earth-vector.mbtiles.manifest.json"
    },
    {
      id: "openmaptiles-street",
      label: "OpenMapTiles Street",
      mode_label: "Street",
      description: "Detailed global OpenMapTiles street map.",
      attribution: "Map data © OpenStreetMap contributors.",
      kind: "vector",
      style: "openmaptiles",
      enabled: true,
      vector_manifest_key: "sys/maps/openmaptiles-street.mbtiles.manifest.json"
    },
    {
      id: "hidden-operator-map",
      label: "Hidden operator map",
      mode_label: "Hidden",
      description: "A configured variant that is intentionally not visible to gallery users.",
      attribution: "Internal test data.",
      kind: "raster",
      style: "raster",
      enabled: false,
      raster_manifest_key: "sys/maps/hidden-operator-map.mbtiles.manifest.json"
    }
  ]
};

/**
 * Registers the shared gallery-map behavior that both the client and admin
 * surfaces must provide. Each target owns authentication and HTTP mocking;
 * the assertions intentionally stay identical.
 */
export function registerGalleryMapContractTests(target: GalleryMapContractTarget): void {
  test(`${target.name} gallery map contract lists visible configured styles`, async ({ page }) => {
    await target.setup(page, { mapConfiguration: configuredMapVariants });
    await target.openGallery(page);
    await page.getByRole("button", { name: "Map" }).click();

    const mapDisplay = page.getByRole("textbox", { name: "Map display", exact: true });
    await expect(mapDisplay).toHaveValue("Natural Earth Globe");
    await mapDisplay.click();
    await expect(page.getByRole("option", { name: "Natural Earth Globe + labels" })).toBeVisible();
    await expect(page.getByRole("option", { name: "Natural Earth Vector" })).toBeVisible();
    await expect(page.getByRole("option", { name: "OpenMapTiles Street" })).toBeVisible();
    await expect(page.getByRole("option", { name: "Hidden operator map" })).toHaveCount(0);
    await page.getByRole("option", { name: "Natural Earth Globe + labels" }).click();
    await expect(mapDisplay).toHaveValue("Natural Earth Globe + labels");
    await mapDisplay.click();
    await page.getByRole("option", { name: "Natural Earth Vector" }).click();
    await expect(mapDisplay).toHaveValue("Natural Earth Vector");

    await page.getByRole("button", { name: "Fullscreen map" }).click();
    await expect(mapDisplay).toBeVisible();
    const mapDisplayControls = page.locator('[data-gallery-map-display-controls="true"]');
    expect(
      await mapDisplayControls.evaluate((element) => element.parentElement?.parentElement?.tagName)
    ).toBe("BODY");
  });

  test(`${target.name} gallery map contract keeps configuration failures explicit`, async ({ page }) => {
    await target.setup(page, { mapConfigurationStatus: 503 });
    await target.openGallery(page);
    await page.getByRole("button", { name: "Map" }).click();

    await expect(page.getByText("Gallery map styles are unavailable")).toBeVisible();
    await expect(
      page.getByText(/The map configuration could not be loaded\. HTTP 503/)
    ).toBeVisible();
    await expect(page.getByRole("button", { name: "Retry map styles" })).toBeVisible();
    await expect(page.locator('[aria-label="Geotagged gallery map"]')).toHaveCount(0);
  });
}
