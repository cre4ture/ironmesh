import {
  updateAdminGalleryMapConfiguration,
  type AdminGalleryMapConfiguration
} from "@ironmesh/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Group,
  Select,
  Stack,
  Switch,
  Text,
  Textarea,
  TextInput
} from "@mantine/core";
import { useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

type MapVariant = AdminGalleryMapConfiguration["variants"][number];
type HybridAssetSource = {
  key: string;
  manifestKey: string;
  variant: MapVariant;
};
type HybridVectorStyle = "natural_earth" | "openmaptiles";

type MapVariantConfigurationCardProps = {
  configuration: AdminGalleryMapConfiguration | null;
  stored: boolean | null;
  loading: boolean;
  error: unknown;
};

export function MapVariantConfigurationCard({
  configuration,
  stored,
  loading,
  error
}: MapVariantConfigurationCardProps) {
  const queryClient = useQueryClient();
  const { adminTokenOverride } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const [draftText, setDraftText] = useState("");
  const [hybridRasterSourceKey, setHybridRasterSourceKey] = useState<string | null>(null);
  const [hybridVectorSourceKey, setHybridVectorSourceKey] = useState<string | null>(null);
  const [hybridStyle, setHybridStyle] = useState<HybridVectorStyle>("natural_earth");
  const [hybridLabel, setHybridLabel] = useState("");
  const [hybridAttribution, setHybridAttribution] = useState("");

  useEffect(() => {
    if (configuration) {
      setDraftText(JSON.stringify(configuration, null, 2));
    }
  }, [configuration]);

  const saveMutation = useMutation({
    mutationFn: (next: AdminGalleryMapConfiguration) =>
      updateAdminGalleryMapConfiguration(next, normalizedAdminTokenOverride || undefined),
    onSuccess: (response) => {
      queryClient.setQueryData(
        ["gallery-page", "map-configuration", normalizedAdminTokenOverride],
        response
      );
    }
  });
  const saveError = firstErrorMessage([error, saveMutation.error]);
  const enabledVariants = configuration?.variants.filter((variant) => variant.enabled) ?? [];
  const rasterSources = mapVariantAssets(configuration?.variants ?? [], "raster");
  const vectorSources = mapVariantAssets(configuration?.variants ?? [], "vector");
  const hybridRasterSource = rasterSources.find((source) => source.key === hybridRasterSourceKey) ?? null;
  const hybridVectorSource = vectorSources.find((source) => source.key === hybridVectorSourceKey) ?? null;
  const hybridDefaultLabel = hybridRasterSource && hybridVectorSource
    ? `${hybridRasterSource.variant.label} + ${hybridVectorSource.variant.label}`
    : "";

  useEffect(() => {
    if (!hybridRasterSource || !hybridVectorSource) {
      setHybridAttribution("");
      return;
    }
    setHybridAttribution(combineAttribution(hybridRasterSource.variant, hybridVectorSource.variant));
  }, [hybridRasterSourceKey, hybridVectorSourceKey]);

  const updateConfiguration = (next: AdminGalleryMapConfiguration) => {
    void saveMutation.mutateAsync(next);
  };
  const chooseActiveVariant = (id: string | null) => {
    if (!configuration || !id || id === configuration.active_variant_id) {
      return;
    }
    updateConfiguration({ ...configuration, active_variant_id: id });
  };
  const setEnabled = (id: string, enabled: boolean) => {
    if (!configuration || (id === configuration.active_variant_id && !enabled)) {
      return;
    }
    updateConfiguration({
      ...configuration,
      variants: configuration.variants.map((variant) =>
        variant.id === id ? { ...variant, enabled } : variant
      )
    });
  };
  const saveAdvancedConfiguration = () => {
    try {
      const parsed = JSON.parse(draftText) as AdminGalleryMapConfiguration;
      updateConfiguration(parsed);
    } catch {
      // Keep the invalid text intact and expose a useful local error below.
      setAdvancedParseError("The configuration must be valid JSON before it can be saved.");
    }
  };
  const createHybridVariant = () => {
    if (
      !configuration ||
      !hybridRasterSource ||
      !hybridVectorSource ||
      !hybridAttribution.trim() ||
      hybridAttribution.trim().length > 2_000
    ) {
      return;
    }
    const label = hybridLabel.trim() || hybridDefaultLabel;
    const variantId = nextHybridVariantId(
      configuration.variants,
      hybridRasterSource.variant.id,
      hybridVectorSource.variant.id
    );
    updateConfiguration({
      ...configuration,
      variants: [
        ...configuration.variants,
        {
          id: variantId,
          label,
          mode_label: "Hybrid",
          description: `${hybridRasterSource.variant.label} raster background with ${hybridVectorSource.variant.label} vector overlay.`,
          attribution: hybridAttribution.trim(),
          kind: "hybrid",
          style: hybridStyle,
          enabled: false,
          raster_manifest_key: hybridRasterSource.manifestKey,
          vector_manifest_key: hybridVectorSource.manifestKey
        }
      ]
    });
    setHybridLabel("");
  };
  const [advancedParseError, setAdvancedParseError] = useState<string | null>(null);

  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text fw={600}>Gallery map variants</Text>
            <Text c="dimmed" size="sm" maw={860}>
              This cluster setting is stored as <Code>sys/maps/gallery-map-config.json</Code> and
              replicated with the map artifacts. Change the active variant here; both the client
              and admin gallery use it as their shared initial map.
            </Text>
          </div>
          <Badge color={stored ? "green" : "yellow"} variant="light">
            {stored ? "cluster stored" : "default not saved"}
          </Badge>
        </Group>

        {saveError ? (
          <Alert color="red" title="Failed to load or save the map configuration">
            {saveError}
          </Alert>
        ) : null}
        {advancedParseError ? (
          <Alert color="red" title="Invalid configuration" withCloseButton onClose={() => setAdvancedParseError(null)}>
            {advancedParseError}
          </Alert>
        ) : null}

        <Select
          label="Initial gallery map"
          description="Clients pick this variant on their next configuration refresh. People can still switch between enabled variants immediately in the map toolbar."
          placeholder={loading ? "Loading map variants…" : "No enabled map variant"}
          value={configuration?.active_variant_id ?? null}
          data={enabledVariants.map((variant) => ({ value: variant.id, label: variant.label }))}
          onChange={chooseActiveVariant}
          disabled={!configuration || saveMutation.isPending}
          searchable
          nothingFoundMessage="No enabled map variants"
        />

        {configuration ? (
          <Stack gap="xs">
            {configuration.variants.map((variant) => (
              <Card key={variant.id} withBorder padding="sm" radius="sm">
                <Group justify="space-between" align="flex-start" wrap="nowrap">
                  <div>
                    <Group gap="xs">
                      <Text fw={600}>{variant.label}</Text>
                      <Badge size="sm" variant="light">
                        {variant.kind}
                      </Badge>
                      {variant.id === configuration.active_variant_id ? (
                        <Badge size="sm" color="blue">
                          active
                        </Badge>
                      ) : null}
                    </Group>
                    <Text size="sm" c="dimmed">
                      {variant.description}
                    </Text>
                    <Text size="xs" c="dimmed" mt={4}>
                      {variant.raster_manifest_key ? <Code>{variant.raster_manifest_key}</Code> : null}
                      {variant.raster_manifest_key && variant.vector_manifest_key ? " + " : null}
                      {variant.vector_manifest_key ? <Code>{variant.vector_manifest_key}</Code> : null}
                    </Text>
                  </div>
                  <Switch
                    label="Visible"
                    checked={variant.enabled}
                    onChange={(event) => setEnabled(variant.id, event.currentTarget.checked)}
                    disabled={saveMutation.isPending || variant.id === configuration.active_variant_id}
                  />
                </Group>
              </Card>
            ))}
          </Stack>
        ) : null}

        <Card withBorder radius="sm" padding="md">
          <Stack gap="sm">
            <div>
              <Text fw={600}>Create hybrid map variant</Text>
              <Text size="sm" c="dimmed">
                Combine any configured raster artifact with any configured vector artifact. The selected
                vector style must match the source-layer schema of the overlay.
              </Text>
            </div>
            <Select
              label="Raster background"
              placeholder="Choose a raster artifact"
              value={hybridRasterSourceKey}
              data={rasterSources.map((source) => ({
                value: source.key,
                label: `${source.variant.label} — ${source.manifestKey}`
              }))}
              onChange={setHybridRasterSourceKey}
              disabled={!configuration || saveMutation.isPending || rasterSources.length === 0}
              searchable
              nothingFoundMessage="No configured raster artifacts"
            />
            <Select
              label="Vector label overlay"
              description="A full vector package is safe to use: the hybrid style draws only its label, border, and road layers."
              placeholder="Choose a vector artifact"
              value={hybridVectorSourceKey}
              data={vectorSources.map((source) => ({
                value: source.key,
                label: `${source.variant.label} — ${source.manifestKey}`
              }))}
              onChange={(value) => {
                setHybridVectorSourceKey(value);
                const selected = vectorSources.find((source) => source.key === value);
                if (selected?.variant.style === "natural_earth") {
                  setHybridStyle("natural_earth");
                } else if (selected?.variant.style === "openmaptiles") {
                  setHybridStyle("openmaptiles");
                }
              }}
              disabled={!configuration || saveMutation.isPending || vectorSources.length === 0}
              searchable
              nothingFoundMessage="No configured vector artifacts"
            />
            <Select
              label="Vector overlay schema"
              description="Natural Earth expects ne_places/ne_boundaries layers; OpenMapTiles expects place/boundary layers."
              value={hybridStyle}
              data={[
                { value: "natural_earth", label: "Natural Earth" },
                { value: "openmaptiles", label: "OpenMapTiles" }
              ]}
              onChange={(value) => {
                if (value === "natural_earth" || value === "openmaptiles") {
                  setHybridStyle(value);
                }
              }}
              disabled={!configuration || saveMutation.isPending}
            />
            <TextInput
              label="Hybrid map name"
              description="Leave empty to use the names of the selected background and overlay."
              placeholder={hybridDefaultLabel || "Example: Terrain + labels"}
              value={hybridLabel}
              onChange={(event) => setHybridLabel(event.currentTarget.value)}
              disabled={!configuration || saveMutation.isPending}
            />
            <TextInput
              label="Attribution"
              description="Pre-filled from both sources. Keep all required attribution and licensing notices."
              value={hybridAttribution}
              onChange={(event) => setHybridAttribution(event.currentTarget.value)}
              disabled={!configuration || saveMutation.isPending}
            />
            <Group justify="flex-end">
              <Button
                onClick={createHybridVariant}
                loading={saveMutation.isPending}
                disabled={
                  !configuration ||
                  !hybridRasterSource ||
                  !hybridVectorSource ||
                  !hybridAttribution.trim() ||
                  hybridAttribution.trim().length > 2_000 ||
                  configuration.variants.length >= 32
                }
              >
                Create hybrid variant
              </Button>
            </Group>
            {(configuration?.variants.length ?? 0) >= 32 ? (
              <Alert color="yellow" variant="light">
                The gallery configuration already contains its maximum of 32 variants.
              </Alert>
            ) : null}
          </Stack>
        </Card>

        <Textarea
          label="Advanced configuration"
          description="Use this to add future map packages or adjust manifest keys. The server validates IDs, styles, assets and the active enabled variant before saving."
          autosize
          minRows={10}
          maxRows={24}
          value={draftText}
          onChange={(event) => {
            setAdvancedParseError(null);
            setDraftText(event.currentTarget.value);
          }}
          disabled={!configuration || saveMutation.isPending}
          styles={{ input: { fontFamily: "monospace", fontSize: 12 } }}
        />
        <Group justify="flex-end">
          <Button
            variant="light"
            onClick={saveAdvancedConfiguration}
            loading={saveMutation.isPending}
            disabled={!configuration || !draftText.trim()}
          >
            Save advanced configuration
          </Button>
        </Group>
      </Stack>
    </Card>
  );
}

function mapVariantAssets(
  variants: MapVariant[],
  asset: "raster" | "vector"
): HybridAssetSource[] {
  return variants.flatMap((variant) => {
    const manifestKey = asset === "raster" ? variant.raster_manifest_key : variant.vector_manifest_key;
    return manifestKey
      ? [
          {
            key: `${variant.id}:${asset}`,
            manifestKey,
            variant
          }
        ]
      : [];
  });
}

function combineAttribution(raster: MapVariant, vector: MapVariant): string {
  return [...new Set([raster.attribution.trim(), vector.attribution.trim()].filter(Boolean))].join(" · ");
}

function nextHybridVariantId(
  variants: MapVariant[],
  rasterVariantId: string,
  vectorVariantId: string
): string {
  const prefix = `hybrid-${rasterVariantId}-${vectorVariantId}`
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 58) || "hybrid-map";
  const existingIds = new Set(variants.map((variant) => variant.id));
  if (!existingIds.has(prefix)) {
    return prefix;
  }
  for (let number = 2; number < 10_000; number += 1) {
    const candidate = `${prefix.slice(0, 64 - String(number).length - 1)}-${number}`;
    if (!existingIds.has(candidate)) {
      return candidate;
    }
  }
  return `${prefix.slice(0, 57)}-${Date.now()}`.slice(0, 64);
}

function firstErrorMessage(errors: unknown[]): string | null {
  for (const error of errors) {
    if (error instanceof Error && error.message.trim()) {
      return error.message;
    }
  }
  return null;
}
