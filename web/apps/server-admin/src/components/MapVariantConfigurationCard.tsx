import {
  updateAdminGalleryMapConfiguration,
  type AdminGalleryMapConfiguration
} from "@ironmesh/api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Alert, Badge, Button, Card, Code, Group, Select, Stack, Switch, Text, Textarea } from "@mantine/core";
import { useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

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

function firstErrorMessage(errors: unknown[]): string | null {
  for (const error of errors) {
    if (error instanceof Error && error.message.trim()) {
      return error.message;
    }
  }
  return null;
}
