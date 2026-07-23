import {
  getTelemetryPreview,
  getTelemetrySettings,
  updateTelemetrySettings,
  type TelemetrySettingsResponse
} from "@ironmesh/api";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { JsonBlock } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Code,
  Collapse,
  Group,
  Loader,
  Stack,
  Switch,
  Text
} from "@mantine/core";
import { useState } from "react";
import { formatUnixTs } from "../lib/format";
import { useAdminAccess } from "../lib/admin-access";

type TelemetryConfigurationCardProps = {
  canInspect: boolean;
};

export function TelemetryConfigurationCard({ canInspect }: TelemetryConfigurationCardProps) {
  const queryClient = useQueryClient();
  const { adminTokenOverride } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const [previewRequested, setPreviewRequested] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const settingsQueryKey = ["hardware-page", "telemetry-settings", normalizedAdminTokenOverride];
  const settingsQuery = useQuery({
    queryKey: settingsQueryKey,
    queryFn: () => getTelemetrySettings(normalizedAdminTokenOverride || undefined),
    enabled: canInspect
  });
  const previewQuery = useQuery({
    queryKey: ["hardware-page", "telemetry-preview", normalizedAdminTokenOverride],
    queryFn: () => getTelemetryPreview(normalizedAdminTokenOverride || undefined),
    enabled: canInspect && previewRequested
  });

  const toggleMutation = useMutation({
    mutationFn: (enabled: boolean) =>
      updateTelemetrySettings({ enabled }, normalizedAdminTokenOverride || undefined),
    onSuccess: (response: TelemetrySettingsResponse) => {
      queryClient.setQueryData(settingsQueryKey, response);
      void queryClient.invalidateQueries({ queryKey: settingsQueryKey });
    }
  });

  const settings: TelemetrySettingsResponse | null = canInspect
    ? settingsQuery.data ?? null
    : null;
  const loadError = firstErrorMessage([settingsQuery.error, toggleMutation.error]);
  const preview = previewRequested && canInspect ? previewQuery.data ?? null : null;
  const sentHistory = settings?.sent_history ?? [];

  const requestPreview = () => {
    if (!previewRequested) {
      setPreviewRequested(true);
      return;
    }
    void previewQuery.refetch();
  };

  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="md">
        <Group justify="space-between" align="flex-start">
          <div>
            <Text fw={700}>Reliability Telemetry</Text>
            <Text c="dimmed" size="sm" maw={860}>
              This node periodically sends an anonymized, reduced hardware reliability summary (SMART
              counters, uptime, ECC and finding statistics — never hostnames, IPs, serial numbers, or
              object data) to the central IronMesh statistics collector so hardware failure trends can
              be compared across the whole fleet. Sending is enabled by default and can be switched
              off here at any time (opt-out); the full concept is documented in{" "}
              <Code>docs/server-node-hardware-reliability-telemetry-strategy.md</Code>.
            </Text>
          </div>
          <Badge
            color={settings ? (settings.enabled ? "green" : "gray") : "yellow"}
            variant="light"
          >
            {settings ? (settings.enabled ? "enabled" : "disabled") : "unknown"}
          </Badge>
        </Group>

        {loadError ? (
          <Alert color="red" title="Failed to load or save telemetry settings">
            {loadError}
          </Alert>
        ) : null}

        {!canInspect ? (
          <Text c="dimmed">Admin access is required to view telemetry settings.</Text>
        ) : settingsQuery.isLoading ? (
          <Loader size="sm" />
        ) : settings ? (
          <>
            <Stack gap={4}>
              <Switch
                label="Send anonymized reliability telemetry"
                checked={settings.enabled}
                onChange={(event) => toggleMutation.mutate(event.currentTarget.checked)}
                disabled={toggleMutation.isPending}
              />
              <Text size="sm" c="dimmed">
                Current value comes from{" "}
                {settings.enabled_source === "env"
                  ? "the environment default"
                  : "an admin override stored on this node"}{" "}
                (environment default: {settings.env_default_enabled ? "enabled" : "disabled"}).
                Changing the switch persists an admin override that survives restarts.
              </Text>
            </Stack>

            <Stack gap={4}>
              <Text size="sm">
                Collector endpoint: <Code>{settings.collector_url}</Code>
              </Text>
              <Text size="sm">
                Send interval: <Code>{formatIntervalSecs(settings.send_interval_secs)}</Code> · Last
                sent: <Code>{formatUnixTs(settings.last_sent_at_unix)}</Code>
              </Text>
            </Stack>
            {settings.last_send_error ? (
              <Alert color="red" title="Last send failed">
                {settings.last_send_error}
              </Alert>
            ) : null}

            <Stack gap={4}>
              <Text size="sm">
                Telemetry subject ID:{" "}
                <Code>{settings.telemetry_subject_id ?? "not generated yet"}</Code>
              </Text>
              <Text size="sm" c="dimmed" maw={860}>
                This pseudonymous ID is derived locally with a secret salt and is the only identifier
                sent to the collector — it cannot be traced back to this node without the local salt.
                To request deletion of (or access to) the centrally stored data, quote exactly this ID
                to the project maintainers; there is no automated flow yet.
              </Text>
            </Stack>

            <Stack gap="xs">
              <Group justify="space-between" align="center">
                <Text fw={600}>Payload preview</Text>
                <Button
                  variant="light"
                  size="xs"
                  onClick={requestPreview}
                  loading={previewRequested && previewQuery.isFetching}
                >
                  {previewRequested ? "Refresh preview" : "Load preview"}
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                This is the exact JSON object that would be sent with the next transmission.
              </Text>
              {previewQuery.error ? (
                <Alert color="red" title="Failed to load telemetry preview">
                  {previewQuery.error instanceof Error
                    ? previewQuery.error.message
                    : String(previewQuery.error)}
                </Alert>
              ) : preview ? (
                preview.payload != null ? (
                  <JsonBlock value={preview.payload} />
                ) : (
                  <Alert color="yellow" title="No payload available yet">
                    {preview.unavailable_reason ??
                      "The first hardware-health collection has not completed yet."}
                  </Alert>
                )
              ) : null}
            </Stack>

            <Stack gap="xs">
              <Group justify="space-between" align="center">
                <Group gap="xs">
                  <Text fw={600}>Sent history</Text>
                  <Badge variant="light">{sentHistory.length}</Badge>
                </Group>
                {sentHistory.length > 0 ? (
                  <Button variant="subtle" size="xs" onClick={() => setHistoryOpen((open) => !open)}>
                    {historyOpen ? "Hide" : "Show"}
                  </Button>
                ) : null}
              </Group>
              {sentHistory.length === 0 ? (
                <Text c="dimmed" size="sm">
                  No telemetry batches have been sent yet.
                </Text>
              ) : (
                <Collapse in={historyOpen}>
                  <Stack gap="xs">
                    {sentHistory.map((entry, index) => (
                      <Card key={`${entry.sent_at_unix}-${index}`} withBorder radius="md" padding="sm">
                        <Stack gap={4}>
                          <Text size="sm">
                            Sent at <Code>{formatUnixTs(entry.sent_at_unix)}</Code>
                          </Text>
                          <JsonBlock value={entry.payload} />
                        </Stack>
                      </Card>
                    ))}
                  </Stack>
                </Collapse>
              )}
            </Stack>
          </>
        ) : (
          <Text c="dimmed">No telemetry settings loaded yet.</Text>
        )}
      </Stack>
    </Card>
  );
}

function formatIntervalSecs(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "unknown";
  }
  if (seconds % 3600 === 0) {
    return `${seconds / 3600}h`;
  }
  if (seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }
  return `${seconds}s`;
}

function firstErrorMessage(errors: unknown[]): string | null {
  for (const error of errors) {
    if (error instanceof Error && error.message.trim()) {
      return error.message;
    }
  }
  return null;
}
