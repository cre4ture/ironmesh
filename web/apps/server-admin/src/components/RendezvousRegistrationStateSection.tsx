import type { RendezvousConfigView } from "@ironmesh/api";
import { Badge, Card, Group, Stack, Text } from "@mantine/core";

function formatUnixTimestamp(value: number | null): string {
  if (!value) {
    return "never";
  }

  return new Date(value * 1000).toLocaleString();
}

function registrationBadgeColor(status: "pending" | "connected" | "disconnected"): string {
  if (status === "connected") {
    return "green";
  }
  if (status === "disconnected") {
    return "red";
  }
  return "gray";
}

type RendezvousRegistrationStateSectionProps = {
  rendezvousConfig: RendezvousConfigView;
  title?: string;
};

export function RendezvousRegistrationStateSection({
  rendezvousConfig,
  title = "Registration state"
}: RendezvousRegistrationStateSectionProps) {
  if (!rendezvousConfig.registration_enabled) {
    return null;
  }

  const endpointRegistrations = rendezvousConfig.endpoint_registrations;
  const connectedRegistrations = endpointRegistrations.filter(
    (endpoint) => endpoint.status === "connected"
  ).length;
  const disconnectedRegistrations = endpointRegistrations.filter(
    (endpoint) => endpoint.status === "disconnected"
  ).length;

  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <Text fw={600}>{title}</Text>
        <Badge color={disconnectedRegistrations > 0 ? "yellow" : "green"} variant="light">
          {endpointRegistrations.length === 0
            ? "no endpoints"
            : `${connectedRegistrations}/${endpointRegistrations.length} connected`}
        </Badge>
      </Group>
      <Text size="sm" c="dimmed">
        Successful registrations refresh every {rendezvousConfig.registration_interval_secs}s.
        When any rendezvous service is disconnected, the node retries every{" "}
        {rendezvousConfig.disconnected_retry_interval_secs}s until all endpoints recover.
      </Text>
      {endpointRegistrations.map((endpoint) => (
        <Card key={endpoint.url} withBorder radius="md" padding="sm">
          <Stack gap={4}>
            <Group justify="space-between" align="flex-start">
              <Text ff="monospace" size="sm" style={{ wordBreak: "break-all" }}>
                {endpoint.url}
              </Text>
              <Badge color={registrationBadgeColor(endpoint.status)} variant="light">
                {endpoint.status}
              </Badge>
            </Group>
            <Text size="sm" c="dimmed">
              Last attempt: {formatUnixTimestamp(endpoint.last_attempt_unix)}
            </Text>
            <Text size="sm" c="dimmed">
              Last success: {formatUnixTimestamp(endpoint.last_success_unix)}
            </Text>
            <Text size="sm" c="dimmed">
              Software version: {endpoint.software_version ?? "unknown"}
            </Text>
            <Text size="sm" c="dimmed">
              Consecutive failures: {endpoint.consecutive_failures}
            </Text>
            {endpoint.last_error ? (
              <Text size="sm" c="red">
                Last error: {endpoint.last_error}
              </Text>
            ) : null}
          </Stack>
        </Card>
      ))}
    </Stack>
  );
}
