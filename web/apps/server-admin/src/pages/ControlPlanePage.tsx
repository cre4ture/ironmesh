import { Card, Stack, Text } from "@mantine/core";

export function ControlPlanePage() {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Text fw={700}>Control-plane promotion</Text>
        <Text c="dimmed">
          This page will replace the current signer backup, managed rendezvous failover, and combined control-plane promotion JSON tools.
        </Text>
      </Stack>
    </Card>
  );
}
