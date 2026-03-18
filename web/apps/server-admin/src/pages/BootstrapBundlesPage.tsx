import { Card, Stack, Text } from "@mantine/core";

export function BootstrapBundlesPage() {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Text fw={700}>Bootstrap and enrollment tools</Text>
        <Text c="dimmed">
          This page is the future home for bootstrap bundle issuance, node enrollment from join requests, and QR-friendly export flows.
        </Text>
      </Stack>
    </Card>
  );
}
