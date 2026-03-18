import { Card, Stack, Text } from "@mantine/core";

export function ClientCredentialsPage() {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Text fw={700}>Client credentials</Text>
        <Text c="dimmed">
          This page will replace the current JSON-heavy listing and revocation controls with a searchable credential management view.
        </Text>
      </Stack>
    </Card>
  );
}
