import { Card, Stack, Text } from "@mantine/core";

export function CertificatesPage() {
  return (
    <Card withBorder radius="md" padding="lg">
      <Stack gap="sm">
        <Text fw={700}>Certificate lifecycle</Text>
        <Text c="dimmed">
          This page will show public/internal certificate state, auto-renew details, and restart or live-reload indicators.
        </Text>
      </Stack>
    </Card>
  );
}
