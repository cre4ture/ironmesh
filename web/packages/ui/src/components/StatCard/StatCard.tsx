import { Card, Stack, Text, Title } from "@mantine/core";
import type { ReactNode } from "react";

type StatCardProps = {
  label: string;
  value: ReactNode;
  hint?: string;
  testId?: string;
};

export function StatCard({ label, value, hint, testId }: StatCardProps) {
  return (
    <Card withBorder radius="md" padding="lg" data-testid={testId}>
      <Stack gap={6}>
        <Text size="sm" tt="uppercase" fw={700} c="dimmed">
          {label}
        </Text>
        <Title order={3}>{value}</Title>
        {hint ? (
          <Text size="sm" c="dimmed">
            {hint}
          </Text>
        ) : null}
      </Stack>
    </Card>
  );
}
