import { Grid, Stack, Text } from "@mantine/core";
import { JsonBlock, StatCard } from "@ironmesh/ui";

export function DashboardPage() {
  return (
    <Stack gap="lg">
      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard label="Cluster Nodes" value="2 / 2" hint="Placeholder data from scaffold" />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard label="Objects" value="0" hint="Will later come from /health and store summaries" />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard label="Replication" value="Healthy" hint="Will later reflect plan and repair status" />
        </Grid.Col>
      </Grid>
      <Text c="dimmed">
        This page is the landing target for the future runtime dashboard, replication overview, and cluster health cards.
      </Text>
      <JsonBlock
        value={{
          next_steps: ["wire live admin session status", "load cluster summary", "render replication cards"]
        }}
      />
    </Stack>
  );
}
