import { Alert, List, Stack, Text } from "@mantine/core";

export function SetupPage() {
  return (
    <Stack gap="lg">
      <Alert color="teal" title="Setup migration target">
        This page will absorb both the current bootstrap setup UI and the runtime-admin setup-related flows.
      </Alert>
      <Text c="dimmed">
        Planned scope:
      </Text>
      <List>
        <List.Item>Start a new cluster</List.Item>
        <List.Item>Generate join request</List.Item>
        <List.Item>Import node enrollment package</List.Item>
        <List.Item>Runtime handoff after setup completion</List.Item>
      </List>
    </Stack>
  );
}
