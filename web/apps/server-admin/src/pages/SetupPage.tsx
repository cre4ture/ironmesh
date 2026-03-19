import { Alert, Card, List, Stack, Text } from "@mantine/core";

export function SetupPage() {
  return (
    <Stack gap="lg">
      <Alert color="teal" title="First-run setup is still separate today">
        The dedicated bootstrap setup UI is still served by the existing zero-touch first-run path. This React app is starting with the runtime admin surface first.
      </Alert>
      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>What still uses the existing setup UI</Text>
          <List>
            <List.Item>Start a new cluster</List.Item>
            <List.Item>Generate join request</List.Item>
            <List.Item>Import node enrollment package</List.Item>
            <List.Item>Runtime handoff immediately after setup</List.Item>
          </List>
        </Stack>
      </Card>
      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>What this new runtime UI already targets</Text>
          <List>
            <List.Item>Admin session and token override management</List.Item>
            <List.Item>Client bootstrap issuance</List.Item>
            <List.Item>Join-request enrollment approval</List.Item>
            <List.Item>Certificate status</List.Item>
            <List.Item>Control-plane promotion</List.Item>
          </List>
        </Stack>
      </Card>
    </Stack>
  );
}
