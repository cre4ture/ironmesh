import { getRecentLogs, type LogsResponse } from "@ironmesh/api";
import {
  Alert,
  Button,
  Card,
  Group,
  NumberInput,
  ScrollArea,
  Stack,
  Text
} from "@mantine/core";
import { useCallback, useEffect, useState } from "react";

export function LogsPage() {
  const [limit, setLimit] = useState<number | string>(200);
  const [logs, setLogs] = useState<LogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resolvedLimit =
        typeof limit === "number" && Number.isFinite(limit) ? Math.max(1, Math.min(1000, limit)) : 200;
      const payload = await getRecentLogs(resolvedLimit);
      setLogs(payload);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      setLoading(false);
    }
  }, [limit]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Failed to load logs">{error}</Alert> : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page is the dedicated replacement for the old inline runtime log block. It keeps the view simple
          on purpose: choose how many recent entries you want, refresh, and inspect the raw server output.
        </Text>
        <Group align="end">
          <NumberInput
            label="Entries"
            min={1}
            max={1000}
            value={limit}
            onChange={setLimit}
            w={140}
          />
          <Button variant="light" onClick={() => void refresh()} loading={loading}>
            Refresh
          </Button>
        </Group>
      </Group>
      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>Recent server logs</Text>
          <ScrollArea type="auto" mah={640}>
            <Text ff="monospace" size="sm" style={{ whiteSpace: "pre-wrap" }}>
              {logs?.entries?.join("\n") || (loading ? "loading..." : "no logs yet")}
            </Text>
          </ScrollArea>
        </Stack>
      </Card>
    </Stack>
  );
}
