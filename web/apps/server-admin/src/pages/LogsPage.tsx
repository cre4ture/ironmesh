import { getRecentLogs, type LogsResponse } from "@ironmesh/api";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  NumberInput,
  Stack,
  Text
} from "@mantine/core";
import { useCallback, useEffect, useRef, useState, type UIEvent } from "react";
import { useAdminAccess } from "../lib/admin-access";

const LOGS_POLL_INTERVAL_MS = 3_000;
const LOGS_AUTO_FOLLOW_THRESHOLD_PX = 24;

export function LogsPage() {
  const { adminTokenOverride } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const [limit, setLimit] = useState<number | string>(200);
  const [logs, setLogs] = useState<LogsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logsAutoFollow, setLogsAutoFollow] = useState(true);
  const logsViewportRef = useRef<HTMLDivElement | null>(null);
  const logsScrollReadyRef = useRef(false);
  const logEntries = logs?.entries ?? [];
  const latestLogEntry = logEntries.length > 0 ? logEntries[logEntries.length - 1] : null;

  const refresh = useCallback(async (options?: { background?: boolean }) => {
    const background = options?.background ?? false;
    if (background) {
      setRefreshing(true);
    } else {
      setLoading(true);
      setError(null);
    }
    try {
      const resolvedLimit =
        typeof limit === "number" && Number.isFinite(limit) ? Math.max(1, Math.min(1000, limit)) : 200;
      const payload = await getRecentLogs(
        resolvedLimit,
        normalizedAdminTokenOverride || undefined
      );
      setLogs(payload);
      setError(null);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      if (background) {
        setRefreshing(false);
      } else {
        setLoading(false);
      }
    }
  }, [limit, normalizedAdminTokenOverride]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      void refresh({ background: true });
    }, LOGS_POLL_INTERVAL_MS);

    return () => window.clearInterval(intervalId);
  }, [refresh]);

  const handleLogsScroll = useCallback((event: UIEvent<HTMLDivElement>) => {
    if (!logsScrollReadyRef.current) {
      return;
    }

    const viewport = event.currentTarget;
    const distanceFromBottom =
      viewport.scrollHeight - (viewport.scrollTop + viewport.clientHeight);
    setLogsAutoFollow(distanceFromBottom <= LOGS_AUTO_FOLLOW_THRESHOLD_PX);
  }, []);

  useEffect(() => {
    if (!logsAutoFollow) {
      return;
    }

    const viewport = logsViewportRef.current;
    if (!viewport) {
      return;
    }

    const frame = window.requestAnimationFrame(() => {
      viewport.scrollTo({
        top: viewport.scrollHeight,
        behavior: "auto"
      });
      logsScrollReadyRef.current = true;
      setLogsAutoFollow(true);
    });

    return () => window.cancelAnimationFrame(frame);
  }, [logsAutoFollow, logEntries.length, latestLogEntry]);

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Failed to load logs">{error}</Alert> : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This page is the dedicated replacement for the old inline runtime log block. It keeps a live tail by default,
          while still letting you scroll back through recent raw server output when you need to inspect older entries.
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
          <Group justify="space-between" align="flex-start">
            <Text fw={700}>Recent server logs</Text>
            <Group gap="xs">
              <Badge variant="light" color={logsAutoFollow ? "teal" : "gray"}>
                {logsAutoFollow ? "live tail" : "scroll paused"}
              </Badge>
              <Badge variant="light" color={refreshing ? "blue" : "gray"}>
                {refreshing ? "updating" : "auto refresh"}
              </Badge>
            </Group>
          </Group>
          <div
            ref={logsViewportRef}
            onScroll={handleLogsScroll}
            role="log"
            aria-live={logsAutoFollow ? "polite" : "off"}
            style={{
              maxHeight: 640,
              overflowY: "scroll",
              overflowX: "auto",
              paddingRight: 8
            }}
          >
            <Text ff="monospace" size="sm" style={{ whiteSpace: "pre-wrap" }}>
              {logEntries.length > 0 ? logEntries.join("\n") : loading ? "loading..." : "no logs yet"}
            </Text>
          </div>
        </Stack>
      </Card>
    </Stack>
  );
}
