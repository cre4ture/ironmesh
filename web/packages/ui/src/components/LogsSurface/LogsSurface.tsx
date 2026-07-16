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
import { useCallback, useEffect, useRef, useState, type ReactNode, type UIEvent } from "react";
import { ironmeshPrimaryColor } from "../../theme/ironmesh-theme";

type LogEntry = {
  captured_at_unix: number;
  line: string;
};

type LogsPayload = {
  entries: LogEntry[];
};

type LogsSurfaceProps = {
  description: ReactNode;
  loadLogs: (limit: number) => Promise<LogsPayload>;
  cardTitle?: ReactNode;
  emptyStateLabel?: string;
};

const LOGS_POLL_INTERVAL_MS = 3_000;
const LOGS_AUTO_FOLLOW_THRESHOLD_PX = 24;

export function LogsSurface({
  description,
  loadLogs,
  cardTitle = "Recent server logs",
  emptyStateLabel = "no logs yet"
}: LogsSurfaceProps) {
  const [limit, setLimit] = useState<number | string>(200);
  const [logs, setLogs] = useState<LogsPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logsAutoFollow, setLogsAutoFollow] = useState(true);
  const logsViewportRef = useRef<HTMLDivElement | null>(null);
  const logsScrollReadyRef = useRef(false);
  const logEntries = logs?.entries ?? [];
  const latestLogEntry = logEntries.length > 0 ? logEntries[logEntries.length - 1] : null;
  const renderedLogEntries = logEntries.flatMap(renderLogEntry);

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
        typeof limit === "number" && Number.isFinite(limit)
          ? Math.max(1, Math.min(1000, Math.trunc(limit)))
          : 200;
      const payload = await loadLogs(resolvedLimit);
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
  }, [limit, loadLogs]);

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
          {description}
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
            <Text fw={700}>{cardTitle}</Text>
            <Group gap="xs">
              <Badge variant="light" color={logsAutoFollow ? ironmeshPrimaryColor : "gray"}>
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
              {renderedLogEntries.length > 0
                ? renderedLogEntries.join("\n")
                : loading
                  ? "loading..."
                  : emptyStateLabel}
            </Text>
          </div>
        </Stack>
      </Card>
    </Stack>
  );
}

function formatUnixTs(unixTs?: number | null): string {
  if (!unixTs || !Number.isFinite(unixTs) || unixTs <= 0) {
    return "unknown";
  }

  return new Date(unixTs * 1000).toISOString();
}

function renderLogEntry(entry: LogEntry): string[] {
  const prefix = formatUnixTs(entry.captured_at_unix);
  const lines = entry.line.replace(/\r\n?/g, "\n").split("\n");

  while (lines.length > 1 && lines[lines.length - 1] === "") {
    lines.pop();
  }

  return lines.map((line) => (line.length > 0 ? `${prefix} ${line}` : prefix));
}
