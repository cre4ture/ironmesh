import { useQuery } from "@tanstack/react-query";
import {
  getDataChangeEvents,
  type DataChangeAction,
  type DataChangeActorKind,
  type DataChangeEventsCursor,
  type DataChangeEvent
} from "@ironmesh/api";
import { ironmeshPrimaryColor, StatCard } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput
} from "@mantine/core";
import { useDeferredValue, useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatBytes, formatUnixTs } from "../lib/format";

const DATA_CHANGE_POLL_INTERVAL_MS = 5_000;
const LIMIT_OPTIONS = ["50", "100", "200", "500"].map((value) => ({
  value,
  label: `${value} recent events`
}));
const ACTION_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "", label: "All actions" },
  { value: "upload", label: "Uploads" },
  { value: "rename", label: "Renames / moves" },
  { value: "copy", label: "Copies" },
  { value: "delete", label: "Deletes" }
];

export function DataChangesPage() {
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const loginRequired = sessionStatus?.login_required ?? true;
  const canInspectDataChanges =
    !sessionLoading && (!loginRequired || hasExplicitAdminAccess);
  const [actionFilter, setActionFilter] = useState<string>("");
  const [pathFilter, setPathFilter] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const [limit, setLimit] = useState("200");
  const [pageCursor, setPageCursor] = useState<DataChangeEventsCursor | null>(null);
  const [cursorHistory, setCursorHistory] = useState<Array<DataChangeEventsCursor | null>>([]);
  const deferredPathFilter = useDeferredValue(pathFilter.trim());
  const deferredActorFilter = useDeferredValue(actorFilter.trim());
  const resolvedLimit = clampLimit(limit);
  const pageIndex = cursorHistory.length;

  useEffect(() => {
    setPageCursor(null);
    setCursorHistory([]);
  }, [normalizedAdminTokenOverride, actionFilter, deferredPathFilter, deferredActorFilter, resolvedLimit]);

  const eventsQuery = useQuery({
    queryKey: [
      "data-changes",
      normalizedAdminTokenOverride,
      actionFilter,
      deferredPathFilter,
      deferredActorFilter,
      resolvedLimit,
      pageCursor?.created_at_unix ?? null,
      pageCursor?.event_id ?? null
    ],
    queryFn: () =>
      getDataChangeEvents(
        {
          limit: resolvedLimit,
          action: normalizeActionFilter(actionFilter),
          pathPrefix: deferredPathFilter || undefined,
          actor: deferredActorFilter || undefined,
          before: pageCursor
        },
        normalizedAdminTokenOverride || undefined
      ),
    enabled: canInspectDataChanges,
    refetchInterval: DATA_CHANGE_POLL_INTERVAL_MS
  });

  const entries = canInspectDataChanges ? eventsQuery.data?.entries ?? [] : [];
  const nextCursor = eventsQuery.data?.next_cursor ?? null;
  const uploadCount = entries.filter((entry) => entry.action === "upload").length;
  const deleteCount = entries.filter((entry) => entry.action === "delete").length;
  const attributedCount = entries.filter((entry) => entry.actor_kind !== "unknown").length;

  function handleOlderPage() {
    if (!nextCursor || eventsQuery.isFetching) {
      return;
    }
    setCursorHistory((current) => [...current, pageCursor]);
    setPageCursor(nextCursor);
  }

  function handleNewerPage() {
    setCursorHistory((current) => {
      if (current.length === 0) {
        setPageCursor(null);
        return current;
      }
      const previousCursor = current[current.length - 1] ?? null;
      setPageCursor(previousCursor);
      return current.slice(0, -1);
    });
  }

  if (!canInspectDataChanges) {
    return (
      <Stack gap="lg">
        <Alert color="yellow" title="Admin access required">
          Sign in with the local admin password to inspect node-local data changes and client
          identity attribution.
        </Alert>
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {eventsQuery.error ? (
        <Alert color="red" title="Request failed">
          {eventsQuery.error instanceof Error ? eventsQuery.error.message : String(eventsQuery.error)}
        </Alert>
      ) : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={820}>
          Inspect the recent node-local feed of uploaded, renamed, copied, and deleted data.
          Attribution follows client identity and optional credential labels when they are known to
          this node; there is no separate user-account model yet.
        </Text>
        <Button variant="light" onClick={() => void eventsQuery.refetch()} loading={eventsQuery.isFetching}>
          Refresh
        </Button>
      </Group>
      <SimpleGrid cols={{ base: 1, md: 4 }}>
        <StatCard label="Loaded Events" value={entries.length} hint={`Current filter window (${resolvedLimit} max)`} />
        <StatCard label="Uploads" value={uploadCount} hint="Direct and chunked uploads" />
        <StatCard label="Deletes" value={deleteCount} hint="Recursive deletes count as one event" />
        <StatCard label="Attributed" value={attributedCount} hint="Client or admin identity attached" />
      </SimpleGrid>
      <Card withBorder radius="md" padding="lg">
        <Group align="end" grow>
          <Select
            label="Action"
            data={ACTION_OPTIONS}
            value={actionFilter}
            onChange={(value) => setActionFilter(value ?? "")}
            allowDeselect={false}
          />
          <TextInput
            label="Path Prefix"
            placeholder="docs/ or photos/2026/"
            value={pathFilter}
            onChange={(event) => setPathFilter(event.currentTarget.value)}
          />
          <TextInput
            label="Identity"
            placeholder="device id, label, or credential fingerprint"
            value={actorFilter}
            onChange={(event) => setActorFilter(event.currentTarget.value)}
          />
          <Select
            label="Limit"
            data={LIMIT_OPTIONS}
            value={limit}
            onChange={(value) => setLimit(value ?? "200")}
            allowDeselect={false}
          />
        </Group>
      </Card>
      <Card withBorder radius="md" padding="lg">
        <Group justify="space-between" align="center" mb="md">
          <Stack gap={4}>
            <Text size="sm" fw={600}>
              Page {pageIndex + 1}
            </Text>
            <Text size="xs" c="dimmed">
              Showing {entries.length} events with backend pagination.
            </Text>
          </Stack>
          <Group gap="xs">
            <Button
              size="xs"
              variant="default"
              onClick={handleNewerPage}
              disabled={pageIndex === 0 || eventsQuery.isFetching}
            >
              Newer
            </Button>
            <Button
              size="xs"
              variant="default"
              onClick={handleOlderPage}
              disabled={!nextCursor || eventsQuery.isFetching}
            >
              Older
            </Button>
          </Group>
        </Group>
        {eventsQuery.isLoading ? (
          <Text c="dimmed">Loading data change activity...</Text>
        ) : entries.length === 0 ? (
          <Text c="dimmed">No matching data changes were recorded for the selected filters.</Text>
        ) : (
          <Table striped highlightOnHover withTableBorder>
            <Table.Thead>
              <Table.Tr>
                <Table.Th>When</Table.Th>
                <Table.Th>Action</Table.Th>
                <Table.Th>Path</Table.Th>
                <Table.Th>Change</Table.Th>
                <Table.Th>Identity</Table.Th>
                <Table.Th>Details</Table.Th>
              </Table.Tr>
            </Table.Thead>
            <Table.Tbody>
              {entries.map((entry) => (
                <Table.Tr key={entry.event_id}>
                  <Table.Td>
                    <Text size="sm">{formatUnixTs(entry.created_at_unix)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Badge color={actionBadgeColor(entry.action)} variant="light">
                      {actionLabel(entry.action)}
                    </Badge>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm" fw={600}>
                      {entry.path}
                    </Text>
                    <Text size="xs" c="dimmed">
                      node {entry.recorded_by_node_id}
                    </Text>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{describeChange(entry)}</Text>
                  </Table.Td>
                  <Table.Td>
                    <Stack gap={4}>
                      <Group gap="xs">
                        <Badge color={actorKindBadgeColor(entry.actor_kind)} variant="light">
                          {actorKindLabel(entry.actor_kind)}
                        </Badge>
                      </Group>
                      <Text size="sm">{describeIdentity(entry)}</Text>
                      {entry.actor_credential_fingerprint ? (
                        <Text size="xs" c="dimmed">
                          credential {entry.actor_credential_fingerprint}
                        </Text>
                      ) : null}
                    </Stack>
                  </Table.Td>
                  <Table.Td>
                    <Text size="sm">{describeDetails(entry)}</Text>
                    {entry.actor_source_node ? (
                      <Text size="xs" c="dimmed">
                        actor source node {entry.actor_source_node}
                      </Text>
                    ) : null}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Card>
    </Stack>
  );
}

function clampLimit(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) {
    return 200;
  }
  return Math.max(1, Math.min(1000, parsed));
}

function normalizeActionFilter(value: string): DataChangeAction | undefined {
  switch (value) {
    case "upload":
    case "rename":
    case "copy":
    case "delete":
      return value;
    default:
      return undefined;
  }
}

function actionLabel(action: DataChangeAction): string {
  switch (action) {
    case "upload":
      return "uploaded";
    case "rename":
      return "renamed";
    case "copy":
      return "copied";
    case "delete":
      return "deleted";
  }
}

function actionBadgeColor(action: DataChangeAction): string {
  switch (action) {
    case "upload":
      return "blue";
    case "rename":
      return ironmeshPrimaryColor;
    case "copy":
      return "cyan";
    case "delete":
      return "red";
  }
}

function actorKindLabel(kind: DataChangeActorKind): string {
  switch (kind) {
    case "client":
      return "client";
    case "admin":
      return "admin";
    case "unknown":
      return "unknown";
  }
}

function actorKindBadgeColor(kind: DataChangeActorKind): string {
  switch (kind) {
    case "client":
      return "indigo";
    case "admin":
      return "grape";
    case "unknown":
      return "gray";
  }
}

function describeChange(entry: DataChangeEvent): string {
  if (entry.from_path && entry.to_path) {
    return `${entry.from_path} -> ${entry.to_path}`;
  }
  if (entry.action === "delete" && entry.recursive) {
    return `recursive delete across ${entry.affected_path_count} paths`;
  }
  if (entry.action === "delete" && entry.affected_path_count > 1) {
    return `${entry.affected_path_count} paths deleted`;
  }
  return entry.path;
}

function describeIdentity(entry: DataChangeEvent): string {
  if (entry.actor_label && entry.actor_id && entry.actor_label !== entry.actor_id) {
    return `${entry.actor_label} (${entry.actor_id})`;
  }
  return entry.actor_label ?? entry.actor_id ?? "identity unavailable";
}

function describeDetails(entry: DataChangeEvent): string {
  const parts: string[] = [];
  if (entry.upload_mode) {
    parts.push(`${entry.upload_mode} upload`);
  }
  if (entry.total_size_bytes != null) {
    parts.push(formatBytes(entry.total_size_bytes));
  }
  if (entry.version_id) {
    parts.push(`version ${entry.version_id}`);
  }
  if (entry.snapshot_id) {
    parts.push(`snapshot ${entry.snapshot_id}`);
  }
  if (entry.action === "delete" && entry.affected_path_count > 1) {
    parts.push(`${entry.affected_path_count} paths`);
  }
  return parts.length > 0 ? parts.join(" • ") : "-";
}
