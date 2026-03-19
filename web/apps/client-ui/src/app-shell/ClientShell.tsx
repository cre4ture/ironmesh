import {
  Alert,
  AppShell,
  Badge,
  Burger,
  Button,
  Card,
  Code,
  Divider,
  FileInput,
  Grid,
  Group,
  NavLink,
  NumberInput,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import {
  IconFiles,
  IconFolder,
  IconPlugConnected,
  IconRefresh,
  IconServer
} from "@tabler/icons-react";
import {
  JsonBlock,
  PageHeader,
  StatCard
} from "@ironmesh/ui";
import {
  deleteStoreValue,
  downloadBinaryObject,
  getClientHealth,
  getClientClusterNodes,
  getClientClusterStatus,
  getClientReplicationPlan,
  getClientPing,
  getStoreValue,
  getVersionGraph,
  listSnapshots,
  listStoreEntries,
  putBinaryObject,
  putStoreValue,
  type ClientUiPingResponse,
  type JsonObject,
  type SnapshotSummary,
  type StoreEntry,
  type StoreListResponse,
  type VersionGraphResponse
} from "@ironmesh/api";
import { useEffect, useState } from "react";

type PageId = "overview" | "store" | "explorer" | "cluster";

const pages = [
  {
    id: "overview" as const,
    label: "Overview",
    icon: IconPlugConnected,
    description: "Connection health, service metadata, and quick cluster summary."
  },
  {
    id: "store" as const,
    label: "Store",
    icon: IconFiles,
    description: "Text and binary object operations through the transport-aware client."
  },
  {
    id: "explorer" as const,
    label: "Explorer",
    icon: IconFolder,
    description: "Browse prefixes, snapshots, and version history."
  },
  {
    id: "cluster" as const,
    label: "Cluster",
    icon: IconServer,
    description: "Inspect cluster status, nodes, and replication planning."
  }
];

export function ClientShell() {
  const [opened, { toggle, close }] = useDisclosure();
  const [activePageId, setActivePageId] = useState<PageId>("overview");
  const [ping, setPing] = useState<ClientUiPingResponse | null>(null);
  const [health, setHealth] = useState<JsonObject | null>(null);
  const [clusterStatus, setClusterStatus] = useState<JsonObject | null>(null);
  const [overviewLoading, setOverviewLoading] = useState(true);
  const [overviewError, setOverviewError] = useState<string | null>(null);

  useEffect(() => {
    void refreshOverview();
  }, []);

  async function refreshOverview() {
    setOverviewLoading(true);
    setOverviewError(null);
    try {
      const [nextPing, nextHealth, nextClusterStatus] = await Promise.all([
        getClientPing(),
        getClientHealth(),
        getClientClusterStatus()
      ]);
      setPing(nextPing);
      setHealth(nextHealth);
      setClusterStatus(nextClusterStatus);
    } catch (error) {
      setOverviewError(error instanceof Error ? error.message : "Failed to refresh client overview");
    } finally {
      setOverviewLoading(false);
    }
  }

  return (
    <AppShell
      className="shell-root"
      header={{ height: 68 }}
      navbar={{ width: 280, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding={{ base: "xs", sm: "md", lg: "lg" }}
    >
      <AppShell.Header className="shell-header">
        <Group className="shell-header-bar" h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Stack gap={0}>
              <Text fw={800} tt="uppercase" size="sm" c="teal">
                ironmesh
              </Text>
              <Text fw={700}>Client UI</Text>
            </Stack>
          </Group>
          <Group gap="sm">
            {ping ? <Badge variant="light">{ping.service}</Badge> : null}
            <Badge color="teal" variant="filled">
              Transport-aware
            </Badge>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar className="shell-navbar" p="sm">
        <Stack gap="xs">
          {pages.map((page) => {
            const Icon = page.icon;
            return (
              <NavLink
                key={page.id}
                active={page.id === activePageId}
                label={page.label}
                description={page.description}
                leftSection={<Icon size={16} />}
                onClick={() => {
                  setActivePageId(page.id);
                  close();
                }}
              />
            );
          })}
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main className="shell-main">
        <Stack className="shell-content" gap="lg">
          {activePageId === "overview" ? (
            <OverviewPage
              ping={ping}
              health={health}
              clusterStatus={clusterStatus}
              loading={overviewLoading}
              error={overviewError}
              onRefresh={refreshOverview}
            />
          ) : null}

          {activePageId === "store" ? <StorePage /> : null}

          {activePageId === "explorer" ? <ExplorerPage /> : null}

          {activePageId === "cluster" ? (
            <ClusterPage
              health={health}
              clusterStatus={clusterStatus}
              overviewLoading={overviewLoading}
              onRefreshOverview={refreshOverview}
            />
          ) : null}
        </Stack>
      </AppShell.Main>
    </AppShell>
  );
}

type OverviewPageProps = {
  ping: ClientUiPingResponse | null;
  health: JsonObject | null;
  clusterStatus: JsonObject | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => Promise<void>;
};

function OverviewPage({ ping, health, clusterStatus, loading, error, onRefresh }: OverviewPageProps) {
  const totalNodes = getNumber(clusterStatus, "total_nodes");
  const onlineNodes = getNumber(clusterStatus, "online_nodes");
  const offlineNodes = getNumber(clusterStatus, "offline_nodes");
  const replicationFactor = getNestedNumber(clusterStatus, "policy", "replication_factor");
  const runtimeMode = typeof health?.mode === "string" ? health.mode : "runtime";

  return (
    <>
      <PageHeader
        title="Overview"
        description="Quick read of the current embedded client connection and upstream cluster state."
        actions={
          <Button leftSection={<IconRefresh size={16} />} loading={loading} onClick={() => void onRefresh()}>
            Refresh
          </Button>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
        <StatCard label="Service" value={ping?.service ?? "Loading..."} hint="Value returned by /api/ping." />
        <StatCard label="Runtime" value={runtimeMode} hint="Derived from /api/health." />
        <StatCard label="Cluster Nodes" value={totalNodes ?? "Unknown"} hint="Current total node count." />
        <StatCard
          label="Replication Factor"
          value={replicationFactor ?? "Unknown"}
          hint="Policy advertised by the upstream cluster."
        />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Connection summary</Text>
              <Group gap="sm">
                <Badge color="teal" variant="light">
                  {onlineNodes ?? 0} online
                </Badge>
                <Badge color={offlineNodes ? "yellow" : "gray"} variant="light">
                  {offlineNodes ?? 0} offline
                </Badge>
                <Badge color="blue" variant="light">
                  {totalNodes ?? 0} total
                </Badge>
              </Group>
              <Text c="dimmed" size="sm">
                This web UI runs on top of the same transport-aware Rust client used by desktop, Android, and CLI flows.
              </Text>
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Health payload</Text>
              <JsonBlock value={health ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={12}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Cluster status payload</Text>
              <JsonBlock value={clusterStatus ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function StorePage() {
  const [textUploadKey, setTextUploadKey] = useState("docs/readme.txt");
  const [textUploadValue, setTextUploadValue] = useState("hello from the React client UI");
  const [textDownloadKey, setTextDownloadKey] = useState("docs/readme.txt");
  const [textDownloadValue, setTextDownloadValue] = useState("");
  const [deleteKey, setDeleteKey] = useState("");
  const [binaryUploadKey, setBinaryUploadKey] = useState("images/demo.bin");
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [binaryDownloadKey, setBinaryDownloadKey] = useState("images/demo.bin");
  const [result, setResult] = useState<unknown>({ message: "No operation run yet." });
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function withAction<T>(action: string, run: () => Promise<T>): Promise<T | null> {
    setPendingAction(action);
    setError(null);
    try {
      return await run();
    } catch (nextError) {
      const message = nextError instanceof Error ? nextError.message : "Operation failed";
      setError(message);
      return null;
    } finally {
      setPendingAction(null);
    }
  }

  async function handleUploadText() {
    const payload = await withAction("upload-text", () => putStoreValue(textUploadKey.trim(), textUploadValue));
    if (payload) {
      setResult(payload);
    }
  }

  async function handleDownloadText() {
    const payload = await withAction("download-text", () => getStoreValue(textDownloadKey.trim()));
    if (payload) {
      setTextDownloadValue(payload.value ?? "");
      setResult(payload);
    }
  }

  async function handleDeleteObject() {
    const payload = await withAction("delete-object", () => deleteStoreValue(deleteKey.trim()));
    if (payload) {
      setResult(payload);
    }
  }

  async function handleUploadBinary() {
    if (!binaryFile) {
      setError("Select a binary file first.");
      return;
    }
    const key = binaryUploadKey.trim() || binaryFile.name;
    const payload = await withAction("upload-binary", () => putBinaryObject(key, binaryFile));
    if (payload) {
      setBinaryUploadKey(key);
      setResult({
        ...payload,
        uploaded_filename: binaryFile.name,
        uploaded_type: binaryFile.type || "application/octet-stream"
      });
    }
  }

  async function handleDownloadBinary() {
    const key = binaryDownloadKey.trim();
    if (!key) {
      setError("Binary download key must not be empty.");
      return;
    }

    const payload = await withAction("download-binary", () => downloadBinaryObject(key));
    if (payload) {
      triggerBrowserDownload(payload);
      setResult({
        key,
        saved_as: payload.filename,
        size_bytes: payload.blob.size,
        type: payload.contentType
      });
    }
  }

  return (
    <>
      <PageHeader
        title="Store"
        description="Read, write, and delete objects without dropping out of the transport-aware client path."
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Text upload</Text>
              <TextInput label="Object key" value={textUploadKey} onChange={(event) => setTextUploadKey(event.currentTarget.value)} />
              <Textarea
                label="Payload"
                autosize
                minRows={8}
                value={textUploadValue}
                onChange={(event) => setTextUploadValue(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "upload-text"} onClick={() => void handleUploadText()}>
                Upload text object
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Text download</Text>
              <TextInput
                label="Object key"
                value={textDownloadKey}
                onChange={(event) => setTextDownloadKey(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "download-text"} onClick={() => void handleDownloadText()}>
                Download text object
              </Button>
              <Textarea label="Downloaded payload" autosize minRows={8} value={textDownloadValue} readOnly />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Binary file upload</Text>
              <TextInput
                label="Object key"
                value={binaryUploadKey}
                onChange={(event) => setBinaryUploadKey(event.currentTarget.value)}
              />
              <FileInput label="File" value={binaryFile} onChange={setBinaryFile} />
              <Button loading={pendingAction === "upload-binary"} onClick={() => void handleUploadBinary()}>
                Upload binary file
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Binary file download</Text>
              <TextInput
                label="Object key"
                value={binaryDownloadKey}
                onChange={(event) => setBinaryDownloadKey(event.currentTarget.value)}
              />
              <Button loading={pendingAction === "download-binary"} onClick={() => void handleDownloadBinary()}>
                Download binary file
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Delete object</Text>
              <TextInput label="Object key" value={deleteKey} onChange={(event) => setDeleteKey(event.currentTarget.value)} />
              <Button color="red" loading={pendingAction === "delete-object"} onClick={() => void handleDeleteObject()}>
                Delete object
              </Button>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Last operation</Text>
              <JsonBlock value={result} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function ExplorerPage() {
  const [prefix, setPrefix] = useState("");
  const [depth, setDepth] = useState(1);
  const [snapshotId, setSnapshotId] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [entriesPayload, setEntriesPayload] = useState<StoreListResponse | null>(null);
  const [selectedPayload, setSelectedPayload] = useState<unknown>({ message: "Select an object or version to preview it." });
  const [versionKey, setVersionKey] = useState("");
  const [versionsPayload, setVersionsPayload] = useState<VersionGraphResponse | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshSnapshots();
    void refreshEntries();
  }, []);

  async function refreshSnapshots() {
    setLoading("snapshots");
    setError(null);
    try {
      const payload = await listSnapshots();
      setSnapshots(payload);
      if (!snapshotId && payload.length > 0) {
        setSnapshotId(payload[0]?.id ?? null);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed to load snapshots");
    } finally {
      setLoading(null);
    }
  }

  async function refreshEntries(nextPrefix?: string) {
    setLoading("entries");
    setError(null);
    const targetPrefix = nextPrefix ?? prefix;
    try {
      const payload = await listStoreEntries(targetPrefix.trim(), depth, snapshotId);
      setEntriesPayload(payload);
      if (typeof nextPrefix === "string") {
        setPrefix(nextPrefix);
      }
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed to load store entries");
    } finally {
      setLoading(null);
    }
  }

  async function readEntry(entry: StoreEntry) {
    if (entry.entry_type === "prefix" || entry.path.endsWith("/")) {
      await refreshEntries(entry.path);
      return;
    }

    setLoading("read-entry");
    setError(null);
    try {
      const payload = await getStoreValue(entry.path, snapshotId);
      setSelectedPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed reading object");
    } finally {
      setLoading(null);
    }
  }

  async function loadVersions() {
    if (!versionKey.trim()) {
      setError("Enter a key to load version history.");
      return;
    }

    setLoading("versions");
    setError(null);
    try {
      const payload = await getVersionGraph(versionKey.trim());
      setVersionsPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading versions");
    } finally {
      setLoading(null);
    }
  }

  async function readVersion(versionId: string) {
    if (!versionKey.trim()) {
      setError("Enter a key before reading a version.");
      return;
    }

    setLoading("read-version");
    setError(null);
    try {
      const payload = await getStoreValue(versionKey.trim(), null, versionId);
      setSelectedPayload(payload);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed reading version");
    } finally {
      setLoading(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Explorer"
        description="Inspect prefixes, snapshots, and version history through the same backend APIs exposed by serve-web and Android."
        actions={
          <Group gap="sm">
            <Button variant="default" loading={loading === "snapshots"} onClick={() => void refreshSnapshots()}>
              Refresh snapshots
            </Button>
            <Button leftSection={<IconRefresh size={16} />} loading={loading === "entries"} onClick={() => void refreshEntries()}>
              Refresh entries
            </Button>
          </Group>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <Grid>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Object browser</Text>
              <Grid>
                <Grid.Col span={{ base: 12, md: 6 }}>
                  <TextInput label="Prefix" value={prefix} onChange={(event) => setPrefix(event.currentTarget.value)} placeholder="docs/" />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 3 }}>
                  <NumberInput
                    label="Depth"
                    min={1}
                    value={depth}
                    onChange={(value) => setDepth(typeof value === "number" && value > 0 ? value : 1)}
                  />
                </Grid.Col>
                <Grid.Col span={{ base: 12, md: 3 }}>
                  <Select
                    label="Snapshot"
                    data={[{ value: "", label: "Current data" }, ...snapshots.map((snapshot) => ({ value: snapshot.id, label: snapshot.id }))]}
                    value={snapshotId ?? ""}
                    onChange={(value) => setSnapshotId(value || null)}
                  />
                </Grid.Col>
              </Grid>
              <Group gap="sm">
                <Button onClick={() => void refreshEntries()}>Load entries</Button>
                <Button variant="default" onClick={() => void refreshEntries(parentPrefix(prefix))}>
                  Up one prefix
                </Button>
                <Button variant="subtle" onClick={() => void refreshEntries("")}>
                  Root
                </Button>
              </Group>
              <Table.ScrollContainer minWidth={720}>
                <Table striped highlightOnHover withTableBorder>
                  <Table.Thead>
                    <Table.Tr>
                      <Table.Th>Path</Table.Th>
                      <Table.Th>Type</Table.Th>
                      <Table.Th>Action</Table.Th>
                    </Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {(entriesPayload?.entries ?? []).map((entry) => {
                      const isPrefix = entry.entry_type === "prefix" || entry.path.endsWith("/");
                      return (
                        <Table.Tr key={entry.path}>
                          <Table.Td>
                            <Code>{entry.path}</Code>
                          </Table.Td>
                          <Table.Td>{isPrefix ? "prefix" : entry.entry_type}</Table.Td>
                          <Table.Td>
                            <Button size="xs" variant="light" onClick={() => void readEntry(entry)}>
                              {isPrefix ? "Open" : "Read"}
                            </Button>
                          </Table.Td>
                        </Table.Tr>
                      );
                    })}
                  </Table.Tbody>
                </Table>
              </Table.ScrollContainer>
              {entriesPayload ? <JsonBlock value={entriesPayload} /> : null}
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Stack gap="lg">
            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Text fw={700}>Selected payload</Text>
                <JsonBlock value={selectedPayload} />
              </Stack>
            </Card>

            <Card withBorder radius="md" padding="lg">
              <Stack gap="sm">
                <Text fw={700}>Version history</Text>
                <TextInput label="Key" value={versionKey} onChange={(event) => setVersionKey(event.currentTarget.value)} placeholder="docs/readme.txt" />
                <Button loading={loading === "versions"} onClick={() => void loadVersions()}>
                  Load versions
                </Button>
                <Table.ScrollContainer minWidth={520}>
                  <Table striped highlightOnHover withTableBorder>
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th>Version ID</Table.Th>
                        <Table.Th>Action</Table.Th>
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {(versionsPayload?.versions ?? []).map((version) => (
                        <Table.Tr key={version.version_id}>
                          <Table.Td>
                            <Code>{version.version_id}</Code>
                          </Table.Td>
                          <Table.Td>
                            <Button size="xs" variant="light" onClick={() => void readVersion(version.version_id)}>
                              Read
                            </Button>
                          </Table.Td>
                        </Table.Tr>
                      ))}
                    </Table.Tbody>
                  </Table>
                </Table.ScrollContainer>
                <Divider />
                <JsonBlock value={versionsPayload ?? { message: "No version graph loaded yet." }} />
              </Stack>
            </Card>
          </Stack>
        </Grid.Col>
      </Grid>
    </>
  );
}

type ClusterPageProps = {
  health: JsonObject | null;
  clusterStatus: JsonObject | null;
  overviewLoading: boolean;
  onRefreshOverview: () => Promise<void>;
};

function ClusterPage({ health, clusterStatus, overviewLoading, onRefreshOverview }: ClusterPageProps) {
  const [nodes, setNodes] = useState<unknown[] | null>(null);
  const [replicationPlan, setReplicationPlan] = useState<JsonObject | null>(null);
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void refreshNodes();
    void refreshReplicationPlan();
  }, []);

  async function refreshNodes() {
    setLoading("nodes");
    setError(null);
    try {
      setNodes(await getClientClusterNodes());
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading nodes");
    } finally {
      setLoading(null);
    }
  }

  async function refreshReplicationPlan() {
    setLoading("replication");
    setError(null);
    try {
      setReplicationPlan(await getClientReplicationPlan());
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Failed loading replication plan");
    } finally {
      setLoading(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Cluster"
        description="Operational cluster details exposed through the client web backend."
        actions={
          <Group gap="sm">
            <Button variant="default" loading={overviewLoading} onClick={() => void onRefreshOverview()}>
              Refresh status
            </Button>
            <Button variant="default" loading={loading === "nodes"} onClick={() => void refreshNodes()}>
              Refresh nodes
            </Button>
            <Button variant="default" loading={loading === "replication"} onClick={() => void refreshReplicationPlan()}>
              Refresh replication
            </Button>
          </Group>
        }
      />

      {error ? <Alert color="red">{error}</Alert> : null}

      <SimpleGrid cols={{ base: 1, md: 2, xl: 4 }}>
        <StatCard label="Total nodes" value={getNumber(clusterStatus, "total_nodes") ?? "Unknown"} />
        <StatCard label="Online nodes" value={getNumber(clusterStatus, "online_nodes") ?? "Unknown"} />
        <StatCard label="Under replicated" value={getNumber(replicationPlan, "under_replicated") ?? "Unknown"} />
        <StatCard label="Over replicated" value={getNumber(replicationPlan, "over_replicated") ?? "Unknown"} />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Health</Text>
              <JsonBlock value={health ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Cluster status</Text>
              <JsonBlock value={clusterStatus ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Nodes</Text>
              <JsonBlock value={nodes ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, lg: 6 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="sm">
              <Text fw={700}>Replication plan</Text>
              <JsonBlock value={replicationPlan ?? { status: "loading" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </>
  );
}

function getNumber(value: JsonObject | null, key: string): number | null {
  if (!value) {
    return null;
  }
  const candidate = value[key];
  return typeof candidate === "number" ? candidate : null;
}

function getNestedNumber(value: JsonObject | null, key: string, nestedKey: string): number | null {
  if (!value) {
    return null;
  }
  const nested = value[key];
  if (!nested || typeof nested !== "object" || Array.isArray(nested)) {
    return null;
  }
  const candidate = (nested as JsonObject)[nestedKey];
  return typeof candidate === "number" ? candidate : null;
}

function parentPrefix(path: string): string {
  const normalized = path.replace(/\/+$/, "");
  if (!normalized.includes("/")) {
    return "";
  }
  return normalized.split("/").slice(0, -1).join("/") + "/";
}

function triggerBrowserDownload(payload: { blob: Blob; filename: string }) {
  const objectUrl = URL.createObjectURL(payload.blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = payload.filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}
