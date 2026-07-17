import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  createS3AccessKey,
  createS3Bucket,
  deleteS3Bucket,
  getS3ControlPlaneStatus,
  listS3AccessKeys,
  listS3Buckets,
  revokeS3AccessKey,
  type CreateS3AccessKeyResponse,
  type S3AccessKeyView,
  type S3BucketVersioningStatus
} from "@ironmesh/api";
import { ironmeshPrimaryColor, JsonBlock, StatCard } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Checkbox,
  Code,
  Grid,
  Group,
  ScrollArea,
  Select,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { useCallback, useMemo, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatRelativeUnixTs, formatUnixTs } from "../lib/format";

const S3_QUERY_REFRESH_INTERVAL_MS = 5000;

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function parseScopeValues(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(/[\r\n,]+/)
        .map((entry) => entry.trim())
        .filter((entry) => entry.length > 0)
    )
  ).sort();
}

function joinScopeValues(values: string[], emptyLabel: string): string {
  return values.length > 0 ? values.join(", ") : emptyLabel;
}

function accessKeyStatusColor(accessKey: S3AccessKeyView): string {
  return accessKey.revoked_at_unix ? "red" : ironmeshPrimaryColor;
}

function bucketModeLabel(readOnly: boolean): string {
  return readOnly ? "read-only" : "read/write";
}

export function S3ControlPlanePage() {
  const queryClient = useQueryClient();
  const { adminTokenOverride, sessionStatus, sessionLoading } = useAdminAccess();
  const [bucketName, setBucketName] = useState("");
  const [bucketRootPrefix, setBucketRootPrefix] = useState("");
  const [bucketVersioningStatus, setBucketVersioningStatus] =
    useState<S3BucketVersioningStatus>("disabled");
  const [bucketReadOnly, setBucketReadOnly] = useState(false);
  const [accessKeyDescription, setAccessKeyDescription] = useState("");
  const [bucketScopeText, setBucketScopeText] = useState("");
  const [prefixScopeText, setPrefixScopeText] = useState("");
  const [allowList, setAllowList] = useState(true);
  const [allowRead, setAllowRead] = useState(true);
  const [allowWrite, setAllowWrite] = useState(false);
  const [allowDelete, setAllowDelete] = useState(false);
  const [allowManage, setAllowManage] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [latestCreatedAccessKey, setLatestCreatedAccessKey] =
    useState<CreateS3AccessKeyResponse | null>(null);
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  const adminCredential = normalizedAdminTokenOverride || undefined;
  const loginRequired = sessionStatus?.login_required ?? true;
  const hasExplicitAdminAccess =
    Boolean(normalizedAdminTokenOverride) || Boolean(sessionStatus?.authenticated);
  const canInspectS3 = !sessionLoading && (!loginRequired || hasExplicitAdminAccess);

  const statusQueryKey = ["s3-page", "status", normalizedAdminTokenOverride] as const;
  const bucketsQueryKey = ["s3-page", "buckets", normalizedAdminTokenOverride] as const;
  const accessKeysQueryKey = ["s3-page", "access-keys", normalizedAdminTokenOverride] as const;

  const statusQuery = useQuery({
    queryKey: statusQueryKey,
    queryFn: () => getS3ControlPlaneStatus(adminCredential),
    enabled: canInspectS3,
    refetchInterval: canInspectS3 ? S3_QUERY_REFRESH_INTERVAL_MS : false
  });
  const bucketsQuery = useQuery({
    queryKey: bucketsQueryKey,
    queryFn: () => listS3Buckets(adminCredential),
    enabled: canInspectS3,
    refetchInterval: canInspectS3 ? S3_QUERY_REFRESH_INTERVAL_MS : false
  });
  const accessKeysQuery = useQuery({
    queryKey: accessKeysQueryKey,
    queryFn: () => listS3AccessKeys(adminCredential),
    enabled: canInspectS3,
    refetchInterval: canInspectS3 ? S3_QUERY_REFRESH_INTERVAL_MS : false
  });

  const refreshAll = useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: statusQueryKey, exact: true }),
      queryClient.invalidateQueries({ queryKey: bucketsQueryKey, exact: true }),
      queryClient.invalidateQueries({ queryKey: accessKeysQueryKey, exact: true })
    ]);
  }, [accessKeysQueryKey, bucketsQueryKey, queryClient, statusQueryKey]);

  const createBucketMutation = useMutation({
    mutationFn: async () => createS3Bucket(
      {
        bucket_name: bucketName.trim(),
        root_prefix: bucketRootPrefix.trim() || null,
        versioning_status: bucketVersioningStatus,
        read_only: bucketReadOnly
      },
      adminCredential
    ),
    onSuccess: async () => {
      setBucketName("");
      setBucketRootPrefix("");
      setBucketVersioningStatus("disabled");
      setBucketReadOnly(false);
      await refreshAll();
    }
  });

  const deleteBucketMutation = useMutation({
    mutationFn: async (targetBucketName: string) => deleteS3Bucket(targetBucketName, adminCredential),
    onSuccess: async () => {
      await refreshAll();
    }
  });

  const createAccessKeyMutation = useMutation({
    mutationFn: async () => createS3AccessKey(
      {
        description: accessKeyDescription.trim() || null,
        bucket_scope: parseScopeValues(bucketScopeText),
        prefix_scope: parseScopeValues(prefixScopeText),
        allow_list: allowList,
        allow_read: allowRead,
        allow_write: allowWrite,
        allow_delete: allowDelete,
        allow_manage: allowManage
      },
      adminCredential
    ),
    onSuccess: async (payload) => {
      setLatestCreatedAccessKey(payload);
      setAccessKeyDescription("");
      setBucketScopeText("");
      setPrefixScopeText("");
      setAllowList(true);
      setAllowRead(true);
      setAllowWrite(false);
      setAllowDelete(false);
      setAllowManage(false);
      await refreshAll();
    }
  });

  const revokeAccessKeyMutation = useMutation({
    mutationFn: async (accessKeyId: string) => revokeS3AccessKey(accessKeyId, adminCredential),
    onSuccess: async () => {
      await refreshAll();
    }
  });

  const bucketRows = bucketsQuery.data ?? [];
  const accessKeyRows = accessKeysQuery.data ?? [];
  const activeAccessKeyCount = accessKeyRows.filter((accessKey) => accessKey.revoked_at_unix == null).length;
  const revokedAccessKeyCount = accessKeyRows.length - activeAccessKeyCount;
  const loading =
    statusQuery.isFetching ||
    bucketsQuery.isFetching ||
    accessKeysQuery.isFetching ||
    createBucketMutation.isPending ||
    deleteBucketMutation.isPending ||
    createAccessKeyMutation.isPending ||
    revokeAccessKeyMutation.isPending;
  const queryError = statusQuery.error ?? bucketsQuery.error ?? accessKeysQuery.error;
  const status = statusQuery.data ?? null;

  const latestPermissionsLabel = useMemo(() => {
    if (!latestCreatedAccessKey) {
      return null;
    }
    const labels = [
      latestCreatedAccessKey.view.allow_list ? "list" : null,
      latestCreatedAccessKey.view.allow_read ? "read" : null,
      latestCreatedAccessKey.view.allow_write ? "write" : null,
      latestCreatedAccessKey.view.allow_delete ? "delete" : null,
      latestCreatedAccessKey.view.allow_manage ? "manage" : null
    ].filter((value): value is string => value != null);
    return labels.join(", ");
  }, [latestCreatedAccessKey]);

  async function handleCreateBucket() {
    if (!canInspectS3) {
      return;
    }
    setActionError(null);
    try {
      await createBucketMutation.mutateAsync();
    } catch (error) {
      setActionError(describeError(error));
    }
  }

  async function handleDeleteBucket(targetBucketName: string) {
    if (!canInspectS3) {
      return;
    }
    const confirmed = window.confirm(
      `Delete the S3 bucket mapping ${targetBucketName}? This only succeeds when the mapped prefix is empty.`
    );
    if (!confirmed) {
      return;
    }
    setActionError(null);
    try {
      await deleteBucketMutation.mutateAsync(targetBucketName);
    } catch (error) {
      setActionError(describeError(error));
    }
  }

  async function handleCreateAccessKey() {
    if (!canInspectS3) {
      return;
    }
    setActionError(null);
    try {
      await createAccessKeyMutation.mutateAsync();
    } catch (error) {
      setActionError(describeError(error));
    }
  }

  async function handleRevokeAccessKey(accessKeyId: string) {
    if (!canInspectS3) {
      return;
    }
    const confirmed = window.confirm(
      `Revoke S3 access key ${accessKeyId}? Existing clients using it will stop authenticating.`
    );
    if (!confirmed) {
      return;
    }
    setActionError(null);
    try {
      await revokeAccessKeyMutation.mutateAsync(accessKeyId);
    } catch (error) {
      setActionError(describeError(error));
    }
  }

  return (
    <Stack gap="lg">
      {queryError ? (
        <Alert color="red" title="S3 control-plane query failed">
          {describeError(queryError)}
        </Alert>
      ) : null}
      {actionError ? (
        <Alert color="red" title="S3 control-plane action failed">
          {actionError}
        </Alert>
      ) : null}
      {!canInspectS3 ? (
        <Alert color="blue" title="Admin access required">
          Sign in with the local admin password before inspecting or mutating the replicated S3
          control-plane state on this node.
        </Alert>
      ) : null}
      {status?.last_error ? (
        <Alert color="red" title="Replication reported an error">
          {status.last_error}
        </Alert>
      ) : null}
      {status && !status.listener_enabled ? (
        <Alert color="yellow" title="Listener not enabled on this node">
          The replicated bucket and access-key state is present, but this node is not yet
          advertising a dedicated S3 listener URL. This page still lets operators stage and review
          the shared control-plane state.
        </Alert>
      ) : null}
      {latestCreatedAccessKey ? (
        <Alert color={ironmeshPrimaryColor} title="New S3 access key issued">
          <Stack gap="sm">
            <Text c="dimmed">
              The secret is shown here once. Capture it now before you refresh or navigate away.
            </Text>
            <TextInput
              label="Access key ID"
              value={latestCreatedAccessKey.access_key_id}
              readOnly
            />
            <Textarea
              label="Secret access key"
              value={latestCreatedAccessKey.secret_access_key}
              readOnly
              autosize
              minRows={2}
            />
            <Text size="sm" c="dimmed">
              Permissions: <Code>{latestPermissionsLabel ?? "none"}</Code>
            </Text>
            <Group justify="flex-end">
              <Button variant="light" onClick={() => setLatestCreatedAccessKey(null)}>
                Hide secret
              </Button>
            </Group>
          </Stack>
        </Alert>
      ) : null}

      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          Buckets here are prefix mappings into Ironmesh storage, and the access keys are replicated
          cluster-wide so any node can eventually expose the same S3 surface. Use this page to
          stage the operator-managed state before or while the listener layer is enabled node by
          node.
        </Text>
        <Button variant="light" onClick={() => void refreshAll()} loading={loading} disabled={!canInspectS3}>
          Refresh
        </Button>
      </Group>

      <SimpleGrid cols={{ base: 1, md: 4 }}>
        <StatCard label="Buckets" value={bucketRows.length} hint="Active bucket mappings" />
        <StatCard label="Active Keys" value={activeAccessKeyCount} hint="Currently usable access keys" />
        <StatCard label="Revoked Keys" value={revokedAccessKeyCount} hint="Retained for audit and replication" />
        <StatCard
          label="Listener"
          value={status?.listener_enabled ? "enabled" : "disabled"}
          hint={status?.public_url ? status.public_url : "No public S3 URL advertised yet"}
        />
      </SimpleGrid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 5 }}>
          <Card withBorder radius="md" padding="lg">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Listener and replication status</Text>
                <Badge color={status?.tls_enabled ? ironmeshPrimaryColor : "gray"} variant="light">
                  {status?.tls_enabled ? "tls enabled" : "tls pending"}
                </Badge>
              </Group>
              <Text c="dimmed">
                The S3 control-plane snapshot is replicated into the node-local metadata store so
                every node can serve from the same bucket and access-key inventory once the runtime
                listener is turned on there.
              </Text>
              <SimpleGrid cols={{ base: 1, sm: 2 }}>
                <StatCard
                  label="Generation"
                  value={status?.local_generation ?? "unknown"}
                  hint="Local persisted mutation counter"
                />
                <StatCard
                  label="Last source"
                  value={status?.last_source_node_id ?? "local"}
                  hint={status?.last_applied_at_unix ? formatUnixTs(status.last_applied_at_unix) : "No remote import yet"}
                />
              </SimpleGrid>
              <Stack gap="xs">
                <Text c="dimmed">
                  Use the gateway mode below when you need a standard S3 endpoint over authenticated
                  Ironmesh direct or relay transport instead of exposing this node&apos;s listener
                  directly.
                </Text>
                <Textarea
                  label="Gateway command"
                  value={
                    status?.gateway_command_hint ??
                    "ironmesh --bootstrap-file <bootstrap.json> --client-identity-file <identity.json> serve-s3 --bind 127.0.0.1:9000"
                  }
                  readOnly
                  autosize
                  minRows={2}
                />
              </Stack>
              <JsonBlock
                value={
                  status ?? {
                    status: canInspectS3 ? "loading" : "admin-auth-required"
                  }
                }
              />
            </Stack>
          </Card>
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 7 }}>
          <Grid>
            <Grid.Col span={{ base: 12, md: 6 }}>
              <Card withBorder radius="md" padding="lg">
                <Stack gap="md">
                  <Group justify="space-between">
                    <Text fw={700}>Create bucket mapping</Text>
                    <Badge variant="light">prefix-backed</Badge>
                  </Group>
                  <Text c="dimmed">
                    Leave the root prefix blank to use the default <Code>s3/&lt;bucket&gt;/</Code>{" "}
                    layout inside Ironmesh storage.
                  </Text>
                  <TextInput
                    label="Bucket name"
                    placeholder="media.example"
                    value={bucketName}
                    onChange={(event) => setBucketName(event.currentTarget.value)}
                    disabled={!canInspectS3}
                  />
                  <TextInput
                    label="Root prefix"
                    placeholder="s3/media.example/"
                    value={bucketRootPrefix}
                    onChange={(event) => setBucketRootPrefix(event.currentTarget.value)}
                    disabled={!canInspectS3}
                  />
                  <Select
                    label="Versioning"
                    data={[
                      { value: "disabled", label: "Disabled" },
                      { value: "enabled", label: "Enabled" }
                    ]}
                    value={bucketVersioningStatus}
                    onChange={(value) => {
                      if (value === "disabled" || value === "enabled") {
                        setBucketVersioningStatus(value);
                      }
                    }}
                    disabled={!canInspectS3}
                  />
                  <Checkbox
                    label="Read-only bucket mapping"
                    checked={bucketReadOnly}
                    onChange={(event) => setBucketReadOnly(event.currentTarget.checked)}
                    disabled={!canInspectS3}
                  />
                  <Group justify="flex-end">
                    <Button
                      onClick={() => void handleCreateBucket()}
                      loading={createBucketMutation.isPending}
                      disabled={!canInspectS3}
                    >
                      Create bucket
                    </Button>
                  </Group>
                </Stack>
              </Card>
            </Grid.Col>
            <Grid.Col span={{ base: 12, md: 6 }}>
              <Card withBorder radius="md" padding="lg">
                <Stack gap="md">
                  <Group justify="space-between">
                    <Text fw={700}>Issue access key</Text>
                    <Badge variant="light">shown once</Badge>
                  </Group>
                  <Text c="dimmed">
                    Scope fields accept one value per line or comma-separated values. Leave them
                    blank to avoid narrowing the key to specific buckets or prefixes. Enable{" "}
                    <Code>manage</Code> when this key should create buckets or change bucket
                    versioning through the S3 API.
                  </Text>
                  <TextInput
                    label="Description"
                    placeholder="build pipeline writer"
                    value={accessKeyDescription}
                    onChange={(event) => setAccessKeyDescription(event.currentTarget.value)}
                    disabled={!canInspectS3}
                  />
                  <Textarea
                    label="Bucket scope"
                    placeholder={"media.example\narchive.example"}
                    autosize
                    minRows={2}
                    value={bucketScopeText}
                    onChange={(event) => setBucketScopeText(event.currentTarget.value)}
                    disabled={!canInspectS3}
                  />
                  <Textarea
                    label="Prefix scope"
                    placeholder={"tenant/media/inbox/\ntenant/media/exports/"}
                    autosize
                    minRows={2}
                    value={prefixScopeText}
                    onChange={(event) => setPrefixScopeText(event.currentTarget.value)}
                    disabled={!canInspectS3}
                  />
                  <Grid gutter="sm">
                    <Grid.Col span={6}>
                      <Checkbox
                        label="List"
                        checked={allowList}
                        onChange={(event) => setAllowList(event.currentTarget.checked)}
                        disabled={!canInspectS3}
                      />
                    </Grid.Col>
                    <Grid.Col span={6}>
                      <Checkbox
                        label="Read"
                        checked={allowRead}
                        onChange={(event) => setAllowRead(event.currentTarget.checked)}
                        disabled={!canInspectS3}
                      />
                    </Grid.Col>
                    <Grid.Col span={6}>
                      <Checkbox
                        label="Write"
                        checked={allowWrite}
                        onChange={(event) => setAllowWrite(event.currentTarget.checked)}
                        disabled={!canInspectS3}
                      />
                    </Grid.Col>
                    <Grid.Col span={6}>
                      <Checkbox
                        label="Delete"
                        checked={allowDelete}
                        onChange={(event) => setAllowDelete(event.currentTarget.checked)}
                        disabled={!canInspectS3}
                      />
                    </Grid.Col>
                    <Grid.Col span={6}>
                      <Checkbox
                        label="Manage"
                        checked={allowManage}
                        onChange={(event) => setAllowManage(event.currentTarget.checked)}
                        disabled={!canInspectS3}
                      />
                    </Grid.Col>
                  </Grid>
                  <Group justify="flex-end">
                    <Button
                      onClick={() => void handleCreateAccessKey()}
                      loading={createAccessKeyMutation.isPending}
                      disabled={!canInspectS3}
                    >
                      Create access key
                    </Button>
                  </Group>
                </Stack>
              </Card>
            </Grid.Col>
          </Grid>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Text fw={700}>Bucket mappings</Text>
            <Badge variant="light">
              {bucketRows.length} configured
            </Badge>
          </Group>
          <ScrollArea type="auto">
            <Table striped highlightOnHover withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Bucket</Table.Th>
                  <Table.Th>Root prefix</Table.Th>
                  <Table.Th>Versioning</Table.Th>
                  <Table.Th>Mode</Table.Th>
                  <Table.Th>Updated</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {bucketRows.length > 0 ? (
                  bucketRows.map((bucket) => (
                    <Table.Tr key={bucket.bucket_name}>
                      <Table.Td>
                        <Stack gap={2}>
                          <Text fw={600}>{bucket.bucket_name}</Text>
                          <Text size="sm" c="dimmed">
                            created {formatRelativeUnixTs(bucket.created_at_unix)} by{" "}
                            {bucket.created_by || "unknown"}
                          </Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td><Code>{bucket.root_prefix}</Code></Table.Td>
                      <Table.Td>
                        <Badge color={bucket.versioning_status === "enabled" ? ironmeshPrimaryColor : "gray"} variant="light">
                          {bucket.versioning_status}
                        </Badge>
                      </Table.Td>
                      <Table.Td>{bucketModeLabel(bucket.read_only)}</Table.Td>
                      <Table.Td>{formatUnixTs(bucket.updated_at_unix)}</Table.Td>
                      <Table.Td>
                        <Button
                          size="xs"
                          color="red"
                          variant="light"
                          onClick={() => void handleDeleteBucket(bucket.bucket_name)}
                          loading={
                            deleteBucketMutation.isPending &&
                            deleteBucketMutation.variables === bucket.bucket_name
                          }
                          disabled={!canInspectS3}
                        >
                          Delete
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))
                ) : (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Text c="dimmed">
                        No active S3 bucket mappings are configured on this node yet.
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Text fw={700}>Access keys</Text>
            <Badge variant="light">
              {accessKeyRows.length} retained
            </Badge>
          </Group>
          <ScrollArea type="auto">
            <Table striped highlightOnHover withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Access key</Table.Th>
                  <Table.Th>Scope</Table.Th>
                  <Table.Th>Permissions</Table.Th>
                  <Table.Th>Last used</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {accessKeyRows.length > 0 ? (
                  accessKeyRows.map((accessKey) => (
                    <Table.Tr key={accessKey.access_key_id}>
                      <Table.Td>
                        <Stack gap={2}>
                          <Text fw={600}>{accessKey.access_key_id}</Text>
                          <Text size="sm" c="dimmed">
                            {accessKey.description || accessKey.secret_fingerprint}
                          </Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td>
                        <Stack gap={2}>
                          <Text size="sm">
                            Buckets: {joinScopeValues(accessKey.bucket_scope, "all buckets")}
                          </Text>
                          <Text size="sm" c="dimmed">
                            Prefixes: {joinScopeValues(accessKey.prefix_scope, "all prefixes")}
                          </Text>
                        </Stack>
                      </Table.Td>
                      <Table.Td>
                        {[
                          accessKey.allow_list ? "list" : null,
                          accessKey.allow_read ? "read" : null,
                          accessKey.allow_write ? "write" : null,
                          accessKey.allow_delete ? "delete" : null,
                          accessKey.allow_manage ? "manage" : null
                        ]
                          .filter((value): value is string => value != null)
                          .join(", ")}
                      </Table.Td>
                      <Table.Td>
                        {accessKey.last_used_at_unix
                          ? `${formatRelativeUnixTs(accessKey.last_used_at_unix)} | ${formatUnixTs(accessKey.last_used_at_unix)}`
                          : "never"}
                      </Table.Td>
                      <Table.Td>
                        <Badge color={accessKeyStatusColor(accessKey)} variant="light">
                          {accessKey.revoked_at_unix ? "revoked" : "active"}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        <Button
                          size="xs"
                          color="red"
                          variant="light"
                          disabled={!canInspectS3 || accessKey.revoked_at_unix != null}
                          onClick={() => void handleRevokeAccessKey(accessKey.access_key_id)}
                          loading={
                            revokeAccessKeyMutation.isPending &&
                            revokeAccessKeyMutation.variables === accessKey.access_key_id
                          }
                        >
                          Revoke
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))
                ) : (
                  <Table.Tr>
                    <Table.Td colSpan={6}>
                      <Text c="dimmed">
                        No S3 access keys are retained yet.
                      </Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Card>
    </Stack>
  );
}
