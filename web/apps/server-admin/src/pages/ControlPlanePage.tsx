import {
  exportManagedControlPlanePromotion,
  exportManagedRendezvousFailover,
  getRendezvousConfig,
  importManagedControlPlanePromotion,
  importManagedRendezvousFailover,
  type ControlPlanePromotionImportResponse,
  type ManagedControlPlanePromotionPackage,
  type ManagedRendezvousFailoverImportResponse,
  type ManagedRendezvousFailoverPackage,
  type RendezvousConfigView,
  updateRendezvousConfig
} from "@ironmesh/api";
import { JsonBlock } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Grid,
  Group,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Textarea
} from "@mantine/core";
import { useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function ControlPlanePage() {
  const { adminTokenOverride } = useAdminAccess();
  const [rendezvousConfig, setRendezvousConfig] = useState<RendezvousConfigView | null>(null);
  const [editableRendezvousUrlsText, setEditableRendezvousUrlsText] = useState("");
  const [rendezvousConfigLoading, setRendezvousConfigLoading] = useState(true);
  const [rendezvousPassphrase, setRendezvousPassphrase] = useState("");
  const [rendezvousTargetNodeId, setRendezvousTargetNodeId] = useState("");
  const [rendezvousPublicUrl, setRendezvousPublicUrl] = useState("");
  const [exportedRendezvousPackage, setExportedRendezvousPackage] = useState<ManagedRendezvousFailoverPackage | null>(null);
  const [rendezvousImportPassphrase, setRendezvousImportPassphrase] = useState("");
  const [rendezvousPackageRaw, setRendezvousPackageRaw] = useState("");
  const [rendezvousBindAddr, setRendezvousBindAddr] = useState("");
  const [rendezvousImportResult, setRendezvousImportResult] = useState<ManagedRendezvousFailoverImportResponse | null>(null);
  const [promotionPassphrase, setPromotionPassphrase] = useState("");
  const [promotionTargetNodeId, setPromotionTargetNodeId] = useState("");
  const [promotionPublicUrl, setPromotionPublicUrl] = useState("");
  const [exportedPromotionPackage, setExportedPromotionPackage] = useState<ManagedControlPlanePromotionPackage | null>(null);
  const [promotionImportPassphrase, setPromotionImportPassphrase] = useState("");
  const [promotionPackageRaw, setPromotionPackageRaw] = useState("");
  const [promotionBindAddr, setPromotionBindAddr] = useState("");
  const [promotionImportResult, setPromotionImportResult] = useState<ControlPlanePromotionImportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<
    "rendezvous-config-save" | "rendezvous-export" | "rendezvous-import" | "promotion-export" | "promotion-import" | null
  >(null);

  useEffect(() => {
    let cancelled = false;

    async function refreshRendezvousConfig() {
      setRendezvousConfigLoading(true);
      try {
        const payload = await getRendezvousConfig(adminTokenOverride);
        if (cancelled) {
          return;
        }
        setRendezvousConfig(payload);
        setEditableRendezvousUrlsText(payload.editable_urls.join("\n"));
      } catch (actionError) {
        if (cancelled) {
          return;
        }
        setError(actionError instanceof Error ? actionError.message : String(actionError));
      } finally {
        if (!cancelled) {
          setRendezvousConfigLoading(false);
        }
      }
    }

    void refreshRendezvousConfig();

    return () => {
      cancelled = true;
    };
  }, [adminTokenOverride]);

  async function handleSaveRendezvousConfig() {
    setPendingAction("rendezvous-config-save");
    setError(null);
    try {
      const editable_urls = editableRendezvousUrlsText
        .split(/\r?\n/)
        .map((value) => value.trim())
        .filter((value) => value.length > 0);
      const payload = await updateRendezvousConfig({ editable_urls }, adminTokenOverride);
      setRendezvousConfig(payload);
      setEditableRendezvousUrlsText(payload.editable_urls.join("\n"));
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleExportRendezvousFailover() {
    setPendingAction("rendezvous-export");
    setError(null);
    try {
      const payload = await exportManagedRendezvousFailover(
        {
          passphrase: rendezvousPassphrase,
          target_node_id: rendezvousTargetNodeId,
          public_url: rendezvousPublicUrl.trim() || null
        },
        adminTokenOverride
      );
      setExportedRendezvousPackage(payload);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleImportRendezvousFailover() {
    setPendingAction("rendezvous-import");
    setError(null);
    try {
      const parsed = JSON.parse(rendezvousPackageRaw) as ManagedRendezvousFailoverPackage;
      const payload = await importManagedRendezvousFailover(
        {
          passphrase: rendezvousImportPassphrase,
          package: parsed,
          bind_addr: rendezvousBindAddr.trim() || null
        },
        adminTokenOverride
      );
      setRendezvousImportResult(payload);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleExportPromotion() {
    setPendingAction("promotion-export");
    setError(null);
    try {
      const payload = await exportManagedControlPlanePromotion(
        {
          passphrase: promotionPassphrase,
          target_node_id: promotionTargetNodeId,
          public_url: promotionPublicUrl.trim() || null
        },
        adminTokenOverride
      );
      setExportedPromotionPackage(payload);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleImportPromotion() {
    setPendingAction("promotion-import");
    setError(null);
    try {
      const parsed = JSON.parse(promotionPackageRaw) as ManagedControlPlanePromotionPackage;
      const payload = await importManagedControlPlanePromotion(
        {
          passphrase: promotionImportPassphrase,
          package: parsed,
          bind_addr: promotionBindAddr.trim() || null
        },
        adminTokenOverride
      );
      setPromotionImportResult(payload);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Request failed">{error}</Alert> : null}
      <Text c="dimmed" maw={760}>
        The new admin surface now exposes both supported transfer paths: move the embedded rendezvous role by itself,
        or move the full control plane together. Both are deliberate failover workflows, not active-active clustering.
      </Text>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Text fw={700}>Rendezvous service URLs</Text>
            <Badge variant="light">
              {rendezvousConfig ? `${rendezvousConfig.effective_urls.length} effective` : "loading"}
            </Badge>
          </Group>
          <Text c="dimmed">
            Review the currently configured rendezvous services for this node, and edit the operator-managed URLs that
            should be used for registration, relay, and issued bootstraps. The node’s own embedded managed rendezvous
            URL stays separate and read-only here.
          </Text>
          {rendezvousConfig?.persistence_source === "runtime_only" ? (
            <Alert color="yellow" title="Runtime-only persistence">
              This node does not currently have a persisted node enrollment package, so rendezvous URL edits apply live
              now but will be lost after restart unless the underlying startup config is updated too.
            </Alert>
          ) : null}
          {!rendezvousConfig?.registration_enabled && !rendezvousConfigLoading ? (
            <Alert color="blue" title="Rendezvous registration is disabled">
              This node currently has rendezvous registration disabled. URL edits are still stored, but they will not
              be used for active registration until rendezvous participation is enabled by the node’s runtime mode.
            </Alert>
          ) : null}
          <Grid>
            <Grid.Col span={{ base: 12, xl: 6 }}>
              <Stack gap="sm">
                <Text fw={600}>Current effective configuration</Text>
                <JsonBlock
                  value={
                    rendezvousConfig ?? {
                      status: rendezvousConfigLoading ? "loading" : "unavailable"
                    }
                  }
                />
              </Stack>
            </Grid.Col>
            <Grid.Col span={{ base: 12, xl: 6 }}>
              <Stack gap="sm">
                <Text fw={600}>Editable operator-managed URLs</Text>
                <Textarea
                  label="Editable operator-managed URLs"
                  minRows={10}
                  autosize
                  value={editableRendezvousUrlsText}
                  onChange={(event) => setEditableRendezvousUrlsText(event.currentTarget.value)}
                  placeholder={"https://rendezvous-a.example:9443\nhttps://rendezvous-b.example:9443"}
                />
                <Text size="sm" c="dimmed">
                  One URL per line. These are merged with the embedded managed rendezvous URL when that role is active
                  on this node.
                </Text>
                <Group>
                  <Button
                    onClick={() => void handleSaveRendezvousConfig()}
                    loading={pendingAction === "rendezvous-config-save"}
                  >
                    Save rendezvous URLs
                  </Button>
                </Group>
              </Stack>
            </Grid.Col>
          </Grid>
        </Stack>
      </Card>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Export rendezvous-only failover package</Text>
                <Badge variant="light">{exportedRendezvousPackage ? "package ready" : "source node action"}</Badge>
              </Group>
              <Text c="dimmed">
                Use this when you only want to move the embedded rendezvous listener to another cluster node and keep
                the signer where it is.
              </Text>
              <PasswordInput
                label="Passphrase"
                value={rendezvousPassphrase}
                onChange={(event) => setRendezvousPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Target node ID"
                value={rendezvousTargetNodeId}
                onChange={(event) => setRendezvousTargetNodeId(event.currentTarget.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
              <TextInput
                label="Public rendezvous URL override"
                value={rendezvousPublicUrl}
                onChange={(event) => setRendezvousPublicUrl(event.currentTarget.value)}
                placeholder="https://rendezvous.example:9443"
              />
              <Group>
                <Button
                  onClick={() => void handleExportRendezvousFailover()}
                  loading={pendingAction === "rendezvous-export"}
                >
                  Export rendezvous failover package
                </Button>
              </Group>
              <JsonBlock value={exportedRendezvousPackage ?? { status: "no rendezvous failover package exported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Import rendezvous-only failover package</Text>
                <Badge
                  color={rendezvousImportResult?.restart_required ? "yellow" : "gray"}
                  variant="light"
                >
                  {rendezvousImportResult ? "package imported" : "target node action"}
                </Badge>
              </Group>
              <Text c="dimmed">
                Import on the promoted node, restart it, then move the stable rendezvous hostname or VIP to that node.
              </Text>
              <PasswordInput
                label="Passphrase"
                value={rendezvousImportPassphrase}
                onChange={(event) => setRendezvousImportPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Bind address override"
                value={rendezvousBindAddr}
                onChange={(event) => setRendezvousBindAddr(event.currentTarget.value)}
                placeholder="0.0.0.0:9443"
              />
              <Textarea
                label="Rendezvous failover package JSON"
                minRows={12}
                autosize
                value={rendezvousPackageRaw}
                onChange={(event) => setRendezvousPackageRaw(event.currentTarget.value)}
                placeholder='{"version":1,"cluster_id":"...","target_node_id":"..."}'
              />
              <Group>
                <Button
                  onClick={() => void handleImportRendezvousFailover()}
                  loading={pendingAction === "rendezvous-import"}
                >
                  Import rendezvous failover package
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                Import result summary: {rendezvousImportResult ? `${rendezvousImportResult.target_node_id} <- ${rendezvousImportResult.source_node_id}` : "none yet"}.
              </Text>
              <JsonBlock value={rendezvousImportResult ?? { status: "no rendezvous failover package imported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Export full control-plane promotion package</Text>
                <Badge variant="light">{exportedPromotionPackage ? "package ready" : "source node action"}</Badge>
              </Group>
              <Text c="dimmed">
                Use this when the promoted node must keep both the embedded rendezvous role and signer duties for
                onboarding new clients and nodes.
              </Text>
              <PasswordInput
                label="Passphrase"
                value={promotionPassphrase}
                onChange={(event) => setPromotionPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Target node ID"
                value={promotionTargetNodeId}
                onChange={(event) => setPromotionTargetNodeId(event.currentTarget.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
              <TextInput
                label="Public rendezvous URL override"
                value={promotionPublicUrl}
                onChange={(event) => setPromotionPublicUrl(event.currentTarget.value)}
                placeholder="https://rendezvous.example:9443"
              />
              <Group>
                <Button
                  onClick={() => void handleExportPromotion()}
                  loading={pendingAction === "promotion-export"}
                >
                  Export promotion package
                </Button>
              </Group>
              <JsonBlock value={exportedPromotionPackage ?? { status: "no promotion package exported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Import full control-plane promotion package</Text>
                <Badge
                  color={promotionImportResult?.restart_required ? "yellow" : "gray"}
                  variant="light"
                >
                  {promotionImportResult ? "package imported" : "target node action"}
                </Badge>
              </Group>
              <PasswordInput
                label="Passphrase"
                value={promotionImportPassphrase}
                onChange={(event) => setPromotionImportPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Bind address override"
                value={promotionBindAddr}
                onChange={(event) => setPromotionBindAddr(event.currentTarget.value)}
                placeholder="0.0.0.0:9443"
              />
              <Textarea
                label="Promotion package JSON"
                minRows={12}
                autosize
                value={promotionPackageRaw}
                onChange={(event) => setPromotionPackageRaw(event.currentTarget.value)}
                placeholder='{"signer_backup":{"version":1},"rendezvous_failover":{"version":1}}'
              />
              <Group>
                <Button
                  onClick={() => void handleImportPromotion()}
                  loading={pendingAction === "promotion-import"}
                >
                  Import promotion package
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                Import result summary: {promotionImportResult ? `${promotionImportResult.target_node_id} <- ${promotionImportResult.source_node_id}` : "none yet"}.
              </Text>
              <JsonBlock value={promotionImportResult ?? { status: "no promotion package imported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Group justify="space-between">
            <Text fw={700}>Dedicated standalone rendezvous-service</Text>
            <Badge color="blue" variant="light">advanced/manual</Badge>
          </Group>
          <Text c="dimmed">
            A pure standalone <code>rendezvous-service</code> is still the advanced operator path. The current UI now
            covers both supported node-to-node transfer workflows, but it does not yet automate direct import into the
            standalone service itself.
          </Text>
          <Text size="sm" c="dimmed">
            Today the supported guided options are:
          </Text>
          <Text size="sm" c="dimmed">1. Move embedded rendezvous to another approved node with the rendezvous-only failover package.</Text>
          <Text size="sm" c="dimmed">2. Move signer plus embedded rendezvous together with the full control-plane promotion package.</Text>
          <Text size="sm" c="dimmed">
            For a dedicated standalone service, keep the same stable public rendezvous URL or VIP, provision the
            service separately with the right TLS and trust material, add its URL in the editor above on the
            participating server nodes, and treat signer/cert material cutover as a manual operator step for now.
          </Text>
        </Stack>
      </Card>
    </Stack>
  );
}
