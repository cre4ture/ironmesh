import {
  exportManagedControlPlanePromotion,
  importManagedControlPlanePromotion,
  type ControlPlanePromotionImportResponse,
  type ManagedControlPlanePromotionPackage
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
import { useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function ControlPlanePage() {
  const { adminTokenOverride } = useAdminAccess();
  const [passphrase, setPassphrase] = useState("");
  const [targetNodeId, setTargetNodeId] = useState("");
  const [publicUrl, setPublicUrl] = useState("");
  const [exportedPackage, setExportedPackage] = useState<ManagedControlPlanePromotionPackage | null>(null);
  const [importPassphrase, setImportPassphrase] = useState("");
  const [packageRaw, setPackageRaw] = useState("");
  const [bindAddr, setBindAddr] = useState("");
  const [importResult, setImportResult] = useState<ControlPlanePromotionImportResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<"export" | "import" | null>(null);

  async function handleExport() {
    setPendingAction("export");
    setError(null);
    try {
      const payload = await exportManagedControlPlanePromotion(
        {
          passphrase,
          target_node_id: targetNodeId,
          public_url: publicUrl.trim() || null
        },
        adminTokenOverride
      );
      setExportedPackage(payload);
    } catch (actionError) {
      setError(actionError instanceof Error ? actionError.message : String(actionError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleImport() {
    setPendingAction("import");
    setError(null);
    try {
      const parsed = JSON.parse(packageRaw) as ManagedControlPlanePromotionPackage;
      const payload = await importManagedControlPlanePromotion(
        {
          passphrase: importPassphrase,
          package: parsed,
          bind_addr: bindAddr.trim() || null
        },
        adminTokenOverride
      );
      setImportResult(payload);
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
        Promotion packages move both the managed signer and the embedded rendezvous role together. This is the
        current guided failover path for the zero-touch control plane and is intended for deliberate promotion,
        not active-active clustering.
      </Text>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Export promotion package</Text>
                <Badge variant="light">{exportedPackage ? "package ready" : "source node action"}</Badge>
              </Group>
              <Text c="dimmed">
                Export from the current control-plane node, then import on the promoted node, restart it, and
                move your stable rendezvous hostname or routing to the new host.
              </Text>
              <PasswordInput
                label="Passphrase"
                value={passphrase}
                onChange={(event) => setPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Target node ID"
                value={targetNodeId}
                onChange={(event) => setTargetNodeId(event.currentTarget.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
              <TextInput
                label="Public rendezvous URL override"
                value={publicUrl}
                onChange={(event) => setPublicUrl(event.currentTarget.value)}
                placeholder="https://rendezvous.example:9443"
              />
              <Group>
                <Button onClick={() => void handleExport()} loading={pendingAction === "export"}>
                  Export promotion package
                </Button>
              </Group>
              <JsonBlock value={exportedPackage ?? { status: "no promotion package exported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Import promotion package</Text>
                <Badge
                  color={importResult?.restart_required ? "yellow" : "gray"}
                  variant="light"
                >
                  {importResult ? "package imported" : "target node action"}
                </Badge>
              </Group>
              <PasswordInput
                label="Passphrase"
                value={importPassphrase}
                onChange={(event) => setImportPassphrase(event.currentTarget.value)}
              />
              <TextInput
                label="Bind address override"
                value={bindAddr}
                onChange={(event) => setBindAddr(event.currentTarget.value)}
                placeholder="0.0.0.0:9443"
              />
              <Textarea
                label="Promotion package JSON"
                minRows={12}
                autosize
                value={packageRaw}
                onChange={(event) => setPackageRaw(event.currentTarget.value)}
                placeholder='{"signer_backup":{"version":1},"rendezvous_failover":{"version":1}}'
              />
              <Group>
                <Button onClick={() => void handleImport()} loading={pendingAction === "import"}>
                  Import promotion package
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                Import result summary: {importResult ? `${importResult.target_node_id} <- ${importResult.source_node_id}` : "none yet"}.
              </Text>
              <JsonBlock value={importResult ?? { status: "no promotion package imported yet" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
