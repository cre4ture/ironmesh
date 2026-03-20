import { issueBootstrapBundle, issueNodeEnrollmentFromJoinRequest, type BootstrapBundle, type NodeEnrollmentPackage } from "@ironmesh/api";
import { Alert, Badge, Button, Card, Grid, Group, NumberInput, Stack, Text, TextInput, Textarea } from "@mantine/core";
import { JsonBlock } from "@ironmesh/ui";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function BootstrapBundlesPage() {
  const { adminTokenOverride } = useAdminAccess();
  const [deviceLabel, setDeviceLabel] = useState("desktop-client");
  const [expiresInSecs, setExpiresInSecs] = useState<number | string>(3600);
  const [bootstrapBundle, setBootstrapBundle] = useState<BootstrapBundle | null>(null);
  const [joinRequestRaw, setJoinRequestRaw] = useState("");
  const [tlsValiditySecs, setTlsValiditySecs] = useState<number | string>(2592000);
  const [tlsRenewalWindowSecs, setTlsRenewalWindowSecs] = useState<number | string>(518400);
  const [issuedEnrollment, setIssuedEnrollment] = useState<NodeEnrollmentPackage | null>(null);
  const [bootstrapBundleQrDataUrl, setBootstrapBundleQrDataUrl] = useState<string | null>(null);
  const [bootstrapBundleQrError, setBootstrapBundleQrError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<"bootstrap" | "join-enrollment" | null>(null);

  const bundleEndpointCount = bootstrapBundle?.direct_endpoints?.length ?? 0;
  const bootstrapBundlePayload = useMemo(
    () => (bootstrapBundle ? JSON.stringify(bootstrapBundle) : null),
    [bootstrapBundle]
  );
  const joinRequestPreview = (() => {
    try {
      const parsed = JSON.parse(joinRequestRaw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        return null;
      }
      const record = parsed as Record<string, unknown>;
      return {
        node_id: typeof record.node_id === "string" ? record.node_id : "unknown",
        cluster_id: typeof record.cluster_id === "string" ? record.cluster_id : "unknown"
      };
    } catch {
      return null;
    }
  })();

  useEffect(() => {
    let cancelled = false;
    if (!bootstrapBundlePayload) {
      setBootstrapBundleQrDataUrl(null);
      setBootstrapBundleQrError(null);
      return;
    }

    setBootstrapBundleQrDataUrl(null);
    setBootstrapBundleQrError(null);

    void QRCode.toDataURL(bootstrapBundlePayload, {
      errorCorrectionLevel: "L",
      margin: 1,
      width: 320
    })
      .then((dataUrl: string) => {
        if (!cancelled) {
          setBootstrapBundleQrDataUrl(dataUrl);
        }
      })
      .catch((qrError: unknown) => {
        if (!cancelled) {
          setBootstrapBundleQrError(qrError instanceof Error ? qrError.message : String(qrError));
        }
      });

    return () => {
      cancelled = true;
    };
  }, [bootstrapBundlePayload]);

  async function handleIssueBootstrap() {
    setPendingAction("bootstrap");
    setError(null);
    setBootstrapBundle(null);
    try {
      const payload = await issueBootstrapBundle(
        {
          label: deviceLabel.trim() || null,
          expires_in_secs:
            typeof expiresInSecs === "number" && Number.isFinite(expiresInSecs) ? expiresInSecs : 3600
        },
        adminTokenOverride
      );
      setBootstrapBundle(payload);
    } catch (issueError) {
      setError(issueError instanceof Error ? issueError.message : String(issueError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleIssueJoinEnrollment() {
    setPendingAction("join-enrollment");
    setError(null);
    try {
      const parsed = JSON.parse(joinRequestRaw);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("join request must be a JSON object");
      }
      const payload = await issueNodeEnrollmentFromJoinRequest(
        {
          join_request: parsed as Record<string, unknown>,
          tls_validity_secs:
            typeof tlsValiditySecs === "number" && Number.isFinite(tlsValiditySecs)
              ? tlsValiditySecs
              : null,
          tls_renewal_window_secs:
            typeof tlsRenewalWindowSecs === "number" && Number.isFinite(tlsRenewalWindowSecs)
              ? tlsRenewalWindowSecs
              : null
        },
        adminTokenOverride
      );
      setIssuedEnrollment(payload);
    } catch (issueError) {
      setError(issueError instanceof Error ? issueError.message : String(issueError));
    } finally {
      setPendingAction(null);
    }
  }

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Request failed">{error}</Alert> : null}
      <Text c="dimmed" maw={760}>
        This page handles the two main provisioning tasks still exposed through the runtime admin surface:
        issuing client bootstrap bundles and approving node join requests into enrollment packages.
      </Text>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Client bootstrap bundle</Text>
                <Badge variant="light">{bootstrapBundle ? "issued" : "ready"}</Badge>
              </Group>
              <Text c="dimmed">
                Issue a bootstrap bundle for a new client. This uses the current admin session or the
                advanced token override from the header drawer.
              </Text>
              <TextInput
                label="Device label"
                value={deviceLabel}
                onChange={(event) => setDeviceLabel(event.currentTarget.value)}
              />
              <NumberInput
                label="Expires in seconds"
                min={60}
                max={86400}
                value={expiresInSecs}
                onChange={setExpiresInSecs}
              />
              <Group>
                <Button onClick={() => void handleIssueBootstrap()} loading={pendingAction === "bootstrap"}>
                  Issue bootstrap bundle
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                Current bundle summary: cluster {String(bootstrapBundle?.cluster_id ?? "unknown")}, relay mode{" "}
                {String(bootstrapBundle?.relay_mode ?? "unknown")}, direct endpoints {bundleEndpointCount}.
              </Text>
              {bootstrapBundle ? (
                <Stack gap="xs">
                  <Text fw={600}>Scan with the ironmesh Android app</Text>
                  {bootstrapBundleQrDataUrl ? (
                    <img
                      src={bootstrapBundleQrDataUrl}
                      alt="Client bootstrap bundle QR code"
                      style={{ width: 320, maxWidth: "100%", display: "block" }}
                    />
                  ) : (
                    <Text size="sm" c={bootstrapBundleQrError ? "red" : "dimmed"}>
                      {bootstrapBundleQrError ? `Failed to generate QR code: ${bootstrapBundleQrError}` : "Generating QR code..."}
                    </Text>
                  )}
                </Stack>
              ) : null}
              <JsonBlock value={bootstrapBundle ?? { status: "no bundle issued yet" }} />
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Issue enrollment from join request</Text>
                <Badge variant="light">
                  {issuedEnrollment ? "enrollment issued" : joinRequestPreview ? "request parsed" : "awaiting request"}
                </Badge>
              </Group>
              <Text c="dimmed">
                Paste a join-request blob from a node in first-run setup mode and issue a node enrollment
                package for it.
              </Text>
              <Textarea
                label="Node join request JSON"
                minRows={10}
                autosize
                value={joinRequestRaw}
                onChange={(event) => setJoinRequestRaw(event.currentTarget.value)}
                placeholder='{"version":1,"node_id":"..."}'
              />
              <Text size="sm" c="dimmed">
                Parsed preview: node {joinRequestPreview?.node_id ?? "unknown"}, cluster{" "}
                {joinRequestPreview?.cluster_id ?? "unknown"}.
              </Text>
              <Group grow>
                <NumberInput
                  label="TLS validity seconds"
                  min={3600}
                  value={tlsValiditySecs}
                  onChange={setTlsValiditySecs}
                />
                <NumberInput
                  label="TLS renewal window seconds"
                  min={300}
                  value={tlsRenewalWindowSecs}
                  onChange={setTlsRenewalWindowSecs}
                />
              </Group>
              <Group>
                <Button
                  onClick={() => void handleIssueJoinEnrollment()}
                  loading={pendingAction === "join-enrollment"}
                >
                  Issue enrollment package
                </Button>
              </Group>
              <JsonBlock value={issuedEnrollment ?? { status: "no enrollment package issued yet" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>
    </Stack>
  );
}
