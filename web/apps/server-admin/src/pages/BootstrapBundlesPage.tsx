import {
  getRendezvousConfig,
  issueBootstrapBundle,
  issueBootstrapClaim,
  issueNodeEnrollmentFromJoinRequest,
  type BootstrapBundle,
  type BootstrapClaim,
  type BootstrapClaimIssueResponse,
  type NodeEnrollmentPackage,
  type RendezvousConfigView
} from "@ironmesh/api";
import { Alert, Badge, Button, Card, Grid, Group, NativeSelect, NumberInput, Stack, Text, TextInput, Textarea } from "@mantine/core";
import { JsonBlock } from "@ironmesh/ui";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

const BOOTSTRAP_QR_WIDTH = 1024;
const BOOTSTRAP_QR_MARGIN = 12;
const BOOTSTRAP_QR_FRAME_PADDING = 24;

function shouldFallbackToFullBootstrapQr(message: string): boolean {
  return (
    message.startsWith("HTTP 404:") ||
    message.startsWith("HTTP 412:") ||
    message.startsWith("HTTP 502:")
  );
}

function normalizeRendezvousUrl(value: string): string {
  try {
    return new URL(value).toString();
  } catch {
    return value;
  }
}

export function BootstrapBundlesPage() {
  const { adminTokenOverride } = useAdminAccess();
  const [deviceLabel, setDeviceLabel] = useState("desktop-client");
  const [expiresInSecs, setExpiresInSecs] = useState<number | string>(3600);
  const [rendezvousConfig, setRendezvousConfig] = useState<RendezvousConfigView | null>(null);
  const [selectedRendezvousUrl, setSelectedRendezvousUrl] = useState("");
  const [issuedBootstrap, setIssuedBootstrap] = useState<BootstrapClaimIssueResponse | null>(null);
  const [fallbackBootstrapBundle, setFallbackBootstrapBundle] = useState<BootstrapBundle | null>(null);
  const [bootstrapNotice, setBootstrapNotice] = useState<string | null>(null);
  const [joinRequestRaw, setJoinRequestRaw] = useState("");
  const [tlsValiditySecs, setTlsValiditySecs] = useState<number | string>(2592000);
  const [tlsRenewalWindowSecs, setTlsRenewalWindowSecs] = useState<number | string>(518400);
  const [issuedEnrollment, setIssuedEnrollment] = useState<NodeEnrollmentPackage | null>(null);
  const [bootstrapBundleQrDataUrl, setBootstrapBundleQrDataUrl] = useState<string | null>(null);
  const [bootstrapBundleQrError, setBootstrapBundleQrError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<"bootstrap" | "join-enrollment" | null>(null);

  const bootstrapBundle: BootstrapBundle | null = issuedBootstrap?.bootstrap_bundle ?? fallbackBootstrapBundle;
  const bootstrapClaim: BootstrapClaim | null = issuedBootstrap?.bootstrap_claim ?? null;
  const bundleEndpointCount = bootstrapBundle?.direct_endpoints?.length ?? 0;
  const bootstrapQrPayload = useMemo(
    () => {
      if (bootstrapClaim) {
        return JSON.stringify(bootstrapClaim);
      }
      if (bootstrapBundle) {
        return JSON.stringify(bootstrapBundle);
      }
      return null;
    },
    [bootstrapBundle, bootstrapClaim]
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
  const rendezvousSelectData = useMemo(() => {
    const managedEmbeddedUrl = rendezvousConfig?.managed_embedded_url
      ? normalizeRendezvousUrl(rendezvousConfig.managed_embedded_url)
      : null;
    const endpointStatusByUrl = new Map(
      (rendezvousConfig?.endpoint_registrations ?? []).map((endpoint) => [
        normalizeRendezvousUrl(endpoint.url),
        endpoint.status
      ])
    );

    return [
      { value: "", label: "Automatic (first successful configured rendezvous)" },
      ...(rendezvousConfig?.effective_urls ?? []).map((url) => {
        const normalized = normalizeRendezvousUrl(url);
        const status = endpointStatusByUrl.get(normalized);
        const details = [
          normalized === managedEmbeddedUrl ? "embedded" : null,
          status ?? null
        ].filter((value): value is string => value !== null);
        return {
          value: normalized,
          label: details.length > 0 ? `${normalized} (${details.join(", ")})` : normalized
        };
      })
    ];
  }, [rendezvousConfig]);

  useEffect(() => {
    let cancelled = false;

    void getRendezvousConfig(adminTokenOverride)
      .then((payload) => {
        if (cancelled) {
          return;
        }
        setRendezvousConfig(payload);
        setSelectedRendezvousUrl((current) => {
          if (!current) {
            return current;
          }
          const available = new Set(payload.effective_urls.map(normalizeRendezvousUrl));
          return available.has(normalizeRendezvousUrl(current)) ? normalizeRendezvousUrl(current) : "";
        });
      })
      .catch(() => {
        if (!cancelled) {
          setRendezvousConfig(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [adminTokenOverride]);

  useEffect(() => {
    let cancelled = false;
    if (!bootstrapQrPayload) {
      setBootstrapBundleQrDataUrl(null);
      setBootstrapBundleQrError(null);
      return;
    }

    setBootstrapBundleQrDataUrl(null);
    setBootstrapBundleQrError(null);

    void QRCode.toString(bootstrapQrPayload, {
      errorCorrectionLevel: "H",
      type: "svg",
      margin: BOOTSTRAP_QR_MARGIN,
      width: BOOTSTRAP_QR_WIDTH,
      color: {
        dark: "#000000",
        light: "#FFFFFF"
      }
    })
      .then((svg: string) => {
        if (!cancelled) {
          setBootstrapBundleQrDataUrl(
            `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
          );
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
  }, [bootstrapQrPayload]);

  async function handleIssueBootstrap() {
    setPendingAction("bootstrap");
    setError(null);
    setIssuedBootstrap(null);
    setFallbackBootstrapBundle(null);
    setBootstrapNotice(null);
    try {
      const preferredRendezvousUrl = selectedRendezvousUrl.trim() || null;
      const request = {
        label: deviceLabel.trim() || null,
        expires_in_secs:
          typeof expiresInSecs === "number" && Number.isFinite(expiresInSecs) ? expiresInSecs : 3600,
        preferred_rendezvous_url: preferredRendezvousUrl
      };
      try {
        const payload = await issueBootstrapClaim(request, adminTokenOverride);
        setIssuedBootstrap(payload);
      } catch (claimError) {
        const message = claimError instanceof Error ? claimError.message : String(claimError);
        if (preferredRendezvousUrl || !shouldFallbackToFullBootstrapQr(message)) {
          throw claimError;
        }
        const fallbackBundle = await issueBootstrapBundle(request, adminTokenOverride);
        setFallbackBootstrapBundle(fallbackBundle);
        setBootstrapNotice("Compact claim issuance is temporarily unavailable on this node, so the page fell back to a full bootstrap QR.");
      }
    } catch (issueError) {
      setError(issueError instanceof Error ? issueError.message : String(issueError));
    } finally {
      setPendingAction(null);
    }
  }

  function handleDownloadBootstrapBundle() {
    if (!bootstrapBundle) {
      return;
    }
    const payload = JSON.stringify(bootstrapBundle, null, 2);
    const blob = new Blob([payload], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `ironmesh-client-bootstrap-${bootstrapBundle.cluster_id ?? "bundle"}.json`;
    link.click();
    window.URL.revokeObjectURL(url);
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
      {bootstrapNotice ? <Alert color="blue" title="Bootstrap QR fallback">{bootstrapNotice}</Alert> : null}
      <Text c="dimmed" maw={760}>
        This page handles the two main provisioning tasks still exposed through the runtime admin surface:
        issuing client bootstrap bundles and approving node join requests into enrollment packages.
      </Text>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Group justify="space-between">
                <Text fw={700}>Client bootstrap claim</Text>
                <Badge variant="light">{bootstrapClaim ? "issued" : "ready"}</Badge>
              </Group>
              <Text c="dimmed">
                Issue a compact QR claim for a new client, then keep the full bootstrap bundle available
                as a file fallback. This uses the current admin session or the advanced token override
                from the header drawer.
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
              <NativeSelect
                label="Primary rendezvous service"
                data={rendezvousSelectData}
                value={selectedRendezvousUrl}
                onChange={(event) => setSelectedRendezvousUrl(event.currentTarget.value)}
              />
              <Text size="sm" c="dimmed">
                Leave this on automatic to let the node choose the first healthy rendezvous endpoint.
                If you pick a specific rendezvous endpoint, the issued claim uses it as the primary
                redeem URL and includes healthy fallbacks when available.
              </Text>
              <Group>
                <Button onClick={() => void handleIssueBootstrap()} loading={pendingAction === "bootstrap"}>
                  Issue bootstrap claim
                </Button>
                <Button
                  variant="default"
                  onClick={handleDownloadBootstrapBundle}
                  disabled={!bootstrapBundle}
                >
                  Download bootstrap bundle
                </Button>
              </Group>
              <Text size="sm" c="dimmed">
                Current bundle summary: cluster {String(bootstrapBundle?.cluster_id ?? "unknown")}, relay mode{" "}
                {String(bootstrapBundle?.relay_mode ?? "unknown")}, direct endpoints {bundleEndpointCount}.
              </Text>
              {bootstrapClaim ? (
                <Stack gap="xs">
                  <Text fw={600}>Scan the compact claim with the ironmesh Android app</Text>
                  {bootstrapBundleQrDataUrl ? (
                    <div
                      style={{
                        background: "#FFFFFF",
                        padding: BOOTSTRAP_QR_FRAME_PADDING,
                        borderRadius: 16,
                        width: "100%",
                        maxWidth: BOOTSTRAP_QR_WIDTH + BOOTSTRAP_QR_FRAME_PADDING * 2,
                        boxSizing: "border-box"
                      }}
                    >
                      <img
                        src={bootstrapBundleQrDataUrl}
                        alt="Client bootstrap QR code"
                        style={{ width: "100%", display: "block" }}
                      />
                    </div>
                  ) : (
                    <Text size="sm" c={bootstrapBundleQrError ? "red" : "dimmed"}>
                      {bootstrapBundleQrError ? `Failed to generate QR code: ${bootstrapBundleQrError}` : "Generating QR code..."}
                    </Text>
                  )}
                </Stack>
              ) : bootstrapBundle ? (
                <Stack gap="xs">
                  <Text fw={600}>Scan the full bootstrap bundle with the ironmesh Android app</Text>
                  {bootstrapBundleQrDataUrl ? (
                    <div
                      style={{
                        background: "#FFFFFF",
                        padding: BOOTSTRAP_QR_FRAME_PADDING,
                        borderRadius: 16,
                        width: "100%",
                        maxWidth: BOOTSTRAP_QR_WIDTH + BOOTSTRAP_QR_FRAME_PADDING * 2,
                        boxSizing: "border-box"
                      }}
                    >
                      <img
                        src={bootstrapBundleQrDataUrl}
                        alt="Client bootstrap QR code"
                        style={{ width: "100%", display: "block" }}
                      />
                    </div>
                  ) : (
                    <Text size="sm" c={bootstrapBundleQrError ? "red" : "dimmed"}>
                      {bootstrapBundleQrError ? `Failed to generate QR code: ${bootstrapBundleQrError}` : "Generating QR code..."}
                    </Text>
                  )}
                </Stack>
              ) : null}
              <JsonBlock value={issuedBootstrap ?? bootstrapBundle ?? { status: "no bootstrap claim issued yet" }} />
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
