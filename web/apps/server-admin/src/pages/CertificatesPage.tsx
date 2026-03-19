import { getNodeCertificateStatus, type NodeCertificateStatus, type NodeCertificateStatusResponse } from "@ironmesh/api";
import { JsonBlock, StatCard } from "@ironmesh/ui";
import { Alert, Badge, Button, Card, Grid, Group, Stack, Text } from "@mantine/core";
import { useCallback, useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatUnixTs } from "../lib/format";

function CertificateDetailCard({
  title,
  status
}: {
  title: string;
  status: NodeCertificateStatus;
}) {
  return (
    <Card withBorder radius="md" padding="lg" h="100%">
      <Stack gap="sm">
        <Group justify="space-between">
          <Text fw={700}>{title}</Text>
          <Badge variant="light" color={status.state === "healthy" ? "teal" : status.state === "expired" ? "red" : "yellow"}>
            {status.state}
          </Badge>
        </Group>
        <Text c="dimmed">{status.configured ? "Configured on this node" : "Not configured on this node"}</Text>
        <Text size="sm">Fingerprint: {status.certificate_fingerprint || "unknown"}</Text>
        <Text size="sm">Issued: {formatUnixTs(status.issued_at_unix)}</Text>
        <Text size="sm">Renew after: {formatUnixTs(status.renew_after_unix)}</Text>
        <Text size="sm">Expires: {formatUnixTs(status.expires_at_unix)}</Text>
        <Text size="sm">Metadata path: {status.metadata_path || "not materialized"}</Text>
        <Text size="sm">
          Metadata matches certificate:{" "}
          {status.metadata_matches_certificate == null ? "unknown" : status.metadata_matches_certificate ? "yes" : "no"}
        </Text>
      </Stack>
    </Card>
  );
}

export function CertificatesPage() {
  const { adminTokenOverride } = useAdminAccess();
  const [status, setStatus] = useState<NodeCertificateStatusResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await getNodeCertificateStatus(adminTokenOverride);
      setStatus(payload);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      setLoading(false);
    }
  }, [adminTokenOverride]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Request failed">{error}</Alert> : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This view summarizes the currently loaded public and internal TLS material together with the
          auto-renew loop state. It is meant to replace the raw JSON-heavy lifecycle section from the old
          admin page without hiding the underlying details.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
        </Button>
      </Group>
      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Public TLS"
            value={status?.public_tls.state || (loading ? "loading..." : "unknown")}
            hint={`Expires: ${formatUnixTs(status?.public_tls.expires_at_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Internal TLS"
            value={status?.internal_tls.state || (loading ? "loading..." : "unknown")}
            hint={`Expires: ${formatUnixTs(status?.internal_tls.expires_at_unix)}`}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Auto renew"
            value={status?.auto_renew.enabled ? "enabled" : loading ? "loading..." : "disabled"}
            hint={
              status?.auto_renew.last_success_unix
                ? `Last success: ${formatUnixTs(status.auto_renew.last_success_unix)}`
                : "No successful renewal recorded yet"
            }
          />
        </Grid.Col>
      </Grid>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <CertificateDetailCard title="Public listener certificate" status={status?.public_tls ?? emptyStatus("public")} />
        </Grid.Col>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <CertificateDetailCard title="Internal mTLS certificate" status={status?.internal_tls ?? emptyStatus("internal")} />
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Group justify="space-between">
            <Text fw={700}>Auto-renew detail</Text>
            <Badge color={status?.auto_renew.restart_required ? "yellow" : "teal"} variant="light">
              {status?.auto_renew.restart_required ? "restart required" : "live state current"}
            </Badge>
          </Group>
          <Text size="sm">Enrollment path: {status?.auto_renew.enrollment_path || "not configured"}</Text>
          <Text size="sm">Issuer URL: {status?.auto_renew.issuer_url || "not configured"}</Text>
          <Text size="sm">Last attempt: {formatUnixTs(status?.auto_renew.last_attempt_unix)}</Text>
          <Text size="sm">Last error: {status?.auto_renew.last_error || "none"}</Text>
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>Certificate lifecycle detail</Text>
          <JsonBlock value={status ?? { status: "loading" }} />
        </Stack>
      </Card>
    </Stack>
  );
}

function emptyStatus(name: string): NodeCertificateStatus {
  return {
    name,
    configured: false,
    cert_path: null,
    metadata_path: null,
    issued_at_unix: null,
    renew_after_unix: null,
    expires_at_unix: null,
    seconds_until_expiry: null,
    certificate_fingerprint: null,
    metadata_matches_certificate: null,
    state: "unknown"
  };
}
