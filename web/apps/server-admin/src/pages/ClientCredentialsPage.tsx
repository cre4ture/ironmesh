import { listClientCredentials, revokeClientCredential, type ClientCredentialView } from "@ironmesh/api";
import { StatCard } from "@ironmesh/ui";
import {
  Alert,
  Badge,
  Button,
  Card,
  Group,
  Modal,
  ScrollArea,
  SimpleGrid,
  Stack,
  Table,
  Text,
  TextInput
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useCallback, useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";
import { formatUnixTs } from "../lib/format";

export function ClientCredentialsPage() {
  const { adminTokenOverride } = useAdminAccess();
  const [credentials, setCredentials] = useState<ClientCredentialView[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedCredential, setSelectedCredential] = useState<ClientCredentialView | null>(null);
  const [revokeReason, setRevokeReason] = useState("");
  const [revokePending, setRevokePending] = useState(false);
  const [opened, disclosure] = useDisclosure(false);
  const activeCount = credentials.filter((credential) => credential.revoked_at_unix == null).length;
  const revokedCount = credentials.length - activeCount;

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const payload = await listClientCredentials(adminTokenOverride);
      setCredentials(payload);
    } catch (refreshError) {
      setError(refreshError instanceof Error ? refreshError.message : String(refreshError));
    } finally {
      setLoading(false);
    }
  }, [adminTokenOverride]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function confirmRevoke() {
    if (!selectedCredential) {
      return;
    }
    setRevokePending(true);
    setError(null);
    try {
      await revokeClientCredential(selectedCredential.device_id, revokeReason || null, adminTokenOverride);
      disclosure.close();
      setSelectedCredential(null);
      setRevokeReason("");
      await refresh();
    } catch (revokeError) {
      setError(revokeError instanceof Error ? revokeError.message : String(revokeError));
    } finally {
      setRevokePending(false);
    }
  }

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Request failed">{error}</Alert> : null}
      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          Credentials listed here are the client identities currently known to this node. Revocation remains
          intentionally explicit, including the recorded reason and actor fields, so operators can audit what
          changed and why.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={loading}>
          Refresh
        </Button>
      </Group>

      <SimpleGrid cols={{ base: 1, md: 3 }}>
        <StatCard label="Known Credentials" value={credentials.length} hint="Total credential records" />
        <StatCard label="Active Credentials" value={activeCount} hint="Not currently revoked" />
        <StatCard label="Revoked Credentials" value={revokedCount} hint="Retained for audit visibility" />
      </SimpleGrid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Text fw={700}>Client credentials</Text>
            <Badge variant="light">{loading ? "refreshing" : "up to date"}</Badge>
          </Group>
          <ScrollArea type="auto">
            <Table striped highlightOnHover withTableBorder>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Device ID</Table.Th>
                  <Table.Th>Label</Table.Th>
                  <Table.Th>Credential fingerprint</Table.Th>
                  <Table.Th>Public key fingerprint</Table.Th>
                  <Table.Th>Created</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Revocation detail</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {credentials.length > 0 ? (
                  credentials.map((credential) => (
                    <Table.Tr key={credential.device_id}>
                      <Table.Td>{credential.device_id}</Table.Td>
                      <Table.Td>{credential.label || "-"}</Table.Td>
                      <Table.Td>{credential.credential_fingerprint || "-"}</Table.Td>
                      <Table.Td>{credential.public_key_fingerprint || "-"}</Table.Td>
                      <Table.Td>{formatUnixTs(credential.created_at_unix)}</Table.Td>
                      <Table.Td>
                        <Badge color={credential.revoked_at_unix ? "red" : "teal"} variant="light">
                          {credential.revoked_at_unix ? "revoked" : "active"}
                        </Badge>
                      </Table.Td>
                      <Table.Td>
                        {credential.revoked_at_unix
                          ? `${formatUnixTs(credential.revoked_at_unix)} | ${credential.revocation_reason || "no reason"}`
                          : "-"}
                      </Table.Td>
                      <Table.Td>
                        <Button
                          size="xs"
                          variant="light"
                          color="red"
                          disabled={credential.revoked_at_unix != null}
                          onClick={() => {
                            setSelectedCredential(credential);
                            disclosure.open();
                          }}
                        >
                          Revoke
                        </Button>
                      </Table.Td>
                    </Table.Tr>
                  ))
                ) : (
                  <Table.Tr>
                    <Table.Td colSpan={8}>
                      <Text c="dimmed">No client credentials have been enrolled yet.</Text>
                    </Table.Td>
                  </Table.Tr>
                )}
              </Table.Tbody>
            </Table>
          </ScrollArea>
        </Stack>
      </Card>

      <Modal opened={opened} onClose={disclosure.close} title="Revoke client credential" centered>
        <Stack gap="md">
          <Text c="dimmed">
            {selectedCredential ? `Revoke ${selectedCredential.device_id}` : "Select a credential first."}
          </Text>
          <TextInput
            label="Revocation reason"
            value={revokeReason}
            onChange={(event) => setRevokeReason(event.currentTarget.value)}
            placeholder="Optional reason"
          />
          <Group justify="flex-end">
            <Button variant="default" onClick={disclosure.close}>
              Cancel
            </Button>
            <Button color="red" onClick={() => void confirmRevoke()} loading={revokePending}>
              Revoke credential
            </Button>
          </Group>
        </Stack>
      </Modal>
    </Stack>
  );
}
