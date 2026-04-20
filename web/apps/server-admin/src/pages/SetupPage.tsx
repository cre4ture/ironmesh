import {
  generateSetupJoinRequest,
  getSetupStatus,
  importSetupEnrollmentPackage,
  isHttpErrorStatus,
  startSetupCluster,
  type SetupStatus,
  type SetupTransitionResponse
} from "@ironmesh/api";
import { JsonBlock, StatCard } from "@ironmesh/ui";
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
  Textarea
} from "@mantine/core";
import { useCallback, useEffect, useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function SetupPage() {
  const { login } = useAdminAccess();
  const [status, setStatus] = useState<SetupStatus | null>(null);
  const [availability, setAvailability] = useState<"loading" | "available" | "unavailable">("loading");
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [startPassword, setStartPassword] = useState("");
  const [joinAdminPassword, setJoinAdminPassword] = useState("");
  const [enrollmentJson, setEnrollmentJson] = useState("");
  const [joinRequestOutput, setJoinRequestOutput] = useState<Record<string, unknown> | null>(null);
  const [transitionOutput, setTransitionOutput] = useState<SetupTransitionResponse | null>(null);
  const [pendingAction, setPendingAction] = useState<"start" | "join-request" | "import" | null>(null);

  const refresh = useCallback(async () => {
    setError(null);
    try {
      const payload = await getSetupStatus();
      setStatus(payload);
      setAvailability("available");
    } catch (refreshError) {
      if (isHttpErrorStatus(refreshError, 401, 403, 404)) {
        setAvailability("unavailable");
        setStatus(null);
        return;
      }
      const message = refreshError instanceof Error ? refreshError.message : String(refreshError);
      setError(message);
      setAvailability("unavailable");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function handleStartCluster() {
    if (!startPassword.trim()) {
      setActionError("initial admin password is required");
      return;
    }

    setPendingAction("start");
    setActionError(null);
    try {
      const payload = await startSetupCluster({
        admin_password: startPassword,
        public_origin: window.location.origin
      });
      setTransitionOutput(payload);
      await waitForRuntimeTransition(startPassword, login);
    } catch (setupError) {
      setActionError(setupError instanceof Error ? setupError.message : String(setupError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleGenerateJoinRequest() {
    setPendingAction("join-request");
    setActionError(null);
    try {
      const payload = await generateSetupJoinRequest({
        public_origin: window.location.origin
      });
      setJoinRequestOutput(payload);
      await refresh();
    } catch (setupError) {
      setActionError(setupError instanceof Error ? setupError.message : String(setupError));
    } finally {
      setPendingAction(null);
    }
  }

  async function handleImportEnrollment() {
    if (!joinAdminPassword.trim()) {
      setActionError("cluster admin password is required");
      return;
    }
    if (!enrollmentJson.trim()) {
      setActionError("node enrollment package JSON is required");
      return;
    }

    setPendingAction("import");
    setActionError(null);
    try {
      const payload = await importSetupEnrollmentPackage({
        admin_password: joinAdminPassword,
        package_json: enrollmentJson
      });
      setTransitionOutput(payload);
      await waitForRuntimeTransition(joinAdminPassword, login);
    } catch (setupError) {
      setActionError(setupError instanceof Error ? setupError.message : String(setupError));
    } finally {
      setPendingAction(null);
    }
  }

  if (availability === "unavailable") {
    return (
      <Stack gap="lg">
        {error ? <Alert color="red" title="Setup endpoint error">{error}</Alert> : null}
        <Alert color="teal" title="Bootstrap setup APIs are not active on this node">
          This node is already in normal runtime mode. The shared React admin app now uses this same Setup page during
          first-run bootstrap mode, and keeps it here as a reference view once setup is complete.
        </Alert>
        <Card withBorder radius="md" padding="lg">
          <Stack gap="sm">
            <Text fw={700}>What setup mode covers</Text>
            <Text c="dimmed">Start a new cluster, generate a join request, import a node enrollment package, and hand off into the runtime admin session.</Text>
          </Stack>
        </Card>
      </Stack>
    );
  }

  return (
    <Stack gap="lg">
      {error ? <Alert color="red" title="Failed to load setup status">{error}</Alert> : null}
      {actionError ? <Alert color="red" title="Setup action failed">{actionError}</Alert> : null}

      <Group justify="space-between" align="flex-start">
        <Text c="dimmed" maw={760}>
          This is the live first-run bootstrap UI for starting a managed cluster or joining an existing one. It uses
          the `/setup/*` endpoints directly and hands off into the normal runtime admin session once the node
          transitions online.
        </Text>
        <Button variant="light" onClick={() => void refresh()} loading={availability === "loading"}>
          Refresh
        </Button>
      </Group>

      <Grid>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Setup State"
            value={status?.state || (availability === "loading" ? "loading..." : "unknown")}
            hint={status?.cluster_id ? `Cluster ${status.cluster_id}` : "Cluster not initialized yet"}
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Bind Address"
            value={status?.bind_addr || (availability === "loading" ? "loading..." : "unknown")}
            hint="Temporary HTTPS setup listener"
          />
        </Grid.Col>
        <Grid.Col span={{ base: 12, md: 4 }}>
          <StatCard
            label="Bootstrap TLS"
            value={status?.bootstrap_tls_fingerprint || (availability === "loading" ? "loading..." : "unknown")}
            hint="Temporary self-signed setup certificate fingerprint"
          />
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Group justify="space-between">
            <Text fw={700}>Current setup status</Text>
            <Badge variant="light">{status?.state || "loading"}</Badge>
          </Group>
          <JsonBlock value={status ?? { status: "loading" }} />
        </Stack>
      </Card>

      <Grid>
        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Text fw={700}>Start a new cluster</Text>
              <Text c="dimmed">
                Creates a managed cluster CA, enrolls this node as the first cluster member, and transitions into
                the normal runtime admin surface.
              </Text>
              <PasswordInput
                label="Initial admin password"
                value={startPassword}
                onChange={(event) => setStartPassword(event.currentTarget.value)}
              />
              <Group>
                <Button onClick={() => void handleStartCluster()} loading={pendingAction === "start"}>
                  Start a new cluster
                </Button>
              </Group>
            </Stack>
          </Card>
        </Grid.Col>

        <Grid.Col span={{ base: 12, xl: 6 }}>
          <Card withBorder radius="md" padding="lg" h="100%">
            <Stack gap="md">
              <Text fw={700}>Generate join request</Text>
              <Text c="dimmed">
                Generates a join request blob that can be copied into an existing cluster admin flow and turned into
                a node enrollment package.
              </Text>
              <Group>
                <Button
                  variant="light"
                  onClick={() => void handleGenerateJoinRequest()}
                  loading={pendingAction === "join-request"}
                >
                  Generate join request
                </Button>
              </Group>
              <JsonBlock value={joinRequestOutput ?? status?.pending_join_request ?? { status: "no join request yet" }} />
            </Stack>
          </Card>
        </Grid.Col>
      </Grid>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="md">
          <Text fw={700}>Import node enrollment package</Text>
          <Text c="dimmed">
            Paste the enrollment package issued by an existing cluster and transition this node into normal runtime.
          </Text>
          <PasswordInput
            label="Cluster admin password"
            value={joinAdminPassword}
            onChange={(event) => setJoinAdminPassword(event.currentTarget.value)}
          />
          <Textarea
            label="Node enrollment package JSON"
            minRows={12}
            autosize
            value={enrollmentJson}
            onChange={(event) => setEnrollmentJson(event.currentTarget.value)}
            placeholder='{"bootstrap": ...}'
          />
          <Group>
            <Button onClick={() => void handleImportEnrollment()} loading={pendingAction === "import"}>
              Import node enrollment package
            </Button>
          </Group>
        </Stack>
      </Card>

      <Card withBorder radius="md" padding="lg">
        <Stack gap="sm">
          <Text fw={700}>Latest transition result</Text>
          <JsonBlock value={transitionOutput ?? { status: "no transition triggered yet" }} />
        </Stack>
      </Card>
    </Stack>
  );
}

async function waitForRuntimeTransition(
  password: string,
  login: (password: string) => Promise<void>
) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
    try {
      const response = await fetch("/api/v1/auth/admin/session", {
        cache: "no-store",
        credentials: "same-origin"
      });
      if (!response.ok) {
        continue;
      }
      await login(password);
      window.location.href = "/";
      return;
    } catch {
      // runtime may still be switching modes
    }
  }

  window.location.href = "/";
}
