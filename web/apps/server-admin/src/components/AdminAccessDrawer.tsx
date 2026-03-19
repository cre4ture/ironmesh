import {
  Badge,
  Button,
  Drawer,
  Group,
  PasswordInput,
  Stack,
  Text,
  TextInput
} from "@mantine/core";
import { JsonBlock } from "@ironmesh/ui";
import { useState } from "react";
import { useAdminAccess } from "../lib/admin-access";

type AdminAccessDrawerProps = {
  opened: boolean;
  onClose: () => void;
};

export function AdminAccessDrawer({ opened, onClose }: AdminAccessDrawerProps) {
  const {
    adminTokenOverride,
    setAdminTokenOverride,
    sessionStatus,
    sessionLoading,
    sessionError,
    refreshSession,
    login,
    logout
  } = useAdminAccess();
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState<"login" | "logout" | "refresh" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  async function handleLogin() {
    if (!password.trim()) {
      setActionError("admin password is required");
      return;
    }
    setPending("login");
    setActionError(null);
    try {
      await login(password);
      setPassword("");
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setPending(null);
    }
  }

  async function handleLogout() {
    setPending("logout");
    setActionError(null);
    try {
      await logout();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setPending(null);
    }
  }

  async function handleRefresh() {
    setPending("refresh");
    setActionError(null);
    try {
      await refreshSession();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setPending(null);
    }
  }

  return (
    <Drawer opened={opened} onClose={onClose} position="right" title="Admin Access" size="md">
      <Stack gap="lg">
        <Text c="dimmed">
          The normal path is password-backed local admin login. Admin token override is still available as an advanced option for env-driven or automation-oriented setups.
        </Text>

        <Stack gap="sm">
          <PasswordInput
            label="Admin password"
            value={password}
            onChange={(event) => setPassword(event.currentTarget.value)}
            placeholder="Enter the local admin password"
          />
          <Group>
            <Button onClick={() => void handleLogin()} loading={pending === "login"}>
              Sign in
            </Button>
            <Button
              variant="default"
              onClick={() => void handleLogout()}
              loading={pending === "logout"}
            >
              Sign out
            </Button>
            <Button
              variant="subtle"
              onClick={() => void handleRefresh()}
              loading={pending === "refresh" || sessionLoading}
            >
              Refresh
            </Button>
          </Group>
        </Stack>

        <TextInput
          label="Admin token override"
          value={adminTokenOverride}
          onChange={(event) => setAdminTokenOverride(event.currentTarget.value)}
          placeholder="Optional advanced override"
        />

        <Group gap="sm">
          <Badge color={sessionStatus?.authenticated ? "teal" : "gray"}>
            {sessionStatus?.authenticated ? "authenticated" : "not authenticated"}
          </Badge>
          <Badge variant="light">
            {sessionStatus?.token_override_enabled ? "token override enabled" : "token override available"}
          </Badge>
        </Group>

        {sessionError ? <Text c="red">{sessionError}</Text> : null}
        {actionError ? <Text c="red">{actionError}</Text> : null}

        <JsonBlock value={sessionStatus ?? { status: "loading" }} />
      </Stack>
    </Drawer>
  );
}
