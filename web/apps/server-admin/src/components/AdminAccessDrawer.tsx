import {
  Badge,
  Button,
  Drawer,
  Group,
  PasswordInput,
  Stack,
  Text
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
          Use the local admin password to open protected runtime views and maintenance actions in
          the server-admin UI.
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

        <Group gap="sm">
          <Badge color={sessionStatus?.authenticated ? "teal" : "gray"}>
            {sessionStatus?.authenticated ? "authenticated" : "not authenticated"}
          </Badge>
        </Group>

        {sessionError ? <Text c="red">{sessionError}</Text> : null}
        {actionError ? <Text c="red">{actionError}</Text> : null}

        <JsonBlock value={sessionStatus ?? { status: "loading" }} />
      </Stack>
    </Drawer>
  );
}
