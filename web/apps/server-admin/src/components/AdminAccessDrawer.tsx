import {
  Badge,
  Button,
  Collapse,
  Drawer,
  Group,
  PasswordInput,
  Stack,
  Text
} from "@mantine/core";
import { ironmeshPrimaryColor, JsonBlock } from "@ironmesh/ui";
import { useState } from "react";
import { changeAdminPassword } from "@ironmesh/api";
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
  const [pending, setPending] = useState<"login" | "logout" | "refresh" | "change-password" | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [changePasswordOpen, setChangePasswordOpen] = useState(false);
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [changePasswordSuccess, setChangePasswordSuccess] = useState(false);

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

  async function handleChangePassword() {
    if (!currentPassword.trim()) {
      setActionError("current password is required");
      return;
    }
    if (!newPassword.trim()) {
      setActionError("new password is required");
      return;
    }
    if (newPassword !== confirmPassword) {
      setActionError("new passwords do not match");
      return;
    }
    setPending("change-password");
    setActionError(null);
    setChangePasswordSuccess(false);
    try {
      await changeAdminPassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setChangePasswordSuccess(true);
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
          <Badge color={sessionStatus?.authenticated ? ironmeshPrimaryColor : "gray"}>
            {sessionStatus?.authenticated ? "authenticated" : "not authenticated"}
          </Badge>
        </Group>

        {sessionStatus?.authenticated ? (
          <Stack gap="sm">
            <Button
              variant="subtle"
              size="compact-sm"
              onClick={() => {
                setChangePasswordOpen((open) => !open);
                setActionError(null);
                setChangePasswordSuccess(false);
              }}
            >
              {changePasswordOpen ? "Hide" : "Change password"}
            </Button>
            <Collapse in={changePasswordOpen}>
              <Stack gap="sm">
                <PasswordInput
                  label="Current password"
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.currentTarget.value)}
                  placeholder="Enter current password"
                />
                <PasswordInput
                  label="New password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.currentTarget.value)}
                  placeholder="Enter new password"
                />
                <PasswordInput
                  label="Confirm new password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.currentTarget.value)}
                  placeholder="Confirm new password"
                />
                <Button
                  onClick={() => void handleChangePassword()}
                  loading={pending === "change-password"}
                >
                  Update password
                </Button>
                {changePasswordSuccess ? (
                  <Text c={ironmeshPrimaryColor}>Password updated successfully.</Text>
                ) : null}
              </Stack>
            </Collapse>
          </Stack>
        ) : null}

        {sessionError ? <Text c="red">{sessionError}</Text> : null}
        {actionError ? <Text c="red">{actionError}</Text> : null}

        <JsonBlock value={sessionStatus ?? { status: "loading" }} />
      </Stack>
    </Drawer>
  );
}
