import { getSetupStatus, isHttpErrorStatus } from "@ironmesh/api";
import { ColorSchemeControl, IronmeshBrand, PageHeader } from "@ironmesh/ui";
import { Alert, AppShell, Badge, Burger, Button, Center, Group, Loader, NavLink, ScrollArea, Stack, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { useEffect, useState } from "react";
import { serverAdminRoutes } from "./routes";
import { AdminAccessDrawer } from "../components/AdminAccessDrawer";
import { useAdminAccess } from "../lib/admin-access";

type SurfaceMode = "probing" | "runtime" | "setup";

export function ServerAdminShell() {
  const [opened, { toggle, close }] = useDisclosure();
  const [accessOpened, accessControls] = useDisclosure(false);
  const [surfaceMode, setSurfaceMode] = useState<SurfaceMode>("probing");
  const [surfaceError, setSurfaceError] = useState<string | null>(null);
  const [activeRouteId, setActiveRouteId] = useState<(typeof serverAdminRoutes)[number]["id"]>(
    serverAdminRoutes[0].id
  );
  const { sessionStatus } = useAdminAccess();
  const visibleRoutes =
    surfaceMode === "setup"
      ? serverAdminRoutes.filter((route) => route.id === "setup")
      : serverAdminRoutes;
  const activeRoute = visibleRoutes.find((route) => route.id === activeRouteId) ?? visibleRoutes[0];

  useEffect(() => {
    let cancelled = false;

    async function detectSurfaceMode() {
      try {
        await getSetupStatus();
        if (cancelled) {
          return;
        }
        setSurfaceMode("setup");
        setSurfaceError(null);
        setActiveRouteId("setup");
      } catch (error) {
        if (cancelled) {
          return;
        }
        setSurfaceMode("runtime");
        if (isHttpErrorStatus(error, 401, 403, 404)) {
          setSurfaceError(null);
        } else {
          const message = error instanceof Error ? error.message : String(error);
          setSurfaceError(`Failed to probe setup mode: ${message}`);
        }
      }
    }

    void detectSurfaceMode();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <>
      <AppShell
        className="shell-root"
        header={{ height: 68 }}
        navbar={{ width: 280, breakpoint: "sm", collapsed: { mobile: !opened } }}
        padding={{ base: "xs", sm: "md", lg: "lg" }}
      >
        <AppShell.Header className="shell-header">
          <Group className="shell-header-bar" h="100%" px="md" justify="space-between">
            <Group gap="sm">
              <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
              <IronmeshBrand surfaceLabel="Server Admin" />
            </Group>
            <Group gap="sm">
              <Badge color={surfaceMode === "setup" ? "blue" : sessionStatus?.authenticated ? "teal" : "gray"}>
                {surfaceMode === "setup"
                  ? "setup mode"
                  : sessionStatus?.authenticated
                    ? "signed in"
                    : "sign in required"}
              </Badge>
              <ColorSchemeControl />
              <Button variant="light" onClick={accessControls.open} disabled={surfaceMode === "setup"}>
                Admin Access
              </Button>
            </Group>
          </Group>
        </AppShell.Header>

        <AppShell.Navbar className="shell-navbar" p="sm">
          <AppShell.Section grow component={ScrollArea}>
            <Stack gap="xs">
              {visibleRoutes.map((route) => {
                const Icon = route.icon;
                return (
                  <NavLink
                    key={route.id}
                    active={route.id === activeRouteId}
                    label={route.label}
                    leftSection={<Icon size={16} />}
                    onClick={() => {
                      setActiveRouteId(route.id);
                      close();
                    }}
                  />
                );
              })}
            </Stack>
          </AppShell.Section>
        </AppShell.Navbar>

        <AppShell.Main className="shell-main">
          <Stack className="shell-content" gap="xl">
            {surfaceMode === "probing" ? (
              <>
                <PageHeader
                  title="Detecting Node Mode"
                  description="Checking whether this node is in first-run setup mode or normal runtime mode."
                />
                <Center py="xl">
                  <Stack align="center" gap="sm">
                    <Loader color="teal" />
                    <Text c="dimmed">Loading the server-admin surface…</Text>
                  </Stack>
                </Center>
              </>
            ) : (
              <>
                <PageHeader title={activeRoute.label} description={activeRoute.description} />
                {surfaceError ? (
                  <Alert color="yellow" title="Setup probe warning">
                    {surfaceError}
                  </Alert>
                ) : null}
                {activeRoute.element}
              </>
            )}
          </Stack>
        </AppShell.Main>
      </AppShell>
      {opened ? <div className="shell-backdrop" onClick={close} /> : null}
      <AdminAccessDrawer opened={accessOpened} onClose={accessControls.close} />
    </>
  );
}
