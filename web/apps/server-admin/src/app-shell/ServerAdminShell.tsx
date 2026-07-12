import { getSetupStatus, isHttpErrorStatus } from "@ironmesh/api";
import { ColorSchemeControl, NavigationShell, PageHeader } from "@ironmesh/ui";
import { Alert, Badge, Button, Center, Loader, Stack, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Suspense, useEffect, useState, type ReactNode } from "react";
import { serverAdminRoutes } from "./routes";
import { AdminAccessDrawer } from "../components/AdminAccessDrawer";
import { useAdminAccess } from "../lib/admin-access";

type SurfaceMode = "probing" | "runtime" | "setup";

type RouteLoadingStateProps = {
  routeLabel: string;
};

export function ServerAdminShell() {
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
      : serverAdminRoutes.filter((route) => route.id !== "setup");
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

  useEffect(() => {
    if (surfaceMode !== "setup") {
      return;
    }

    let cancelled = false;
    let timeoutId: number | null = null;

    async function probeForRuntimeTransition() {
      try {
        await getSetupStatus();
      } catch (error) {
        if (!cancelled && isHttpErrorStatus(error, 401, 403, 404)) {
          setSurfaceMode("runtime");
          setSurfaceError(null);
          return;
        }
      }

      if (!cancelled) {
        timeoutId = window.setTimeout(() => {
          void probeForRuntimeTransition();
        }, 1000);
      }
    }

    timeoutId = window.setTimeout(() => {
      void probeForRuntimeTransition();
    }, 1000);

    return () => {
      cancelled = true;
      if (timeoutId !== null) {
        window.clearTimeout(timeoutId);
      }
    };
  }, [surfaceMode]);

  return (
    <>
      <NavigationShell
        surfaceLabel="Server Admin"
        navigationItems={visibleRoutes}
        activeItemId={activeRoute.id}
        onNavigate={setActiveRouteId}
        contentGap="xl"
        headerActions={
          <>
            <Badge
              data-testid="server-admin-session-badge"
              color={
                surfaceMode === "setup" ? "blue" : sessionStatus?.authenticated ? "teal" : "gray"
              }
            >
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
          </>
        }
      >
        {surfaceMode === "probing" ? (
          <>
            <PageHeader
              title="Detecting Node Mode"
              description="Checking whether this node is in first-run setup mode or normal runtime mode."
            />
            <Center py="xl">
              <Stack align="center" gap="sm">
                <Loader color="teal" />
                <Text c="dimmed">Loading the server-admin surface...</Text>
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
            <Suspense fallback={<RouteLoadingState routeLabel={activeRoute.label} />}>
              <RouteReadyState routeId={activeRoute.id}>{activeRoute.element}</RouteReadyState>
            </Suspense>
          </>
        )}
      </NavigationShell>
      <AdminAccessDrawer opened={accessOpened} onClose={accessControls.close} />
    </>
  );
}

function RouteLoadingState({ routeLabel }: RouteLoadingStateProps) {
  return (
    <Center py="xl">
      <Stack align="center" gap="sm">
        <Loader color="teal" />
        <Text c="dimmed">Loading {routeLabel}...</Text>
      </Stack>
    </Center>
  );
}

function RouteReadyState({
  routeId,
  children
}: {
  routeId: (typeof serverAdminRoutes)[number]["id"];
  children: ReactNode;
}) {
  return <div data-testid={`server-admin-route-${routeId}`}>{children}</div>;
}
