import { AppShell, Burger, Button, Group, NavLink, ScrollArea, Stack, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { PageHeader } from "@ironmesh/ui";
import { ironmeshProductName } from "@ironmesh/config";
import { useState } from "react";
import { serverAdminRoutes } from "./routes";

export function ServerAdminShell() {
  const [opened, { toggle }] = useDisclosure();
  const [activeRouteId, setActiveRouteId] = useState<(typeof serverAdminRoutes)[number]["id"]>(
    serverAdminRoutes[0].id
  );
  const activeRoute = serverAdminRoutes.find((route) => route.id === activeRouteId) ?? serverAdminRoutes[0];

  return (
    <AppShell
      header={{ height: 72 }}
      navbar={{ width: 280, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="lg"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Stack gap={0}>
              <Text fw={800} tt="uppercase" size="sm" c="teal">
                {ironmeshProductName}
              </Text>
              <Text fw={700}>Server Admin</Text>
            </Stack>
          </Group>
          <Button variant="light">Admin Session Placeholder</Button>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        <AppShell.Section grow component={ScrollArea}>
          <Stack gap="xs">
            {serverAdminRoutes.map((route) => {
              const Icon = route.icon;
              return (
                <NavLink
                  key={route.id}
                  active={route.id === activeRouteId}
                  label={route.label}
                  leftSection={<Icon size={16} />}
                  onClick={() => setActiveRouteId(route.id)}
                />
              );
            })}
          </Stack>
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>
        <Stack gap="xl">
          <PageHeader
            title={activeRoute.label}
            description="Scaffolded React + Mantine replacement for the handwritten server-node admin UI."
          />
          {activeRoute.element}
        </Stack>
      </AppShell.Main>
    </AppShell>
  );
}
