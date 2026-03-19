import { AppShell, Burger, Card, Group, NavLink, Stack, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconFolder, IconPhoto, IconSettings, IconUpload } from "@tabler/icons-react";
import { useState } from "react";

const pages = [
  { id: "browser", label: "Browser", icon: IconFolder, description: "Transport-aware object browser scaffold" },
  { id: "uploads", label: "Uploads", icon: IconUpload, description: "Upload queue and transfer status scaffold" },
  { id: "media", label: "Media", icon: IconPhoto, description: "Gallery and media preview scaffold" },
  { id: "settings", label: "Settings", icon: IconSettings, description: "Bootstrap, identity, and runtime settings scaffold" }
] as const;

export function ClientShell() {
  const [opened, { toggle }] = useDisclosure();
  const [activePageId, setActivePageId] = useState<(typeof pages)[number]["id"]>(pages[0].id);
  const activePage = pages.find((page) => page.id === activePageId) ?? pages[0];

  return (
    <AppShell
      header={{ height: 72 }}
      navbar={{ width: 260, breakpoint: "sm", collapsed: { mobile: !opened } }}
      padding="lg"
    >
      <AppShell.Header>
        <Group h="100%" px="md" justify="space-between">
          <Group gap="sm">
            <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
            <Stack gap={0}>
              <Text fw={800} tt="uppercase" size="sm" c="teal">
                ironmesh
              </Text>
              <Text fw={700}>Client UI</Text>
            </Stack>
          </Group>
        </Group>
      </AppShell.Header>

      <AppShell.Navbar p="sm">
        <Stack gap="xs">
          {pages.map((page) => {
            const Icon = page.icon;
            return (
              <NavLink
                key={page.id}
                active={page.id === activePageId}
                label={page.label}
                leftSection={<Icon size={16} />}
                onClick={() => setActivePageId(page.id)}
              />
            );
          })}
        </Stack>
      </AppShell.Navbar>

      <AppShell.Main>
        <Card withBorder radius="md" padding="xl">
          <Stack gap="sm">
            <Text fw={700} size="xl">
              {activePage.label}
            </Text>
            <Text c="dimmed">{activePage.description}</Text>
          </Stack>
        </Card>
      </AppShell.Main>
    </AppShell>
  );
}
