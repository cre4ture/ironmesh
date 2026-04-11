import {
  AppShell,
  Burger,
  Group,
  NavLink,
  ScrollArea,
  Stack,
  type StackProps
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { type ComponentType, type ReactNode } from "react";
import { IronmeshBrand } from "../IronmeshBrand/IronmeshBrand";

type NavigationShellIcon = ComponentType<{ size?: number | string }>;

export type NavigationShellItem<ItemId extends string = string> = {
  id: ItemId;
  label: string;
  description?: string;
  icon: NavigationShellIcon;
};

type NavigationShellProps<ItemId extends string = string> = {
  surfaceLabel: string;
  navigationItems: ReadonlyArray<NavigationShellItem<ItemId>>;
  activeItemId: ItemId;
  onNavigate: (id: ItemId) => void;
  children: ReactNode;
  headerActions?: ReactNode;
  contentGap?: StackProps["gap"];
  navbarAriaLabel?: string;
};

export function NavigationShell<ItemId extends string = string>({
  surfaceLabel,
  navigationItems,
  activeItemId,
  onNavigate,
  children,
  headerActions,
  contentGap = "lg",
  navbarAriaLabel = "Primary navigation"
}: NavigationShellProps<ItemId>) {
  const [mobileOpened, mobileControls] = useDisclosure(false);
  const [desktopOpened, desktopControls] = useDisclosure(true);

  return (
    <>
      <AppShell
        className="shell-root"
        header={{ height: 68 }}
        navbar={{
          width: 280,
          breakpoint: "sm",
          collapsed: { mobile: !mobileOpened, desktop: !desktopOpened }
        }}
        padding={{ base: "xs", sm: "md", lg: "lg" }}
      >
        <AppShell.Header className="shell-header">
          <Group className="shell-header-bar" h="100%" px="md" justify="space-between">
            <Group gap="sm">
              <Burger
                opened={mobileOpened}
                onClick={mobileControls.toggle}
                hiddenFrom="sm"
                size="sm"
                aria-label="Toggle navigation menu"
              />
              <Burger
                opened={desktopOpened}
                onClick={desktopControls.toggle}
                visibleFrom="sm"
                size="sm"
                aria-label="Toggle navigation sidebar"
              />
              <IronmeshBrand surfaceLabel={surfaceLabel} />
            </Group>

            {headerActions ? <Group gap="sm">{headerActions}</Group> : null}
          </Group>
        </AppShell.Header>

        <AppShell.Navbar
          aria-label={navbarAriaLabel}
          className="shell-navbar"
          p="sm"
          style={{ display: "flex", flexDirection: "column", minHeight: 0, overflow: "hidden" }}
        >
          <AppShell.Section
            grow
            component={ScrollArea}
            className="shell-navbar-scroll"
            scrollbars="y"
            type="auto"
            style={{ flex: "1 1 auto", minHeight: 0 }}
          >
            <Stack gap="xs">
              {navigationItems.map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.id}
                    active={item.id === activeItemId}
                    label={item.label}
                    description={item.description}
                    leftSection={<Icon size={16} />}
                    onClick={() => {
                      onNavigate(item.id);
                      mobileControls.close();
                    }}
                  />
                );
              })}
            </Stack>
          </AppShell.Section>
        </AppShell.Navbar>

        <AppShell.Main className="shell-main">
          <Stack className="shell-content" gap={contentGap}>
            {children}
          </Stack>
        </AppShell.Main>
      </AppShell>

      {mobileOpened ? <div className="shell-backdrop" onClick={mobileControls.close} /> : null}
    </>
  );
}