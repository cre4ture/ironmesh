import {
  Box,
  Button,
  Code,
  Group,
  Menu,
  Text,
  UnstyledButton,
  useComputedColorScheme,
  useMantineColorScheme
} from "@mantine/core";
import { IconCheck, IconChevronDown, IconDeviceDesktop, IconMoonStars, IconSunHigh } from "@tabler/icons-react";
import { useIronmeshAccentColor } from "../../theme/ironmesh-provider";
import { defaultIronmeshAccentColor } from "../../theme/ironmesh-theme";

const colorSchemeOptions = [
  {
    value: "light" as const,
    label: "Bright",
    Icon: IconSunHigh
  },
  {
    value: "dark" as const,
    label: "Dark",
    Icon: IconMoonStars
  },
  {
    value: "auto" as const,
    label: "Auto",
    Icon: IconDeviceDesktop
  }
];

const accentColorSwatches = [
  "#14b8a6",
  "#2563eb",
  "#7c3aed",
  "#db2777",
  "#ea580c",
  "#d4a017"
];

export function ColorSchemeControl() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const { accentColor, setAccentColor, resetAccentColor } = useIronmeshAccentColor();
  const computedColorScheme = useComputedColorScheme("light", {
    getInitialValueInEffect: false
  });
  const activeOption =
    colorSchemeOptions.find((option) => option.value === colorScheme) ?? colorSchemeOptions[2];
  const ActiveIcon = activeOption.Icon;
  const autoDescription =
    colorScheme === "auto"
      ? `Auto is currently matching ${computedColorScheme === "dark" ? "dark" : "bright"}.`
      : "Auto follows the browser or operating-system preference.";

  return (
    <Menu shadow="md" width={220} position="bottom-end" withArrow>
      <Menu.Target>
        <Button
          variant="default"
          size="xs"
          leftSection={<ActiveIcon size={14} />}
          rightSection={<IconChevronDown size={14} />}
          aria-label={`Style: ${activeOption.label}`}
        >
          {activeOption.label}
        </Button>
      </Menu.Target>

      <Menu.Dropdown>
        <Menu.Label>Style</Menu.Label>
        {colorSchemeOptions.map((option) => {
          const OptionIcon = option.Icon;
          return (
            <Menu.Item
              key={option.value}
              leftSection={<OptionIcon size={14} />}
              rightSection={colorScheme === option.value ? <IconCheck size={14} /> : null}
              onClick={() => setColorScheme(option.value)}
            >
              {option.label}
            </Menu.Item>
          );
        })}
        <Text c="dimmed" size="xs" px="sm" py={6}>
          {autoDescription}
        </Text>
        <Menu.Divider />
        <Menu.Label>Accent</Menu.Label>
        <Box px="sm" py="xs">
          <Group align="center" gap="xs" wrap="nowrap">
            <Box
              component="input"
              type="color"
              value={accentColor}
              aria-label="Accent color"
              onChange={(event) => setAccentColor(event.currentTarget.value)}
              style={{
                width: "2.25rem",
                height: "2.25rem",
                padding: 0,
                border: "none",
                background: "transparent",
                cursor: "pointer"
              }}
            />
            <Code>{accentColor.toUpperCase()}</Code>
            <Button
              variant="subtle"
              size="compact-xs"
              onClick={resetAccentColor}
              disabled={accentColor === defaultIronmeshAccentColor}
            >
              Reset
            </Button>
          </Group>
          <Group gap={6} mt="xs">
            {accentColorSwatches.map((swatch) => (
              <UnstyledButton
                key={swatch}
                aria-label={`Use accent color ${swatch}`}
                onClick={() => setAccentColor(swatch)}
                style={{
                  width: "1.25rem",
                  height: "1.25rem",
                  borderRadius: "999px",
                  backgroundColor: swatch,
                  outline: swatch === accentColor ? "2px solid var(--mantine-color-text)" : "none",
                  outlineOffset: 2
                }}
              />
            ))}
          </Group>
          <Text c="dimmed" size="xs" mt={6}>
            Stored locally in this browser.
          </Text>
        </Box>
      </Menu.Dropdown>
    </Menu>
  );
}
