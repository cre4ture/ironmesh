import { Button, Menu, Text, useComputedColorScheme, useMantineColorScheme } from "@mantine/core";
import { IconCheck, IconChevronDown, IconDeviceDesktop, IconMoonStars, IconSunHigh } from "@tabler/icons-react";

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

export function ColorSchemeControl() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
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
      </Menu.Dropdown>
    </Menu>
  );
}
