import { createTheme, type MantineColorsTuple } from "@mantine/core";

export const ironmeshPrimaryColor = "brand";
export const defaultIronmeshAccentColor = "#14b8a6";
export const ironmeshAccentColorStorageKey = "ironmesh-accent-color";

type RgbColor = {
  r: number;
  g: number;
  b: number;
};

const white: RgbColor = { r: 255, g: 255, b: 255 };
const black: RgbColor = { r: 0, g: 0, b: 0 };

export const ironmeshTheme = createIronmeshTheme();

export function normalizeIronmeshAccentColor(value: string | null | undefined): string | null {
  const trimmed = value?.trim();
  if (!trimmed) {
    return null;
  }

  const shortHexMatch = /^#?([\da-f]{3})$/i.exec(trimmed);
  if (shortHexMatch) {
    return `#${shortHexMatch[1]
      .split("")
      .map((channel) => `${channel}${channel}`)
      .join("")
      .toLowerCase()}`;
  }

  const longHexMatch = /^#?([\da-f]{6})$/i.exec(trimmed);
  if (longHexMatch) {
    return `#${longHexMatch[1].toLowerCase()}`;
  }

  return null;
}

export function createIronmeshTheme(accentColor = defaultIronmeshAccentColor) {
  const colors = {
    [ironmeshPrimaryColor]: buildIronmeshColorScale(accentColor)
  } satisfies Record<typeof ironmeshPrimaryColor, MantineColorsTuple>;

  return createTheme({
    colors,
    primaryColor: ironmeshPrimaryColor,
    fontFamily: "Space Grotesk, system-ui, sans-serif",
    headings: {
      fontFamily: "Space Grotesk, system-ui, sans-serif"
    }
  });
}

function buildIronmeshColorScale(accentColor: string): MantineColorsTuple {
  const normalized = normalizeIronmeshAccentColor(accentColor) ?? defaultIronmeshAccentColor;
  const rgb = parseHexColor(normalized);

  return [
    mixColors(rgb, white, 0.92),
    mixColors(rgb, white, 0.82),
    mixColors(rgb, white, 0.68),
    mixColors(rgb, white, 0.52),
    mixColors(rgb, white, 0.35),
    mixColors(rgb, white, 0.18),
    normalized,
    mixColors(rgb, black, 0.12),
    mixColors(rgb, black, 0.24),
    mixColors(rgb, black, 0.38)
  ];
}

function parseHexColor(color: string): RgbColor {
  const normalized = normalizeIronmeshAccentColor(color) ?? defaultIronmeshAccentColor;
  const value = normalized.slice(1);

  return {
    r: Number.parseInt(value.slice(0, 2), 16),
    g: Number.parseInt(value.slice(2, 4), 16),
    b: Number.parseInt(value.slice(4, 6), 16)
  };
}

function mixColors(color: RgbColor, target: RgbColor, amount: number): string {
  return rgbToHex({
    r: mixChannel(color.r, target.r, amount),
    g: mixChannel(color.g, target.g, amount),
    b: mixChannel(color.b, target.b, amount)
  });
}

function mixChannel(value: number, target: number, amount: number) {
  return Math.round(value + (target - value) * amount);
}

function rgbToHex(color: RgbColor): string {
  return `#${toHexChannel(color.r)}${toHexChannel(color.g)}${toHexChannel(color.b)}`;
}

function toHexChannel(value: number): string {
  return Math.max(0, Math.min(255, value)).toString(16).padStart(2, "0");
}
