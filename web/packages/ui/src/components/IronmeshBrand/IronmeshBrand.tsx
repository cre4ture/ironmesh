import { Box, Group, Stack, Text } from "@mantine/core";

type IronmeshMarkProps = {
  size?: number;
};

type IronmeshBrandProps = {
  surfaceLabel: string;
  markSize?: number;
};

export function IronmeshMark({ size = 42 }: IronmeshMarkProps) {
  return (
    <Box
      component="svg"
      width={size}
      height={size}
      viewBox="0 0 256 256"
      role="img"
      aria-label="ironmesh mark"
      style={{ flex: "0 0 auto", display: "block" }}
    >
      <defs>
        <linearGradient id="ironmesh-panel" x1="36" y1="28" x2="214" y2="228" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#112523" />
          <stop offset="0.52" stopColor="#163f3a" />
          <stop offset="1" stopColor="#0d6b5c" />
        </linearGradient>
        <linearGradient id="ironmesh-mesh" x1="72" y1="68" x2="184" y2="188" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#d9fff4" />
          <stop offset="0.45" stopColor="#74e4c8" />
          <stop offset="1" stopColor="#14b8a6" />
        </linearGradient>
      </defs>

      <rect x="28" y="28" width="200" height="200" rx="54" fill="url(#ironmesh-panel)" />
      <rect x="28.75" y="28.75" width="198.5" height="198.5" rx="53.25" fill="none" stroke="#d9fff4" strokeOpacity="0.18" />

      <g fill="none" stroke="url(#ironmesh-mesh)" strokeWidth="10" strokeLinecap="round" strokeLinejoin="round">
        <path d="M128 68 L176 96 L176 160 L128 188 L80 160 L80 96 Z" />
        <path d="M128 68 L128 188" />
        <path d="M80 96 L176 160" />
        <path d="M176 96 L80 160" />
        <path d="M80 96 L176 96" />
        <path d="M80 160 L176 160" />
      </g>

      <g fill="#effff9">
        <circle cx="128" cy="68" r="10" />
        <circle cx="176" cy="96" r="10" />
        <circle cx="176" cy="160" r="10" />
        <circle cx="128" cy="188" r="10" />
        <circle cx="80" cy="160" r="10" />
        <circle cx="80" cy="96" r="10" />
        <circle cx="128" cy="128" r="12" fill="#14b8a6" />
      </g>

      <g fill="#0d3d37">
        <circle cx="128" cy="68" r="4" />
        <circle cx="176" cy="96" r="4" />
        <circle cx="176" cy="160" r="4" />
        <circle cx="128" cy="188" r="4" />
        <circle cx="80" cy="160" r="4" />
        <circle cx="80" cy="96" r="4" />
        <circle cx="128" cy="128" r="4" fill="#e9fff8" />
      </g>
    </Box>
  );
}

export function IronmeshBrand({ surfaceLabel, markSize = 42 }: IronmeshBrandProps) {
  return (
    <Group gap="sm" wrap="nowrap">
      <IronmeshMark size={markSize} />
      <Stack gap={0}>
        <Text fw={800} tt="uppercase" size="sm" c="teal">
          ironmesh
        </Text>
        <Text fw={700}>{surfaceLabel}</Text>
      </Stack>
    </Group>
  );
}
