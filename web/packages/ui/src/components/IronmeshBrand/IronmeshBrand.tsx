import { Box, Group, Stack, Text } from "@mantine/core";
import { ironmeshPrimaryColor } from "../../theme/ironmesh-theme";

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
      viewBox="0 0 200 200"
      role="img"
      aria-label="berrykeep mark"
      style={{ flex: "0 0 auto", display: "block" }}
    >
      <defs>
        <linearGradient id="ironmesh-panel" x1="0" y1="0" x2="200" y2="200" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#7c3aed" />
          <stop offset="1" stopColor="#c026d3" />
        </linearGradient>
        <linearGradient id="ironmesh-leaf" x1="100" y1="6.24" x2="152.8" y2="37.92" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#86efac" />
          <stop offset="1" stopColor="#22c55e" />
        </linearGradient>
      </defs>

      <rect width="200" height="200" rx="44" fill="url(#ironmesh-panel)" />
      <path d="M100 22.08 Q126.4 6.24 152.8 16.8 Q140.92 37.92 113.2 37.92 Z" fill="url(#ironmesh-leaf)" />
      <line x1="100" y1="35.28" x2="100" y2="53.76" stroke="#22c55e" strokeWidth="6.6" strokeLinecap="round" />

      <g stroke="#ffffff" strokeWidth="6.6" opacity={0.85} strokeLinecap="round">
        <line x1="100" y1="69.6" x2="57.76" y2="109.2" />
        <line x1="100" y1="69.6" x2="142.24" y2="109.2" />
        <line x1="57.76" y1="109.2" x2="142.24" y2="109.2" />
        <line x1="57.76" y1="109.2" x2="100" y2="162" />
        <line x1="142.24" y1="109.2" x2="100" y2="162" />
      </g>

      <circle cx="100" cy="69.6" r="18.48" fill="#ffffff" />
      <circle cx="57.76" cy="109.2" r="18.48" fill="#ffffff" />
      <circle cx="142.24" cy="109.2" r="18.48" fill="#ffffff" />
      <circle cx="100" cy="162" r="18.48" fill="#ffffff" />
      <circle cx="93.4" cy="63" r="5.016" fill="#e9d5ff" opacity={0.75} />
      <circle cx="51.16" cy="102.6" r="5.016" fill="#e9d5ff" opacity={0.75} />
    </Box>
  );
}

export function IronmeshBrand({ surfaceLabel, markSize = 42 }: IronmeshBrandProps) {
  return (
    <Group gap="sm" wrap="nowrap">
      <IronmeshMark size={markSize} />
      <Stack gap={0}>
        <Text fw={800} tt="uppercase" size="sm" c={ironmeshPrimaryColor}>
          berrykeep
        </Text>
        <Text fw={700}>{surfaceLabel}</Text>
      </Stack>
    </Group>
  );
}
