import { MantineProvider, localStorageColorSchemeManager } from "@mantine/core";
import type { ReactNode } from "react";
import { ironmeshTheme } from "./ironmesh-theme";

export const ironmeshColorSchemeStorageKey = "ironmesh-color-scheme";

const ironmeshColorSchemeManager = localStorageColorSchemeManager({
  key: ironmeshColorSchemeStorageKey
});

type IronmeshMantineProviderProps = {
  children: ReactNode;
};

export function IronmeshMantineProvider({ children }: IronmeshMantineProviderProps) {
  return (
    <MantineProvider
      theme={ironmeshTheme}
      colorSchemeManager={ironmeshColorSchemeManager}
      defaultColorScheme="auto"
    >
      {children}
    </MantineProvider>
  );
}
