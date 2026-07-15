import { MantineProvider, localStorageColorSchemeManager } from "@mantine/core";
import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";
import {
  createIronmeshTheme,
  defaultIronmeshAccentColor,
  ironmeshAccentColorStorageKey,
  normalizeIronmeshAccentColor
} from "./ironmesh-theme";

export const ironmeshColorSchemeStorageKey = "ironmesh-color-scheme";

const ironmeshColorSchemeManager = localStorageColorSchemeManager({
  key: ironmeshColorSchemeStorageKey
});

type IronmeshMantineProviderProps = {
  children: ReactNode;
};

type IronmeshAccentColorContextValue = {
  accentColor: string;
  setAccentColor: (value: string) => void;
  resetAccentColor: () => void;
};

const IronmeshAccentColorContext = createContext<IronmeshAccentColorContextValue | null>(null);

export function IronmeshMantineProvider({ children }: IronmeshMantineProviderProps) {
  const [accentColor, setAccentColorState] = useState(readStoredAccentColor);
  const theme = useMemo(() => createIronmeshTheme(accentColor), [accentColor]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    try {
      if (accentColor === defaultIronmeshAccentColor) {
        window.localStorage.removeItem(ironmeshAccentColorStorageKey);
      } else {
        window.localStorage.setItem(ironmeshAccentColorStorageKey, accentColor);
      }
    } catch {
      // Ignore local persistence failures and keep the active in-memory theme.
    }
  }, [accentColor]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    function handleStorage(event: StorageEvent) {
      if (event.storageArea !== window.localStorage || event.key !== ironmeshAccentColorStorageKey) {
        return;
      }

      setAccentColorState(readStoredAccentColor());
    }

    window.addEventListener("storage", handleStorage);
    return () => window.removeEventListener("storage", handleStorage);
  }, []);

  const accentColorContextValue = useMemo<IronmeshAccentColorContextValue>(
    () => ({
      accentColor,
      setAccentColor(value: string) {
        const normalized = normalizeIronmeshAccentColor(value);
        if (normalized) {
          setAccentColorState(normalized);
        }
      },
      resetAccentColor() {
        setAccentColorState(defaultIronmeshAccentColor);
      }
    }),
    [accentColor]
  );

  return (
    <IronmeshAccentColorContext.Provider value={accentColorContextValue}>
      <MantineProvider
        theme={theme}
        colorSchemeManager={ironmeshColorSchemeManager}
        defaultColorScheme="auto"
      >
        {children}
      </MantineProvider>
    </IronmeshAccentColorContext.Provider>
  );
}

export function useIronmeshAccentColor() {
  const context = useContext(IronmeshAccentColorContext);
  if (!context) {
    throw new Error("useIronmeshAccentColor must be used inside IronmeshMantineProvider");
  }

  return context;
}

function readStoredAccentColor() {
  if (typeof window === "undefined") {
    return defaultIronmeshAccentColor;
  }

  try {
    return normalizeIronmeshAccentColor(window.localStorage.getItem(ironmeshAccentColorStorageKey))
      ?? defaultIronmeshAccentColor;
  } catch {
    return defaultIronmeshAccentColor;
  }
}
