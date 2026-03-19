import type { AdminSessionStatus } from "@ironmesh/api";
import { getAdminSessionStatus, loginAdmin, logoutAdmin } from "@ironmesh/api";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from "react";

const ADMIN_TOKEN_STORAGE_KEY = "ironmesh.server-admin.admin-token-override";

type AdminAccessContextValue = {
  adminTokenOverride: string;
  setAdminTokenOverride: (value: string) => void;
  sessionStatus: AdminSessionStatus | null;
  sessionLoading: boolean;
  sessionError: string | null;
  refreshSession: () => Promise<void>;
  login: (password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const AdminAccessContext = createContext<AdminAccessContextValue | null>(null);

export function AdminAccessProvider({ children }: { children: ReactNode }) {
  const [adminTokenOverride, setAdminTokenOverrideState] = useState(() => {
    if (typeof window === "undefined") {
      return "";
    }

    return window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) ?? "";
  });
  const [sessionStatus, setSessionStatus] = useState<AdminSessionStatus | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [sessionError, setSessionError] = useState<string | null>(null);

  const setAdminTokenOverride = useCallback((value: string) => {
    setAdminTokenOverrideState(value);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, value);
    }
  }, []);

  const refreshSession = useCallback(async () => {
    setSessionLoading(true);
    setSessionError(null);
    try {
      const status = await getAdminSessionStatus(adminTokenOverride);
      setSessionStatus(status);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setSessionError(message);
    } finally {
      setSessionLoading(false);
    }
  }, [adminTokenOverride]);

  const login = useCallback(
    async (password: string) => {
      await loginAdmin(password);
      await refreshSession();
    },
    [refreshSession]
  );

  const logout = useCallback(async () => {
    await logoutAdmin(adminTokenOverride);
    await refreshSession();
  }, [adminTokenOverride, refreshSession]);

  useEffect(() => {
    void refreshSession();
  }, [refreshSession]);

  const value = useMemo<AdminAccessContextValue>(
    () => ({
      adminTokenOverride,
      setAdminTokenOverride,
      sessionStatus,
      sessionLoading,
      sessionError,
      refreshSession,
      login,
      logout
    }),
    [
      adminTokenOverride,
      setAdminTokenOverride,
      sessionStatus,
      sessionLoading,
      sessionError,
      refreshSession,
      login,
      logout
    ]
  );

  return <AdminAccessContext.Provider value={value}>{children}</AdminAccessContext.Provider>;
}

export function useAdminAccess() {
  const context = useContext(AdminAccessContext);
  if (!context) {
    throw new Error("useAdminAccess must be used within AdminAccessProvider");
  }
  return context;
}
