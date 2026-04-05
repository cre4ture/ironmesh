import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AdminSessionStatus } from "@ironmesh/api";
import { getAdminSessionStatus, loginAdmin, logoutAdmin } from "@ironmesh/api";
import {
  createContext,
  useCallback,
  useContext,
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

function adminSessionQueryOptions(adminTokenOverride: string) {
  const normalizedAdminTokenOverride = adminTokenOverride.trim();
  return {
    queryKey: ["admin-session", normalizedAdminTokenOverride] as const,
    queryFn: () =>
      getAdminSessionStatus(
        normalizedAdminTokenOverride.length > 0 ? normalizedAdminTokenOverride : undefined
      )
  };
}

function errorMessage(error: unknown): string | null {
  if (!error) {
    return null;
  }
  return error instanceof Error ? error.message : String(error);
}

export function AdminAccessProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [adminTokenOverride, setAdminTokenOverrideState] = useState(() => {
    if (typeof window === "undefined") {
      return "";
    }

    return window.localStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) ?? "";
  });
  const sessionQueryOptions = useMemo(
    () => adminSessionQueryOptions(adminTokenOverride),
    [adminTokenOverride]
  );

  const setAdminTokenOverride = useCallback((value: string) => {
    setAdminTokenOverrideState(value);
    if (typeof window !== "undefined") {
      window.localStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, value);
    }
  }, []);

  const sessionQuery = useQuery({
    ...sessionQueryOptions
  });

  const refreshSession = useCallback(async () => {
    await queryClient.invalidateQueries({
      queryKey: sessionQueryOptions.queryKey,
      exact: true
    });
    await queryClient.fetchQuery(sessionQueryOptions);
  }, [queryClient, sessionQueryOptions]);

  const loginMutation = useMutation({
    mutationFn: async (password: string) => {
      await loginAdmin(password);
      await queryClient.invalidateQueries({
        queryKey: sessionQueryOptions.queryKey,
        exact: true
      });
      return queryClient.fetchQuery(sessionQueryOptions);
    },
    onSuccess: (status) => {
      queryClient.setQueryData(sessionQueryOptions.queryKey, status);
    }
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await logoutAdmin(
        adminTokenOverride.trim().length > 0 ? adminTokenOverride.trim() : undefined
      );
      await queryClient.invalidateQueries({
        queryKey: sessionQueryOptions.queryKey,
        exact: true
      });
      return queryClient.fetchQuery(sessionQueryOptions);
    },
    onSuccess: (status) => {
      queryClient.setQueryData(sessionQueryOptions.queryKey, status);
    }
  });

  const login = useCallback(async (password: string) => {
    await loginMutation.mutateAsync(password);
  }, [loginMutation]);

  const logout = useCallback(async () => {
    await logoutMutation.mutateAsync();
  }, [logoutMutation]);

  const sessionStatus = sessionQuery.data ?? null;
  const sessionLoading =
    sessionQuery.status === "pending" || loginMutation.isPending || logoutMutation.isPending;
  const sessionError =
    errorMessage(loginMutation.error) ??
    errorMessage(logoutMutation.error) ??
    errorMessage(sessionQuery.error);

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
