import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { AdminSessionStatus } from "@ironmesh/api";
import { getAdminSessionStatus, loginAdmin, logoutAdmin } from "@ironmesh/api";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  type ReactNode
} from "react";

const ADMIN_TOKEN_STORAGE_KEY = "ironmesh.server-admin.admin-token-override";
const ADMIN_SESSION_CONFIRMATION_ATTEMPTS = 8;
const ADMIN_SESSION_CONFIRMATION_DELAY_MS = 100;

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

function adminSessionQueryOptions() {
  return {
    queryKey: ["admin-session"] as const,
    queryFn: () => getAdminSessionStatus()
  };
}

function errorMessage(error: unknown): string | null {
  if (!error) {
    return null;
  }
  return error instanceof Error ? error.message : String(error);
}

async function delay(timeoutMs: number): Promise<void> {
  await new Promise<void>((resolve) => {
    window.setTimeout(resolve, timeoutMs);
  });
}

export function AdminAccessProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const adminTokenOverride = "";
  const sessionQueryOptions = useMemo(() => adminSessionQueryOptions(), []);

  const setAdminTokenOverride = useCallback((_value: string) => {
  }, []);

  useEffect(() => {
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
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
      let lastStatus: AdminSessionStatus | null = null;
      for (let attempt = 0; attempt < ADMIN_SESSION_CONFIRMATION_ATTEMPTS; attempt += 1) {
        await queryClient.invalidateQueries({
          queryKey: sessionQueryOptions.queryKey,
          exact: true
        });
        const status = await queryClient.fetchQuery(sessionQueryOptions);
        lastStatus = status;
        if (!status.login_required || status.authenticated) {
          return status;
        }
        if (attempt + 1 < ADMIN_SESSION_CONFIRMATION_ATTEMPTS) {
          await delay(ADMIN_SESSION_CONFIRMATION_DELAY_MS);
        }
      }
      throw new Error(
        lastStatus?.login_required
          ? "admin session cookie was not confirmed after login"
          : "failed to confirm admin session state after login"
      );
    },
    onSuccess: (status) => {
      queryClient.setQueryData(sessionQueryOptions.queryKey, status);
    }
  });

  const logoutMutation = useMutation({
    mutationFn: async () => {
      await logoutAdmin();
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
