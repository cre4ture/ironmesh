import { getRecentLogs } from "@ironmesh/api";
import { LogsSurface } from "@ironmesh/ui";
import { useCallback } from "react";
import { useAdminAccess } from "../lib/admin-access";

export function LogsPage() {
  const { adminTokenOverride } = useAdminAccess();
  const normalizedAdminTokenOverride = adminTokenOverride.trim();

  const loadLogs = useCallback(
    (limit: number) =>
      getRecentLogs(limit, normalizedAdminTokenOverride || undefined),
    [normalizedAdminTokenOverride]
  );

  return (
    <LogsSurface
      description="This page is the dedicated replacement for the old inline runtime log block. It keeps a live tail by default, while still letting you scroll back through recent raw server output when you need to inspect older entries."
      loadLogs={loadLogs}
    />
  );
}
