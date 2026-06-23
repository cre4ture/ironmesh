import { getClientRecentLogs } from "@ironmesh/api";
import { LogsSurface, PageHeader } from "@ironmesh/ui";
import { useCallback } from "react";

export function LogsPage() {
  const loadLogs = useCallback((limit: number) => getClientRecentLogs(limit), []);

  return (
    <>
      <PageHeader
        title="Logs"
        description="Inspect recent runtime output from the connected node without leaving the client web UI."
      />
      <LogsSurface
        description="This mirrors the dedicated admin log view so you can keep a live tail running, then scroll back through recent raw server output when you need more detail on a failure."
        loadLogs={loadLogs}
      />
    </>
  );
}
