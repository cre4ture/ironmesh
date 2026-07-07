import { getClientRecentLogs } from "@ironmesh/api";
import { LogsSurface, PageHeader } from "@ironmesh/ui";
import { useCallback } from "react";

export function LogsPage() {
  const loadLogs = useCallback((limit: number) => getClientRecentLogs(limit), []);

  return (
    <>
      <PageHeader
        title="Logs"
        description="Inspect recent client runtime, SDK, and transport logs without leaving the client web UI."
      />
      <LogsSurface
        description="This stream is captured inside the client process. Use it to diagnose failed direct or relay connections, SDK request failures, rendezvous probe errors, and other transport/runtime issues."
        loadLogs={loadLogs}
        cardTitle="Recent client runtime logs"
        emptyStateLabel="no client runtime logs yet"
      />
    </>
  );
}
