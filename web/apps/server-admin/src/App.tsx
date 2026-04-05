import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { ServerAdminShell } from "./app-shell/ServerAdminShell";
import { AdminAccessProvider } from "./lib/admin-access";

export function App() {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            retry: false,
            refetchOnWindowFocus: false
          },
          mutations: {
            retry: false
          }
        }
      })
  );

  return (
    <QueryClientProvider client={queryClient}>
      <AdminAccessProvider>
        <ServerAdminShell />
      </AdminAccessProvider>
    </QueryClientProvider>
  );
}
