import { ServerAdminShell } from "./app-shell/ServerAdminShell";
import { AdminAccessProvider } from "./lib/admin-access";

export function App() {
  return (
    <AdminAccessProvider>
      <ServerAdminShell />
    </AdminAccessProvider>
  );
}
