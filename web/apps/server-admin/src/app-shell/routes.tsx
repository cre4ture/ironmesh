import { IconArrowsTransferUp, IconCertificate, IconDashboard, IconFileText, IconKey, IconPlugConnected, IconServerCog } from "@tabler/icons-react";
import { DashboardPage } from "../pages/DashboardPage";
import { SetupPage } from "../pages/SetupPage";
import { BootstrapBundlesPage } from "../pages/BootstrapBundlesPage";
import { ClientCredentialsPage } from "../pages/ClientCredentialsPage";
import { CertificatesPage } from "../pages/CertificatesPage";
import { ControlPlanePage } from "../pages/ControlPlanePage";
import { LogsPage } from "../pages/LogsPage";

export const serverAdminRoutes = [
  {
    id: "dashboard",
    label: "Dashboard",
    description: "Cluster health, replication state, and recent server activity.",
    icon: IconDashboard,
    element: <DashboardPage />
  },
  {
    id: "setup",
    label: "Setup",
    description: "Notes about the first-run zero-touch setup flow and its current handoff points.",
    icon: IconServerCog,
    element: <SetupPage />
  },
  {
    id: "bootstrap",
    label: "Provisioning",
    description: "Issue client bootstrap bundles and approve node join requests into enrollment packages.",
    icon: IconPlugConnected,
    element: <BootstrapBundlesPage />
  },
  {
    id: "credentials",
    label: "Credentials",
    description: "Review enrolled client credentials and revoke access when needed.",
    icon: IconKey,
    element: <ClientCredentialsPage />
  },
  {
    id: "certificates",
    label: "Certificates",
    description: "Inspect current public and internal TLS state plus auto-renew health.",
    icon: IconCertificate,
    element: <CertificatesPage />
  },
  {
    id: "control-plane",
    label: "Control Plane",
    description: "Export and import managed signer plus embedded rendezvous promotion packages.",
    icon: IconArrowsTransferUp,
    element: <ControlPlanePage />
  },
  {
    id: "logs",
    label: "Logs",
    description: "Inspect recent server logs without relying on the old inline preformatted block.",
    icon: IconFileText,
    element: <LogsPage />
  }
] as const;
