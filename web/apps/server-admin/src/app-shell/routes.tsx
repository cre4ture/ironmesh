import { IconActivity, IconArrowsTransferUp, IconCertificate, IconDashboard, IconFileText, IconFolder, IconKey, IconPhoto, IconPlugConnected, IconServerCog } from "@tabler/icons-react";
import { DashboardPage } from "../pages/DashboardPage";
import { RepairPage } from "../pages/RepairPage";
import { SetupPage } from "../pages/SetupPage";
import { BootstrapBundlesPage } from "../pages/BootstrapBundlesPage";
import { ClientCredentialsPage } from "../pages/ClientCredentialsPage";
import { CertificatesPage } from "../pages/CertificatesPage";
import { ControlPlanePage } from "../pages/ControlPlanePage";
import { LogsPage } from "../pages/LogsPage";
import { GalleryPage } from "../pages/GalleryPage";
import { ExplorerPage } from "../pages/ExplorerPage";

export const serverAdminRoutes = [
  {
    id: "dashboard",
    label: "Dashboard",
    description: "Cluster health, replication state, and recent server activity.",
    icon: IconDashboard,
    element: <DashboardPage />
  },
  {
    id: "repair",
    label: "Repair",
    description: "Monitor live repair activity, inspect retained repair runs, and trigger cluster repair passes without crowding the dashboard.",
    icon: IconActivity,
    element: <RepairPage />
  },
  {
    id: "setup",
    label: "Setup",
    description: "First-run zero-touch setup for starting a cluster, generating join requests, and importing enrollment packages.",
    icon: IconServerCog,
    element: <SetupPage />
  },
  {
    id: "gallery",
    label: "Gallery",
    description: "Browse image objects from the server node side using admin-authenticated snapshot, index, and preview routes.",
    icon: IconPhoto,
    element: <GalleryPage />
  },
  {
    id: "explorer",
    label: "Explorer",
    description: "Browse prefixes, snapshots, and version history from the node side, with admin-authenticated rename and delete on current data.",
    icon: IconFolder,
    element: <ExplorerPage />
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
