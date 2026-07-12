import { IconActivity, IconArrowsTransferUp, IconCertificate, IconDashboard, IconDatabase, IconFileText, IconFolder, IconHistory, IconKey, IconPhoto, IconPlugConnected, IconServerCog } from "@tabler/icons-react";
import { lazy } from "react";
import { SetupPage } from "../pages/SetupPage";

const DashboardPage = lazy(async () => ({
  default: (await import("../pages/DashboardPage")).DashboardPage
}));
const RepairPage = lazy(async () => ({
  default: (await import("../pages/RepairPage")).RepairPage
}));
const BootstrapBundlesPage = lazy(async () => ({
  default: (await import("../pages/BootstrapBundlesPage")).BootstrapBundlesPage
}));
const ClientCredentialsPage = lazy(async () => ({
  default: (await import("../pages/ClientCredentialsPage")).ClientCredentialsPage
}));
const ClientConnectionsPage = lazy(async () => ({
  default: (await import("../pages/ClientConnectionsPage")).ClientConnectionsPage
}));
const CertificatesPage = lazy(async () => ({
  default: (await import("../pages/CertificatesPage")).CertificatesPage
}));
const ControlPlanePage = lazy(async () => ({
  default: (await import("../pages/ControlPlanePage")).ControlPlanePage
}));
const DataChangesPage = lazy(async () => ({
  default: (await import("../pages/DataChangesPage")).DataChangesPage
}));
const DependenciesPage = lazy(async () => ({
  default: (await import("../pages/DependenciesPage")).DependenciesPage
}));
const LogsPage = lazy(async () => ({
  default: (await import("../pages/LogsPage")).LogsPage
}));
const GalleryPage = lazy(async () => ({
  default: (await import("../pages/GalleryPage")).GalleryPage
}));
const ExplorerPage = lazy(async () => ({
  default: (await import("../pages/ExplorerPage")).ExplorerPage
}));
const MetadataPage = lazy(async () => ({
  default: (await import("../pages/MetadataPage")).MetadataPage
}));

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
    description: "Monitor live repair activity, inspect retained repair and scrub runs, and trigger clustered maintenance passes without crowding the dashboard.",
    icon: IconActivity,
    element: <RepairPage />
  },
  {
    id: "metadata",
    label: "Metadata",
    description: "Inspect how node-local metadata storage is split across the SQLite state DB, manifest files, and generated media cache over time.",
    icon: IconDatabase,
    element: <MetadataPage />
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
    description: "Browse prefixes, snapshots, and version history from the node side, with admin-authenticated rename and delete on current data plus snapshot restore.",
    icon: IconFolder,
    element: <ExplorerPage />
  },
  {
    id: "data-changes",
    label: "Data Changes",
    description: "Inspect the recent node-local feed of uploaded, renamed, copied, and deleted data with client identity attribution when available.",
    icon: IconHistory,
    element: <DataChangesPage />
  },
  {
    id: "client-connections",
    label: "Connections",
    description: "Inspect currently active client HTTP requests and accepted transport sessions with live cursor paging from the node runtime.",
    icon: IconPlugConnected,
    element: <ClientConnectionsPage />
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
    description: "Review enrolled client credentials, recent bootstrap claims, and revoke access when needed.",
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
    id: "dependencies",
    label: "Dependencies",
    description: "Check host runtime dependencies such as ffprobe and ffmpeg before media-heavy test rounds.",
    icon: IconServerCog,
    element: <DependenciesPage />
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
