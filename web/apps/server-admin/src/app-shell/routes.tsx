import { IconArrowsTransferUp, IconCertificate, IconDashboard, IconKey, IconPlugConnected, IconServerCog } from "@tabler/icons-react";
import { DashboardPage } from "../pages/DashboardPage";
import { SetupPage } from "../pages/SetupPage";
import { BootstrapBundlesPage } from "../pages/BootstrapBundlesPage";
import { ClientCredentialsPage } from "../pages/ClientCredentialsPage";
import { CertificatesPage } from "../pages/CertificatesPage";
import { ControlPlanePage } from "../pages/ControlPlanePage";

export const serverAdminRoutes = [
  { id: "dashboard", label: "Dashboard", icon: IconDashboard, element: <DashboardPage /> },
  { id: "setup", label: "Setup", icon: IconServerCog, element: <SetupPage /> },
  { id: "bootstrap", label: "Bootstrap", icon: IconPlugConnected, element: <BootstrapBundlesPage /> },
  { id: "credentials", label: "Credentials", icon: IconKey, element: <ClientCredentialsPage /> },
  { id: "certificates", label: "Certificates", icon: IconCertificate, element: <CertificatesPage /> },
  { id: "control-plane", label: "Control Plane", icon: IconArrowsTransferUp, element: <ControlPlanePage /> }
] as const;
