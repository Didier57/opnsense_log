import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { useAuth } from "./auth";
import { useInstance } from "./instance";
import { Instances } from "./pages/Instances";
import { Login } from "./pages/Login";
import { Setup } from "./pages/Setup";
import { Dashboard } from "./pages/Dashboard/Dashboard";
import { Live } from "./pages/Live/Live";
import { Historical } from "./pages/Logs/Historical";
import { SavedFilters } from "./pages/Logs/SavedFilters";
import { Analysis } from "./pages/Analysis/Analysis";
import { Alerts } from "./pages/Security/Alerts";
import { DetectionSettings } from "./pages/Security/DetectionSettings";
import { OpnsenseStatus } from "./pages/OPNsense/OpnsenseStatus";
import { OpnsenseInterfaces } from "./pages/OPNsense/OpnsenseInterfaces";
import { OpnsenseRules } from "./pages/OPNsense/OpnsenseRules";
import { Settings } from "./pages/Settings/Settings";
import { NotificationsSettings } from "./pages/Settings/NotificationsSettings";
import { GeoipSettings } from "./pages/Settings/GeoipSettings";
import { OpnsenseSettings } from "./pages/Settings/OpnsenseSettings";
import { Users } from "./pages/Settings/Users";
import { SystemStatus } from "./pages/System/SystemStatus";
import { SystemLogs } from "./pages/System/SystemLogs";

function RequireAdmin({ children }: { children: ReactNode }) {
  const { isAdmin } = useAuth();
  return isAdmin ? <>{children}</> : <Navigate to="/" replace />;
}

export function App() {
  const { authEnabled, username, ready, needsSetup } = useAuth();
  const { instance } = useInstance();

  if (!ready) return <div className="muted">Chargement…</div>;
  if (needsSetup) return <Setup />;

  return (
    <Routes>
      <Route path="/login" element={authEnabled && username ? <Navigate to="/" replace /> : <Login />} />
      <Route
        path="/*"
        element={
          authEnabled && !username ? (
            <Navigate to="/login" replace />
          ) : (
            <Layout>
              <div key={instance?.id ?? "none"}>
              <Routes>
                <Route index element={<Dashboard />} />
                <Route path="live" element={<Live />} />
                <Route path="historical" element={<Historical />} />
                <Route path="saved-filters" element={<SavedFilters />} />
                <Route path="analysis" element={<Analysis />} />
                <Route path="analysis/:kind" element={<Analysis />} />
                <Route path="security/alerts" element={<RequireAdmin><Alerts /></RequireAdmin>} />
                <Route path="security/detection" element={<RequireAdmin><DetectionSettings /></RequireAdmin>} />
                <Route path="opnsense/status" element={<RequireAdmin><OpnsenseStatus /></RequireAdmin>} />
                <Route path="opnsense/interfaces" element={<RequireAdmin><OpnsenseInterfaces /></RequireAdmin>} />
                <Route path="opnsense/rules" element={<RequireAdmin><OpnsenseRules /></RequireAdmin>} />
                <Route path="settings" element={<RequireAdmin><Settings /></RequireAdmin>} />
                <Route path="settings/notifications" element={<RequireAdmin><NotificationsSettings /></RequireAdmin>} />
                <Route path="settings/geoip" element={<RequireAdmin><GeoipSettings /></RequireAdmin>} />
                <Route path="settings/opnsense" element={<RequireAdmin><OpnsenseSettings /></RequireAdmin>} />
                <Route path="settings/users" element={<RequireAdmin><Users /></RequireAdmin>} />
                <Route path="system" element={<RequireAdmin><SystemStatus /></RequireAdmin>} />
                <Route path="system/logs" element={<RequireAdmin><SystemLogs /></RequireAdmin>} />
                <Route path="instances" element={<RequireAdmin><Instances /></RequireAdmin>} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
              </div>
            </Layout>
          )
        }
      />
    </Routes>
  );
}
