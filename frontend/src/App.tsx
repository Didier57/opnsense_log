import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { useAuth } from "./auth";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard/Dashboard";
import { Live } from "./pages/Live/Live";
import { Historical } from "./pages/Logs/Historical";
import { SavedFilters } from "./pages/Logs/SavedFilters";
import { Analysis } from "./pages/Analysis/Analysis";
import { OpnsenseStatus } from "./pages/OPNsense/OpnsenseStatus";
import { OpnsenseInterfaces } from "./pages/OPNsense/OpnsenseInterfaces";
import { OpnsenseRules } from "./pages/OPNsense/OpnsenseRules";
import { Settings } from "./pages/Settings/Settings";
import { OpnsenseSettings } from "./pages/Settings/OpnsenseSettings";
import { SystemStatus } from "./pages/System/SystemStatus";
import { SystemLogs } from "./pages/System/SystemLogs";

export function App() {
  const { authEnabled, username, ready } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={ready && authEnabled && username ? <Navigate to="/" replace /> : <Login />} />
      <Route
        path="/*"
        element={
          !ready ? (
            <div className="muted">Chargement…</div>
          ) : authEnabled && !username ? (
            <Navigate to="/login" replace />
          ) : (
            <Layout>
              <Routes>
                <Route index element={<Dashboard />} />
                <Route path="live" element={<Live />} />
                <Route path="historical" element={<Historical />} />
                <Route path="saved-filters" element={<SavedFilters />} />
                <Route path="analysis" element={<Analysis />} />
                <Route path="analysis/:kind" element={<Analysis />} />
                <Route path="opnsense/status" element={<OpnsenseStatus />} />
                <Route path="opnsense/interfaces" element={<OpnsenseInterfaces />} />
                <Route path="opnsense/rules" element={<OpnsenseRules />} />
                <Route path="settings" element={<Settings />} />
                <Route path="settings/opnsense" element={<OpnsenseSettings />} />
                <Route path="system" element={<SystemStatus />} />
                <Route path="system/logs" element={<SystemLogs />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Layout>
          )
        }
      />
    </Routes>
  );
}
