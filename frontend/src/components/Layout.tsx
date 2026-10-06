import { NavLink, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../auth";

const NAV: { group: string; links: { to: string; label: string }[] }[] = [
  { group: "", links: [{ to: "/", label: "Dashboard" }] },
  {
    group: "Logs",
    links: [
      { to: "/live", label: "Live" },
      { to: "/historical", label: "Historical" },
      { to: "/saved-filters", label: "Saved Filters" },
    ],
  },
  {
    group: "Analysis",
    links: [
      { to: "/analysis", label: "Overview" },
      { to: "/analysis/sources", label: "Sources" },
      { to: "/analysis/destinations", label: "Destinations" },
      { to: "/analysis/ports", label: "Ports" },
      { to: "/analysis/rules", label: "Rules" },
      { to: "/analysis/interfaces", label: "Interfaces" },
    ],
  },
  {
    group: "OPNsense",
    links: [
      { to: "/opnsense/status", label: "Status" },
      { to: "/opnsense/interfaces", label: "Interfaces" },
      { to: "/opnsense/rules", label: "Rules" },
    ],
  },
  {
    group: "Settings",
    links: [
      { to: "/settings", label: "Application" },
      { to: "/settings/opnsense", label: "OPNsense" },
    ],
  },
  { group: "System", links: [{ to: "/system", label: "Status" }, { to: "/system/logs", label: "Logs" }] },
];

export function Layout({ children }: { children: ReactNode }) {
  const { username, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>OPNsense Log Analyzer</h1>
        {NAV.map((section) => (
          <div key={section.group || "root"}>
            {section.group && <div className="nav-group">{section.group}</div>}
            {section.links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.to === "/"}
                className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
              >
                {link.label}
              </NavLink>
            ))}
          </div>
        ))}
      </aside>
      <main className="main">
        <div className="topbar">
          <div />
          <div className="muted">
            {username ? (
              <>
                <span>{username}</span>{" "}
                <button
                  onClick={async () => {
                    await logout();
                    navigate("/login");
                  }}
                >
                  Logout
                </button>
              </>
            ) : null}
          </div>
        </div>
        {children}
      </main>
    </div>
  );
}
