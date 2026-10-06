import { NavLink, useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { useAuth } from "../auth";

const NAV: { group: string; links: { to: string; label: string }[] }[] = [
  { group: "", links: [{ to: "/", label: "Tableau de bord" }] },
  {
    group: "Journaux",
    links: [
      { to: "/live", label: "Temps réel" },
      { to: "/historical", label: "Historique" },
      { to: "/saved-filters", label: "Filtres enregistrés" },
    ],
  },
  {
    group: "Analyse",
    links: [
      { to: "/analysis", label: "Vue d'ensemble" },
      { to: "/analysis/sources", label: "Sources" },
      { to: "/analysis/destinations", label: "Destinations" },
      { to: "/analysis/ports", label: "Ports" },
      { to: "/analysis/rules", label: "Règles" },
      { to: "/analysis/interfaces", label: "Interfaces" },
    ],
  },
  {
    group: "OPNsense",
    links: [
      { to: "/opnsense/status", label: "État" },
      { to: "/opnsense/interfaces", label: "Interfaces" },
      { to: "/opnsense/rules", label: "Règles" },
    ],
  },
  {
    group: "Paramètres",
    links: [
      { to: "/settings", label: "Application" },
      { to: "/settings/opnsense", label: "OPNsense" },
    ],
  },
  { group: "Système", links: [{ to: "/system", label: "État" }, { to: "/system/logs", label: "Journaux" }] },
];

export function Layout({ children }: { children: ReactNode }) {
  const { username, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>Analyseur de logs OPNsense</h1>
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
                   Déconnexion
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
