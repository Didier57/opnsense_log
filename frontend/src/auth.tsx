import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "./api/client";

interface AuthState {
  username: string | null;
  role: string | null;
  isAdmin: boolean;
  authEnabled: boolean;
  needsSetup: boolean;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  registerAdmin: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [role, setRole] = useState<string | null>(null);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [needsSetup, setNeedsSetup] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const status = await api.setupStatus();
        setAuthEnabled(status.auth_enabled);
        if (status.auth_enabled && status.needs_setup) {
          setNeedsSetup(true);
          return;
        }
        const me = await api.me();
        setUsername(me.username);
        setRole(me.role ?? "admin");
        setAuthEnabled(me.auth_enabled);
      } catch {
        setAuthEnabled(true);
      } finally {
        setReady(true);
      }
    })();
  }, []);

  const login = async (user: string, password: string) => {
    const result = await api.login(user, password);
    setToken(result.access_token);
    setUsername(result.username);
    setRole(result.role ?? "viewer");
  };

  const registerAdmin = async (user: string, password: string) => {
    const result = await api.setup(user, password);
    setToken(result.access_token);
    setUsername(result.username);
    setRole(result.role ?? "admin");
    setNeedsSetup(false);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    setToken(null);
    setUsername(null);
    setRole(null);
  };

  const isAdmin = !authEnabled || role === "admin";

  return (
    <AuthContext.Provider
      value={{ username, role, isAdmin, authEnabled, needsSetup, ready, login, registerAdmin, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}

export { getToken };
