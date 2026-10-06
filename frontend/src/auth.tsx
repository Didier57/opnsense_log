import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, getToken, setToken } from "./api/client";

interface AuthState {
  username: string | null;
  authEnabled: boolean;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [authEnabled, setAuthEnabled] = useState(true);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const me = await api.me();
        setUsername(me.username);
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
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    setToken(null);
    setUsername(null);
  };

  return (
    <AuthContext.Provider value={{ username, authEnabled, ready, login, logout }}>
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
