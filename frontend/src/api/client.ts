import type {
  FirewallEvent,
  OpnsenseInterface,
  OpnsenseRule,
  SavedFilter,
  SearchRequest,
  SearchResult,
  Summary,
  TimeseriesPoint,
  TopItem,
} from "../types";

const TOKEN_KEY = "ola_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (!headers.has("Content-Type") && init.body) {
    headers.set("Content-Type", "application/json");
  }
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) {
    setToken(null);
    throw new Error("unauthorized");
  }
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`${response.status}: ${text}`);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; username: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>("/api/auth/logout", { method: "POST" }),
  me: () => request<{ username: string; auth_enabled: boolean }>("/api/auth/me"),

  health: () => request<{ status: string }>("/api/health"),
  monitoring: () =>
    request<{
      received: number;
      parsed: number;
      invalid: number;
      events_per_sec: number;
      uptime_seconds: number;
    }>("/api/monitoring"),
  systemStatus: () => request<Record<string, unknown>>("/api/system/status"),
  systemLogs: (limit = 200) =>
    request<{ items: { ts: string; level: string; source: string; message: string }[] }>(
      `/api/system/logs?limit=${limit}`,
    ),

  logs: (params: Record<string, string | number | undefined>) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") query.set(k, String(v));
    });
    return request<SearchResult>(`/api/logs?${query.toString()}`);
  },
  search: (payload: SearchRequest) =>
    request<SearchResult>("/api/search", { method: "POST", body: JSON.stringify(payload) }),

  summary: (start?: string, end?: string) => {
    const query = new URLSearchParams();
    if (start) query.set("start", start);
    if (end) query.set("end", end);
    return request<Summary>(`/api/statistics/summary?${query.toString()}`);
  },
  top: (dimension: string, start?: string, end?: string, limit = 10) => {
    const query = new URLSearchParams();
    if (start) query.set("start", start);
    if (end) query.set("end", end);
    query.set("limit", String(limit));
    return request<{ dimension: string; items: TopItem[] }>(
      `/api/statistics/top/${dimension}?${query.toString()}`,
    );
  },
  timeseries: (start?: string, end?: string, bucket = "minute") => {
    const query = new URLSearchParams();
    if (start) query.set("start", start);
    if (end) query.set("end", end);
    query.set("bucket", bucket);
    return request<{ bucket: string; points: TimeseriesPoint[] }>(
      `/api/statistics/timeseries?${query.toString()}`,
    );
  },

  savedFilters: () => request<{ items: SavedFilter[] }>("/api/filters"),
  saveFilter: (name: string, definition: SearchRequest) =>
    request<{ id: number; name: string }>("/api/filters", {
      method: "POST",
      body: JSON.stringify({ name, definition }),
    }),
  deleteFilter: (id: number) =>
    request<{ ok: boolean }>(`/api/filters/${id}`, { method: "DELETE" }),

  rules: () => request<{ items: OpnsenseRule[] }>("/api/rules"),
  syncRules: () => request<{ ok: boolean }>("/api/rules/sync", { method: "POST" }),
  interfaces: () => request<{ items: OpnsenseInterface[] }>("/api/interfaces"),

  lookupHostnames: (ips: string[]) =>
    request<{ items: Record<string, string | null> }>(
      `/api/lookup?ips=${encodeURIComponent(ips.join(","))}`,
    ),

  settings: () => request<Record<string, unknown>>("/api/settings"),
  appSettings: () => request<Record<string, unknown>>("/api/settings/application"),
  updateAppSettings: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/settings/application", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  opnsenseSettings: () => request<Record<string, unknown>>("/api/settings/opnsense"),
  updateOpnsense: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/settings/opnsense", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  testOpnsense: () =>
    request<{ ok: boolean; message: string }>("/api/settings/opnsense/test", { method: "POST" }),

  exportUrl: (format: string) => `/api/export?fmt=${format}`,
  export: async (payload: SearchRequest, format: string): Promise<Blob> => {
    const headers = new Headers({ "Content-Type": "application/json" });
    const token = getToken();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const response = await fetch(`/api/export?fmt=${format}`, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error(`export failed: ${response.status}`);
    return response.blob();
  },
};

export function liveSocketUrl(): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const token = getToken();
  const suffix = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${proto}://${window.location.host}/api/live/ws${suffix}`;
}

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export type { FirewallEvent };
