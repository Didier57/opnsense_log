export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "0";
  return value.toLocaleString();
}

export function formatTime(iso: string): string {
  if (!iso) return "";
  const date = new Date(iso);
  return date.toLocaleTimeString(undefined, { hour12: false });
}

export function formatDateTime(iso: string): string {
  if (!iso) return "";
  const date = new Date(iso);
  return date.toLocaleString(undefined, { hour12: false });
}

export function actionClass(action: string): "pass" | "block" | "other" {
  const value = (action || "").toLowerCase();
  if (value === "pass") return "pass";
  if (value === "block" || value === "reject") return "block";
  return "other";
}

export function toLocalInput(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function portLabel(port: number | null | undefined): string {
  return port === null || port === undefined ? "" : `:${port}`;
}

const REGIONAL_BASE = 0x1f1e6;

export function flagEmoji(code: string | null | undefined): string {
  if (!code || code.length !== 2) return "";
  const upper = code.toUpperCase();
  const a = upper.charCodeAt(0);
  const b = upper.charCodeAt(1);
  if (a < 65 || a > 90 || b < 65 || b > 90) return "";
  return String.fromCodePoint(REGIONAL_BASE + (a - 65), REGIONAL_BASE + (b - 65));
}
