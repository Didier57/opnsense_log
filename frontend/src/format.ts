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
