import type { FirewallEvent, SearchClause } from "./types";

function asNumber(value: unknown): number {
  return typeof value === "number" ? value : Number(value);
}

function collapse(value: unknown): string {
  return String(value ?? "").toLowerCase();
}

function clauseMatches(event: FirewallEvent, clause: SearchClause): boolean {
  const raw = event[clause.field];
  const { op, value } = clause;
  switch (op) {
    case "eq":
      return typeof value === "number" ? asNumber(raw) === value : collapse(raw) === collapse(value);
    case "ne":
      return typeof value === "number" ? asNumber(raw) !== value : collapse(raw) !== collapse(value);
    case "contains":
      return collapse(raw).includes(collapse(value));
    case "not_contains":
      return !collapse(raw).includes(collapse(value));
    case "regex":
      try {
        return new RegExp(String(value), "i").test(String(raw ?? ""));
      } catch {
        return false;
      }
    case "in": {
      const list = Array.isArray(value) ? value : String(value ?? "").split(",");
      return list.map((item) => collapse(item)).includes(collapse(raw));
    }
    case "gt":
      return asNumber(raw) > asNumber(value);
    case "lt":
      return asNumber(raw) < asNumber(value);
    case "gte":
      return asNumber(raw) >= asNumber(value);
    case "lte":
      return asNumber(raw) <= asNumber(value);
    default:
      return true;
  }
}

function parseUtc(value?: string | null): number | null {
  if (!value) return null;
  const hasTimezone = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(value);
  const date = new Date(hasTimezone ? value : `${value}Z`);
  return Number.isNaN(date.getTime()) ? null : date.getTime();
}

export function eventMatches(
  event: FirewallEvent,
  clauses: SearchClause[],
  logic = "AND",
  start?: string | null,
  end?: string | null,
): boolean {
  const startMs = parseUtc(start);
  const endMs = parseUtc(end);
  if (startMs !== null || endMs !== null) {
    const eventMs = parseUtc(event.event_time);
    if (eventMs === null) return false;
    if (startMs !== null && eventMs < startMs) return false;
    if (endMs !== null && eventMs > endMs) return false;
  }
  if (clauses.length === 0) return true;
  const results = clauses.map((clause) => clauseMatches(event, clause));
  return logic === "OR" ? results.some(Boolean) : results.every(Boolean);
}
