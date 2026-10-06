export interface FirewallEvent {
  event_time: string;
  rule_id: string;
  rule_number: number | null;
  interface: string;
  reason: string;
  action: string;
  direction: string;
  ip_version: number | null;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  tcp_flags: string;
  options: string;
  hostname: string;
  length: number | null;
  raw: string;
  parse_status: string;
  [key: string]: unknown;
}

export interface SearchClause {
  field: string;
  op: string;
  value: string | number | string[] | null;
}

export interface SearchRequest {
  clauses: SearchClause[];
  logic: string;
  start?: string | null;
  end?: string | null;
  limit?: number;
  offset?: number;
  order_by?: string;
  order_dir?: string;
}

export interface SearchResult {
  total: number;
  limit: number;
  offset: number;
  events: FirewallEvent[];
}

export interface Summary {
  total: number;
  passed: number;
  blocked: number;
  interfaces: number;
  sources: number;
}

export interface TopItem {
  value: string | number | null;
  count: number;
}

export interface TimeseriesPoint {
  bucket: string;
  total: number;
  blocked: number;
}

export interface SavedFilter {
  id: number;
  name: string;
  definition: SearchRequest;
  created_at: string;
}

export interface OpnsenseRule {
  rule_id: string;
  description: string;
  interface: string;
  action: string;
  direction: string;
  protocol: string;
  source: string;
  destination: string;
  enabled: boolean;
  history?: unknown[];
}

export interface OpnsenseInterface {
  name: string;
  device: string;
  description: string;
  ipv4: string;
  ipv6: string;
}

export interface Alert {
  id: string;
  created_at: string;
  rule: string;
  severity: string;
  src_ip: string;
  title: string;
  message: string;
  details: Record<string, unknown>;
}

export interface GeoItem {
  value: string;
  name: string;
  count: number;
}
