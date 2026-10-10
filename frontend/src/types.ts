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
  start?: string;
  end?: string;
  limit?: number;
  offset?: number;
  order_by?: string;
  order_dir?: string;
  countries?: string[];
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
  interface_description?: string;
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
  event_time?: string | null;
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

export interface Overview {
  countries: GeoItem[];
  dst_countries: GeoItem[];
  countries_blocked: GeoItem[];
  src_external: TopItem[];
  src_internal: TopItem[];
  dst_external: TopItem[];
  dst_internal: TopItem[];
  blocked_ips: TopItem[];
  src_ports: TopItem[];
  dst_ports: TopItem[];
  directions: TopItem[];
  protocols: TopItem[];
  rules: TopItem[];
}

export interface BlockedIp {
  ip: string;
  rule: string;
  source: string;
  added_at: string;
  expires_at: string | null;
}

export interface AllowlistEntry {
  ip: string;
  note: string;
  added_at: string;
}

export interface FilterlogImportStatus {
  running: boolean;
  started_at: string | null;
  finished_at: string | null;
  current_file: string | null;
  error: string | null;
  files_total: number;
  files_scanned: number;
  files_imported: number;
  files_skipped: number;
  lines: number;
  parsed: number;
  invalid: number;
  skipped: number;
  inserted: number;
}

export interface Instance {
  id: string;
  name: string;
  enabled: boolean;
  position: number;
  syslog_port: number | null;
  syslog_protocol: string | null;
  created_at: string | null;
}
