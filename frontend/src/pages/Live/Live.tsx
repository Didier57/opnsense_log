import { useEffect, useMemo, useRef, useState } from "react";
import { liveSocketUrl } from "../../api/client";
import { LogTable } from "../../components/LogTable/LogTable";
import { EventDetails } from "../../components/EventDetails/EventDetails";
import { QuickFilters, QUICK_FILTERS } from "../../components/Filters/QuickFilters";
import { useInterfaceMap } from "../../hooks/useInterfaceMap";
import { useInterfaces, findInterfaceDevice } from "../../hooks/useInterfaces";
import { useRuleMap } from "../../hooks/useRuleMap";
import type { FirewallEvent, SearchClause } from "../../types";

const LIMITS = [500, 1000, 5000];

interface TextFilters {
  src_ip: string;
  dst_ip: string;
  src_port: string;
  dst_port: string;
  rule_id: string;
  interface: string;
}

const EMPTY_TEXT: TextFilters = {
  src_ip: "",
  dst_ip: "",
  src_port: "",
  dst_port: "",
  rule_id: "",
  interface: "",
};

const TEXT_FIELDS: { key: keyof TextFilters; label: string; placeholder: string }[] = [
  { key: "src_ip", label: "Source IP", placeholder: "10.0.0.1" },
  { key: "dst_ip", label: "Destination IP", placeholder: "8.8.8.8" },
  { key: "src_port", label: "Source port", placeholder: "443" },
  { key: "dst_port", label: "Destination port", placeholder: "80" },
  { key: "rule_id", label: "Rule ID", placeholder: "tracker" },
  { key: "interface", label: "Interface", placeholder: "vtnet0" },
];

function textClauses(text: TextFilters): SearchClause[] {
  const out: SearchClause[] = [];
  if (text.src_ip) out.push({ field: "src_ip", op: "contains", value: text.src_ip });
  if (text.dst_ip) out.push({ field: "dst_ip", op: "contains", value: text.dst_ip });
  if (/^\d+$/.test(text.src_port)) out.push({ field: "src_port", op: "eq", value: Number(text.src_port) });
  if (/^\d+$/.test(text.dst_port)) out.push({ field: "dst_port", op: "eq", value: Number(text.dst_port) });
  if (text.rule_id) out.push({ field: "rule_id", op: "contains", value: text.rule_id });
  if (text.interface) out.push({ field: "interface", op: "contains", value: text.interface });
  return out;
}

function matches(event: FirewallEvent, clauses: SearchClause[]): boolean {
  return clauses.every((clause) => {
    const value = event[clause.field];
    if (clause.op === "eq") {
      if (typeof clause.value === "number") return Number(value) === clause.value;
      return String(value ?? "").toLowerCase() === String(clause.value).toLowerCase();
    }
    if (clause.op === "contains") {
      return String(value ?? "").toLowerCase().includes(String(clause.value).toLowerCase());
    }
    return true;
  });
}

export function Live() {
  const [raw, setRaw] = useState<FirewallEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [limit, setLimit] = useState(1000);
  const [clauses, setClauses] = useState<SearchClause[]>([]);
  const [text, setText] = useState<TextFilters>(EMPTY_TEXT);
  const [selected, setSelected] = useState<FirewallEvent | null>(null);

  const pausedRef = useRef(paused);
  const limitRef = useRef(limit);
  const interfaceMap = useInterfaceMap();
  const interfaces = useInterfaces();
  const ruleMap = useRuleMap();

  pausedRef.current = paused;
  limitRef.current = limit;

  const lanDev = findInterfaceDevice(interfaces, "LAN");
  const wanDev = findInterfaceDevice(interfaces, "WAN");
  const quickList = [
    ...QUICK_FILTERS,
    ...(lanDev ? [{ label: "LAN", clause: { field: "interface", op: "eq", value: lanDev } }] : []),
    ...(wanDev ? [{ label: "WAN", clause: { field: "interface", op: "eq", value: wanDev } }] : []),
  ];

  useEffect(() => {
    const socket = new WebSocket(liveSocketUrl());
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      if (pausedRef.current) return;
      const event = JSON.parse(message.data) as FirewallEvent;
      setRaw((prev) => {
        const next = [event, ...prev];
        return next.length > limitRef.current ? next.slice(0, limitRef.current) : next;
      });
    };
    return () => socket.close();
  }, []);

  const events = useMemo(
    () => raw.filter((event) => matches(event, [...clauses, ...textClauses(text)])),
    [raw, clauses, text],
  );

  const clearAll = () => {
    setClauses([]);
    setText(EMPTY_TEXT);
  };

  return (
    <>
      <div className="topbar">
        <h2>
          Live view <span className={`status-dot ${connected ? "ok" : "bad"}`} />
          <span className="muted" style={{ fontSize: 13 }}>
            {connected ? "connected" : "disconnected"}
          </span>
        </h2>
        <div className="filters">
          <button onClick={() => setPaused((p) => !p)} className={paused ? "active" : ""}>
            {paused ? "Resume" : "Pause"}
          </button>
          <button onClick={() => setRaw([])}>Clear</button>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {LIMITS.map((l) => (
              <option key={l} value={l}>
                last {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="panel">
        <div className="filters">
          <button className={`chip${clauses.length === 0 && text === EMPTY_TEXT ? " active" : ""}`} onClick={clearAll}>
            All
          </button>
          <QuickFilters active={clauses} onChange={setClauses} quickList={quickList} />
        </div>
        <div className="filters">
          {TEXT_FIELDS.map((field) => (
            <label key={field.key} className="muted" style={{ fontSize: 12 }}>
              {field.label}
              <br />
              <input
                placeholder={field.placeholder}
                value={text[field.key]}
                onChange={(e) => setText({ ...text, [field.key]: e.target.value })}
              />
            </label>
          ))}
          <button onClick={() => setText(EMPTY_TEXT)}>Reset fields</button>
        </div>
      </div>

      <div className="panel">
        <p className="muted">
          {events.length} events shown of {raw.length} buffered
        </p>
        <LogTable
          events={events}
          onSelect={setSelected}
          interfaceMap={interfaceMap}
          ruleMap={ruleMap}
        />
      </div>
      <EventDetails
        event={selected}
        onClose={() => setSelected(null)}
        ruleDescription={selected ? ruleMap[selected.rule_id] : undefined}
      />
    </>
  );
}
