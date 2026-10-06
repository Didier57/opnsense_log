import { useState } from "react";
import { useInterfaces } from "../../hooks/useInterfaces";
import type { SearchClause } from "../../types";

export const FILTER_FIELD_OPTIONS = [
  "action",
  "protocol",
  "interface",
  "direction",
  "src_ip",
  "dst_ip",
  "src_port",
  "dst_port",
  "rule_id",
  "hostname",
  "ip_version",
  "tcp_flags",
  "raw",
];

export const FILTER_FIELD_LABELS: Record<string, string> = {
  action: "Action",
  protocol: "Protocole",
  interface: "Interface",
  direction: "Sens",
  src_ip: "IP source",
  dst_ip: "IP destination",
  src_port: "Port source",
  dst_port: "Port destination",
  rule_id: "ID de règle",
  hostname: "Hôte",
  ip_version: "Version IP",
  tcp_flags: "Drapeaux TCP",
  raw: "Ligne brute",
};

export const FILTER_OPS = [
  "eq",
  "ne",
  "contains",
  "not_contains",
  "regex",
  "gt",
  "lt",
  "gte",
  "lte",
];

export const FILTER_OP_LABELS: Record<string, string> = {
  eq: "égal à",
  ne: "différent de",
  contains: "contient",
  not_contains: "ne contient pas",
  regex: "expression régulière",
  gt: "supérieur à",
  lt: "inférieur à",
  gte: "supérieur ou égal à",
  lte: "inférieur ou égal à",
};

interface Props {
  clauses: SearchClause[];
  logic: string;
  onLogicChange: (logic: string) => void;
  onChange: (clauses: SearchClause[]) => void;
}

export function AdvancedFilters({ clauses, logic, onLogicChange, onChange }: Props) {
  const [field, setField] = useState("src_ip");
  const [op, setOp] = useState("eq");
  const [value, setValue] = useState("");
  const interfaces = useInterfaces();

  const add = () => {
    if (!value && op !== "eq") return;
    onChange([...clauses, { field, op, value }]);
    setValue("");
  };

  const remove = (index: number) => {
    onChange(clauses.filter((_, i) => i !== index));
  };

  return (
    <div className="panel">
      <div className="filters">
        <strong>Filtres</strong>
        <select value={logic} onChange={(e) => onLogicChange(e.target.value)}>
          <option value="AND">Correspond à tous (ET)</option>
          <option value="OR">Correspond à au moins un (OU)</option>
        </select>
      </div>
      <div className="filters">
        <select value={field} onChange={(e) => setField(e.target.value)}>
          {FILTER_FIELD_OPTIONS.map((f) => (
            <option key={f} value={f}>
              {FILTER_FIELD_LABELS[f] ?? f}
            </option>
          ))}
        </select>
        <select value={op} onChange={(e) => setOp(e.target.value)}>
          {FILTER_OPS.map((o) => (
            <option key={o} value={o}>
              {FILTER_OP_LABELS[o] ?? o}
            </option>
          ))}
        </select>
        {field === "interface" ? (
          <select value={value} onChange={(e) => setValue(e.target.value)}>
            <option value="">— interface —</option>
            {interfaces.map((iface) => (
              <option key={iface.device} value={iface.device}>
                {iface.description || iface.name || iface.device}
              </option>
            ))}
          </select>
        ) : (
          <input
            placeholder="valeur"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && add()}
          />
        )}
        <button onClick={add}>Ajouter</button>
      </div>
      {clauses.length > 0 && (
        <div className="filters">
          {clauses.map((clause, index) => (
            <span key={index} className="chip active">
              {FILTER_FIELD_LABELS[clause.field] ?? clause.field}{" "}
              {FILTER_OP_LABELS[clause.op] ?? clause.op} {String(clause.value)}{" "}
              <span style={{ cursor: "pointer" }} onClick={() => remove(index)}>
                ✕
              </span>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
