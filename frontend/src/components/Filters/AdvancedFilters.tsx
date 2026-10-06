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

// Fields whose value is best chosen from a predefined list (multi-select).
const ENUM_FIELDS = ["action", "protocol", "interface", "direction"];

const STATIC_OPTIONS: Record<string, string[]> = {
  action: ["pass", "block", "reject"],
  protocol: ["tcp", "udp", "icmp", "icmp6", "gre", "esp", "ah", "igmp"],
  direction: ["in", "out"],
};

interface Option {
  value: string;
  label: string;
}

interface Props {
  clauses: SearchClause[];
  logic: string;
  onLogicChange: (logic: string) => void;
  onChange: (clauses: SearchClause[]) => void;
}

function chipValue(value: SearchClause["value"]): string {
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

export function AdvancedFilters({ clauses, logic, onLogicChange, onChange }: Props) {
  const [field, setField] = useState("src_ip");
  const [op, setOp] = useState("eq");
  const [value, setValue] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const interfaces = useInterfaces();

  const isEnum = ENUM_FIELDS.includes(field);

  const options: Option[] =
    field === "interface"
      ? interfaces.map((iface) => ({
          value: iface.device,
          label: iface.description || iface.name || iface.device,
        }))
      : (STATIC_OPTIONS[field] ?? []).map((v) => ({ value: v, label: v }));

  const changeField = (next: string) => {
    setField(next);
    setSelected([]);
    setValue("");
    setOpen(false);
    if (ENUM_FIELDS.includes(next)) setOp("in");
    else setOp("eq");
  };

  const toggle = (optionValue: string) => {
    setSelected((prev) =>
      prev.includes(optionValue) ? prev.filter((v) => v !== optionValue) : [...prev, optionValue],
    );
  };

  const add = () => {
    if (isEnum) {
      if (selected.length === 0) return;
      onChange([...clauses, { field, op: "in", value: selected }]);
      setSelected([]);
    } else {
      if (!value && op !== "eq") return;
      onChange([...clauses, { field, op, value }]);
      setValue("");
    }
    setOpen(false);
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
        <select value={field} onChange={(e) => changeField(e.target.value)}>
          {FILTER_FIELD_OPTIONS.map((f) => (
            <option key={f} value={f}>
              {FILTER_FIELD_LABELS[f] ?? f}
            </option>
          ))}
        </select>
        {!isEnum && (
          <select value={op} onChange={(e) => setOp(e.target.value)}>
            {FILTER_OPS.map((o) => (
              <option key={o} value={o}>
                {FILTER_OP_LABELS[o] ?? o}
              </option>
            ))}
          </select>
        )}
        {isEnum ? (
          <div style={{ position: "relative" }}>
            <button type="button" onClick={() => setOpen((o) => !o)}>
              {selected.length > 0 ? `${selected.length} sélectionné(s)` : "— valeur —"} ▾
            </button>
            {open && (
              <div
                style={{
                  position: "absolute",
                  top: "100%",
                  left: 0,
                  zIndex: 20,
                  minWidth: 200,
                  maxHeight: 260,
                  overflowY: "auto",
                  background: "var(--panel, #1e1e1e)",
                  border: "1px solid var(--border, #333)",
                  borderRadius: 6,
                  padding: 8,
                  boxShadow: "0 6px 20px rgba(0,0,0,0.4)",
                }}
              >
                {options.length === 0 && <p className="muted">Aucune valeur disponible.</p>}
                {options.map((option) => (
                  <label key={option.value} style={{ display: "block", padding: "2px 0" }}>
                    <input
                      type="checkbox"
                      checked={selected.includes(option.value)}
                      onChange={() => toggle(option.value)}
                    />{" "}
                    {option.label}
                  </label>
                ))}
                <div className="filters" style={{ marginTop: 6 }}>
                  <button type="button" onClick={() => setOpen(false)}>
                    Valider
                  </button>
                  <button type="button" onClick={() => setSelected([])}>
                    Tout décocher
                  </button>
                </div>
              </div>
            )}
          </div>
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
              {clause.op === "in" ? "parmi" : FILTER_OP_LABELS[clause.op] ?? clause.op}{" "}
              {chipValue(clause.value)}{" "}
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
