import { useState } from "react";
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
        <strong>Filters</strong>
        <select value={logic} onChange={(e) => onLogicChange(e.target.value)}>
          <option value="AND">Match ALL (AND)</option>
          <option value="OR">Match ANY (OR)</option>
        </select>
      </div>
      <div className="filters">
        <select value={field} onChange={(e) => setField(e.target.value)}>
          {FILTER_FIELD_OPTIONS.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        <select value={op} onChange={(e) => setOp(e.target.value)}>
          {FILTER_OPS.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
        <input
          placeholder="value"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
        />
        <button onClick={add}>Add</button>
      </div>
      {clauses.length > 0 && (
        <div className="filters">
          {clauses.map((clause, index) => (
            <span key={index} className="chip active">
              {clause.field} {clause.op} {String(clause.value)}{" "}
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
