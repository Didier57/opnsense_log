import type { SearchClause } from "../../types";

export const QUICK_FILTERS: { label: string; clause: SearchClause }[] = [
  { label: "Pass", clause: { field: "action", op: "eq", value: "pass" } },
  { label: "Block", clause: { field: "action", op: "eq", value: "block" } },
  { label: "Reject", clause: { field: "action", op: "eq", value: "reject" } },
  { label: "TCP", clause: { field: "protocol", op: "eq", value: "tcp" } },
  { label: "UDP", clause: { field: "protocol", op: "eq", value: "udp" } },
  { label: "ICMP", clause: { field: "protocol", op: "eq", value: "icmp" } },
  { label: "IPv4", clause: { field: "ip_version", op: "eq", value: 4 } },
  { label: "IPv6", clause: { field: "ip_version", op: "eq", value: 6 } },
  { label: "Inbound", clause: { field: "direction", op: "eq", value: "in" } },
  { label: "Outbound", clause: { field: "direction", op: "eq", value: "out" } },
];

function clauseKey(clause: SearchClause): string {
  return `${clause.field}:${clause.op}:${String(clause.value)}`;
}

interface Props {
  active: SearchClause[];
  onChange: (clauses: SearchClause[]) => void;
  quickList?: { label: string; clause: SearchClause }[];
}

export function QuickFilters({ active, onChange, quickList = QUICK_FILTERS }: Props) {
  const activeKeys = new Set(active.map(clauseKey));
  const toggle = (clause: SearchClause) => {
    const key = clauseKey(clause);
    if (activeKeys.has(key)) {
      onChange(active.filter((c) => clauseKey(c) !== key));
    } else {
      onChange([...active, clause]);
    }
  };
  return (
    <div className="filters">
      {quickList.map(({ label, clause }) => (
        <button
          key={label}
          className={`chip${activeKeys.has(clauseKey(clause)) ? " active" : ""}`}
          onClick={() => toggle(clause)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}
