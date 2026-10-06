import { formatNumber } from "../format";

export function StatCard({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="card">
      <div className="label">{label}</div>
      <div className="value">{typeof value === "number" ? formatNumber(value) : value}</div>
    </div>
  );
}
