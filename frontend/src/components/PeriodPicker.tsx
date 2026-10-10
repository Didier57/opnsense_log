import { useEffect, useState } from "react";

type Period = "day" | "week" | "month" | "year";

const PERIODS: { value: Period; label: string }[] = [
  { value: "day", label: "Jour" },
  { value: "week", label: "Semaine" },
  { value: "month", label: "Mois" },
  { value: "year", label: "Année" },
];

function startOfDay(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate());
}

function startOfWeek(d: Date): Date {
  const day = startOfDay(d);
  const shift = (day.getDay() + 6) % 7; // Monday = 0
  day.setDate(day.getDate() - shift);
  return day;
}

function startOfMonth(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}

function startOfYear(d: Date): Date {
  return new Date(d.getFullYear(), 0, 1);
}

function periodStart(period: Period, anchor: Date): Date {
  switch (period) {
    case "day":
      return startOfDay(anchor);
    case "week":
      return startOfWeek(anchor);
    case "month":
      return startOfMonth(anchor);
    case "year":
      return startOfYear(anchor);
  }
}

function periodEnd(period: Period, start: Date): Date {
  const end = new Date(start);
  switch (period) {
    case "day":
      end.setDate(end.getDate() + 1);
      break;
    case "week":
      end.setDate(end.getDate() + 7);
      break;
    case "month":
      end.setMonth(end.getMonth() + 1);
      break;
    case "year":
      end.setFullYear(end.getFullYear() + 1);
      break;
  }
  return end;
}

function shift(period: Period, start: Date, direction: number): Date {
  const next = new Date(start);
  switch (period) {
    case "day":
      next.setDate(next.getDate() + direction);
      break;
    case "week":
      next.setDate(next.getDate() + 7 * direction);
      break;
    case "month":
      next.setMonth(next.getMonth() + direction);
      break;
    case "year":
      next.setFullYear(next.getFullYear() + direction);
      break;
  }
  return next;
}

function toDateInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function fromDateInput(value: string): Date {
  const [year, month, day] = value.split("-").map(Number);
  return new Date(year, (month || 1) - 1, day || 1);
}

interface Props {
  onApply: (start: string | undefined, end: string | undefined) => void;
}

export function PeriodPicker({ onApply }: Props) {
  const [period, setPeriod] = useState<Period>("day");
  const [anchor, setAnchor] = useState<Date>(() => startOfDay(new Date()));

  const changePeriod = (next: Period) => {
    setPeriod(next);
    setAnchor((current) => periodStart(next, current));
  };

  const move = (direction: number) => {
    setAnchor((current) => shift(period, periodStart(period, current), direction));
  };

  const start = periodStart(period, anchor);
  const end = periodEnd(period, start);

  useEffect(() => {
    onApply(start.toISOString(), end.toISOString());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [period, start.getTime()]);

  const fmt = (d: Date) => d.toLocaleDateString("fr-FR");

  return (
    <div className="panel">
      <div className="filters">
        <label>
          Période
          <select value={period} onChange={(e) => changePeriod(e.target.value as Period)}>
            {PERIODS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <button className="period-nav" onClick={() => move(-1)} title="Période précédente">
          ◀
        </button>
        <input
          type="date"
          value={toDateInput(anchor)}
          onChange={(e) => e.target.value && setAnchor(fromDateInput(e.target.value))}
        />
        <button className="period-nav" onClick={() => move(1)} title="Période suivante">
          ▶
        </button>
        <span className="muted">
          {fmt(start)} → {fmt(new Date(end.getTime() - 1))}
        </span>
      </div>
    </div>
  );
}
