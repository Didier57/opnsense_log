import { useState } from "react";

interface Props {
  onApply: (start: string | undefined, end: string | undefined) => void;
}

function defaultStart(): string {
  const d = new Date(Date.now() - 60 * 60 * 1000);
  return toLocal(d);
}

function defaultEnd(): string {
  return toLocal(new Date());
}

function toLocal(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(
    date.getHours(),
  )}:${pad(date.getMinutes())}`;
}

export function TimeRangePicker({ onApply }: Props) {
  const [start, setStart] = useState(defaultStart());
  const [end, setEnd] = useState(defaultEnd());

  return (
    <div className="panel">
      <div className="filters">
        <label>
          From <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
        </label>
        <label>
          To <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
        </label>
        <button
          className="active"
          onClick={() =>
            onApply(start ? new Date(start).toISOString() : undefined, end ? new Date(end).toISOString() : undefined)
          }
        >
          Analyze
        </button>
        <button
          onClick={() => {
            setStart(defaultStart());
            setEnd(defaultEnd());
          }}
        >
          Last hour
        </button>
      </div>
    </div>
  );
}
