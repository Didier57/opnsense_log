import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import type { SavedFilter } from "../../types";

export function SavedFilters() {
  const [items, setItems] = useState<SavedFilter[]>([]);
  const navigate = useNavigate();

  const load = () => api.savedFilters().then((r) => setItems(r.items)).catch(() => undefined);

  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>Saved filters</h2>
      </div>
      <div className="panel">
        {items.length === 0 && <p className="muted">No saved filters yet.</p>}
        <div className="filters">
          {items.map((filter) => (
            <span key={filter.id} className="chip active">
              <span
                style={{ cursor: "pointer" }}
                onClick={() =>
                  navigate("/historical", { state: { filter: filter.definition } })
                }
              >
                {filter.name}
              </span>{" "}
              <span
                style={{ cursor: "pointer" }}
                onClick={async () => {
                  await api.deleteFilter(filter.id);
                  load();
                }}
              >
                ✕
              </span>
            </span>
          ))}
        </div>
        <p className="muted">
          Saved filters are stored server-side. Open the Historical page and apply a filter to reuse it.
        </p>
      </div>
    </>
  );
}
