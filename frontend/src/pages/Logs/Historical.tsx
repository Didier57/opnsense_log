import { useEffect, useState } from "react";
import { api, downloadBlob } from "../../api/client";
import { LogTable } from "../../components/LogTable/LogTable";
import { EventDetails } from "../../components/EventDetails/EventDetails";
import { QuickFilters } from "../../components/Filters/QuickFilters";
import { AdvancedFilters } from "../../components/Filters/AdvancedFilters";
import { CountryFilter } from "../../components/Filters/CountryFilter";
import { TimeRangePicker } from "../../components/TimeRangePicker";
import { useInterfaceMap } from "../../hooks/useInterfaceMap";
import { useRuleMap } from "../../hooks/useRuleMap";
import { formatNumber } from "../../format";
import type { FirewallEvent, SearchClause, SearchResult } from "../../types";

const PAGE_SIZE = 100;

export function Historical() {
  const [result, setResult] = useState<SearchResult | null>(null);
  const [clauses, setClauses] = useState<SearchClause[]>([]);
  const [logic, setLogic] = useState("AND");
  const [range, setRange] = useState<{ start?: string; end?: string }>({});
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<FirewallEvent | null>(null);
  const [filterName, setFilterName] = useState("");
  const [countries, setCountries] = useState<string[]>([]);
  const [countryOptions, setCountryOptions] = useState<string[]>([]);
  const [countryMap, setCountryMap] = useState<Record<string, string>>({});
  const interfaceMap = useInterfaceMap();
  const ruleMap = useRuleMap();

  const run = async (
    nextOffset = 0,
    overrideClauses = clauses,
    overrideLogic = logic,
    overrideCountries = countries,
  ) => {
    setLoading(true);
    try {
      const res = await api.search({
        clauses: overrideClauses,
        logic: overrideLogic,
        start: range.start,
        end: range.end,
        limit: PAGE_SIZE,
        offset: nextOffset,
        countries: overrideCountries.length ? overrideCountries : undefined,
      });
      setResult(res);
      setOffset(nextOffset);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    api
      .countries(range.start, range.end, 50)
      .then((res) => setCountryOptions(res.items.map((item) => item.value)))
      .catch(() => setCountryOptions([]));
  }, [range.start, range.end]);

  useEffect(() => {
    const events = result?.events ?? [];
    if (events.length === 0) {
      setCountryMap({});
      return;
    }
    const ips = Array.from(new Set(events.flatMap((e) => [e.src_ip, e.dst_ip]).filter(Boolean)));
    let cancelled = false;
    api
      .geoLookup(ips)
      .then((res) => {
        if (cancelled) return;
        const map: Record<string, string> = {};
        Object.entries(res.items).forEach(([ip, info]) => {
          if (info) map[ip] = info.country;
        });
        setCountryMap(map);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [result]);

  const updateClauses = (next: SearchClause[]) => {
    setClauses(next);
    run(0, next, logic);
  };

  const saveCurrentFilter = async () => {
    if (!filterName.trim()) return;
    await api.saveFilter(filterName.trim(), {
      clauses,
      logic,
      start: range.start,
      end: range.end,
    });
    setFilterName("");
  };

  const exportResults = async (format: string) => {
    const blob = await api.export(
      { clauses, logic, start: range.start, end: range.end },
      format,
    );
    downloadBlob(blob, `events.${format}`);
  };

  const total = result?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <>
      <div className="topbar">
        <h2>Recherche historique</h2>
      </div>
      <TimeRangePicker
        onApply={(start, end) => {
          setRange({ start, end });
          run(0, clauses, logic);
        }}
      />
      <QuickFilters active={clauses} onChange={updateClauses} />
      <AdvancedFilters
        clauses={clauses}
        logic={logic}
        onLogicChange={(next) => {
          setLogic(next);
          run(0, clauses, next);
        }}
        onChange={updateClauses}
      />
      <CountryFilter
        value={countries}
        options={countryOptions}
        onChange={(next) => {
          setCountries(next);
          run(0, clauses, logic, next);
        }}
      />
      <div className="panel filters">
        <button className="active" onClick={() => run(0)} disabled={loading}>
          {loading ? "Recherche…" : "Rechercher"}
        </button>
        <input
          placeholder="Enregistrer le filtre sous…"
          value={filterName}
          onChange={(e) => setFilterName(e.target.value)}
        />
        <button onClick={saveCurrentFilter} disabled={!filterName.trim()}>
          Enregistrer le filtre
        </button>
        <span className="muted">Export :</span>
        <button onClick={() => exportResults("csv")}>CSV</button>
        <button onClick={() => exportResults("json")}>JSON</button>
        <button onClick={() => exportResults("parquet")}>Parquet</button>
      </div>

      <div className="panel">
        <p className="muted">
          Affichage de {result ? formatNumber(result.events.length) : 0} sur {formatNumber(total)} événements
        </p>
        <LogTable
          events={result?.events ?? []}
          onSelect={setSelected}
          interfaceMap={interfaceMap}
          ruleMap={ruleMap}
          countryMap={countryMap}
        />
        <div className="filters" style={{ marginTop: 12 }}>
          <button onClick={() => run(0)} disabled={offset === 0}>
            Premier
          </button>
          <button onClick={() => run(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
            Précédent
          </button>
          <span className="muted">
            Page {currentPage} / {pages}
          </span>
          <button onClick={() => run(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total}>
            Suivant
          </button>
          <button onClick={() => run((pages - 1) * PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total}>
            Dernier
          </button>
        </div>
      </div>
      <EventDetails event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
