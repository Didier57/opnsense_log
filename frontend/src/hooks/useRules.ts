import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { OpnsenseRule } from "../types";

/** Rules synced from OPNsense (rule_id + description). */
export function useRules(): OpnsenseRule[] {
  const [items, setItems] = useState<OpnsenseRule[]>([]);
  useEffect(() => {
    api
      .rules()
      .then((res) => setItems(res.items))
      .catch(() => setItems([]));
  }, []);
  return items;
}
