import { useEffect, useState } from "react";
import { api } from "../api/client";

/** Map of rule_id -> human-readable rule description (the "label"). */
export function useRuleMap(): Record<string, string> {
  const [map, setMap] = useState<Record<string, string>>({});
  useEffect(() => {
    api
      .rules()
      .then((res) => {
        const next: Record<string, string> = {};
        res.items.forEach((rule) => {
          if (rule.rule_id) next[rule.rule_id] = rule.description || rule.rule_id;
        });
        setMap(next);
      })
      .catch(() => setMap({}));
  }, []);
  return map;
}
