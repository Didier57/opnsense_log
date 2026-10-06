import { useEffect, useState } from "react";
import { api } from "../api/client";

export function useInterfaceMap(): Record<string, string> {
  const [map, setMap] = useState<Record<string, string>>({});
  useEffect(() => {
    api
      .interfaces()
      .then((res) => {
        const next: Record<string, string> = {};
        res.items.forEach((iface) => {
          const label = iface.description || iface.name;
          if (iface.device) next[iface.device] = label;
          if (iface.name) next[iface.name] = label;
        });
        setMap(next);
      })
      .catch(() => setMap({}));
  }, []);
  return map;
}
