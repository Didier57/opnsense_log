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
          if (iface.device) next[iface.device] = iface.description || iface.name;
        });
        setMap(next);
      })
      .catch(() => setMap({}));
  }, []);
  return map;
}
