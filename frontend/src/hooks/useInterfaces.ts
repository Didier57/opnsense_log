import { useEffect, useState } from "react";
import { api } from "../api/client";

export interface InterfaceInfo {
  name: string;
  device: string;
  description: string;
  ipv4: string;
  ipv6: string;
}

export function useInterfaces(): InterfaceInfo[] {
  const [items, setItems] = useState<InterfaceInfo[]>([]);
  useEffect(() => {
    api
      .interfaces()
      .then((res) => setItems(res.items as InterfaceInfo[]))
      .catch(() => setItems([]));
  }, []);
  return items;
}

function matchesInterface(iface: InterfaceInfo, wanted: string): boolean {
  return (
    (iface.description || "").toUpperCase() === wanted ||
    iface.name.toUpperCase() === wanted
  );
}

/** Find the device (e.g. vtnet0) behind a well-known interface role (LAN/WAN). */
export function findInterfaceDevice(items: InterfaceInfo[], role: string): string | null {
  const found = items.find((iface) => matchesInterface(iface, role));
  return found ? found.device : null;
}
