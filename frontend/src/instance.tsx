import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api, setCurrentInstance } from "./api/client";
import type { Instance } from "./types";

const STORAGE_KEY = "ola_instance";

interface InstanceContextValue {
  instances: Instance[];
  instance: Instance | null;
  selectInstance: (id: string) => void;
  reload: () => Promise<void>;
}

const InstanceContext = createContext<InstanceContextValue>({
  instances: [],
  instance: null,
  selectInstance: () => undefined,
  reload: async () => undefined,
});

export function InstanceProvider({ children }: { children: ReactNode }) {
  const [instances, setInstances] = useState<Instance[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(() =>
    localStorage.getItem(STORAGE_KEY),
  );

  const apply = useCallback((list: Instance[], wanted: string | null) => {
    const valid =
      list.find((item) => item.id === wanted) ??
      list.find((item) => item.enabled) ??
      list[0] ??
      null;
    const id = valid ? valid.id : null;
    setCurrentId(id);
    setCurrentInstance(id);
    if (id) localStorage.setItem(STORAGE_KEY, id);
  }, []);

  const reload = useCallback(async () => {
    try {
      const res = await api.instances();
      setInstances(res.items);
      apply(res.items, localStorage.getItem(STORAGE_KEY));
    } catch {
      // keep whatever we had; the app still works against the first instance
    }
  }, [apply]);

  useEffect(() => {
    setCurrentInstance(currentId);
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectInstance = useCallback((id: string) => {
    setCurrentId(id);
    setCurrentInstance(id);
    localStorage.setItem(STORAGE_KEY, id);
  }, []);

  const instance = instances.find((item) => item.id === currentId) ?? null;

  return (
    <InstanceContext.Provider value={{ instances, instance, selectInstance, reload }}>
      {children}
    </InstanceContext.Provider>
  );
}

export function useInstance(): InstanceContextValue {
  return useContext(InstanceContext);
}
