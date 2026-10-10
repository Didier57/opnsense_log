import { useState } from "react";
import { api } from "../api/client";
import { useInstance } from "../instance";

export function Instances() {
  const { instances, instance, reload } = useInstance();
  const [name, setName] = useState("");
  const [port, setPort] = useState("");
  const [message, setMessage] = useState("");

  const create = async () => {
    setMessage("");
    try {
      const res = await api.createInstance({
        name: name || null,
        syslog_port: port ? Number(port) : null,
      });
      setMessage(
        `Instance « ${res.instance.name} » créée (port syslog ${res.instance.syslog_port}).`,
      );
      setName("");
      setPort("");
      await reload();
    } catch (err) {
      setMessage(String(err));
    }
  };

  const rename = async (id: string, current: string) => {
    const value = window.prompt("Nom de l'instance", current);
    if (value === null) return;
    await api.updateInstance(id, { name: value });
    await reload();
  };

  const toggle = async (id: string, enabled: boolean) => {
    await api.updateInstance(id, { enabled: !enabled });
    await reload();
  };

  const remove = async (id: string, label: string) => {
    if (!window.confirm(`Supprimer l'instance « ${label} » et toutes ses données ?`)) return;
    await api.deleteInstance(id);
    await reload();
  };

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Instances OPNsense</h3>
      <p className="muted">
        Chaque instance possède ses propres logs, configuration, alertes et détection, sur son propre
        port syslog. Seul l'e-mail (SMTP) est partagé.
      </p>
      <div className="topbar">
        <input
          placeholder="Nom (ex. Site Paris)"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          placeholder="Port syslog (auto si vide)"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <button className="active" onClick={create}>
          Ajouter une instance
        </button>
      </div>
      {message && <p className="muted">{message}</p>}
      <table className="table">
        <thead>
          <tr>
            <th>Nom</th>
            <th>Port syslog</th>
            <th>Protocole</th>
            <th>État</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {instances.map((inst) => (
            <tr key={inst.id}>
              <td>
                {inst.name}
                {inst.id === instance?.id ? " ★" : ""}
              </td>
              <td>{inst.syslog_port ?? "—"}</td>
              <td>{inst.syslog_protocol ?? "—"}</td>
              <td>{inst.enabled ? "activée" : "désactivée"}</td>
              <td>
                <button onClick={() => rename(inst.id, inst.name)}>Renommer</button>{" "}
                <button onClick={() => toggle(inst.id, inst.enabled)}>
                  {inst.enabled ? "Désactiver" : "Activer"}
                </button>{" "}
                <button onClick={() => remove(inst.id, inst.name)}>Supprimer</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
