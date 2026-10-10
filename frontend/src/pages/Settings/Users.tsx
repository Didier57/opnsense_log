import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { User } from "../../types";

const ROLES = [
  { value: "admin", label: "Administrateur" },
  { value: "viewer", label: "Lecteur" },
];

export function Users() {
  const [users, setUsers] = useState<User[]>([]);
  const [message, setMessage] = useState("");
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("viewer");

  const load = () =>
    api
      .users()
      .then((r) => setUsers(r.items))
      .catch(() => undefined);

  useEffect(() => {
    load();
  }, []);

  const create = async () => {
    setMessage("");
    try {
      await api.createUser({ username: newName, password: newPassword, role: newRole });
      setNewName("");
      setNewPassword("");
      setNewRole("viewer");
      setMessage("Utilisateur créé.");
      await load();
    } catch (err) {
      setMessage(String(err));
    }
  };

  const changeRole = async (username: string, role: string) => {
    setMessage("");
    try {
      await api.updateUser(username, { role });
      await load();
    } catch (err) {
      setMessage(String(err));
    }
  };

  const resetPassword = async (username: string) => {
    const pwd = window.prompt(`Nouveau mot de passe pour « ${username} » :`);
    if (!pwd) return;
    setMessage("");
    try {
      await api.updateUser(username, { password: pwd });
      setMessage("Mot de passe mis à jour.");
    } catch (err) {
      setMessage(String(err));
    }
  };

  const remove = async (username: string) => {
    if (!window.confirm(`Supprimer l'utilisateur « ${username} » ?`)) return;
    setMessage("");
    try {
      await api.deleteUser(username);
      await load();
    } catch (err) {
      setMessage(String(err));
    }
  };

  return (
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Utilisateurs</h3>
      <p className="muted">
        <strong>Administrateur</strong> : accès complet. <strong>Lecteur</strong> : Tableau de bord,
        Journaux et Analyse uniquement.
      </p>
      {message && <p className="muted">{message}</p>}
      <table className="table">
        <thead>
          <tr>
            <th>Utilisateur</th>
            <th>Rôle</th>
            <th>Créé</th>
            <th>Dernière connexion</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.username}>
              <td>{u.username}</td>
              <td>
                <select value={u.role} onChange={(e) => changeRole(u.username, e.target.value)}>
                  {ROLES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
              </td>
              <td className="muted">{u.created_at ? new Date(u.created_at).toLocaleString() : "—"}</td>
              <td className="muted">
                {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}
              </td>
              <td>
                <button onClick={() => resetPassword(u.username)}>Mot de passe</button>{" "}
                <button onClick={() => remove(u.username)}>Supprimer</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <h4>Ajouter un utilisateur</h4>
      <div className="topbar">
        <input
          placeholder="Nom d'utilisateur"
          value={newName}
          onChange={(e) => setNewName(e.target.value)}
        />
        <input
          type="password"
          placeholder="Mot de passe"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
        <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
          {ROLES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
        <button className="active" onClick={create} disabled={!newName || !newPassword}>
          Ajouter
        </button>
      </div>
    </div>
  );
}
