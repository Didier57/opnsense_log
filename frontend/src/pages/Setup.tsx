import { useState } from "react";
import { useAuth } from "../auth";

export function Setup() {
  const { registerAdmin } = useAuth();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (password.length < 6) {
      setError("Le mot de passe doit contenir au moins 6 caractères.");
      return;
    }
    if (password !== confirm) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    try {
      await registerAdmin(username, password);
    } catch (err) {
      setError(String(err));
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-box" onSubmit={submit}>
        <h1>Création du compte administrateur</h1>
        <p className="muted">
          Première utilisation : créez le compte administrateur. Il n'est plus nécessaire de mettre
          les identifiants dans le fichier .env.
        </p>
        <label htmlFor="username">Nom d'utilisateur</label>
        <input
          id="username"
          name="username"
          autoComplete="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <label htmlFor="password">Mot de passe</label>
        <input
          id="password"
          name="new-password"
          type="password"
          autoComplete="new-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <label htmlFor="confirm">Confirmer le mot de passe</label>
        <input
          id="confirm"
          name="new-password"
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {error && <div className="error">{error}</div>}
        <button type="submit">Créer le compte</button>
      </form>
    </div>
  );
}
