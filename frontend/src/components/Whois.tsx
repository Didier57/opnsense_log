import { useEffect, useState, type CSSProperties } from "react";
import { api } from "../api/client";

function WhoisModal({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setText(null);
    setError("");
    api
      .whoisIp(ip)
      .then((res) => {
        if (active) setText(res.text || "(réponse vide)");
      })
      .catch((e) => {
        if (active) setError(String(e));
      });
    return () => {
      active = false;
    };
  }, [ip]);

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3 style={{ margin: 0 }}>WHOIS — {ip}</h3>
          <button onClick={onClose}>Fermer</button>
        </div>
        {error && <p className="error">{error}</p>}
        {text === null && !error && <p className="muted">Interrogation du WHOIS…</p>}
        {text !== null && <pre className="whois-text">{text}</pre>}
        <p className="muted" style={{ fontSize: 12 }}>
          Source : serveurs WHOIS officiels (IANA / RIR).{" "}
          <a
            href={`https://bgp.he.net/ip/${encodeURIComponent(ip)}`}
            target="_blank"
            rel="noreferrer"
          >
            Ouvrir sur bgp.he.net
          </a>
        </p>
      </div>
    </div>
  );
}

export function WhoisButton({ ip, style }: { ip: string; style?: CSSProperties }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        className="whois-btn"
        title="WHOIS de cette adresse IP"
        style={style}
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
      >
        🔎
      </button>
      {open && <WhoisModal ip={ip} onClose={() => setOpen(false)} />}
    </>
  );
}
