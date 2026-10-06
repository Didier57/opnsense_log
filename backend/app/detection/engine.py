"""Background detection engine.

Runs simple, configurable heuristics against the stored events and produces
alerts. Alerts are de-duplicated by a deterministic id so the same finding is
only reported once per detection window. When SMTP notifications are enabled a
single digest e-mail is sent per cycle containing the newly raised alerts.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from ..notifications.mailer import send_email
from ..notifications.store import get_smtp_settings
from ..storage.database import get_database
from .store import get_detection_settings

logger = logging.getLogger("opnsense.detection")

_MAX_PER_RULE = 25


def _rows(sql: str, params: list) -> list[tuple]:
    return get_database().execute_read(sql, params).fetchall()


def _is_internal(ip: str) -> bool:
    """True for private/loopback/link-local/reserved addresses (LAN traffic)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _skip_source(cfg: dict, src_ip: str) -> bool:
    return bool(cfg.get("detection_ignore_private", True)) and _is_internal(src_ip)


def _detect_port_scan(cfg: dict) -> list[dict]:
    window = cfg["detection_portscan_window_sec"]
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    rows = _rows(
        """
        SELECT "src_ip", COUNT(DISTINCT "dst_port") AS ports
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> '' AND "dst_port" IS NOT NULL
        GROUP BY 1
        HAVING COUNT(DISTINCT "dst_port") >= ?
        ORDER BY ports DESC
        LIMIT ?
        """,
        [cutoff, cfg["detection_portscan_ports"], _MAX_PER_RULE],
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    alerts = []
    for src_ip, ports in rows:
        if _skip_source(cfg, src_ip):
            continue
        alerts.append(
            {
                "id": f"port_scan:{src_ip}:{bucket}",
                "rule": "port_scan",
                "severity": "warning",
                "src_ip": src_ip,
                "title": "Scan de ports détecté",
                "message": f"{src_ip} a contacté {ports} ports distincts en {window}s",
                "details": {"ports": ports, "window_sec": window},
            }
        )
    return alerts


def _detect_bruteforce(cfg: dict) -> list[dict]:
    window = cfg["detection_bruteforce_window_sec"]
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    rows = _rows(
        """
        SELECT "src_ip", COUNT(*) AS attempts
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> ''
              AND lower("action") IN ('block', 'reject')
        GROUP BY 1
        HAVING COUNT(*) >= ?
        ORDER BY attempts DESC
        LIMIT ?
        """,
        [cutoff, cfg["detection_bruteforce_count"], _MAX_PER_RULE],
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    alerts = []
    for src_ip, attempts in rows:
        if _skip_source(cfg, src_ip):
            continue
        alerts.append(
            {
                "id": f"bruteforce:{src_ip}:{bucket}",
                "rule": "bruteforce",
                "severity": "critical",
                "src_ip": src_ip,
                "title": "Tentatives répétées bloquées",
                "message": f"{src_ip} a été bloqué {attempts} fois en {window}s",
                "details": {"attempts": attempts, "window_sec": window},
            }
        )
    return alerts


def _detect_spike(cfg: dict) -> list[dict]:
    window = cfg["detection_spike_window_sec"]
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    total = _rows("SELECT COUNT(*) FROM events WHERE \"event_time\" >= ?", [cutoff])[0][0]
    if total < cfg["detection_spike_threshold"]:
        return []
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    return [
        {
            "id": f"traffic_spike:global:{bucket}",
            "rule": "traffic_spike",
            "severity": "warning",
            "src_ip": "",
            "title": "Pic de trafic",
            "message": f"{total} événements en {window}s (seuil {cfg['detection_spike_threshold']})",
            "details": {"total": total, "window_sec": window},
        }
    ]


def _existing_ids(ids: list[str]) -> set[str]:
    if not ids:
        return set()
    marks = ", ".join("?" for _ in ids)
    rows = _rows(f'SELECT "id" FROM alerts WHERE "id" IN ({marks})', list(ids))
    return {r[0] for r in rows}


def _store_alert(alert: dict) -> None:
    get_database().execute_write(
        'INSERT INTO alerts ("id", "created_at", "rule", "severity", "src_ip", "title", '
        '"message", "details", "notified") VALUES (?, now(), ?, ?, ?, ?, ?, ?, ?)',
        [
            alert["id"],
            alert["rule"],
            alert["severity"],
            alert["src_ip"],
            alert["title"],
            alert["message"],
            json.dumps(alert["details"]),
            False,
        ],
    )


def run_cycle() -> list[dict]:
    """Run every detection rule once and persist new alerts. Returns the new ones."""
    cfg = get_detection_settings()
    if not cfg["detection_enabled"]:
        return []

    candidates: list[dict] = []
    for detector in (_detect_port_scan, _detect_bruteforce, _detect_spike):
        try:
            candidates.extend(detector(cfg))
        except Exception:  # noqa: BLE001
            logger.exception("Detection rule failed: %s", detector.__name__)

    existing = _existing_ids([c["id"] for c in candidates])
    new_alerts = [c for c in candidates if c["id"] not in existing]
    for alert in new_alerts:
        try:
            _store_alert(alert)
        except Exception:  # noqa: BLE001
            logger.exception("Could not store alert %s", alert.get("id"))

    if new_alerts:
        logger.info("Detection raised %d new alert(s)", len(new_alerts))
        _notify(new_alerts)
    return new_alerts


def _notify(alerts: list[dict]) -> None:
    try:
        smtp = get_smtp_settings(mask_password=False)
    except Exception:  # noqa: BLE001
        return
    if not smtp.get("smtp_enabled"):
        return
    lines = [f"- [{a['severity']}] {a['title']} : {a['message']}" for a in alerts]
    subject = f"[OPNsense Log Analyzer] {len(alerts)} alerte(s) de sécurité"
    body = "Nouvelles alertes détectées :\n\n" + "\n".join(lines) + "\n\n-- Analyseur de logs OPNsense"
    result = send_email(subject, body, smtp)
    if not result.get("ok"):
        logger.warning("Alert e-mail not sent: %s", result.get("message"))


def list_alerts(limit: int = 200, offset: int = 0) -> dict:
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    total = _rows("SELECT COUNT(*) FROM alerts", [])[0][0]
    rows = _rows(
        'SELECT "id", "created_at", "rule", "severity", "src_ip", "title", "message", "details" '
        'FROM alerts ORDER BY "created_at" DESC LIMIT ? OFFSET ?',
        [limit, offset],
    )
    items = []
    for row in rows:
        details = {}
        try:
            details = json.loads(row[7]) if row[7] else {}
        except (ValueError, TypeError):
            details = {}
        items.append(
            {
                "id": row[0],
                "created_at": row[1],
                "rule": row[2],
                "severity": row[3],
                "src_ip": row[4],
                "title": row[5],
                "message": row[6],
                "details": details,
            }
        )
    return {"total": total, "limit": limit, "offset": offset, "items": items}


def count_alerts() -> int:
    return _rows("SELECT COUNT(*) FROM alerts", [])[0][0]


def clear_alerts() -> int:
    result = get_database().execute_write("DELETE FROM alerts RETURNING 1")
    return len(result.fetchall())


async def detection_loop() -> None:
    """Periodically run the detection engine off the event loop."""
    while True:
        interval = 60
        try:
            cfg = get_detection_settings()
            if cfg["detection_enabled"]:
                interval = max(15, cfg["detection_interval_sec"])
                await asyncio.to_thread(run_cycle)
            else:
                interval = 30
        except Exception:  # noqa: BLE001
            logger.exception("Detection loop error")
            interval = 60
        await asyncio.sleep(interval)
