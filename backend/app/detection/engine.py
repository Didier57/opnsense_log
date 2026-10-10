"""Background detection engine.

Runs simple, configurable heuristics against the stored events and produces
alerts. Alerts are de-duplicated by a deterministic id so the same finding is
only reported once per detection window. When SMTP notifications are enabled a
single digest e-mail is sent per cycle containing the newly raised alerts.
"""
from __future__ import annotations

import asyncio
import html as html_lib
import ipaddress
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from ..config import settings
from ..instances import resolve_instance_id
from ..notifications.mailer import send_email
from ..notifications.store import get_smtp_settings
from ..storage.database import get_database
from .store import get_detection_settings

logger = logging.getLogger("opnsense.detection")

_MAX_PER_RULE = 25

# Events older than the moment the process started are ignored during the very
# first detection cycle, so a restart does not re-notify about a backlog the
# previous run already reported.
_STARTED_AT = datetime.now(timezone.utc)
_first_cycle: set[str] = set()


def _rows(sql: str, params: list, instance_id: str | None = None) -> list[tuple]:
    return get_database(resolve_instance_id(instance_id)).execute_read(sql, params).fetchall()


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


def _skip_source(cfg: dict, src_ip: str, allow_nets: list | None = None) -> bool:
    """True when a source must never raise an alert (trusted/internal)."""
    if allow_nets:
        try:
            addr = ipaddress.ip_address(src_ip)
        except ValueError:
            addr = None
        if addr is not None and any(addr in net for net in allow_nets):
            return True
    return bool(cfg.get("detection_ignore_private", True)) and _is_internal(src_ip)


def _window_start(window: int, floor: datetime | None) -> datetime:
    """Start of the detection window, never earlier than ``floor`` if set."""
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
    if floor is not None and floor > cutoff:
        return floor
    return cutoff


def _block_labels(src_ips: list[str], cutoff: datetime, instance_id: str | None = None) -> dict[str, str]:
    """Map each source IP to the label of the rule that most often blocked it.

    The firewall rule description is joined from ``opnsense_rules``; the raw rule
    id is used when no description is known. Used to tell *what* blocked an IP.
    """
    ips = [ip for ip in dict.fromkeys(src_ips) if ip]
    if not ips:
        return {}
    marks = ", ".join("?" for _ in ips)
    rows = _rows(
        "SELECT e.\"src_ip\", e.\"rule_id\", COUNT(*) AS c, MAX(r.\"description\") "
        "FROM events e LEFT JOIN opnsense_rules r ON r.\"rule_id\" = e.\"rule_id\" "
        "WHERE e.\"event_time\" >= ? AND lower(e.\"action\") IN ('block', 'reject') "
        f"AND e.\"rule_id\" <> '' AND e.\"src_ip\" IN ({marks}) "
        "GROUP BY 1, 2 ORDER BY 1, 3 DESC",
        [cutoff, *ips],
        instance_id,
    )
    labels: dict[str, str] = {}
    for src_ip, rule_id, _count, description in rows:
        if src_ip in labels:
            continue
        labels[src_ip] = (description or rule_id or "").strip()
    return labels


def _iso(value: datetime | None) -> str | None:
    """UTC ISO string for JSON storage (``None`` when unavailable)."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _fmt_time(value: datetime | None) -> str:
    """Human readable event time in the configured display timezone."""
    if value is None:
        return "date inconnue"
    tz_name = settings.display_timezone or "UTC"
    try:
        from ..settings_store import get_app_settings

        tz_name = get_app_settings().get("display_timezone") or tz_name
    except Exception:  # noqa: BLE001
        pass
    try:
        tz = ZoneInfo(tz_name)
    except Exception:  # noqa: BLE001
        tz = timezone.utc
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(tz).strftime("%d/%m/%Y %H:%M:%S")


def _ignore_ports(cfg: dict) -> list[int]:
    """Destination ports excluded from the brute-force detectors.

    Legitimate mail clients retry the same IMAP/SMTP port many times, which
    would otherwise look like a service brute-force. Configured in the UI.
    """
    ports: list[int] = []
    for token in str(cfg.get("detection_bruteforce_ignore_ports") or "").replace(";", ",").split(","):
        token = token.strip()
        if token.isdigit():
            port = int(token)
            if 0 < port <= 65535 and port not in ports:
                ports.append(port)
    return ports


def _port_filter(cfg: dict, params: list) -> str:
    """SQL fragment excluding the ignore ports; appends their values to ``params``."""
    ports = _ignore_ports(cfg)
    if not ports:
        return ""
    params.extend(ports)
    placeholders = ", ".join("?" for _ in ports)
    return f' AND ("dst_port" IS NULL OR "dst_port" NOT IN ({placeholders}))'


def _detect_port_scan(cfg: dict, floor: datetime | None = None, allow_nets: list | None = None, instance_id: str | None = None) -> list[dict]:
    window = cfg["detection_portscan_window_sec"]
    cutoff = _window_start(window, floor)
    rows = _rows(
        """
        SELECT "src_ip", COUNT(DISTINCT "dst_port") AS ports, MAX("event_time") AS last_seen
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> '' AND "dst_port" IS NOT NULL
        GROUP BY 1
        HAVING COUNT(DISTINCT "dst_port") >= ?
        ORDER BY ports DESC
        LIMIT ?
        """,
        [cutoff, cfg["detection_portscan_ports"], _MAX_PER_RULE],
        instance_id,
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    labels = _block_labels([r[0] for r in rows], cutoff, instance_id)
    alerts = []
    for src_ip, ports, last_seen in rows:
        if _skip_source(cfg, src_ip, allow_nets):
            continue
        alerts.append(
            {
                "id": f"port_scan:{src_ip}:{bucket}",
                "rule": "port_scan",
                "severity": "warning",
                "src_ip": src_ip,
                "event_time": last_seen,
                "title": "Scan de ports détecté",
                "message": f"{src_ip} a contacté {ports} ports distincts en {window}s",
                "details": {
                    "ports": ports,
                    "window_sec": window,
                    "rule_label": labels.get(src_ip, ""),
                    "event_time": _iso(last_seen),
                },
            }
        )
    return alerts


def _detect_bruteforce(cfg: dict, floor: datetime | None = None, allow_nets: list | None = None, instance_id: str | None = None) -> list[dict]:
    window = cfg["detection_bruteforce_window_sec"]
    cutoff = _window_start(window, floor)
    params: list = [cutoff]
    port_filter = _port_filter(cfg, params)
    params += [cfg["detection_bruteforce_count"], _MAX_PER_RULE]
    rows = _rows(
        f"""
        SELECT "src_ip", COUNT(*) AS attempts, MAX("event_time") AS last_seen
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> ''
              AND lower("action") IN ('block', 'reject'){port_filter}
        GROUP BY 1
        HAVING COUNT(*) >= ?
        ORDER BY attempts DESC
        LIMIT ?
        """,
        params,
        instance_id,
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    labels = _block_labels([r[0] for r in rows], cutoff, instance_id)
    alerts = []
    for src_ip, attempts, last_seen in rows:
        if _skip_source(cfg, src_ip, allow_nets):
            continue
        alerts.append(
            {
                "id": f"bruteforce:{src_ip}:{bucket}",
                "rule": "bruteforce",
                "severity": "critical",
                "src_ip": src_ip,
                "event_time": last_seen,
                "title": "Tentatives répétées bloquées",
                "message": f"{src_ip} a été bloqué {attempts} fois en {window}s",
                "details": {
                    "attempts": attempts,
                    "window_sec": window,
                    "rule_label": labels.get(src_ip, ""),
                    "event_time": _iso(last_seen),
                },
            }
        )
    return alerts


def _detect_bruteforce_service(cfg: dict, floor: datetime | None = None, allow_nets: list | None = None, instance_id: str | None = None) -> list[dict]:
    """Repeated blocks against the same destination port (service brute-force)."""
    window = cfg["detection_bruteforce_window_sec"]
    cutoff = _window_start(window, floor)
    params: list = [cutoff]
    port_filter = _port_filter(cfg, params)
    params += [cfg["detection_bruteforce_service_count"], _MAX_PER_RULE]
    rows = _rows(
        f"""
        SELECT "src_ip", "dst_port", COUNT(*) AS attempts, MAX("event_time") AS last_seen
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> '' AND "dst_port" IS NOT NULL
              AND lower("action") IN ('block', 'reject'){port_filter}
        GROUP BY 1, 2
        HAVING COUNT(*) >= ?
        ORDER BY attempts DESC
        LIMIT ?
        """,
        params,
        instance_id,
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    labels = _block_labels([r[0] for r in rows], cutoff, instance_id)
    alerts = []
    for src_ip, dst_port, attempts, last_seen in rows:
        if _skip_source(cfg, src_ip, allow_nets):
            continue
        alerts.append(
            {
                "id": f"bruteforce_service:{src_ip}:{dst_port}:{bucket}",
                "rule": "bruteforce_service",
                "severity": "critical",
                "src_ip": src_ip,
                "event_time": last_seen,
                "title": "Force brute sur un service",
                "message": f"{src_ip} a été bloqué {attempts} fois sur le port {dst_port} en {window}s",
                "details": {
                    "attempts": attempts,
                    "dst_port": dst_port,
                    "window_sec": window,
                    "rule_label": labels.get(src_ip, ""),
                    "event_time": _iso(last_seen),
                },
            }
        )
    return alerts


def _detect_horizontal_scan(cfg: dict, floor: datetime | None = None, allow_nets: list | None = None, instance_id: str | None = None) -> list[dict]:
    """One source contacting many distinct destination hosts (network scan)."""
    window = cfg["detection_horizontalscan_window_sec"]
    cutoff = _window_start(window, floor)
    rows = _rows(
        """
        SELECT "src_ip", COUNT(DISTINCT "dst_ip") AS hosts, MAX("event_time") AS last_seen
        FROM events
        WHERE "event_time" >= ? AND "src_ip" <> '' AND "dst_ip" <> ''
        GROUP BY 1
        HAVING COUNT(DISTINCT "dst_ip") >= ?
        ORDER BY hosts DESC
        LIMIT ?
        """,
        [cutoff, cfg["detection_horizontalscan_hosts"], _MAX_PER_RULE],
        instance_id,
    )
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    labels = _block_labels([r[0] for r in rows], cutoff, instance_id)
    alerts = []
    for src_ip, hosts, last_seen in rows:
        if _skip_source(cfg, src_ip, allow_nets):
            continue
        alerts.append(
            {
                "id": f"horizontal_scan:{src_ip}:{bucket}",
                "rule": "horizontal_scan",
                "severity": "warning",
                "src_ip": src_ip,
                "event_time": last_seen,
                "title": "Balayage réseau détecté",
                "message": f"{src_ip} a contacté {hosts} hôtes distincts en {window}s",
                "details": {
                    "hosts": hosts,
                    "window_sec": window,
                    "rule_label": labels.get(src_ip, ""),
                    "event_time": _iso(last_seen),
                },
            }
        )
    return alerts


def _detect_spike(cfg: dict, floor: datetime | None = None, allow_nets: list | None = None, instance_id: str | None = None) -> list[dict]:
    if not cfg.get("detection_spike_enabled", False):
        return []
    window = cfg["detection_spike_window_sec"]
    cutoff = _window_start(window, floor)
    row = _rows('SELECT COUNT(*), MAX("event_time") FROM events WHERE "event_time" >= ?', [cutoff], instance_id)[0]
    total, last_seen = row[0], row[1]
    if total < cfg["detection_spike_threshold"]:
        return []
    bucket = int(datetime.now(timezone.utc).timestamp() // max(window, 1))
    return [
        {
            "id": f"traffic_spike:global:{bucket}",
            "rule": "traffic_spike",
            "severity": "warning",
            "src_ip": "",
            "event_time": last_seen,
            "title": "Pic de trafic",
            "message": f"{total} événements en {window}s (seuil {cfg['detection_spike_threshold']})",
            "details": {"total": total, "window_sec": window, "event_time": _iso(last_seen)},
        }
    ]


def _existing_ids(ids: list[str], instance_id: str | None = None) -> set[str]:
    if not ids:
        return set()
    marks = ", ".join("?" for _ in ids)
    rows = _rows(f'SELECT "id" FROM alerts WHERE "id" IN ({marks})', list(ids), instance_id)
    return {r[0] for r in rows}


def _store_alert(alert: dict, instance_id: str | None = None) -> None:
    get_database(resolve_instance_id(instance_id)).execute_write(
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


def run_cycle(instance_id: str | None = None) -> list[dict]:
    """Run every detection rule once and persist new alerts. Returns the new ones."""
    cfg = get_detection_settings(instance_id)
    if not cfg["detection_enabled"]:
        return []

    # On the first cycle after startup ignore pre-boot events (per instance).
    key = resolve_instance_id(instance_id) or ""
    if key not in _first_cycle:
        floor = _STARTED_AT
        _first_cycle.add(key)
    else:
        floor = None

    try:
        from .allowlist_store import allowlist_nets

        allow_nets = allowlist_nets(instance_id)
    except Exception:  # noqa: BLE001 - allowlist must never break detection
        logger.exception("Could not load allowlist")
        allow_nets = []

    candidates: list[dict] = []
    for detector in (
        _detect_port_scan,
        _detect_bruteforce,
        _detect_bruteforce_service,
        _detect_horizontal_scan,
        _detect_spike,
    ):
        try:
            candidates.extend(detector(cfg, floor, allow_nets, instance_id))
        except Exception:  # noqa: BLE001
            logger.exception("Detection rule failed: %s", detector.__name__)

    existing = _existing_ids([c["id"] for c in candidates], instance_id)
    new_alerts = [c for c in candidates if c["id"] not in existing]
    for alert in new_alerts:
        try:
            _store_alert(alert, instance_id)
        except Exception:  # noqa: BLE001
            logger.exception("Could not store alert %s", alert.get("id"))

    blocked_by_us: set[str] = set()
    try:
        from ..opnsense.blocker import block_alerts, prune_expired
        from .blocking_store import get_blocking_settings

        bcfg = get_blocking_settings(instance_id)
        if bcfg.get("blocking_enabled") and bcfg.get("blocking_mode") == "auto" and new_alerts:
            result = block_alerts(new_alerts, instance_id)
            blocked_by_us = {ip for ip in (result.get("added") or []) if ip}
            if blocked_by_us:
                logger.info("Auto-blocked %d IP(s): %s", len(blocked_by_us), sorted(blocked_by_us))
        prune_expired(instance_id)
    except Exception:  # noqa: BLE001
        logger.exception("Blocking step failed")

    if new_alerts:
        logger.info("Detection raised %d new alert(s)", len(new_alerts))
        _notify(new_alerts, cfg, blocked_by_us, instance_id)

    return new_alerts


def _recently_notified(rule: str, src_ip: str, cutoff: datetime, instance_id: str | None = None) -> bool:
    rows = _rows(
        'SELECT 1 FROM alerts WHERE "rule" = ? AND "src_ip" = ? AND "notified" = TRUE '
        'AND "created_at" >= ? LIMIT 1',
        [rule, src_ip, cutoff],
        instance_id,
    )
    return bool(rows)


def _mark_notified(ids: list[str], instance_id: str | None = None) -> None:
    if not ids:
        return
    marks = ", ".join("?" for _ in ids)
    get_database(resolve_instance_id(instance_id)).execute_write(
        f'UPDATE alerts SET "notified" = TRUE WHERE "id" IN ({marks})', list(ids)
    )


def _alerts_html(alerts: list[dict]) -> str:
    """HTML digest of the alerts, with a link back to the app when configured."""
    try:
        from ..settings_store import get_public_url

        base = get_public_url()
    except Exception:  # noqa: BLE001
        base = ""
    rows = ""
    for alert in alerts:
        severity = html_lib.escape(str(alert.get("severity") or ""))
        color = "#dc2626" if severity == "critical" else "#d97706"
        rows += (
            "<tr>"
            '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">'
            f'<span style="color:{color};font-weight:600">{severity.upper()}</span></td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;white-space:nowrap">'
            f'{html_lib.escape(_fmt_time(alert.get("event_time")))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{html_lib.escape(str(alert.get("title") or ""))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">'
            f'{html_lib.escape(str(alert.get("src_ip") or ""))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">'
            f'{html_lib.escape(str(alert.get("details", {}).get("rule_label") or ""))}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{html_lib.escape(str(alert.get("message") or ""))}</td>'
            "</tr>"
        )
    link = ""
    if base:
        link = (
            '<p style="margin:16px 0 0">'
            f'<a href="{html_lib.escape(base)}">Ouvrir l\'analyseur de logs</a></p>'
        )
    return (
        '<html><body style="font-family:Arial,Helvetica,sans-serif;color:#111827">'
        '<h2 style="margin:0 0 12px">Alertes de sécurité</h2>'
        f'<p style="margin:0 0 16px;color:#374151">{len(alerts)} nouvelle(s) alerte(s) détectée(s).</p>'
        '<table style="border-collapse:collapse;width:100%;max-width:900px">'
        '<thead><tr>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Gravité</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Date</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Type</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Source</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Label</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Détail</th>'
        '</tr></thead>'
        f"<tbody>{rows}</tbody></table>"
        f"{link}"
        "</body></html>"
    )


def _notify(alerts: list[dict], cfg: dict, blocked_by_us: set[str] | None = None, instance_id: str | None = None) -> None:
    # Skip alerts already covered by a block e-mail (the app just blocked the IP)
    # or handled by another plugin (the blocking rule is not our own alias), so
    # the alert digest never duplicates a blocking notification.
    blocked_by_us = blocked_by_us or set()
    try:
        from .blocking_store import get_blocking_settings

        own_alias = str(get_blocking_settings(instance_id).get("blocking_alias") or "").strip().lower()
    except Exception:  # noqa: BLE001
        own_alias = ""

    def _handled(alert: dict) -> bool:
        ip = alert.get("src_ip") or ""
        if ip and ip in blocked_by_us:
            return True
        label = str(alert.get("details", {}).get("rule_label") or "").strip().lower()
        return bool(label and own_alias and label != own_alias)

    alerts = [a for a in alerts if not _handled(a)]
    if not alerts:
        logger.info("Alert e-mail skipped: every alert is already handled by a blocking")
        return

    try:
        smtp = get_smtp_settings(mask_password=False)
    except Exception:  # noqa: BLE001
        return
    if not smtp.get("smtp_enabled"):
        return

    cooldown_min = int(cfg.get("detection_notify_cooldown_min", 60) or 0)
    to_send = alerts
    if cooldown_min > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=cooldown_min)
        to_send = [a for a in alerts if not _recently_notified(a["rule"], a["src_ip"], cutoff, instance_id)]
        if not to_send:
            logger.info("E-mail notification suppressed by cooldown (%d alert(s))", len(alerts))
            return

    lines = [
        f"- [{a['severity']}] {_fmt_time(a.get('event_time'))} — {a['title']} : {a['message']}" for a in to_send
    ]
    subject = f"[OPNsense Log Analyzer] {len(to_send)} alerte(s) de sécurité"
    body = "Nouvelles alertes détectées :\n\n" + "\n".join(lines) + "\n\n-- Analyseur de logs OPNsense"
    result = send_email(subject, body, smtp, html=_alerts_html(to_send))
    if result.get("ok"):
        try:
            _mark_notified([a["id"] for a in to_send], instance_id)
        except Exception:  # noqa: BLE001
            logger.exception("Could not mark alerts as notified")
    else:
        logger.warning("Alert e-mail not sent: %s", result.get("message"))


def list_alerts(limit: int = 200, offset: int = 0, instance_id: str | None = None) -> dict:
    limit = max(1, min(limit, 1000))
    offset = max(0, offset)
    total = _rows("SELECT COUNT(*) FROM alerts", [], instance_id)[0][0]
    rows = _rows(
        'SELECT "id", "created_at", "rule", "severity", "src_ip", "title", "message", "details" '
        'FROM alerts ORDER BY "created_at" DESC LIMIT ? OFFSET ?',
        [limit, offset],
        instance_id,
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
                "event_time": details.get("event_time"),
                "rule": row[2],
                "severity": row[3],
                "src_ip": row[4],
                "title": row[5],
                "message": row[6],
                "details": details,
            }
        )
    return {"total": total, "limit": limit, "offset": offset, "items": items}


def count_alerts(instance_id: str | None = None) -> int:
    return _rows("SELECT COUNT(*) FROM alerts", [], instance_id)[0][0]


def clear_alerts(instance_id: str | None = None) -> int:
    result = get_database(resolve_instance_id(instance_id)).execute_write("DELETE FROM alerts RETURNING 1")
    return len(result.fetchall())


async def detection_loop() -> None:
    """Periodically run the detection engine for every instance, off the loop."""
    from ..instances import list_instances

    last: dict[str, float] = {}
    while True:
        try:
            try:
                instances = list_instances()
            except Exception:  # noqa: BLE001
                instances = []
            now = time.monotonic()
            for inst in instances:
                iid = inst["id"]
                cfg = get_detection_settings(iid)
                if not cfg.get("detection_enabled"):
                    continue
                interval = max(15, int(cfg.get("detection_interval_sec") or 60))
                if now - last.get(iid, 0.0) < interval:
                    continue
                last[iid] = now
                try:
                    await asyncio.to_thread(run_cycle, iid)
                except Exception:  # noqa: BLE001
                    logger.exception("Detection cycle failed for %s", iid)
        except Exception:  # noqa: BLE001
            logger.exception("Detection loop error")
        await asyncio.sleep(15)
