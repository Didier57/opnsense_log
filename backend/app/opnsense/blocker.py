"""Automatic blocking: push alert source IPs into an OPNsense firewall alias.

Only bruteforce and port-scan alert source IPs are pushed. IPs that are private,
invalid, or in the configured whitelist are never blocked (avoids self-lockout).
"""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone

from ..instances import resolve_instance_id
from ..storage.database import get_database
from ..detection.allowlist_store import allowlist_nets
from ..detection.blocking_store import get_blocking_settings, set_detected_skip_tables
from ..notifications.blocking_mail import send_block_notification
from .api_client import APIError, OPNsenseAPI
from .settings_store import get_opnsense_settings
from .ssh import OPNsenseSSH, SSHError

logger = logging.getLogger("opnsense.blocking")

_BLOCKABLE_RULES = {"bruteforce", "port_scan", "bruteforce_service", "horizontal_scan"}

# Substrings that mark a pf table as an existing block list (CrowdSec, Q-Feeds,
# Spamhaus, DShield...). Such tables are auto-added to the skip list so an IP
# they already block is never blocked (or notified) a second time.
_AUTO_TABLE_PATTERNS = (
    "crowdsec",
    "qfeeds",
    "q_feed",
    "spamhaus",
    "dshield",
    "firehol",
    "blocklist",
    "blacklist",
    "block",
    "abuse",
    "drop",
)


def _api(instance_id: str | None = None) -> OPNsenseAPI:
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance_id)
    return OPNsenseAPI(
        host=cfg.get("opnsense_host", ""),
        port=int(cfg.get("opnsense_api_port", 443) or 443),
        scheme=cfg.get("opnsense_api_scheme", "https") or "https",
        key=cfg.get("opnsense_api_key", ""),
        secret=cfg.get("opnsense_api_secret", ""),
    )


def _whitelist_nets(text: str) -> list:
    nets = []
    for token in str(text or "").replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return nets


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _is_blockable(ip: str, nets: list) -> bool:
    if not _is_public(ip):
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not any(addr in net for net in nets)


def _skip_tables(cfg: dict) -> list[str]:
    """Names of pf tables / aliases an IP may already be blocked by.

    Merges the user-configured list with the tables auto-detected on the
    firewall (``blocking_skip_tables_detected``).
    """
    raw = f"{cfg.get('blocking_skip_tables') or ''} {cfg.get('blocking_skip_tables_detected') or ''}"
    alias = str(cfg.get("blocking_alias") or "").strip().lower()
    tables: list[str] = []
    for token in re.split(r"[,\s]+", raw):
        token = token.strip()
        if (
            token
            and re.fullmatch(r"[A-Za-z0-9_.\-]+", token)
            and token not in tables
            and token.lower() != alias
        ):
            tables.append(token)
    return tables


def detect_block_tables(instance_id: str | None = None) -> list[str]:
    """List the pf tables on OPNsense that look like existing block lists.

    Best-effort: any SSH problem returns an empty list so blocking keeps working.
    """
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance_id)
    if not cfg.get("opnsense_host"):
        return []
    try:
        ssh = OPNsenseSSH(
            host=cfg["opnsense_host"],
            port=cfg["opnsense_ssh_port"],
            username=cfg["opnsense_username"],
            auth_type=cfg["opnsense_auth_type"],
            password=cfg.get("opnsense_password"),
            key_path=cfg["opnsense_key_path"],
        )
        output = ssh.run("sh -c 'pfctl -sTables 2>/dev/null'")
    except SSHError as exc:
        logger.warning("Could not list pf tables: %s", exc)
        return []
    except Exception:  # noqa: BLE001
        logger.exception("Could not list pf tables")
        return []
    alias = ""
    try:
        alias = str(get_blocking_settings(instance_id).get("blocking_alias") or "").strip().lower()
    except Exception:  # noqa: BLE001 - detection must not break on settings errors
        alias = ""
    tables: list[str] = []
    for line in output.splitlines():
        name = line.strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
            continue
        low = name.lower()
        # Never list our own blocking alias: it is not a foreign block list and
        # treating it as one would be a self-reference.
        if alias and low == alias:
            continue
        if any(pattern in low for pattern in _AUTO_TABLE_PATTERNS) and name not in tables:
            tables.append(name)
    return tables


def refresh_detected_tables(instance_id: str | None = None) -> list[str]:
    """Detect pf block tables on the firewall and persist them for the skip list."""
    tables = detect_block_tables(instance_id)
    try:
        set_detected_skip_tables(tables, instance_id)
    except Exception:  # noqa: BLE001 - detection must not break anything
        logger.exception("Could not persist detected block tables")
    return tables


def _already_blocked(ips: list[str], tables: list[str], instance_id: str | None = None) -> set[str]:
    """Return the subset of ``ips`` already present in one of the pf tables.

    Best-effort: any SSH problem returns an empty set (never blocks blocking).
    """
    if not ips or not tables:
        return set()
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance_id)
    if not cfg.get("opnsense_host"):
        return set()
    script = (
        "for ip in " + " ".join(ips) + "; do "
        "for t in " + " ".join(tables) + "; do "
        'pfctl -t "$t" -T test "$ip" >/dev/null 2>&1 && echo "$ip"; '
        "done; done"
    )
    try:
        ssh = OPNsenseSSH(
            host=cfg["opnsense_host"],
            port=cfg["opnsense_ssh_port"],
            username=cfg["opnsense_username"],
            auth_type=cfg["opnsense_auth_type"],
            password=cfg.get("opnsense_password"),
            key_path=cfg["opnsense_key_path"],
        )
        output = ssh.run("sh -c '" + script + "'")
    except SSHError as exc:
        logger.warning("Could not check existing block tables: %s", exc)
        return set()
    except Exception:  # noqa: BLE001
        logger.exception("Could not check existing block tables")
        return set()
    found = {line.strip() for line in output.splitlines() if line.strip()}
    return found & set(ips)


# Absolute upper bound for an escalated duration (hours). Purely a safety net to
# avoid timedelta overflow when a persistent offender keeps coming back.
_HARD_MAX_HOURS = 24 * 365 * 100  # ~100 years


def _record_blocked(
    ips: list[str],
    rule: str,
    source: str,
    ttl_hours: int,
    escalate: bool = False,
    max_hours: int = 0,
    instance_id: str | None = None,
) -> dict[str, dict]:
    if not ips:
        return {}
    db = get_database(resolve_instance_id(instance_id))
    now = datetime.now(timezone.utc)
    records: dict[str, dict] = {}
    for ip in ips:
        # The offence counter lives in ``block_counts`` so it survives the
        # expiry of a block (``prune_expired`` only deletes the ``blocked_ips``
        # row). Fall back to the legacy ``blocked_ips.hits`` for pre-existing
        # databases so escalation keeps accumulating after the upgrade.
        row = db.execute_read('SELECT "hits" FROM block_counts WHERE "ip" = ?', [ip]).fetchone()
        if row and row[0] is not None:
            hits = int(row[0]) + 1
        else:
            legacy = db.execute_read('SELECT "hits" FROM blocked_ips WHERE "ip" = ?', [ip]).fetchone()
            hits = (int(legacy[0]) if legacy and legacy[0] is not None else 0) + 1
        expires = None
        if ttl_hours and ttl_hours > 0:
            # Escalation doubles the duration on every repeat offence:
            # ttl, ttl*2, ttl*4, ttl*8 ... (hits 1, 2, 3, 4 ...).
            hours = ttl_hours * (2 ** (hits - 1)) if escalate else ttl_hours
            if max_hours and max_hours > 0:
                hours = min(hours, max_hours)
            hours = min(hours, _HARD_MAX_HOURS)
            expires = now + timedelta(hours=hours)
        db.execute_write(
            'INSERT INTO block_counts ("ip", "hits", "last_blocked_at") VALUES (?, ?, now()) '
            'ON CONFLICT ("ip") DO UPDATE SET "hits" = excluded."hits", "last_blocked_at" = now()',
            [ip, hits],
        )
        db.execute_write(
            'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at", "hits") '
            "VALUES (?, ?, ?, now(), ?, ?) ON CONFLICT (\"ip\") DO UPDATE SET "
            '"rule" = excluded."rule", "source" = excluded."source", '
            '"added_at" = excluded."added_at", "expires_at" = excluded."expires_at", '
            '"hits" = excluded."hits"',
            [ip, rule, source, expires, hits],
        )
        records[ip] = {"hits": hits, "expires_at": expires}
    return records


def apply_ips(ips: list[str], rule: str = "", source: str = "manual", reasons: dict | None = None, instance_id: str | None = None) -> dict:
    """Add the given IPs to the configured alias and apply the change."""
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if not alias:
        return {"ok": False, "error": "Aucun alias de blocage configuré", "added": []}
    nets = _whitelist_nets(cfg.get("blocking_whitelist", ""))
    nets += allowlist_nets(instance_id)

    wanted: list[str] = []
    for raw in ips:
        ip = str(raw or "").strip()
        if ip and ip not in wanted and _is_blockable(ip, nets):
            wanted.append(ip)
    if not wanted:
        return {"ok": True, "added": [], "skipped": [], "alias": alias, "message": "Aucune IP éligible"}

    already = _already_blocked(wanted, _skip_tables(cfg), instance_id)
    if already:
        logger.info("Skipping %d IP(s) already blocked by other tables", len(already))
        wanted = [ip for ip in wanted if ip not in already]
    if not wanted:
        return {
            "ok": True,
            "added": [],
            "skipped": sorted(already),
            "alias": alias,
            "message": "IP déjà bloquée par une autre liste",
        }

    if cfg.get("blocking_dry_run"):
        logger.info("Blocking dry-run: %d IP(s) would be blocked", len(wanted))
        return {
            "ok": True,
            "dry_run": True,
            "added": [],
            "would_block": wanted,
            "skipped": sorted(already),
            "alias": alias,
            "message": "Mode simulation : aucune IP n'a été bloquée",
        }

    api = _api(instance_id)
    if not api.is_configured():
        return {"ok": False, "error": "Clé API OPNsense non configurée", "added": []}

    try:
        row, content = api.get_alias_content(alias)
        if row is None:
            api.ensure_host_alias(alias, wanted)
            api.reconfigure()
            added = wanted
        else:
            existing = set(content)
            added = [ip for ip in wanted if ip not in existing]
            if added:
                api.set_alias_content(row, content + added)
                api.reconfigure()
    except APIError as exc:
        return {"ok": False, "error": str(exc), "added": []}

    records = _record_blocked(
        added,
        rule,
        source,
        int(cfg.get("blocking_ttl_hours", 0) or 0),
        escalate=bool(cfg.get("blocking_escalate", False)),
        max_hours=int(cfg.get("blocking_ttl_max_hours", 0) or 0),
        instance_id=instance_id,
    )
    # Only notify on the first block of an IP: a repeat offender (escalated TTL)
    # is blocked silently so a recurrence does not spam the mailbox again.
    first_time = [ip for ip in added if records.get(ip, {}).get("hits", 1) <= 1]
    if first_time and cfg.get("blocking_notify_email", True):
        try:
            filtered_reasons = {k: v for k, v in (reasons or {}).items() if k in first_time} or None
            send_block_notification(
                first_time,
                rule=rule,
                reasons=filtered_reasons,
                days=int(cfg.get("blocking_token_days", 7) or 7),
                details={ip: records[ip] for ip in first_time},
                instance_id=instance_id,
            )
        except Exception:  # noqa: BLE001 - never fail a block because of e-mail
            logger.exception("Could not send block notification")
    return {"ok": True, "added": added, "skipped": sorted(already), "alias": alias}


def block_alerts(alerts: list[dict], instance_id: str | None = None) -> dict:
    """Block source IPs of bruteforce/port-scan alerts (used in auto mode)."""
    ips = [
        a.get("src_ip", "")
        for a in alerts
        if a.get("rule") in _BLOCKABLE_RULES and a.get("src_ip")
    ]
    if not ips:
        return {"ok": True, "added": [], "message": "Aucune alerte concernée"}
    reasons: dict = {}
    for alert in alerts:
        ip = alert.get("src_ip")
        if alert.get("rule") in _BLOCKABLE_RULES and ip:
            detail = str(alert.get("message") or alert.get("title") or "").strip()
            if detail:
                reasons[ip] = detail
    return apply_ips(ips, rule="detection", source="auto", reasons=reasons, instance_id=instance_id)


def prune_expired(instance_id: str | None = None) -> int:
    """Remove expired IPs (TTL) from the alias. Returns the number removed."""
    cfg = get_blocking_settings(instance_id)
    ttl = int(cfg.get("blocking_ttl_hours", 0) or 0)
    if ttl <= 0:
        return 0
    db = get_database(resolve_instance_id(instance_id))
    rows = db.execute_read(
        'SELECT "ip" FROM blocked_ips WHERE "expires_at" IS NOT NULL AND "expires_at" < now()'
    ).fetchall()
    expired = [r[0] for r in rows]
    if not expired:
        return 0
    alias = str(cfg.get("blocking_alias") or "").strip()
    if alias:
        try:
            api = _api(instance_id)
            row, content = api.get_alias_content(alias)
            if row is not None:
                keep = [c for c in content if c not in set(expired)]
                if len(keep) != len(content):
                    api.set_alias_content(row, keep)
                    api.reconfigure()
        except APIError as exc:
            logger.warning("Could not prune alias: %s", exc)
    marks = ", ".join("?" for _ in expired)
    db.execute_write(f'DELETE FROM blocked_ips WHERE "ip" IN ({marks})', expired)
    return len(expired)


def unblock_ips(ips: list[str], instance_id: str | None = None) -> dict:
    """Remove the given IPs from the alias and from the blocked list."""
    targets = [str(ip or "").strip() for ip in ips if str(ip or "").strip()]
    if not targets:
        return {"ok": False, "error": "Aucune IP fournie"}
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if alias:
        api = _api(instance_id)
        if api.is_configured():
            try:
                row, content = api.get_alias_content(alias)
                if row is not None:
                    wanted = set(targets)
                    keep = [c for c in content if c not in wanted]
                    if len(keep) != len(content):
                        api.set_alias_content(row, keep)
                        api.reconfigure()
            except APIError as exc:
                return {"ok": False, "error": str(exc)}
    marks = ", ".join("?" for _ in targets)
    db = get_database(resolve_instance_id(instance_id))
    db.execute_write(f'DELETE FROM blocked_ips WHERE "ip" IN ({marks})', targets)
    # A manual unblock resets the escalation counter for these IPs.
    db.execute_write(f'DELETE FROM block_counts WHERE "ip" IN ({marks})', targets)
    return {"ok": True, "removed": targets}


def list_blocked(instance_id: str | None = None) -> list[dict]:
    rows = get_database(resolve_instance_id(instance_id)).execute_read(
        'SELECT "ip", "rule", "source", "added_at", "expires_at" FROM blocked_ips ORDER BY "added_at" DESC'
    ).fetchall()
    return [
        {"ip": r[0], "rule": r[1], "source": r[2], "added_at": r[3], "expires_at": r[4]}
        for r in rows
    ]


def reconcile_alias(instance_id: str | None = None) -> dict:
    """Re-add IPs recorded as blocked but missing from the firewall alias.

    Detects drift (e.g. after an OPNsense reboot cleared the alias) and re-applies
    the recorded, non-expired blocks. Never removes anything.
    """
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if not cfg.get("blocking_enabled") or not alias:
        return {"ok": True, "reconciled": 0}
    rows = get_database(resolve_instance_id(instance_id)).execute_read(
        'SELECT "ip" FROM blocked_ips WHERE "expires_at" IS NULL OR "expires_at" > now()'
    ).fetchall()
    desired = [r[0] for r in rows if r[0]]
    if not desired:
        return {"ok": True, "reconciled": 0}
    api = _api(instance_id)
    if not api.is_configured():
        return {"ok": False, "error": "Clé API OPNsense non configurée", "reconciled": 0}
    try:
        row, content = api.get_alias_content(alias)
        existing = set(content)
        missing = [ip for ip in desired if ip not in existing]
        if missing:
            if row is None:
                api.ensure_host_alias(alias, missing)
            else:
                api.set_alias_content(row, content + missing)
            api.reconfigure()
            logger.info("Reconciled %d missing IP(s) into alias '%s'", len(missing), alias)
        return {"ok": True, "reconciled": len(missing), "missing": missing, "alias": alias}
    except APIError as exc:
        return {"ok": False, "error": str(exc), "reconciled": 0}
