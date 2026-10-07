"""Automatic blocking: push alert source IPs into an OPNsense firewall alias.

Only bruteforce and port-scan alert source IPs are pushed. IPs that are private,
invalid, or in the configured whitelist are never blocked (avoids self-lockout).
"""
from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from ..storage.database import get_database
from ..detection.blocking_store import get_blocking_settings
from .api_client import APIError, OPNsenseAPI
from .settings_store import get_opnsense_settings

logger = logging.getLogger("opnsense.blocking")

_BLOCKABLE_RULES = {"bruteforce", "port_scan"}


def _api() -> OPNsenseAPI:
    cfg = get_opnsense_settings(mask_password=False)
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


def _record_blocked(ips: list[str], rule: str, source: str, ttl_hours: int) -> None:
    if not ips:
        return
    expires = None
    if ttl_hours and ttl_hours > 0:
        expires = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    db = get_database()
    for ip in ips:
        db.execute_write(
            'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
            "VALUES (?, ?, ?, now(), ?) ON CONFLICT (\"ip\") DO UPDATE SET "
            '"rule" = excluded."rule", "source" = excluded."source", '
            '"added_at" = excluded."added_at", "expires_at" = excluded."expires_at"',
            [ip, rule, source, expires],
        )


def apply_ips(ips: list[str], rule: str = "", source: str = "manual") -> dict:
    """Add the given IPs to the configured alias and apply the change."""
    cfg = get_blocking_settings()
    alias = str(cfg.get("blocking_alias") or "").strip()
    if not alias:
        return {"ok": False, "error": "Aucun alias de blocage configuré", "added": []}
    nets = _whitelist_nets(cfg.get("blocking_whitelist", ""))

    wanted: list[str] = []
    for raw in ips:
        ip = str(raw or "").strip()
        if ip and ip not in wanted and _is_blockable(ip, nets):
            wanted.append(ip)
    if not wanted:
        return {"ok": True, "added": [], "alias": alias, "message": "Aucune IP éligible"}

    api = _api()
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

    _record_blocked(added, rule, source, int(cfg.get("blocking_ttl_hours", 0) or 0))
    return {"ok": True, "added": added, "alias": alias}


def block_alerts(alerts: list[dict]) -> dict:
    """Block source IPs of bruteforce/port-scan alerts (used in auto mode)."""
    ips = [
        a.get("src_ip", "")
        for a in alerts
        if a.get("rule") in _BLOCKABLE_RULES and a.get("src_ip")
    ]
    if not ips:
        return {"ok": True, "added": [], "message": "Aucune alerte concernée"}
    return apply_ips(ips, rule="detection", source="auto")


def prune_expired() -> int:
    """Remove expired IPs (TTL) from the alias. Returns the number removed."""
    cfg = get_blocking_settings()
    ttl = int(cfg.get("blocking_ttl_hours", 0) or 0)
    if ttl <= 0:
        return 0
    db = get_database()
    rows = db.execute_read(
        'SELECT "ip" FROM blocked_ips WHERE "expires_at" IS NOT NULL AND "expires_at" < now()'
    ).fetchall()
    expired = [r[0] for r in rows]
    if not expired:
        return 0
    alias = str(cfg.get("blocking_alias") or "").strip()
    if alias:
        try:
            api = _api()
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


def list_blocked() -> list[dict]:
    rows = get_database().execute_read(
        'SELECT "ip", "rule", "source", "added_at", "expires_at" FROM blocked_ips ORDER BY "added_at" DESC'
    ).fetchall()
    return [
        {"ip": r[0], "rule": r[1], "source": r[2], "added_at": r[3], "expires_at": r[4]}
        for r in rows
    ]
