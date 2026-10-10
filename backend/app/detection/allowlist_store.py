"""Managed allowlist of trusted IPs/networks.

Entries are honored by both the detection engine (no alert is raised for a
trusted source) and the automatic blocker (trusted IPs are never blocked).  This
is the single source of truth: the legacy free-text ``blocking_whitelist``
setting is imported here once (see :func:`migrate_legacy_whitelist`) and then
cleared.
"""
from __future__ import annotations

import ipaddress

from ..instances import resolve_instance_id
from ..storage.database import get_database
from .blocking_store import get_blocking_settings, update_blocking_settings


def _normalize(token: str) -> str | None:
    """Return a canonical IP/CIDR string, or ``None`` when invalid."""
    token = str(token or "").strip()
    if not token:
        return None
    try:
        if "/" in token:
            return str(ipaddress.ip_network(token, strict=False))
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def list_allowlist(instance_id: str | None = None) -> list[dict]:
    rows = get_database(resolve_instance_id(instance_id)).execute_read(
        'SELECT "ip", "note", "added_at" FROM allowlist_ips ORDER BY "added_at" DESC'
    ).fetchall()
    return [{"ip": r[0], "note": r[1] or "", "added_at": r[2]} for r in rows]


def add_allowlist(entries: list[str], note: str = "", instance_id: str | None = None) -> list[str]:
    """Validate and store entries (IP or CIDR). Returns the added tokens."""
    tokens: list[str] = []
    for entry in entries or []:
        norm = _normalize(entry)
        if norm and norm not in tokens:
            tokens.append(norm)
    if not tokens:
        return []
    db = get_database(resolve_instance_id(instance_id))
    note = str(note or "")
    for ip in tokens:
        db.execute_write(
            'INSERT INTO allowlist_ips ("ip", "note", "added_at") VALUES (?, ?, now()) '
            'ON CONFLICT ("ip") DO UPDATE SET "note" = excluded."note"',
            [ip, note],
        )
    return tokens


def remove_allowlist(entries: list[str], instance_id: str | None = None) -> list[str]:
    """Remove entries. Returns the tokens that were targeted (best effort)."""
    targets: list[str] = []
    for entry in entries or []:
        norm = _normalize(entry)
        if norm and norm not in targets:
            targets.append(norm)
    if not targets:
        return []
    marks = ", ".join("?" for _ in targets)
    get_database(resolve_instance_id(instance_id)).execute_write(
        f'DELETE FROM allowlist_ips WHERE "ip" IN ({marks})', targets
    )
    return targets


def allowlist_nets(instance_id: str | None = None) -> list:
    """Every allowlist entry as an ``ip_network`` (invalid rows skipped)."""
    rows = get_database(resolve_instance_id(instance_id)).execute_read(
        'SELECT "ip" FROM allowlist_ips'
    ).fetchall()
    nets = []
    for row in rows:
        try:
            nets.append(ipaddress.ip_network(str(row[0]), strict=False))
        except ValueError:
            continue
    return nets


def is_allowlisted(ip: str, instance_id: str | None = None) -> bool:
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(addr in net for net in allowlist_nets(instance_id))


def migrate_legacy_whitelist(instance_id: str | None = None) -> list[str]:
    """Import the legacy ``blocking_whitelist`` text into the managed allowlist.

    Runs once: valid IP/CIDR tokens are added to ``allowlist_ips`` and the
    setting is cleared so trusted sources live in a single place. Returns the
    tokens that were imported.
    """
    try:
        legacy = str(get_blocking_settings(instance_id).get("blocking_whitelist") or "").strip()
    except Exception:  # noqa: BLE001 - migration must never break startup
        return []
    if not legacy:
        return []
    tokens = legacy.replace(",", " ").split()
    added = add_allowlist(tokens, note="importé de l'ancienne liste blanche", instance_id=instance_id)
    try:
        update_blocking_settings({"blocking_whitelist": ""}, instance_id=instance_id)
    except Exception:  # noqa: BLE001
        pass
    return added
