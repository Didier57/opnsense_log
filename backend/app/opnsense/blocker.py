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


def _reconfigure(api: OPNsenseAPI) -> None:
    """Apply an alias change on the firewall (trigger the filter reload).

    The alias content is already persisted by the preceding ``setItem`` call;
    this only triggers the reload that makes it effective. A reload can be slow,
    so a timeout must not fail the whole operation — otherwise the IP would be
    in the firewall alias but never recorded in the app (leaving the alias and
    the app out of sync). We log and carry on.
    """
    try:
        api.reconfigure()
    except APIError as exc:
        logger.warning("Filter reload not confirmed: %s", exc)


def _ha_sync(api: OPNsenseAPI) -> None:
    """Trigger the OPNsense HA configuration sync on the master node.

    The alias is only written on the master; this asks OPNsense to replicate the
    configuration (aliases included, when selected) to the HA peers. Best-effort:
    a failed sync never fails the operation performed on the master.
    """
    try:
        api.ha_sync()
    except APIError as exc:
        logger.warning("HA configuration sync not confirmed: %s", exc)


def _cluster_targets(instance_id: str | None) -> tuple[list[str], str, bool]:
    """Instances whose firewall alias must be edited for an HA-aware change.

    Inside an HA cluster the alias is written directly on every member (master
    and slaves) and the master's OPNsense configuration sync is also triggered.
    Returns ``(member_ids, master_id, in_cluster)``.
    """
    base = resolve_instance_id(instance_id)
    try:
        from .settings_store import ha_cluster_ids, ha_cluster_master

        master = ha_cluster_master(instance_id)
        members = ha_cluster_ids(instance_id)
    except Exception:  # noqa: BLE001 - never break blocking on HA lookup
        master = None
        members = []
    if master and len(members) > 1:
        return members, master, True
    return [base or ""], (base or ""), False


def _cluster_member_ids(instance_id: str | None) -> list[str]:
    """Instance ids whose ``blocked_ips`` rows belong to the same HA cluster.

    Blocks are recorded only in the database of the instance that triggered them
    (typically the node running detection), so listing/reconciling must aggregate
    every HA member's rows. Outside a cluster this is the instance itself.
    """
    members, _master, in_cluster = _cluster_targets(instance_id)
    if in_cluster:
        return members
    return [resolve_instance_id(instance_id)]


def _cluster_blocked_rows(
    instance_id: str | None, *, exclude_expired: bool = False
) -> list[tuple]:
    """Union of the ``blocked_ips`` rows across every HA cluster member database."""
    sql = 'SELECT "ip", "rule", "source", "added_at", "expires_at" FROM blocked_ips'
    if exclude_expired:
        sql += ' WHERE "expires_at" IS NULL OR "expires_at" > now()'
    seen: dict[str, tuple] = {}
    for member in _cluster_member_ids(instance_id):
        rows = get_database(member).execute_read(sql).fetchall()
        for row in rows:
            ip = row[0]
            if not ip:
                continue
            prev = seen.get(ip)
            if prev is None or (row[3] and (prev[3] is None or row[3] > prev[3])):
                seen[ip] = row
    return list(seen.values())


def _alias_remove_nodes(instance_id: str | None, alias: str, ips) -> list[str]:
    """Remove ``ips`` from the alias on every HA member node. Best-effort."""
    wanted = set(ips)
    if not wanted:
        return []
    members, master_id, in_cluster = _cluster_targets(instance_id)
    nodes = members if in_cluster else [instance_id]
    touched: list[str] = []
    for node in nodes:
        try:
            api = _api(node)
            if not api.is_configured():
                continue
            row, content = api.get_alias_content(alias)
            if row is None:
                continue
            keep = [c for c in content if c not in wanted]
            if len(keep) != len(content):
                api.set_alias_content(row, keep)
                _reconfigure(api)
                touched.append(node or "")
        except APIError as exc:
            logger.warning("Could not update alias on %s: %s", node, exc)
    if in_cluster and nodes:
        _ha_sync(_api(master_id))
    return touched


def _alias_add(api: OPNsenseAPI, alias: str, wanted: list[str]) -> tuple[list[str], list[str]]:
    """Add ``wanted`` IPs to a node's alias; returns ``(added, present)``."""
    row, content = api.get_alias_content(alias)
    if row is None:
        api.ensure_host_alias(alias, wanted)
        _reconfigure(api)
        return list(wanted), []
    existing = set(content)
    added = [ip for ip in wanted if ip not in existing]
    present = [ip for ip in wanted if ip in existing]
    if added:
        api.set_alias_content(row, content + added)
        _reconfigure(api)
    return added, present


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

# When an IP we already block keeps scanning, its TTL is renewed (doubled) this
# many minutes before the current block expires, so an active offender is never
# freed. If it stops scanning, the block simply expires.
_ESCALATE_LEAD_MIN = 5


def _due_for_escalation(ips: list[str], instance_id: str | None = None) -> list[str]:
    """Blocked IPs whose current block is about to expire (within the lead time)."""
    if not ips:
        return []
    db = get_database(resolve_instance_id(instance_id))
    marks = ", ".join("?" for _ in ips)
    cutoff = datetime.now(timezone.utc) + timedelta(minutes=_ESCALATE_LEAD_MIN)
    rows = db.execute_read(
        f'SELECT "ip" FROM blocked_ips WHERE "ip" IN ({marks}) '
        'AND "expires_at" IS NOT NULL AND "expires_at" <= ?',
        [*ips, cutoff],
    ).fetchall()
    return [r[0] for r in rows]


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

    members, master_id, in_cluster = _cluster_targets(instance_id)
    if not members:
        return {"ok": False, "error": "Aucune instance cible", "added": []}
    master_api = _api(master_id)
    if not master_api.is_configured():
        return {"ok": False, "error": "Clé API OPNsense non configurée", "added": []}

    try:
        added, present = _alias_add(master_api, alias, wanted)
    except APIError as exc:
        return {"ok": False, "error": str(exc), "added": []}

    # In an HA cluster, propagate the change to the other nodes directly and
    # also trigger the master's OPNsense configuration sync (the sync only
    # covers aliases when "Aliases" is selected in the HA settings).
    if in_cluster:
        for member in members:
            if member == master_id:
                continue
            try:
                peer = _api(member)
                if peer.is_configured():
                    _alias_add(peer, alias, wanted)
                    logger.info("HA: block propagated directly to %s", member)
            except APIError as exc:
                logger.warning("HA: could not update alias on %s: %s", member, exc)
        _ha_sync(master_api)

    ttl = int(cfg.get("blocking_ttl_hours", 0) or 0)
    escalate = bool(cfg.get("blocking_escalate", False))
    max_hours = int(cfg.get("blocking_ttl_max_hours", 0) or 0)
    records = _record_blocked(
        added, rule, source, ttl, escalate=escalate, max_hours=max_hours, instance_id=instance_id
    )
    # An IP we already block keeps scanning: renew (double) its TTL shortly
    # before the current block expires, so an active offender is never freed.
    if escalate and ttl > 0 and present:
        due = _due_for_escalation(present, instance_id)
        if due:
            records.update(
                _record_blocked(
                    due, rule, source, ttl, escalate=True, max_hours=max_hours, instance_id=instance_id
                )
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


def block_permanently(ips: list[str], instance_id: str | None = None) -> dict:
    """Mark the given IPs as permanently blocked (never expiring).

    The block's ``expires_at`` is cleared in every HA member database so
    ``prune_expired`` never removes it, and the IPs are (re)added to the alias
    on every cluster node. Only a manual "Retirer" removes them.
    """
    targets = [str(ip or "").strip() for ip in ips if str(ip or "").strip()]
    if not targets:
        return {"ok": False, "error": "Aucune IP fournie"}
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    # Clear the expiry in every HA member so the block survives pruning. The
    # upsert also records a block for an IP that was only present in the alias
    # (orphan) without an application row.
    for member in _cluster_member_ids(instance_id):
        mdb = get_database(member)
        for ip in targets:
            mdb.execute_write(
                'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
                "VALUES (?, 'manual', 'manual', now(), NULL) "
                'ON CONFLICT ("ip") DO UPDATE SET "expires_at" = NULL',
                [ip],
            )
    # Make sure the IPs are present in the alias on every node.
    if alias:
        members, master_id, in_cluster = _cluster_targets(instance_id)
        master_api = _api(master_id)
        if master_api.is_configured():
            try:
                _alias_add(master_api, alias, targets)
            except APIError as exc:
                return {"ok": False, "error": str(exc), "updated": []}
            if in_cluster:
                for member in members:
                    if member == master_id:
                        continue
                    try:
                        peer = _api(member)
                        if peer.is_configured():
                            _alias_add(peer, alias, targets)
                            logger.info("HA: permanent block propagated directly to %s", member)
                    except APIError as exc:
                        logger.warning("HA: could not update alias on %s: %s", member, exc)
                _ha_sync(master_api)
    return {"ok": True, "updated": targets, "alias": alias}


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
    members = _cluster_member_ids(instance_id)
    expired: set[str] = set()
    for member in members:
        rows = get_database(member).execute_read(
            'SELECT "ip" FROM blocked_ips WHERE "expires_at" IS NOT NULL AND "expires_at" < now()'
        ).fetchall()
        expired.update(r[0] for r in rows if r[0])
    if not expired:
        return 0
    alias = str(cfg.get("blocking_alias") or "").strip()
    if alias:
        _alias_remove_nodes(instance_id, alias, expired)
    marks = ", ".join("?" for _ in expired)
    values = list(expired)
    for member in members:
        get_database(member).execute_write(
            f'DELETE FROM blocked_ips WHERE "ip" IN ({marks})', values
        )
    return len(expired)


def unblock_ips(ips: list[str], instance_id: str | None = None) -> dict:
    """Remove the given IPs from the alias and from the blocked list."""
    targets = [str(ip or "").strip() for ip in ips if str(ip or "").strip()]
    if not targets:
        return {"ok": False, "error": "Aucune IP fournie"}
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if alias:
        members, master_id, in_cluster = _cluster_targets(instance_id)
        api = _api(master_id)
        if api.is_configured():
            wanted = set(targets)
            try:
                row, content = api.get_alias_content(alias)
                if row is not None:
                    keep = [c for c in content if c not in wanted]
                    if len(keep) != len(content):
                        api.set_alias_content(row, keep)
                        _reconfigure(api)
            except APIError as exc:
                return {"ok": False, "error": str(exc)}
            # Propagate the removal to the other HA nodes directly and also
            # trigger the master's OPNsense configuration sync.
            if in_cluster:
                for member in members:
                    if member == master_id:
                        continue
                    try:
                        peer = _api(member)
                        if not peer.is_configured():
                            continue
                        prow, pcontent = peer.get_alias_content(alias)
                        if prow is not None:
                            pkeep = [c for c in pcontent if c not in wanted]
                            if len(pkeep) != len(pcontent):
                                peer.set_alias_content(prow, pkeep)
                                _reconfigure(peer)
                                logger.info("HA: unblock propagated directly to %s", member)
                    except APIError as exc:
                        logger.warning("HA: could not update alias on %s: %s", member, exc)
                _ha_sync(api)
    marks = ", ".join("?" for _ in targets)
    # Clear the record from every HA member so the (shared) blocked list stays
    # consistent whichever node the unblock is triggered from.
    for member in _cluster_member_ids(instance_id):
        mdb = get_database(member)
        mdb.execute_write(f'DELETE FROM blocked_ips WHERE "ip" IN ({marks})', targets)
        # A manual unblock resets the escalation counter for these IPs.
        mdb.execute_write(f'DELETE FROM block_counts WHERE "ip" IN ({marks})', targets)
    return {"ok": True, "removed": targets}


def list_blocked(instance_id: str | None = None) -> list[dict]:
    rows = _cluster_blocked_rows(instance_id)
    rows.sort(key=lambda r: (r[3] is not None, r[3]), reverse=True)
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
    # In an HA cluster the recorded blocks may live in any member's database
    # (e.g. the master), so the desired set is the cluster-wide union.
    desired = [
        r[0] for r in _cluster_blocked_rows(instance_id, exclude_expired=True) if r[0]
    ]
    if not desired:
        return {"ok": True, "reconciled": 0}
    members, master_id, in_cluster = _cluster_targets(instance_id)
    api = _api(master_id if in_cluster else instance_id)
    if not api.is_configured():
        return {"ok": False, "error": "Clé API OPNsense non configurée", "reconciled": 0}
    try:
        added, _present = _alias_add(api, alias, desired)
    except APIError as exc:
        return {"ok": False, "error": str(exc), "reconciled": 0}
    if in_cluster:
        for member in members:
            if member == master_id:
                continue
            try:
                peer = _api(member)
                if peer.is_configured():
                    _alias_add(peer, alias, desired)
                    logger.info("HA: reconcile propagated directly to %s", member)
            except APIError as exc:
                logger.warning("HA: could not reconcile alias on %s: %s", member, exc)
        _ha_sync(api)
    if added:
        logger.info("Reconciled %d missing IP(s) into alias '%s'", len(added), alias)
    return {"ok": True, "reconciled": len(added), "missing": added, "alias": alias}


def alias_ips(instance_id: str | None = None) -> dict:
    """Return the IPs currently stored in the configured firewall alias.

    Lets the UI display the real alias content, including entries that are no
    longer tracked as blocked (orphans left by an earlier failure).
    """
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if not alias:
        return {"ok": True, "alias": "", "configured": False, "ips": []}
    api = _api(instance_id)
    if not api.is_configured():
        return {
            "ok": False,
            "alias": alias,
            "configured": False,
            "ips": [],
            "error": "Clé API OPNsense non configurée",
        }
    try:
        row, content = api.get_alias_content(alias)
    except APIError as exc:
        return {"ok": False, "alias": alias, "configured": True, "ips": [], "error": str(exc)}
    return {"ok": True, "alias": alias, "configured": True, "ips": content, "exists": row is not None}


def clean_alias_orphans(instance_id: str | None = None) -> dict:
    """Remove from the alias the IPs that are no longer tracked as blocked.

    ``reconcile_alias`` only ADDS missing IPs; this removes the leftovers (an IP
    still present in the firewall alias while its ``blocked_ips`` row is gone).
    Only entries absent from the app's blocked list are removed, so a tracked
    (and possibly not-yet-expired) block is never touched.
    """
    cfg = get_blocking_settings(instance_id)
    alias = str(cfg.get("blocking_alias") or "").strip()
    if not alias:
        return {"ok": False, "error": "Aucun alias de blocage configuré", "removed": []}
    members, master_id, in_cluster = _cluster_targets(instance_id)
    api = _api(master_id if in_cluster else instance_id)
    if not api.is_configured():
        return {"ok": False, "error": "Clé API OPNsense non configurée", "removed": []}
    # Orphan = present in the alias but absent from the cluster-wide blocked set.
    tracked = {r[0] for r in _cluster_blocked_rows(instance_id) if r[0]}
    nodes = members if in_cluster else [instance_id]
    removed: list[str] = []
    try:
        for node in nodes:
            if node == master_id:
                node_api = api
            else:
                node_api = _api(node)
            if not node_api.is_configured():
                continue
            row, content = node_api.get_alias_content(alias)
            if row is None:
                continue
            orphans = [ip for ip in content if ip not in tracked]
            if orphans:
                keep = [ip for ip in content if ip in tracked]
                node_api.set_alias_content(row, keep)
                _reconfigure(node_api)
                removed.extend(orphans)
    except APIError as exc:
        return {"ok": False, "error": str(exc), "removed": removed}
    if removed:
        logger.info("Removed %d orphan IP(s) from alias '%s'", len(removed), alias)
    if in_cluster:
        _ha_sync(api)
    return {"ok": True, "removed": removed, "alias": alias}
