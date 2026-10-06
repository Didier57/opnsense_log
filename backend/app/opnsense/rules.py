"""Read access to synchronised OPNsense rules and their history."""
from __future__ import annotations

from ..storage.database import get_database


def list_rules() -> list[dict]:
    db = get_database()
    rows = db.execute_read(
        """
        SELECT rule_id, rule_number, description, interface, action, direction,
               protocol, source, destination, enabled, updated_at
        FROM opnsense_rules ORDER BY description
        """
    ).fetchall()
    keys = [
        "rule_id", "rule_number", "description", "interface", "action", "direction",
        "protocol", "source", "destination", "enabled", "updated_at",
    ]
    return [dict(zip(keys, row)) for row in rows]


def get_rule(rule_id: str) -> dict | None:
    db = get_database()
    row = db.execute_read(
        "SELECT rule_id, description, interface, action, direction, protocol, "
        "source, destination, enabled, updated_at FROM opnsense_rules WHERE rule_id = ?",
        [rule_id],
    ).fetchone()
    if row is None:
        return None
    keys = [
        "rule_id", "description", "interface", "action", "direction",
        "protocol", "source", "destination", "enabled", "updated_at",
    ]
    return dict(zip(keys, row))


def get_rule_history(rule_id: str) -> list[dict]:
    db = get_database()
    rows = db.execute_read(
        "SELECT valid_from, description, interface, action FROM rule_history "
        "WHERE rule_id = ? ORDER BY valid_from",
        [rule_id],
    ).fetchall()
    keys = ["valid_from", "description", "interface", "action"]
    return [dict(zip(keys, row)) for row in rows]
