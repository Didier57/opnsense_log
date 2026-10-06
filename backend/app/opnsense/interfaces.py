"""Read access to synchronised OPNsense interfaces."""
from __future__ import annotations

from ..storage.database import get_database


def list_interfaces() -> list[dict]:
    db = get_database()
    rows = db.execute_read(
        "SELECT name, device, description, ipv4, ipv6, updated_at FROM opnsense_interfaces ORDER BY name"
    ).fetchall()
    keys = ["name", "device", "description", "ipv4", "ipv6", "updated_at"]
    return [dict(zip(keys, row)) for row in rows]


def device_to_name_map() -> dict[str, str]:
    return {i["device"]: i["description"] for i in list_interfaces() if i["device"]}
