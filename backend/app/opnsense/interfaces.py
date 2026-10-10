"""Read access to synchronised OPNsense interfaces."""
from __future__ import annotations

from ..instances import resolve_instance_id
from ..storage.database import get_database


def list_interfaces(instance_id: str | None = None) -> list[dict]:
    db = get_database(resolve_instance_id(instance_id))
    rows = db.execute_read(
        "SELECT name, device, description, ipv4, ipv6, updated_at FROM opnsense_interfaces ORDER BY name"
    ).fetchall()
    keys = ["name", "device", "description", "ipv4", "ipv6", "updated_at"]
    return [dict(zip(keys, row)) for row in rows]


def device_to_name_map(instance_id: str | None = None) -> dict[str, str]:
    return {
        i["device"]: i["description"]
        for i in list_interfaces(instance_id)
        if i["device"]
    }
