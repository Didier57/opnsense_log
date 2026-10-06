"""Runtime-mutable OPNsense connection settings persisted in DuckDB.

Environment variables provide defaults; values saved from the UI override them
and survive container restarts (they live in the mounted data volume).
"""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database

_KEYS = [
    "opnsense_host",
    "opnsense_ssh_port",
    "opnsense_username",
    "opnsense_auth_type",
    "opnsense_password",
    "opnsense_key_path",
]


def get_opnsense_settings(mask_password: bool = True) -> dict:
    db = get_database()
    overrides: dict[str, str] = {}
    try:
        rows = db.execute_read('SELECT "key", "value" FROM app_settings').fetchall()
        overrides = {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        pass

    def value(key: str):
        return overrides.get(key, getattr(settings, key, ""))

    result = {
        "host": value("opnsense_host"),
        "port": int(value("opnsense_ssh_port") or 22),
        "username": value("opnsense_username"),
        "auth_type": value("opnsense_auth_type"),
        "key_path": value("opnsense_key_path"),
        "has_password": bool(value("opnsense_password")),
    }
    if not mask_password:
        result["password"] = value("opnsense_password")
    return result


def update_opnsense_settings(payload: dict) -> dict:
    db = get_database()
    mapping = {
        "host": "opnsense_host",
        "port": "opnsense_ssh_port",
        "username": "opnsense_username",
        "auth_type": "opnsense_auth_type",
        "password": "opnsense_password",
        "key_path": "opnsense_key_path",
    }
    for field, key in mapping.items():
        if field in payload and payload[field] is not None:
            db.execute_write(
                'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
                'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", "updated_at" = excluded."updated_at"',
                [key, str(payload[field])],
            )
    return get_opnsense_settings()
