"""Runtime-mutable OPNsense connection settings persisted in DuckDB.

Environment variables provide defaults; values saved from the web UI override
them and survive container restarts (they live in the mounted data volume).
"""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database

# Keys here match the application Settings field names (and therefore the
# environment variable names), so the web UI and .env share one vocabulary.
_KEYS = [
    "opnsense_host",
    "opnsense_ssh_port",
    "opnsense_username",
    "opnsense_auth_type",
    "opnsense_password",
    "opnsense_key_path",
    "opnsense_sync_enabled",
    "opnsense_sync_interval_min",
    "opnsense_import_on_start",
    "opnsense_api_key",
    "opnsense_api_secret",
    "opnsense_api_port",
]


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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
        "opnsense_host": value("opnsense_host"),
        "opnsense_ssh_port": int(value("opnsense_ssh_port") or 22),
        "opnsense_username": value("opnsense_username"),
        "opnsense_auth_type": value("opnsense_auth_type"),
        "opnsense_key_path": value("opnsense_key_path"),
        "opnsense_sync_enabled": _as_bool(value("opnsense_sync_enabled")),
        "opnsense_sync_interval_min": int(value("opnsense_sync_interval_min") or 30),
        "opnsense_import_on_start": _as_bool(value("opnsense_import_on_start")),
        "has_password": bool(value("opnsense_password")),
        "has_api_key": bool(value("opnsense_api_key")),
        "has_api_secret": bool(value("opnsense_api_secret")),
        "opnsense_api_port": int(value("opnsense_api_port") or 443),
    }
    if not mask_password:
        result["opnsense_password"] = value("opnsense_password")
        result["opnsense_api_key"] = value("opnsense_api_key")
        result["opnsense_api_secret"] = value("opnsense_api_secret")
    return result


def update_opnsense_settings(payload: dict) -> dict:
    db = get_database()
    for key in _KEYS:
        if key in payload and payload[key] is not None:
            value = payload[key]
            if isinstance(value, bool):
                value = "true" if value else "false"
            db.execute_write(
                'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
                'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", "updated_at" = excluded."updated_at"',
                [key, str(value)],
            )
    return get_opnsense_settings()
