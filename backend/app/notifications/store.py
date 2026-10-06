"""Runtime-mutable SMTP notification settings persisted in DuckDB."""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database

_STR_KEYS = [
    "smtp_host",
    "smtp_security",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    "smtp_to",
]
_INT_KEYS = ["smtp_port"]
_BOOL_KEYS = ["smtp_enabled"]
_KEYS = _BOOL_KEYS + _INT_KEYS + _STR_KEYS

_SECURITY = {"none", "ssl", "starttls"}


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_smtp_settings(mask_password: bool = True) -> dict:
    try:
        rows = get_database().execute_read('SELECT "key", "value" FROM app_settings').fetchall()
        overrides = {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        overrides = {}

    def value(key: str):
        return overrides.get(key, getattr(settings, key, ""))

    security = str(value("smtp_security") or "starttls").lower()
    if security not in _SECURITY:
        security = "starttls"
    try:
        port = int(value("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587

    result = {
        "smtp_enabled": _as_bool(value("smtp_enabled")),
        "smtp_host": str(value("smtp_host") or ""),
        "smtp_port": port,
        "smtp_security": security,
        "smtp_username": str(value("smtp_username") or ""),
        "smtp_from_email": str(value("smtp_from_email") or ""),
        "smtp_from_name": str(value("smtp_from_name") or ""),
        "smtp_to": str(value("smtp_to") or ""),
        "has_password": bool(value("smtp_password")),
    }
    if not mask_password:
        result["smtp_password"] = str(value("smtp_password") or "")
    return result


def update_smtp_settings(payload: dict) -> dict:
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
    return get_smtp_settings()
