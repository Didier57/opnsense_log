"""Runtime-mutable automatic-blocking settings persisted in DuckDB."""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database

_STR_KEYS = ["blocking_alias", "blocking_mode", "blocking_whitelist"]
_BOOL_KEYS = ["blocking_enabled"]
_INT_KEYS = ["blocking_ttl_hours"]
_MINIMUMS = {"blocking_ttl_hours": 0}
_KEYS = _BOOL_KEYS + _STR_KEYS + _INT_KEYS


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_int(value: object, default: int, minimum: int) -> int:
    try:
        return max(minimum, int(str(value).strip()))
    except (TypeError, ValueError):
        return default


def _overrides() -> dict[str, str]:
    try:
        rows = get_database().execute_read('SELECT "key", "value" FROM app_settings').fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        return {}


def get_blocking_settings() -> dict:
    overrides = _overrides()

    def value(key: str):
        return overrides.get(key, getattr(settings, key))

    result: dict = {key: _as_bool(value(key)) for key in _BOOL_KEYS}
    for key in _STR_KEYS:
        result[key] = str(value(key) or "")
    mode = result.get("blocking_mode", "manual").strip().lower()
    result["blocking_mode"] = mode if mode in {"manual", "auto"} else "manual"
    for key in _INT_KEYS:
        result[key] = _as_int(value(key), int(getattr(settings, key)), _MINIMUMS[key])
    return result


def update_blocking_settings(payload: dict) -> dict:
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
    return get_blocking_settings()
