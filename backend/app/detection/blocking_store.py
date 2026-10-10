"""Runtime-mutable automatic-blocking settings persisted in DuckDB."""
from __future__ import annotations

from ..config import settings
from ..instances import resolve_instance_id
from ..storage.database import get_database

_STR_KEYS = [
    "blocking_alias",
    "blocking_mode",
    "blocking_whitelist",
    "blocking_skip_tables",
    "blocking_skip_tables_detected",
]
_BOOL_KEYS = ["blocking_enabled", "blocking_notify_email", "blocking_dry_run", "blocking_escalate"]
_INT_KEYS = ["blocking_ttl_hours", "blocking_token_days", "blocking_ttl_max_hours"]
_MINIMUMS = {"blocking_ttl_hours": 0, "blocking_token_days": 1, "blocking_ttl_max_hours": 0}
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


def _overrides(instance_id: str | None = None) -> dict[str, str]:
    try:
        rows = (
            get_database(resolve_instance_id(instance_id))
            .execute_read('SELECT "key", "value" FROM app_settings')
            .fetchall()
        )
        return {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        return {}


def get_blocking_settings(instance_id: str | None = None) -> dict:
    overrides = _overrides(instance_id)

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


def update_blocking_settings(payload: dict, instance_id: str | None = None) -> dict:
    db = get_database(resolve_instance_id(instance_id))
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
    return get_blocking_settings(instance_id=instance_id)


def set_detected_skip_tables(names: list[str], instance_id: str | None = None) -> list[str]:
    """Persist the pf tables auto-detected on the firewall (not user-editable)."""
    clean: list[str] = []
    for name in names:
        name = str(name or "").strip()
        if name and name not in clean:
            clean.append(name)
    get_database(resolve_instance_id(instance_id)).execute_write(
        'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
        'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", "updated_at" = excluded."updated_at"',
        ["blocking_skip_tables_detected", ", ".join(clean)],
    )
    return clean
