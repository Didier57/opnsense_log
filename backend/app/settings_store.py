"""Runtime-mutable application settings persisted in DuckDB.

Environment variables provide defaults; values saved from the web UI override
them and survive container restarts (they live in the mounted data volume).
Currently used for the log retention policy and a few display options.
"""
from __future__ import annotations

from .config import settings
from .storage.database import get_database

# Keys here match the application Settings field names (and therefore the
# environment variable names), so the web UI and .env share one vocabulary.
_KEYS = [
    "log_retention_days",
    "retention_check_interval_min",
    "display_timezone",
]


def _read_overrides() -> dict[str, str]:
    try:
        db = get_database()
        rows = db.execute_read('SELECT "key", "value" FROM app_settings').fetchall()
        return {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        return {}


def _as_int(value: object, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def get_app_settings() -> dict:
    overrides = _read_overrides()

    def value(key: str):
        return overrides.get(key, getattr(settings, key, ""))

    return {
        "log_retention_days": _as_int(value("log_retention_days"), settings.log_retention_days),
        "retention_check_interval_min": max(
            5, _as_int(value("retention_check_interval_min"), settings.retention_check_interval_min)
        ),
        "display_timezone": str(value("display_timezone") or settings.display_timezone),
    }


def update_app_settings(payload: dict) -> dict:
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
    return get_app_settings()
