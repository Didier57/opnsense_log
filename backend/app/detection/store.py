"""Runtime-mutable detection engine settings persisted in DuckDB.

Environment variables provide defaults; values saved from the web UI override
them and survive container restarts (they live in the mounted data volume).
"""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database

_INT_KEYS = [
    "detection_interval_sec",
    "detection_portscan_ports",
    "detection_portscan_window_sec",
    "detection_bruteforce_count",
    "detection_bruteforce_window_sec",
    "detection_spike_threshold",
    "detection_spike_window_sec",
]
_BOOL_KEYS = ["detection_enabled"]
_KEYS = _BOOL_KEYS + _INT_KEYS

# (key, minimum) so a user cannot disable detection by entering an absurd value.
_MINIMUMS = {
    "detection_interval_sec": 15,
    "detection_portscan_ports": 2,
    "detection_portscan_window_sec": 5,
    "detection_bruteforce_count": 2,
    "detection_bruteforce_window_sec": 5,
    "detection_spike_threshold": 1,
    "detection_spike_window_sec": 5,
}


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


def get_detection_settings() -> dict:
    overrides = _overrides()

    def value(key: str):
        return overrides.get(key, getattr(settings, key))

    result: dict = {}
    for key in _BOOL_KEYS:
        result[key] = _as_bool(value(key))
    for key in _INT_KEYS:
        default = int(getattr(settings, key))
        result[key] = _as_int(value(key), default, _MINIMUMS[key])
    return result


def update_detection_settings(payload: dict) -> dict:
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
    return get_detection_settings()
