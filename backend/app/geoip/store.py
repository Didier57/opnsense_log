"""Runtime GeoIP settings (shared ``app_settings`` table).

The licence key is never returned in clear text (only a ``has_license_key``
flag) and is never logged.
"""
from __future__ import annotations

from ..config import settings

_STR_KEYS = ["geoip_account_id", "geoip_license_key"]
_BOOL_KEYS = ["geoip_enabled"]


def _read_overrides() -> dict:
    from ..storage.database import get_database

    result: dict[str, str] = {}
    try:
        rows = get_database().execute_read('SELECT "key", "value" FROM app_settings').fetchall()
    except Exception:  # noqa: BLE001
        return result
    for key, value in rows:
        result[key] = value
    return result


def _as_bool(value, default: bool) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_geo_settings(mask_key: bool = True) -> dict:
    overrides = _read_overrides()
    enabled = _as_bool(overrides.get("geoip_enabled"), settings.geoip_enabled)
    account_id = overrides.get("geoip_account_id", settings.geoip_account_id) or ""
    license_key = overrides.get("geoip_license_key", settings.geoip_license_key) or ""
    return {
        "geoip_enabled": enabled,
        "geoip_account_id": account_id,
        "geoip_license_key": "" if mask_key else license_key,
        "has_license_key": bool(license_key),
    }


def update_geo_settings(payload: dict) -> dict:
    from ..storage.database import get_database

    updates: list[tuple[str, str]] = []
    for key in _BOOL_KEYS:
        if payload.get(key) is not None:
            updates.append((key, "true" if payload[key] else "false"))
    for key in _STR_KEYS:
        if payload.get(key) is not None:
            value = str(payload[key])
            # An empty (or masked) licence key keeps the stored one.
            if key == "geoip_license_key" and value in ("", "***"):
                continue
            updates.append((key, value))

    db = get_database()
    for key, value in updates:
        db.execute_write(
            'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
            'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", '
            '"updated_at" = excluded."updated_at"',
            [key, value],
        )
    return get_geo_settings(mask_key=True)


def set_geo_credentials(account_id: str = "", license_key: str = "") -> None:
    """Store credentials discovered in the OPNsense configuration.

    Only non-empty values are written so a manual UI entry is not wiped when
    OPNsense exposes nothing.
    """
    payload: dict = {}
    if account_id:
        payload["geoip_account_id"] = account_id
    if license_key:
        payload["geoip_license_key"] = license_key
    if payload:
        update_geo_settings(payload)
