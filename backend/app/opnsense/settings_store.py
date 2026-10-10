"""Runtime-mutable OPNsense connection settings persisted in DuckDB.

Environment variables provide defaults; values saved from the web UI override
them and survive container restarts (they live in the mounted data volume).
"""
from __future__ import annotations

from ..config import settings
from ..instances import resolve_instance_id
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
    "opnsense_import_wait_syslog_sec",
    "opnsense_import_max_days",
    "opnsense_api_key",
    "opnsense_api_secret",
    "opnsense_api_scheme",
    "opnsense_api_port",
    "opnsense_ha_enabled",
    "opnsense_ha_master",
]


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def get_opnsense_settings(
    mask_password: bool = True,
    instance_id: str | None = None,
    _inherit_ha: bool = True,
) -> dict:
    resolved = resolve_instance_id(instance_id)
    db = get_database(resolved)
    overrides: dict[str, str] = {}
    try:
        rows = db.execute_read('SELECT "key", "value" FROM app_settings').fetchall()
        overrides = {r[0]: r[1] for r in rows}
    except Exception:  # noqa: BLE001
        pass

    def value(key: str):
        return overrides.get(key, getattr(settings, key, ""))

    # High availability: OPNsense replicates the config (including the API
    # keys) from the master node to the backup, so a key managed per node gets
    # overwritten. When HA is enabled, this instance therefore uses the API
    # key/secret of the chosen master instance instead of its own.
    ha_enabled = _as_bool(value("opnsense_ha_enabled"))
    ha_master = value("opnsense_ha_master") or ""
    api_key = value("opnsense_api_key")
    api_secret = value("opnsense_api_secret")
    if _inherit_ha and ha_enabled and ha_master and ha_master != resolved:
        try:
            master = get_opnsense_settings(
                mask_password=False, instance_id=ha_master, _inherit_ha=False
            )
            api_key = master.get("opnsense_api_key", "")
            api_secret = master.get("opnsense_api_secret", "")
        except Exception:  # noqa: BLE001 - inherit best effort
            pass

    result = {
        "opnsense_host": value("opnsense_host"),
        "opnsense_ssh_port": int(value("opnsense_ssh_port") or 22),
        "opnsense_username": value("opnsense_username"),
        "opnsense_auth_type": value("opnsense_auth_type"),
        "opnsense_key_path": value("opnsense_key_path"),
        "opnsense_sync_enabled": _as_bool(value("opnsense_sync_enabled")),
        "opnsense_sync_interval_min": int(value("opnsense_sync_interval_min") or 30),
        "opnsense_import_on_start": _as_bool(value("opnsense_import_on_start")),
        "opnsense_import_wait_syslog_sec": max(
            0, int(value("opnsense_import_wait_syslog_sec") or 120)
        ),
        "opnsense_import_max_days": max(0, int(value("opnsense_import_max_days") or 7)),
        "has_password": bool(value("opnsense_password")),
        "has_api_key": bool(api_key),
        "has_api_secret": bool(api_secret),
        "opnsense_api_scheme": (str(value("opnsense_api_scheme") or "https").lower() or "https"),
        "opnsense_api_port": int(value("opnsense_api_port") or 443),
        "opnsense_ha_enabled": ha_enabled,
        "opnsense_ha_master": ha_master,
        "api_key_from_master": bool(ha_enabled and ha_master and ha_master != resolved),
    }
    if not mask_password:
        result["opnsense_password"] = value("opnsense_password")
        result["opnsense_api_key"] = api_key
        result["opnsense_api_secret"] = api_secret
    return result


def update_opnsense_settings(payload: dict, instance_id: str | None = None) -> dict:
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
    return get_opnsense_settings(instance_id=instance_id)
