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
    "opnsense_ha_role",
    "opnsense_ha_master",
    "opnsense_ha_slaves",
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
    ha_role = str(value("opnsense_ha_role") or "").strip().lower()
    ha_master = value("opnsense_ha_master") or ""
    ha_slaves = value("opnsense_ha_slaves") or ""
    if ha_enabled and ha_role not in {"master", "slave"}:
        # Backwards compatibility: an instance that only declared a master is a
        # slave; otherwise no role.
        ha_role = "slave" if ha_master else ""
    api_key = value("opnsense_api_key")
    api_secret = value("opnsense_api_secret")
    inherit = bool(
        _inherit_ha
        and ha_enabled
        and ha_role == "slave"
        and ha_master
        and ha_master != resolved
    )
    if inherit:
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
        "opnsense_ha_role": ha_role,
        "opnsense_ha_master": ha_master,
        "opnsense_ha_slaves": ha_slaves,
        "api_key_from_master": inherit,
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


def _ha_role(setting: dict) -> str:
    role = str(setting.get("opnsense_ha_role") or "").strip().lower()
    if role in {"master", "slave"}:
        return role
    return "slave" if (setting.get("opnsense_ha_master") or "") else ""


def _ha_slave_ids(setting: dict) -> list[str]:
    raw = str(setting.get("opnsense_ha_slaves") or "")
    return [token.strip() for token in raw.split(",") if token.strip()]


def _ha_cluster(instance_id: str | None = None) -> tuple[str | None, list[str]]:
    """Return ``(master_id, member_ids)`` for the HA cluster of ``instance_id``.

    The cluster is centred on the master node: it contains the master, the
    slaves it declares (``opnsense_ha_slaves``) and any instance that declares
    itself a slave of that master (``opnsense_ha_master``). Outside a cluster
    the instance is alone and the master is ``None``.
    """
    base = resolve_instance_id(instance_id)
    if not base:
        return None, []
    try:
        from ..instances import list_instances
    except Exception:  # noqa: BLE001
        return None, [base]
    infos: dict[str, dict] = {}
    for inst in list_instances():
        iid = inst.get("id")
        if not iid:
            continue
        setting = get_opnsense_settings(instance_id=iid, _inherit_ha=False)
        infos[iid] = {
            "role": _ha_role(setting) if setting.get("opnsense_ha_enabled") else "",
            "master": setting.get("opnsense_ha_master") or "",
            "slaves": _ha_slave_ids(setting),
        }
    info = infos.get(base)
    if not info or info["role"] not in {"master", "slave"}:
        return None, [base]
    master = base if info["role"] == "master" else (info["master"] or base)
    members = {master}
    for sid in infos.get(master, {}).get("slaves", []):
        if sid in infos:
            members.add(sid)
    for iid, other in infos.items():
        if other["role"] == "slave" and other["master"] == master:
            members.add(iid)
    return master, sorted(members)


def ha_cluster_ids(instance_id: str | None = None) -> list[str]:
    """Ids of the instances forming the HA cluster of ``instance_id``."""
    return _ha_cluster(instance_id)[1]


def ha_cluster_master(instance_id: str | None = None) -> str | None:
    """Master instance id of the cluster, or ``None`` when not in a cluster."""
    master, members = _ha_cluster(instance_id)
    return master if len(members) > 1 else None
