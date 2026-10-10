"""Registry of OPNsense instances (multi-firewall support).

Every OPNsense firewall is a fully isolated *instance*: it owns a dedicated
DuckDB file holding its logs, alerts, blocking state, detection thresholds and
OPNsense connection settings. Only the SMTP/e-mail configuration and a few web
application settings are shared; they live in the small *system* database.

The registry itself (the list of instances) also lives in the system database.
"""
from __future__ import annotations

import logging
import shutil
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import duckdb

from .config import settings
from .storage.database import (
    Database,
    close_database,
    get_database,
    instance_db_path,
    legacy_db_path,
    system_db_path,
)

logger = logging.getLogger("opnsense.instances")

# Global (shared) settings keys copied from the legacy single database into the
# new system database during the first migration.
_GLOBAL_KEYS = [
    "log_retention_days",
    "retention_check_interval_min",
    "display_timezone",
    "public_url",
    "smtp_enabled",
    "smtp_host",
    "smtp_port",
    "smtp_security",
    "smtp_username",
    "smtp_password",
    "smtp_from_email",
    "smtp_from_name",
    "smtp_to",
    "geoip_enabled",
    "geoip_account_id",
    "geoip_license_key",
    "geoip_update_interval_hours",
    "hostname_lookup_ttl_min",
    "syslog_timezone",
]

# Per-instance OPNsense connection keys seeded from the environment for the very
# first instance (keeps existing .env-based deployments working).
_ENV_CONNECTOR_KEYS = [
    "opnsense_host",
    "opnsense_ssh_port",
    "opnsense_username",
    "opnsense_auth_type",
    "opnsense_password",
    "opnsense_key_path",
    "opnsense_api_key",
    "opnsense_api_secret",
    "opnsense_api_scheme",
    "opnsense_api_port",
    "opnsense_sync_enabled",
    "opnsense_sync_interval_min",
    "opnsense_import_on_start",
    "opnsense_import_wait_syslog_sec",
    "opnsense_import_max_days",
]

# Neutral values written for extra instances so they never inherit the first
# firewall's environment-provided connector settings.
_BLANK_CONNECTOR_KEYS = {
    "opnsense_host": "",
    "opnsense_ssh_port": "22",
    "opnsense_username": "root",
    "opnsense_auth_type": "password",
    "opnsense_password": "",
    "opnsense_key_path": "",
    "opnsense_api_key": "",
    "opnsense_api_secret": "",
    "opnsense_api_scheme": "https",
    "opnsense_api_port": "443",
    "opnsense_sync_enabled": "false",
    "opnsense_sync_interval_min": "30",
    "opnsense_import_on_start": "true",
    "opnsense_import_wait_syslog_sec": "120",
    "opnsense_import_max_days": "7",
}

_SETTING_INSERT = (
    'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
    'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", "updated_at" = excluded."updated_at"'
)

_bootstrap_lock = threading.Lock()

_SELECT = (
    'SELECT "id", "name", "enabled", "position", "syslog_port", "syslog_protocol", "created_at" '
    "FROM instances"
)


def _row_to_dict(row) -> dict:
    if row is None:
        return {}
    created = row[6]
    return {
        "id": row[0],
        "name": row[1],
        "enabled": True if row[2] is None else bool(row[2]),
        "position": int(row[3] or 0),
        "syslog_port": int(row[4]) if row[4] is not None else None,
        "syslog_protocol": row[5] or "udp",
        "created_at": created.isoformat() if isinstance(created, datetime) else created,
    }


def list_instances() -> list[dict]:
    db = get_database(None)
    rows = db.execute_read(_SELECT + ' ORDER BY "position", "created_at"').fetchall()
    return [_row_to_dict(r) for r in rows]


def get_instance(instance_id: str) -> dict | None:
    db = get_database(None)
    row = db.execute_read(_SELECT + ' WHERE "id" = ?', [instance_id]).fetchone()
    return _row_to_dict(row) if row else None


def first_instance_id() -> str | None:
    """Id of the first enabled instance (default when none is specified)."""
    for inst in list_instances():
        if inst["enabled"]:
            return inst["id"]
    return None


def resolve_instance_id(instance_id: str | None = None) -> str | None:
    """Return ``instance_id`` when given, otherwise the first enabled instance.

    Used by the per-instance stores/services so a call without an explicit
    instance targets the default (first) firewall. Falls back to ``None`` (the
    system database) when the registry cannot be read (e.g. very early startup
    or a test harness that has not bootstrapped instances yet).
    """
    if instance_id:
        return instance_id
    try:
        return first_instance_id()
    except Exception:  # noqa: BLE001 - never break a settings read
        return None


def next_syslog_port() -> int:
    db = get_database(None)
    row = db.execute_read(
        'SELECT COALESCE(MAX("syslog_port"), ?) FROM instances', [settings.syslog_port - 1]
    ).fetchone()
    base = int(row[0]) if row and row[0] is not None else settings.syslog_port - 1
    return max(settings.syslog_port, base + 1)


def _next_position() -> int:
    db = get_database(None)
    row = db.execute_read('SELECT COALESCE(MAX("position"), 0) FROM instances').fetchone()
    return int(row[0] or 0) + 1


def _write_settings(db: Database, values: dict[str, str]) -> None:
    for key, value in values.items():
        db.execute_write(_SETTING_INSERT, [key, str(value)])


def _seed_from_env(db: Database) -> None:
    values: dict[str, str] = {}
    for key in _ENV_CONNECTOR_KEYS:
        value = getattr(settings, key, None)
        if value is None:
            continue
        if isinstance(value, bool):
            value = "true" if value else "false"
        values[key] = str(value)
    _write_settings(db, values)


def _insert_instance(
    instance_id: str, name: str, position: int, syslog_port: int, protocol: str
) -> None:
    db = get_database(None)
    db.execute_write(
        'INSERT INTO instances '
        '("id", "name", "enabled", "position", "syslog_port", "syslog_protocol", "created_at") '
        "VALUES (?, ?, TRUE, ?, ?, ?, now())",
        [instance_id, name, position, syslog_port, protocol],
    )


def create_instance(
    name: str | None = None,
    *,
    from_env: bool = False,
    syslog_port: int | None = None,
) -> dict:
    """Create a new isolated instance (its own database file)."""
    position = _next_position()
    display = (name or "").strip() or f"OPNsense {position}"
    port = int(syslog_port) if syslog_port else next_syslog_port()
    instance_id = uuid.uuid4().hex[:12]
    _insert_instance(instance_id, display, position, port, settings.syslog_protocol)
    inst_db = get_database(instance_id)  # creates the file + schema
    if from_env:
        _seed_from_env(inst_db)
    else:
        _write_settings(inst_db, _BLANK_CONNECTOR_KEYS)
    logger.info("Created instance %s (%s) on syslog port %d", instance_id, display, port)
    return get_instance(instance_id) or {}


def update_instance(
    instance_id: str,
    *,
    name: str | None = None,
    enabled: bool | None = None,
    syslog_port: int | None = None,
    syslog_protocol: str | None = None,
) -> dict | None:
    db = get_database(None)
    if name is not None:
        db.execute_write('UPDATE instances SET "name" = ? WHERE "id" = ?', [name.strip(), instance_id])
    if enabled is not None:
        db.execute_write('UPDATE instances SET "enabled" = ? WHERE "id" = ?', [enabled, instance_id])
    if syslog_port is not None:
        db.execute_write(
            'UPDATE instances SET "syslog_port" = ? WHERE "id" = ?', [int(syslog_port), instance_id]
        )
    if syslog_protocol is not None:
        db.execute_write(
            'UPDATE instances SET "syslog_protocol" = ? WHERE "id" = ?',
            [syslog_protocol, instance_id],
        )
    return get_instance(instance_id)


def delete_instance(instance_id: str, *, drop_data: bool = True) -> bool:
    db = get_database(None)
    row = db.execute_read('SELECT 1 FROM instances WHERE "id" = ?', [instance_id]).fetchone()
    if not row:
        return False
    db.execute_write('DELETE FROM instances WHERE "id" = ?', [instance_id])
    close_database(instance_id)
    if drop_data:
        path = Path(instance_db_path(instance_id))
        for candidate in (path, Path(str(path) + ".wal")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError:  # noqa: BLE001
                logger.warning("Could not remove instance database %s", candidate)
    logger.info("Deleted instance %s", instance_id)
    return True


def _copy_legacy(legacy: Path, dest: Path) -> None:
    shutil.copy2(legacy, dest)


def _copy_global_settings(legacy: Path, system_db: Database) -> None:
    try:
        conn = duckdb.connect(str(legacy), read_only=True)
    except Exception:  # noqa: BLE001
        logger.exception("Could not read legacy database for global settings")
        return
    try:
        rows = conn.execute('SELECT "key", "value" FROM app_settings').fetchall()
    except Exception:  # noqa: BLE001
        rows = []
    finally:
        conn.close()
    values = {r[0]: r[1] for r in rows if r[0] in _GLOBAL_KEYS and r[1] is not None}
    if values:
        _write_settings(system_db, values)


def bootstrap() -> None:
    """Ensure at least one instance exists, migrating the legacy database."""
    with _bootstrap_lock:
        if list_instances():
            return
        instance_id = uuid.uuid4().hex[:12]
        legacy = Path(legacy_db_path())
        port = settings.syslog_port
        from_env = True
        if legacy.exists() and legacy.resolve() != Path(system_db_path()).resolve():
            dest = Path(instance_db_path(instance_id))
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                _copy_legacy(legacy, dest)
                _copy_global_settings(legacy, get_database(None))
                from_env = False
                logger.info("Migrated legacy database to instance %s", instance_id)
            except Exception:  # noqa: BLE001
                logger.exception("Legacy migration failed; starting a fresh instance")
                from_env = True
        _insert_instance(instance_id, "OPNsense 1", 1, port, settings.syslog_protocol)
        inst_db = get_database(instance_id)
        if from_env:
            _seed_from_env(inst_db)
