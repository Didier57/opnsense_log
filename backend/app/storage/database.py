"""DuckDB connection management and schema definition."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import duckdb

from ..config import settings

_EVENT_COLUMNS = [
    "event_time", "rule_id", "rule_number", "sub_rule", "anchor", "interface",
    "reason", "action", "direction", "ip_version", "tos", "ecn", "ttl",
    "packet_id", "offset", "flags", "protocol_id", "protocol", "length",
    "src_ip", "dst_ip", "src_port", "dst_port", "data_length", "tcp_flags",
    "seq", "ack", "window", "urg", "options", "icmp_type", "icmp_code",
    "icmp_id", "icmp_seq", "hostname", "raw", "format", "parse_status",
]

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    "event_time"   TIMESTAMPTZ,
    "rule_id"      VARCHAR,
    "rule_number"  INTEGER,
    "sub_rule"     VARCHAR,
    "anchor"       VARCHAR,
    "interface"    VARCHAR,
    "reason"       VARCHAR,
    "action"       VARCHAR,
    "direction"    VARCHAR,
    "ip_version"   INTEGER,
    "tos"          VARCHAR,
    "ecn"          VARCHAR,
    "ttl"          INTEGER,
    "packet_id"    INTEGER,
    "offset"       INTEGER,
    "flags"        VARCHAR,
    "protocol_id"  INTEGER,
    "protocol"     VARCHAR,
    "length"       INTEGER,
    "src_ip"       VARCHAR,
    "dst_ip"       VARCHAR,
    "src_port"     INTEGER,
    "dst_port"     INTEGER,
    "data_length"  INTEGER,
    "tcp_flags"    VARCHAR,
    "seq"          VARCHAR,
    "ack"          VARCHAR,
    "window"       VARCHAR,
    "urg"          VARCHAR,
    "options"      VARCHAR,
    "icmp_type"    VARCHAR,
    "icmp_code"    VARCHAR,
    "icmp_id"      VARCHAR,
    "icmp_seq"     VARCHAR,
    "hostname"     VARCHAR,
    "raw"          VARCHAR,
    "format"       VARCHAR,
    "parse_status" VARCHAR
);

CREATE TABLE IF NOT EXISTS opnsense_interfaces (
    "name"        VARCHAR,
    "device"      VARCHAR,
    "description" VARCHAR,
    "ipv4"        VARCHAR,
    "ipv6"        VARCHAR,
    "updated_at"  TIMESTAMPTZ,
    PRIMARY KEY ("name")
);

CREATE TABLE IF NOT EXISTS opnsense_rules (
    "rule_id"     VARCHAR PRIMARY KEY,
    "rule_number" INTEGER,
    "description" VARCHAR,
    "interface"   VARCHAR,
    "action"      VARCHAR,
    "direction"   VARCHAR,
    "protocol"    VARCHAR,
    "source"      VARCHAR,
    "destination" VARCHAR,
    "enabled"     BOOLEAN,
    "updated_at"  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS rule_history (
    "rule_id"     VARCHAR,
    "valid_from"  TIMESTAMPTZ,
    "description" VARCHAR,
    "interface"   VARCHAR,
    "action"      VARCHAR,
    "snapshot"    VARCHAR
);

CREATE TABLE IF NOT EXISTS saved_filters (
    "id"          INTEGER,
    "name"        VARCHAR,
    "definition"  VARCHAR,
    "created_at"  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS app_settings (
    "key"         VARCHAR PRIMARY KEY,
    "value"       VARCHAR,
    "updated_at"  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS ingest_stats (
    "ts"          TIMESTAMPTZ,
    "received"    BIGINT,
    "parsed"      BIGINT,
    "invalid"     BIGINT
);

CREATE TABLE IF NOT EXISTS app_logs (
    "ts"       TIMESTAMPTZ,
    "level"    VARCHAR,
    "source"   VARCHAR,
    "message"  VARCHAR
);

CREATE TABLE IF NOT EXISTS hostname_cache (
    "ip"         VARCHAR PRIMARY KEY,
    "hostname"   VARCHAR,
    "updated_at" TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS dhcp_leases (
    "ip"         VARCHAR PRIMARY KEY,
    "hostname"   VARCHAR,
    "mac"        VARCHAR,
    "source"     VARCHAR,
    "updated_at" TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS geoip_cache (
    "ip"           VARCHAR PRIMARY KEY,
    "country"      VARCHAR,
    "country_name" VARCHAR,
    "updated_at"   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS alerts (
    "id"         VARCHAR PRIMARY KEY,
    "created_at" TIMESTAMPTZ,
    "rule"       VARCHAR,
    "severity"   VARCHAR,
    "src_ip"     VARCHAR,
    "title"      VARCHAR,
    "message"    VARCHAR,
    "details"    VARCHAR,
    "notified"   BOOLEAN
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    "ip"         VARCHAR PRIMARY KEY,
    "rule"       VARCHAR,
    "source"     VARCHAR,
    "added_at"   TIMESTAMPTZ,
    "expires_at" TIMESTAMPTZ,
    "hits"       INTEGER
);

CREATE TABLE IF NOT EXISTS block_counts (
    "ip"              VARCHAR PRIMARY KEY,
    "hits"            INTEGER,
    "last_blocked_at" TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS allowlist_ips (
    "ip"         VARCHAR PRIMARY KEY,
    "note"       VARCHAR,
    "added_at"   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS instances (
    "id"              VARCHAR PRIMARY KEY,
    "name"            VARCHAR,
    "enabled"         BOOLEAN,
    "position"        INTEGER,
    "syslog_port"     INTEGER,
    "syslog_protocol" VARCHAR,
    "created_at"      TIMESTAMPTZ
);
"""


class Database:
    """Thread-safe DuckDB wrapper using a dedicated write connection.

    DuckDB allows many readers but only a single writer per database file, so we
    keep one connection for writes (guarded by a lock) and a separate connection
    for read-only queries.
    """

    def __init__(self, path: str | None = None) -> None:
        self.path = path or str(Path(settings.data_dir) / settings.db_filename)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._write_lock = threading.RLock()
        config = {"timezone": "UTC"}
        self._write_conn = duckdb.connect(self.path, config=config)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._write_lock:
            self._write_conn.execute(_DDL)
            # Lightweight migrations for databases created by older versions.
            for statement in (
                'ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS "hits" INTEGER',
            ):
                try:
                    self._write_conn.execute(statement)
                except Exception:  # noqa: BLE001 - column already there / older engine
                    pass

    @property
    def write_conn(self):
        return self._write_conn

    def execute_write(self, sql: str, params: list | None = None):
        with self._write_lock:
            return self._write_conn.execute(sql, params or [])

    def executemany_write(self, sql: str, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._write_lock:
            self._write_conn.executemany(sql, rows)

    def execute_read(self, sql: str, params: list | None = None):
        # Each read uses its own cursor (connection) so reads can run while a
        # write transaction is active on the primary connection.
        return self._write_conn.cursor().execute(sql, params or [])

    def close(self) -> None:
        self._write_conn.close()


def system_db_path() -> str:
    """Path of the small system database (instance registry + global settings)."""
    return str(Path(settings.data_dir) / "system.duckdb")


def instance_db_path(instance_id: str) -> str:
    """Path of the dedicated database file of one OPNsense instance."""
    return str(Path(settings.data_dir) / "instances" / f"{instance_id}.duckdb")


def legacy_db_path() -> str:
    """Path of the pre-multi-instance single database (for migration)."""
    return str(Path(settings.data_dir) / settings.db_filename)


_databases: dict[str | None, Database] = {}
_databases_lock = threading.Lock()


def get_database(instance_id: str | None = None) -> Database:
    """Return the DuckDB wrapper for the system DB or for one instance.

    ``None`` maps to the system database that stores the instance registry and
    the global (shared) settings. Any other value is a per-instance database
    holding that firewall's logs, alerts, blocking state and settings.
    """
    with _databases_lock:
        db = _databases.get(instance_id)
        if db is None:
            path = system_db_path() if instance_id is None else instance_db_path(instance_id)
            db = Database(path)
            _databases[instance_id] = db
        return db


def close_database(instance_id: str | None) -> None:
    with _databases_lock:
        db = _databases.pop(instance_id, None)
    if db is not None:
        db.close()


def reset_databases() -> None:
    """Close and forget every open database (used by tests)."""
    with _databases_lock:
        dbs = list(_databases.values())
        _databases.clear()
    for db in dbs:
        try:
            db.close()
        except Exception:  # noqa: BLE001
            pass
