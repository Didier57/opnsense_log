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


_instance: Database | None = None
_instance_lock = threading.Lock()


def get_database() -> Database:
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = Database()
        return _instance
