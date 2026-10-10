"""Tests for the automatic blocking (OPNsense alias) feature."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.storage.database import Database
import app.detection.allowlist_store as als
import app.detection.blocking_store as bs
import app.opnsense.blocker as blocker


class FakeAPI:
    def __init__(self, rows: dict | None = None) -> None:
        self.rows = rows or {}
        self.reconfig = 0

    def is_configured(self) -> bool:
        return True

    def get_alias_content(self, name: str):
        row = self.rows.get(name)
        if row is None:
            return None, []
        return row, list(row.get("content", []))

    def ensure_host_alias(self, name: str, content: list):
        self.rows[name] = {"uuid": "u1", "name": name, "type": "host", "enabled": "1", "content": list(content)}
        return self.rows[name]

    def set_alias_content(self, row: dict, content: list) -> None:
        self.rows[row["name"]] = {**row, "content": list(content)}

    def reconfigure(self) -> None:
        self.reconfig += 1


@pytest.fixture
def database(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "t.duckdb"))
    monkeypatch.setattr(bs, "get_database", lambda *a, **k: db)
    monkeypatch.setattr(blocker, "get_database", lambda *a, **k: db)
    monkeypatch.setattr(als, "get_database", lambda *a, **k: db)
    yield db
    db.close()


def _cfg(**overrides) -> dict:
    base = {
        "blocking_enabled": True,
        "blocking_alias": "BLOCK",
        "blocking_mode": "manual",
        "blocking_whitelist": "",
        "blocking_ttl_hours": 0,
    }
    base.update(overrides)
    return base


def test_blocking_settings_defaults(database):
    cfg = bs.get_blocking_settings()
    assert cfg["blocking_enabled"] is False
    assert cfg["blocking_mode"] == "manual"


def test_blocking_settings_update(database):
    updated = bs.update_blocking_settings({"blocking_enabled": True, "blocking_alias": "BLOCK", "blocking_mode": "auto"})
    assert updated["blocking_enabled"] is True
    assert updated["blocking_alias"] == "BLOCK"
    assert updated["blocking_mode"] == "auto"


def test_apply_ips_filters_and_creates_alias(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_whitelist="10.0.0.1"))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)

    result = blocker.apply_ips(["1.2.3.4", "10.0.0.1", "192.168.1.5", "1.2.3.4", "bad"])
    assert result["ok"] is True
    assert result["added"] == ["1.2.3.4"]
    assert fake.rows["BLOCK"]["content"] == ["1.2.3.4"]
    assert fake.reconfig == 1
    assert [r["ip"] for r in blocker.list_blocked()] == ["1.2.3.4"]


def test_apply_ips_merges_existing(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg())
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4"]}})
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)

    result = blocker.apply_ips(["1.2.3.4", "5.6.7.8"])
    assert result["added"] == ["5.6.7.8"]
    assert fake.rows["BLOCK"]["content"] == ["1.2.3.4", "5.6.7.8"]


def test_skip_tables_parsing():
    assert blocker._skip_tables({"blocking_skip_tables": "crowdsec_blacklists, bad!name crowdsec6_blacklists"}) == [
        "crowdsec_blacklists",
        "crowdsec6_blacklists",
    ]
    assert blocker._skip_tables({"blocking_skip_tables": ""}) == []
    # Auto-detected tables are merged in and de-duplicated.
    assert blocker._skip_tables(
        {"blocking_skip_tables": "a, b", "blocking_skip_tables_detected": "c b"}
    ) == ["a", "b", "c"]
    # The app's own blocking alias is never treated as a foreign block list.
    assert blocker._skip_tables(
        {"blocking_skip_tables": "BLOCK_IP crowdsec_blacklists", "blocking_alias": "BLOCK_IP"}
    ) == ["crowdsec_blacklists"]


def test_detect_block_tables_filters_names(monkeypatch):
    class FakeSSH:
        def __init__(self, **kwargs):
            pass

        def run(self, command):
            return "crowdsec_blacklists\nqfeeds4\nlo0\nBLOCK_IP\nrandomtable\n"

    monkeypatch.setattr(blocker, "OPNsenseSSH", FakeSSH)
    monkeypatch.setattr(
        blocker,
        "get_opnsense_settings",
            lambda mask_password=False, *a, **k: {"opnsense_host": "h", "opnsense_ssh_port": 22,
                                     "opnsense_username": "root", "opnsense_auth_type": "password",
                                     "opnsense_key_path": ""},
    )
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_alias="BLOCK_IP"))
    tables = blocker.detect_block_tables()
    assert "crowdsec_blacklists" in tables
    assert "qfeeds4" in tables
    assert "BLOCK_IP" not in tables
    assert "lo0" not in tables
    assert "randomtable" not in tables


def test_apply_ips_dry_run_does_not_touch_alias(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_dry_run=True))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)

    result = blocker.apply_ips(["1.2.3.4"])
    assert result["dry_run"] is True
    assert result["would_block"] == ["1.2.3.4"]
    assert result["added"] == []
    assert fake.rows == {}
    assert blocker.list_blocked() == []


def test_apply_ips_respects_allowlist(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg())
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    als.add_allowlist(["203.0.113.0/24"])

    result = blocker.apply_ips(["203.0.113.5", "1.2.3.4"])

    assert result["added"] == ["1.2.3.4"]
    assert fake.rows["BLOCK"]["content"] == ["1.2.3.4"]


def test_record_blocked_returns_details(database):
    records = blocker._record_blocked(["1.2.3.4"], "detection", "auto", 2)
    assert records["1.2.3.4"]["hits"] == 1
    assert records["1.2.3.4"]["expires_at"] is not None


def test_record_blocked_escalates_ttl(database):
    blocker._record_blocked(["1.2.3.4"], "detection", "auto", 1, escalate=True, max_hours=10)
    blocker._record_blocked(["1.2.3.4"], "detection", "auto", 1, escalate=True, max_hours=10)
    hits, expires = database.execute_read(
        'SELECT "hits", "expires_at" FROM blocked_ips WHERE "ip" = ?', ["1.2.3.4"]
    ).fetchone()
    assert hits == 2
    assert expires is not None


def test_record_blocked_escalation_capped(database):
    blocker._record_blocked(["1.2.3.4"], "detection", "auto", 5, escalate=True, max_hours=6)
    blocker._record_blocked(["1.2.3.4"], "detection", "auto", 5, escalate=True, max_hours=6)
    expires = database.execute_read(
        'SELECT "expires_at" FROM blocked_ips WHERE "ip" = ?', ["1.2.3.4"]
    ).fetchone()[0]
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    # 5h * 2 = 10h capped at 6h.
    delta = expires - datetime.now(timezone.utc)
    assert 5.5 <= delta.total_seconds() / 3600 <= 6.5


def test_reconcile_alias_readds_missing(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_enabled=True))
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["5.6.7.8"]}})
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    database.execute_write(
        'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at", "hits") '
        "VALUES ('1.2.3.4', 'detection', 'auto', now(), NULL, 1)"
    )

    result = blocker.reconcile_alias()
    assert result["ok"] is True
    assert result["reconciled"] == 1
    assert "1.2.3.4" in fake.rows["BLOCK"]["content"]
    assert fake.reconfig == 1


def test_reconcile_alias_disabled_is_noop(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_enabled=False))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    result = blocker.reconcile_alias()
    assert result == {"ok": True, "reconciled": 0}
    assert fake.rows == {}


def test_apply_ips_skips_already_blocked(database, monkeypatch):
    monkeypatch.setattr(
        blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_skip_tables="crowdsec_blacklists")
    )
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    monkeypatch.setattr(blocker, "_already_blocked", lambda ips, tables, *a, **k: {"1.2.3.4"})

    result = blocker.apply_ips(["1.2.3.4", "5.6.7.8"])
    assert result["added"] == ["5.6.7.8"]
    assert result["skipped"] == ["1.2.3.4"]
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]


def test_apply_ips_all_already_blocked(database, monkeypatch):
    monkeypatch.setattr(
        blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_skip_tables="crowdsec_blacklists")
    )
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    monkeypatch.setattr(blocker, "_already_blocked", lambda ips, tables, *a, **k: {"1.2.3.4"})

    result = blocker.apply_ips(["1.2.3.4"])
    assert result["ok"] is True
    assert result["added"] == []
    assert result["skipped"] == ["1.2.3.4"]
    assert fake.reconfig == 0
    assert blocker.list_blocked() == []


def test_apply_ips_sends_block_notification(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_notify_email=True))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    sent = {}
    monkeypatch.setattr(
        blocker,
        "send_block_notification",
        lambda ips, rule="", reasons=None, days=7, details=None, **k: sent.update(ips=ips, rule=rule) or {"ok": True},
    )

    result = blocker.apply_ips(["1.2.3.4"], rule="detection", source="auto")

    assert result["added"] == ["1.2.3.4"]
    assert sent == {"ips": ["1.2.3.4"], "rule": "detection"}


def test_apply_ips_no_notification_when_disabled(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_notify_email=False))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    called = {"count": 0}
    monkeypatch.setattr(
        blocker,
        "send_block_notification",
        lambda *a, **k: called.update(count=called["count"] + 1) or {"ok": True},
    )

    blocker.apply_ips(["1.2.3.4"], rule="detection", source="auto")

    assert called["count"] == 0


def test_block_alerts_only_blockable_rules(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg())
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)

    alerts = [
        {"rule": "port_scan", "src_ip": "1.1.1.1"},
        {"rule": "bruteforce", "src_ip": "2.2.2.2"},
        {"rule": "traffic_spike", "src_ip": "3.3.3.3"},
    ]
    result = blocker.block_alerts(alerts)
    assert sorted(result["added"]) == ["1.1.1.1", "2.2.2.2"]


def test_prune_expired_removes_from_alias(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg(blocking_ttl_hours=1))
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4", "5.6.7.8"]}})
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    database.execute_write(
        'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
        "VALUES ('1.2.3.4', 'detection', 'auto', now(), now() - INTERVAL 1 HOUR)"
    )
    removed = blocker.prune_expired()
    assert removed == 1
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]


def test_unblock_ips_removes_from_alias_and_list(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda *a, **k: _cfg())
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4", "5.6.7.8"]}})
    monkeypatch.setattr(blocker, "_api", lambda *a, **k: fake)
    database.execute_write(
        'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
        "VALUES ('1.2.3.4', 'manual', 'manual', now(), NULL)"
    )

    result = blocker.unblock_ips(["1.2.3.4"])
    assert result["ok"] is True
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]
    assert fake.reconfig == 1
    assert blocker.list_blocked() == []
