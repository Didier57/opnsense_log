"""Tests for the automatic blocking (OPNsense alias) feature."""
from __future__ import annotations

import pytest

from app.storage.database import Database
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
    monkeypatch.setattr(bs, "get_database", lambda: db)
    monkeypatch.setattr(blocker, "get_database", lambda: db)
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
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda: _cfg(blocking_whitelist="10.0.0.1"))
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda: fake)

    result = blocker.apply_ips(["1.2.3.4", "10.0.0.1", "192.168.1.5", "1.2.3.4", "bad"])
    assert result["ok"] is True
    assert result["added"] == ["1.2.3.4"]
    assert fake.rows["BLOCK"]["content"] == ["1.2.3.4"]
    assert fake.reconfig == 1
    assert [r["ip"] for r in blocker.list_blocked()] == ["1.2.3.4"]


def test_apply_ips_merges_existing(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda: _cfg())
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4"]}})
    monkeypatch.setattr(blocker, "_api", lambda: fake)

    result = blocker.apply_ips(["1.2.3.4", "5.6.7.8"])
    assert result["added"] == ["5.6.7.8"]
    assert fake.rows["BLOCK"]["content"] == ["1.2.3.4", "5.6.7.8"]


def test_skip_tables_parsing():
    assert blocker._skip_tables({"blocking_skip_tables": "crowdsec_blacklists, bad!name crowdsec6_blacklists"}) == [
        "crowdsec_blacklists",
        "crowdsec6_blacklists",
    ]
    assert blocker._skip_tables({"blocking_skip_tables": ""}) == []


def test_apply_ips_skips_already_blocked(database, monkeypatch):
    monkeypatch.setattr(
        blocker, "get_blocking_settings", lambda: _cfg(blocking_skip_tables="crowdsec_blacklists")
    )
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda: fake)
    monkeypatch.setattr(blocker, "_already_blocked", lambda ips, tables: {"1.2.3.4"})

    result = blocker.apply_ips(["1.2.3.4", "5.6.7.8"])
    assert result["added"] == ["5.6.7.8"]
    assert result["skipped"] == ["1.2.3.4"]
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]


def test_apply_ips_all_already_blocked(database, monkeypatch):
    monkeypatch.setattr(
        blocker, "get_blocking_settings", lambda: _cfg(blocking_skip_tables="crowdsec_blacklists")
    )
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda: fake)
    monkeypatch.setattr(blocker, "_already_blocked", lambda ips, tables: {"1.2.3.4"})

    result = blocker.apply_ips(["1.2.3.4"])
    assert result["ok"] is True
    assert result["added"] == []
    assert result["skipped"] == ["1.2.3.4"]
    assert fake.reconfig == 0
    assert blocker.list_blocked() == []


def test_block_alerts_only_blockable_rules(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda: _cfg())
    fake = FakeAPI()
    monkeypatch.setattr(blocker, "_api", lambda: fake)

    alerts = [
        {"rule": "port_scan", "src_ip": "1.1.1.1"},
        {"rule": "bruteforce", "src_ip": "2.2.2.2"},
        {"rule": "traffic_spike", "src_ip": "3.3.3.3"},
    ]
    result = blocker.block_alerts(alerts)
    assert sorted(result["added"]) == ["1.1.1.1", "2.2.2.2"]


def test_prune_expired_removes_from_alias(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda: _cfg(blocking_ttl_hours=1))
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4", "5.6.7.8"]}})
    monkeypatch.setattr(blocker, "_api", lambda: fake)
    database.execute_write(
        'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
        "VALUES ('1.2.3.4', 'detection', 'auto', now(), now() - INTERVAL 1 HOUR)"
    )
    removed = blocker.prune_expired()
    assert removed == 1
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]


def test_unblock_ips_removes_from_alias_and_list(database, monkeypatch):
    monkeypatch.setattr(blocker, "get_blocking_settings", lambda: _cfg())
    fake = FakeAPI({"BLOCK": {"uuid": "u1", "name": "BLOCK", "type": "host", "enabled": "1", "content": ["1.2.3.4", "5.6.7.8"]}})
    monkeypatch.setattr(blocker, "_api", lambda: fake)
    database.execute_write(
        'INSERT INTO blocked_ips ("ip", "rule", "source", "added_at", "expires_at") '
        "VALUES ('1.2.3.4', 'manual', 'manual', now(), NULL)"
    )

    result = blocker.unblock_ips(["1.2.3.4"])
    assert result["ok"] is True
    assert fake.rows["BLOCK"]["content"] == ["5.6.7.8"]
    assert fake.reconfig == 1
    assert blocker.list_blocked() == []
