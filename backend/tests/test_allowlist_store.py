"""Tests for the managed allowlist store."""
from __future__ import annotations

import pytest

import app.detection.allowlist_store as als
from app.storage.database import Database


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "a.duckdb"))
    monkeypatch.setattr(als, "get_database", lambda *a, **k: database)
    yield database
    database.close()


def test_add_list_remove_normalization(db):
    added = als.add_allowlist(["192.168.1.1", "10.0.0.0/8", "10.0.0.0/8", "bad", "2001:DB8::1"])
    assert "192.168.1.1" in added
    assert "10.0.0.0/8" in added
    assert "bad" not in added
    assert added.count("10.0.0.0/8") == 1

    items = {i["ip"] for i in als.list_allowlist()}
    assert {"192.168.1.1", "10.0.0.0/8"} <= items

    removed = als.remove_allowlist(["10.0.0.0/8"])
    assert removed == ["10.0.0.0/8"]
    assert "10.0.0.0/8" not in {i["ip"] for i in als.list_allowlist()}


def test_add_allowlist_keeps_note(db):
    als.add_allowlist(["1.2.3.4"], note="backup server")
    item = als.list_allowlist()[0]
    assert item["ip"] == "1.2.3.4"
    assert item["note"] == "backup server"


def test_is_allowlisted_membership(db):
    als.add_allowlist(["10.0.0.0/8"])
    assert als.is_allowlisted("10.1.2.3") is True
    assert als.is_allowlisted("11.0.0.1") is False
    assert als.is_allowlisted("not-an-ip") is False


def test_migrate_legacy_whitelist(db, monkeypatch):
    written: dict = {}
    monkeypatch.setattr(
        als,
        "get_blocking_settings",
        lambda *a, **k: {"blocking_whitelist": "192.168.1.10, 10.0.0.0/8 bad"},
    )
    monkeypatch.setattr(
        als, "update_blocking_settings", lambda payload, *a, **k: written.update(payload)
    )

    added = als.migrate_legacy_whitelist()
    assert "192.168.1.10" in added
    assert "10.0.0.0/8" in added
    assert "bad" not in added
    assert written.get("blocking_whitelist") == ""
    assert {"192.168.1.10", "10.0.0.0/8"} <= {i["ip"] for i in als.list_allowlist()}


def test_migrate_legacy_whitelist_noop_when_empty(db, monkeypatch):
    monkeypatch.setattr(als, "get_blocking_settings", lambda *a, **k: {"blocking_whitelist": ""})
    monkeypatch.setattr(als, "update_blocking_settings", lambda payload, *a, **k: None)
    assert als.migrate_legacy_whitelist() == []
