"""HA (High Availability) API key inheritance in the OPNsense settings store."""
from __future__ import annotations

import pytest

import app.opnsense.settings_store as ss
from app.storage.database import Database


@pytest.fixture
def dbs(tmp_path, monkeypatch):
    system = Database(str(tmp_path / "system.duckdb"))
    master = Database(str(tmp_path / "master.duckdb"))
    slave = Database(str(tmp_path / "slave.duckdb"))
    mapping = {"master": master, "slave": slave}
    monkeypatch.setattr(ss, "resolve_instance_id", lambda iid=None: iid)
    monkeypatch.setattr(
        ss, "get_database", lambda iid=None: mapping.get(iid, system)
    )
    yield mapping
    for db in (master, slave, system):
        db.close()


def test_ha_inherits_api_key_from_master(dbs):
    ss.update_opnsense_settings(
        {"opnsense_api_key": "KEY1", "opnsense_api_secret": "SEC1"}, instance_id="master"
    )
    ss.update_opnsense_settings(
        {"opnsense_ha_enabled": True, "opnsense_ha_master": "master"}, instance_id="slave"
    )
    slave = ss.get_opnsense_settings(mask_password=False, instance_id="slave")
    assert slave["opnsense_api_key"] == "KEY1"
    assert slave["opnsense_api_secret"] == "SEC1"
    assert slave["api_key_from_master"] is True


def test_ha_masked_reports_inherited_key(dbs):
    ss.update_opnsense_settings(
        {"opnsense_api_key": "K", "opnsense_api_secret": "S"}, instance_id="master"
    )
    ss.update_opnsense_settings(
        {"opnsense_ha_enabled": True, "opnsense_ha_master": "master"}, instance_id="slave"
    )
    masked = ss.get_opnsense_settings(instance_id="slave")
    assert masked["has_api_key"] is True
    assert masked["has_api_secret"] is True
    assert "opnsense_api_key" not in masked


def test_without_ha_uses_own_key(dbs):
    ss.update_opnsense_settings({"opnsense_api_key": "MASTERKEY"}, instance_id="master")
    ss.update_opnsense_settings({"opnsense_api_key": "SLAVEKEY"}, instance_id="slave")
    slave = ss.get_opnsense_settings(mask_password=False, instance_id="slave")
    assert slave["opnsense_api_key"] == "SLAVEKEY"
    assert slave["api_key_from_master"] is False


def test_ha_flags_roundtrip(dbs):
    ss.update_opnsense_settings(
        {"opnsense_ha_enabled": True, "opnsense_ha_master": "master"}, instance_id="slave"
    )
    slave = ss.get_opnsense_settings(instance_id="slave")
    assert slave["opnsense_ha_enabled"] is True
    assert slave["opnsense_ha_master"] == "master"


def test_ha_master_role_uses_own_key(dbs):
    ss.update_opnsense_settings({"opnsense_api_key": "MK"}, instance_id="master")
    ss.update_opnsense_settings(
        {
            "opnsense_ha_enabled": True,
            "opnsense_ha_role": "master",
            "opnsense_ha_slaves": "slave",
        },
        instance_id="master",
    )
    master = ss.get_opnsense_settings(mask_password=False, instance_id="master")
    assert master["opnsense_ha_role"] == "master"
    assert master["opnsense_api_key"] == "MK"
    assert master["api_key_from_master"] is False


def test_ha_cluster_ids_groups_master_and_slaves(dbs, monkeypatch):
    import app.instances as inst

    monkeypatch.setattr(
        inst,
        "list_instances",
        lambda: [{"id": "master"}, {"id": "slave"}, {"id": "other"}],
    )
    ss.update_opnsense_settings(
        {
            "opnsense_ha_enabled": True,
            "opnsense_ha_role": "master",
            "opnsense_ha_slaves": "slave",
        },
        instance_id="master",
    )
    ss.update_opnsense_settings(
        {
            "opnsense_ha_enabled": True,
            "opnsense_ha_role": "slave",
            "opnsense_ha_master": "master",
        },
        instance_id="slave",
    )
    assert ss.ha_cluster_ids("master") == ["master", "slave"]
    assert ss.ha_cluster_ids("slave") == ["master", "slave"]
    assert ss.ha_cluster_ids("other") == ["other"]
