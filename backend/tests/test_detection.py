"""Tests for the detection engine (no network, temp DuckDB)."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import app.detection.engine as deng
import app.detection.store as dstore
import app.notifications.store as nstore
from app.parser.models import FirewallEvent
from app.storage.database import Database
from app.storage.repository import EventRepository


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "detection.duckdb"))
    monkeypatch.setattr(dstore, "get_database", lambda: database)
    monkeypatch.setattr(deng, "get_database", lambda: database)
    monkeypatch.setattr(nstore, "get_database", lambda: database)
    return database


def _event(**kw) -> FirewallEvent:
    base = {
        "event_time": datetime.now(timezone.utc),
        "src_ip": "1.2.3.4",
        "action": "pass",
        "protocol": "tcp",
    }
    base.update(kw)
    return FirewallEvent(**base)


def _raise_thresholds(**overrides) -> None:
    payload = {
        "detection_portscan_ports": 3,
        "detection_bruteforce_count": 3,
        "detection_spike_threshold": 100000,
    }
    payload.update(overrides)
    dstore.update_detection_settings(payload)


def test_port_scan_alert(db):
    _raise_thresholds()
    EventRepository(db).insert_events([_event(dst_port=p) for p in (22, 80, 443)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "port_scan" for a in alerts)


def test_alert_is_deduplicated_within_window(db):
    _raise_thresholds()
    EventRepository(db).insert_events([_event(dst_port=p) for p in (22, 80, 443)])
    first = deng.run_cycle()
    second = deng.run_cycle()
    assert any(a["rule"] == "port_scan" for a in first)
    assert second == []


def test_bruteforce_alert(db):
    _raise_thresholds(detection_portscan_ports=100000)
    EventRepository(db).insert_events([_event(action="block") for _ in range(3)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "bruteforce" for a in alerts)


def test_traffic_spike_alert(db):
    _raise_thresholds(detection_portscan_ports=100000, detection_bruteforce_count=100000, detection_spike_threshold=5)
    EventRepository(db).insert_events([_event() for _ in range(6)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "traffic_spike" for a in alerts)


def test_disabled_detection_returns_nothing(db):
    _raise_thresholds()
    dstore.update_detection_settings({"detection_enabled": False})
    EventRepository(db).insert_events([_event(dst_port=p) for p in (22, 80, 443)])
    assert deng.run_cycle() == []


def test_private_source_ignored_by_default(db):
    # LAN traffic must not raise a port-scan alert by default.
    _raise_thresholds()
    EventRepository(db).insert_events(
        [_event(src_ip="10.0.0.5", dst_port=p) for p in (22, 80, 443)]
    )
    assert not any(a["rule"] == "port_scan" for a in deng.run_cycle())
    # ...but it does when the filter is disabled.
    dstore.update_detection_settings({"detection_ignore_private": False})
    assert any(a["rule"] == "port_scan" for a in deng.run_cycle())


def test_list_and_clear_alerts(db):
    _raise_thresholds()
    EventRepository(db).insert_events([_event(dst_port=p) for p in (22, 80, 443)])
    deng.run_cycle()
    page = deng.list_alerts(limit=10, offset=0)
    assert page["total"] >= 1
    assert page["items"][0]["created_at"] is not None
    deleted = deng.clear_alerts()
    assert deleted >= 1
    assert deng.count_alerts() == 0
