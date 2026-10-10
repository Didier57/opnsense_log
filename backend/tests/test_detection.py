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
        "detection_bruteforce_service_count": 100000,
        "detection_horizontalscan_hosts": 100000,
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


def test_bruteforce_service_alert(db):
    _raise_thresholds(
        detection_portscan_ports=100000,
        detection_bruteforce_count=100000,
        detection_bruteforce_service_count=3,
    )
    EventRepository(db).insert_events([_event(action="block", dst_port=22) for _ in range(3)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "bruteforce_service" for a in alerts)


def test_horizontal_scan_alert(db):
    _raise_thresholds(
        detection_portscan_ports=100000,
        detection_bruteforce_count=100000,
        detection_bruteforce_service_count=100000,
        detection_horizontalscan_hosts=3,
    )
    EventRepository(db).insert_events([_event(dst_ip=f"9.9.9.{i}") for i in range(3)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "horizontal_scan" for a in alerts)


def test_horizontal_scan_ignores_repeated_host(db):
    _raise_thresholds(
        detection_portscan_ports=100000,
        detection_bruteforce_count=100000,
        detection_bruteforce_service_count=100000,
        detection_horizontalscan_hosts=3,
    )
    # Same destination three times is not a horizontal scan.
    EventRepository(db).insert_events([_event(dst_ip="9.9.9.9") for _ in range(3)])
    assert not any(a["rule"] == "horizontal_scan" for a in deng.run_cycle())


def test_traffic_spike_alert(db):
    _raise_thresholds(
        detection_portscan_ports=100000,
        detection_bruteforce_count=100000,
        detection_spike_enabled=True,
        detection_spike_threshold=5,
    )
    EventRepository(db).insert_events([_event() for _ in range(6)])
    alerts = deng.run_cycle()
    assert any(a["rule"] == "traffic_spike" for a in alerts)


def test_traffic_spike_disabled_by_default(db):
    _raise_thresholds(detection_portscan_ports=100000, detection_bruteforce_count=100000, detection_spike_threshold=5)
    EventRepository(db).insert_events([_event() for _ in range(6)])
    assert not any(a["rule"] == "traffic_spike" for a in deng.run_cycle())


def test_notification_cooldown_suppresses_duplicates(db, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        deng,
        "get_smtp_settings",
        lambda mask_password=False: {"smtp_enabled": True, "smtp_host": "h", "smtp_to": "a@b.c"},
    )
    monkeypatch.setattr(
        deng,
        "send_email",
        lambda subject, body, settings=None: (calls.append(subject), {"ok": True, "message": "sent"})[1],
    )
    cfg = {"detection_notify_cooldown_min": 60}
    first = {
        "id": "port_scan:1.2.3.4:1",
        "rule": "port_scan",
        "severity": "warning",
        "src_ip": "1.2.3.4",
        "title": "t",
        "message": "m",
        "details": {},
    }
    deng._store_alert(first)
    deng._notify([first], cfg)
    assert len(calls) == 1
    # Same finding, different window bucket -> suppressed by the cooldown.
    second = {**first, "id": "port_scan:1.2.3.4:2"}
    deng._store_alert(second)
    deng._notify([second], cfg)
    assert len(calls) == 1
    # Cooldown disabled -> it is sent again.
    deng._notify([second], {"detection_notify_cooldown_min": 0})
    assert len(calls) == 2


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
