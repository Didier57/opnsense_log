from datetime import datetime, timedelta, timezone

import pytest

from app.parser.models import FirewallEvent
from app.storage.database import Database
from app.storage.repository import EventRepository

BASE = datetime(2025, 9, 8, 20, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def repo(tmp_path):
    db = Database(str(tmp_path / "test.duckdb"))
    r = EventRepository(db)
    events = [
        FirewallEvent(event_time=BASE, action="pass", protocol="tcp", interface="vtnet0",
                      src_ip="10.13.37.2", dst_ip="8.8.8.8", dst_port=443, rule_id="AAA"),
        FirewallEvent(event_time=BASE + timedelta(minutes=1), action="block", protocol="udp",
                      interface="vtnet1", src_ip="45.12.32.10", dst_ip="10.13.37.5", dst_port=22,
                      rule_id="BBB"),
        FirewallEvent(event_time=BASE + timedelta(minutes=2), action="block", protocol="tcp",
                      interface="vtnet1", src_ip="91.22.13.5", dst_ip="10.13.37.5", dst_port=22,
                      rule_id="BBB"),
    ]
    r.insert_events(events)
    yield r
    db.close()


def test_count(repo):
    assert repo.count() == 3


def test_filter_and(repo):
    res = repo.search(clauses=[
        {"field": "action", "op": "eq", "value": "block"},
        {"field": "interface", "op": "eq", "value": "vtnet1"},
    ], logic="AND")
    assert res["total"] == 2


def test_filter_or(repo):
    res = repo.search(clauses=[
        {"field": "dst_port", "op": "eq", "value": 443},
        {"field": "dst_port", "op": "eq", "value": 22},
    ], logic="OR")
    assert res["total"] == 3


def test_filter_regex(repo):
    res = repo.search(clauses=[{"field": "src_ip", "op": "regex", "value": r"^10\.13\."}])
    assert res["total"] == 1


def test_filter_time_range(repo):
    res = repo.search(start=BASE, end=BASE + timedelta(seconds=90))
    assert res["total"] == 2


def test_filter_ip(repo):
    res = repo.search(clauses=[{"field": "src_ip", "op": "eq", "value": "91.22.13.5"}])
    assert res["total"] == 1


def test_filter_rule(repo):
    res = repo.search(clauses=[{"field": "rule_id", "op": "eq", "value": "BBB"}])
    assert res["total"] == 2


def test_filter_contains(repo):
    res = repo.search(clauses=[{"field": "src_ip", "op": "contains", "value": "10.13"}])
    assert res["total"] == 1


def test_summary(repo):
    s = repo.summary()
    assert s["total"] == 3
    assert s["passed"] == 1
    assert s["blocked"] == 2


def test_top(repo):
    top = repo.top_values("dst_port")
    assert top[0]["value"] == 22
    assert top[0]["count"] == 2


def test_invalid_field_raises(repo):
    with pytest.raises(ValueError):
        repo.search(clauses=[{"field": "drop_table", "op": "eq", "value": "x"}])
