from datetime import datetime, timedelta, timezone

from app.parser.models import FirewallEvent
from app.storage.database import Database
from app.storage.repository import EventRepository

BASE = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


def _event(hours_ago: int) -> FirewallEvent:
    return FirewallEvent(
        event_time=BASE - timedelta(hours=hours_ago),
        action="pass",
        protocol="tcp",
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
    )


def test_compact_events_reorders_and_counts(tmp_path):
    db = Database(str(tmp_path / "compact.duckdb"))
    repo = EventRepository(db)
    repo.insert_events([_event(h) for h in (5, 1, 3, 0, 2)])

    assert db.compact_events() == 5

    times = [row[0] for row in db.execute_read('SELECT "event_time" FROM events').fetchall()]
    assert times == sorted(times)
    assert EventRepository(db).count() == 5
    db.close()


def test_compact_events_is_idempotent(tmp_path):
    db = Database(str(tmp_path / "compact2.duckdb"))
    EventRepository(db).insert_events([_event(0)])

    assert db.compact_events() == 1
    assert db.compact_events() == 1
    db.close()


def test_delete_events_before_returns_count(tmp_path):
    db = Database(str(tmp_path / "retention.duckdb"))
    repo = EventRepository(db)
    repo.insert_events([_event(h) for h in (48, 30, 2, 1, 0)])

    assert repo.delete_older_than(BASE - timedelta(hours=24)) == 2
    assert repo.count() == 3
    assert repo.delete_older_than(BASE - timedelta(hours=24)) == 0
    db.close()
