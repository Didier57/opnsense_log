"""Tests for the OPNsense filter log SSH importer."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.opnsense import filterlog_import as fi
from app.storage.database import Database
from app.storage.repository import EventRepository

LINE_10H = (
    "<134>1 2026-10-06T10:00:00+00:00 host filterlog 1 - [meta sequenceId=\"1\"] "
    "5,,,abcd,vtnet0,match,pass,out,4,0x0,,64,1,0,DF,6,tcp,60,10.0.0.1,8.8.8.8,1234,443,0,S,1,,64240,,"
)
LINE_08H = (
    "<134>1 2026-10-06T08:00:00+00:00 host filterlog 1 - [meta sequenceId=\"2\"] "
    "6,,,abcd,vtnet0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,9.9.9.9,10.0.0.1,5555,22,0,S,1,,64240,,"
)
LINE_07H = (
    "<134>1 2026-10-06T07:00:00+00:00 host filterlog 1 - [meta sequenceId=\"0\"] "
    "7,,,abcd,vtnet0,match,pass,out,4,0x0,,64,1,0,DF,6,tcp,60,10.0.0.1,1.1.1.1,1,80,0,S,1,,64240,,"
)


@pytest.fixture()
def database(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "t.duckdb"))
    monkeypatch.setattr("app.storage.repository.get_database", lambda: db)
    monkeypatch.setattr("app.storage.database.get_database", lambda: db)
    yield db
    db.close()


class FakeSSH:
    def __init__(self, files, lines_by_path):
        self._files = files
        self._lines = lines_by_path

    def run(self, command):
        if "ls -1" in command:
            return "".join(path + "\n" for path in self._files)
        return ""

    def read_lines(self, command):
        for line in self._lines.get(command, []):
            yield line

    def read_chunks(self, command, size=65536):
        data = "\n".join(self._lines.get(command, []))
        if data:
            yield data


def test_file_day_parses_date():
    assert fi._file_day("/var/log/filter/filter_20261006.log") == datetime(2026, 10, 6)
    assert fi._file_day("/var/log/filter/latest.log") is None


def test_import_file_respects_watermark(database):
    repo = EventRepository()
    ssh = FakeSSH([], {f"cat /var/log/filter/filter_20261006.log": [LINE_10H, LINE_08H]})
    fi.import_job._reset_run()
    after = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)
    before = datetime(2026, 10, 7, tzinfo=timezone.utc)
    fi._import_file(repo, ssh, "/var/log/filter/filter_20261006.log", after, before)
    assert fi.import_job.inserted == 1
    assert fi.import_job.skipped == 1
    assert fi.import_job.invalid == 0
    assert repo.count() == 1


def test_import_file_splits_concatenated_records(database):
    repo = EventRepository()
    path = "/var/log/filter/filter_20261006.log"
    blob = LINE_10H + LINE_08H  # two records concatenated with no separator
    ssh = FakeSSH([], {f"cat {path}": [blob]})
    fi.import_job._reset_run()
    fi._import_file(repo, ssh, path, None, None)
    assert fi.import_job.parsed == 2
    assert fi.import_job.inserted == 2
    assert repo.count() == 2


def test_run_import_gap_mode(database, monkeypatch):
    path = "/var/log/filter/filter_20261006.log"
    repo = EventRepository()
    # Seed one older event so the day is only partially covered (gap to fill).
    seed = FakeSSH([], {f"cat {path}": [LINE_07H]})
    fi.import_job._reset_run()
    fi._import_file(repo, seed, path, None, None)
    ssh = FakeSSH([path], {f"cat {path}": [LINE_10H, LINE_08H]})
    monkeypatch.setattr(fi, "_build_ssh", lambda: ssh)
    result = fi.run_import()
    assert result["error"] is None
    assert result["files_total"] == 1
    assert result["files_imported"] == 1
    assert result["inserted"] == 2
    assert repo.count() == 3


def test_run_import_empty_db_skips_all(database, monkeypatch):
    path = "/var/log/filter/filter_20261006.log"
    ssh = FakeSSH([path], {f"cat {path}": [LINE_10H, LINE_08H]})
    monkeypatch.setattr(fi, "_build_ssh", lambda: ssh)
    result = fi.run_import()
    assert result["error"] is None
    assert result["files_skipped"] == 1
    assert result["files_imported"] == 0
    assert result["inserted"] == 0
    assert EventRepository().count() == 0


def test_heartbeat_roundtrip(database):
    when = datetime(2026, 10, 6, 9, 30, tzinfo=timezone.utc)
    fi.set_last_run(when)
    assert fi._get_last_run(EventRepository()) == when


def test_run_import_fills_gap_after_newest_event(database, monkeypatch):
    path = "/var/log/filter/filter_20261006.log"
    repo = EventRepository()
    # Seed records at 07:00 and 08:00 so the newest stored event is 08:00.
    seed = FakeSSH([], {f"cat {path}": [LINE_07H, LINE_08H]})
    fi.import_job._reset_run()
    fi._import_file(repo, seed, path, None, None)
    assert repo.count() == 2
    # The file still contains the already-stored 07:00/08:00 plus a new 10:00;
    # only the record newer than the newest stored event must be imported.
    ssh = FakeSSH([path], {f"cat {path}": [LINE_07H, LINE_08H, LINE_10H]})
    monkeypatch.setattr(fi, "_build_ssh", lambda: ssh)
    result = fi.run_import(until=datetime(2026, 10, 6, 10, 30, tzinfo=timezone.utc))
    assert result["error"] is None
    assert result["inserted"] == 1
    assert repo.count() == 3


def test_run_import_skips_covered_day(database, monkeypatch):
    path = "/var/log/filter/filter_20261006.log"
    repo = EventRepository()
    seed = FakeSSH([], {f"cat {path}": [LINE_10H]})
    fi.import_job._reset_run()
    fi._import_file(repo, seed, path, None, None)
    # Heartbeat after the day is over -> the whole day file must be skipped.
    fi.set_last_run(datetime(2026, 10, 8, tzinfo=timezone.utc))
    ssh = FakeSSH([path], {f"cat {path}": [LINE_08H]})
    monkeypatch.setattr(fi, "_build_ssh", lambda: ssh)
    result = fi.run_import()
    assert result["files_skipped"] == 1
    assert result["inserted"] == 0
    assert repo.count() == 1


def test_first_event_after(database):
    path = "/var/log/filter/filter_20261006.log"
    repo = EventRepository()
    seed = FakeSSH([], {f"cat {path}": [LINE_07H, LINE_10H]})
    fi.import_job._reset_run()
    fi._import_file(repo, seed, path, None, None)
    assert fi.first_event_after(None) == datetime(2026, 10, 6, 7, 0, tzinfo=timezone.utc)
    assert fi.first_event_after(datetime(2026, 10, 6, 7, 0, tzinfo=timezone.utc)) == datetime(
        2026, 10, 6, 10, 0, tzinfo=timezone.utc
    )
    assert fi.first_event_after(datetime(2026, 10, 6, 10, 0, tzinfo=timezone.utc)) is None


def test_run_import_until_caps_window(database, monkeypatch):
    path = "/var/log/filter/filter_20261006.log"
    repo = EventRepository()
    # Seed 07:00 only so the newest stored event (overall) is 07:00.
    seed = FakeSSH([], {f"cat {path}": [LINE_07H]})
    fi.import_job._reset_run()
    fi._import_file(repo, seed, path, None, None)
    ssh = FakeSSH([path], {f"cat {path}": [LINE_08H, LINE_10H]})
    monkeypatch.setattr(fi, "_build_ssh", lambda: ssh)
    # until=08:30 caps the window: only the 08:00 record is imported, the 10:00
    # one is left to live syslog (already covered).
    result = fi.run_import(until=datetime(2026, 10, 6, 8, 30, tzinfo=timezone.utc))
    assert result["error"] is None
    assert result["inserted"] == 1
    assert result["skipped"] == 1
    assert repo.count() == 2


def test_start_import_rejects_concurrent():
    fi.import_job._reset_run()
    fi.import_job.running = True
    try:
        assert fi.start_import() is False
    finally:
        fi.import_job.running = False
