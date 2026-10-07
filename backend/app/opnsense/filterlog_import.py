"""Import firewall filter logs directly from OPNsense over SSH.

OPNsense keeps one file per day in ``/var/log/filter/filter_YYYYMMDD.log``
(``latest.log`` is a symlink to the current file).  Files can be several
hundred MB, so they are streamed in chunks and inserted in batches.

Records are syslog framed (they start with a ``<PRI>`` marker) but are NOT
reliably newline separated (several records can be concatenated on one line),
so the stream is split on the ``<PRI>`` marker instead of newlines.

The importer fills the gap left while the container was down.  The gap is the
downtime window ``(last_run, now)`` where ``last_run`` is a persistent heartbeat
recorded while the application is running.  Every day file is intersected with
this window and only the matching records are imported, so a gap located in the
middle of a day (or spanning several days) is filled too, without re-reading
days that are already covered.  When the database is still empty nothing is
imported automatically (a heavy full history backfill is left to the manual
button).  ``full=True`` re-imports every line regardless of the window.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone

from ..parser import parse_message
from ..parser.tz import source_tz
from ..storage.repository import EventRepository
from .settings_store import get_opnsense_settings
from .ssh import OPNsenseSSH

logger = logging.getLogger("opnsense.filterlog_import")

LOG_DIR = "/var/log/filter"
BATCH_SIZE = 5000
CHUNK_SIZE = 65536
_DATE_RE = re.compile(r"filter_(\d{8})\.log$")
_PRI_RE = re.compile(r"<\d{1,3}>")


class ImportJob:
    """Shared progress state for the (single) background import job."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reset_run()

    def _reset_run(self) -> None:
        self.running = False
        self.started_at: datetime | None = None
        self.finished_at: datetime | None = None
        self.current_file: str | None = None
        self.error: str | None = None
        self.files_total = 0
        self.files_scanned = 0
        self.files_imported = 0
        self.files_skipped = 0
        self.lines = 0
        self.parsed = 0
        self.invalid = 0
        self.skipped = 0
        self.inserted = 0

    def begin(self) -> None:
        with self._lock:
            self._reset_run()
            self.running = True
            self.started_at = datetime.now(timezone.utc)

    def finish(self, error: str | None = None) -> None:
        with self._lock:
            self.running = False
            self.error = error
            self.finished_at = datetime.now(timezone.utc)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "running": self.running,
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
                "current_file": self.current_file,
                "error": self.error,
                "files_total": self.files_total,
                "files_scanned": self.files_scanned,
                "files_imported": self.files_imported,
                "files_skipped": self.files_skipped,
                "lines": self.lines,
                "parsed": self.parsed,
                "invalid": self.invalid,
                "skipped": self.skipped,
                "inserted": self.inserted,
            }


import_job = ImportJob()


def _build_ssh() -> OPNsenseSSH:
    cfg = get_opnsense_settings(mask_password=False)
    if not cfg.get("opnsense_host"):
        raise RuntimeError("OPNsense host not configured")
    return OPNsenseSSH(
        host=cfg["opnsense_host"],
        port=cfg["opnsense_ssh_port"],
        username=cfg["opnsense_username"],
        password=cfg["opnsense_password"],
        key_path=cfg["opnsense_key_path"],
        auth_type=cfg["opnsense_auth_type"],
    )


def _file_day(path: str) -> datetime | None:
    match = _DATE_RE.search(path)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%Y%m%d")
    except ValueError:
        return None


def _day_window(day: datetime) -> tuple[datetime, datetime]:
    """Return the UTC [start, end) window covering a local calendar day."""
    tz = source_tz()
    start_local = day.replace(tzinfo=tz)
    end_local = (day + timedelta(days=1)).replace(tzinfo=tz)
    return start_local.astimezone(timezone.utc), end_local.astimezone(timezone.utc)


def _list_log_files(ssh: OPNsenseSSH) -> list[str]:
    command = f"sh -c 'ls -1 {LOG_DIR}/filter_*.log 2>/dev/null'"
    output = ssh.run(command)
    return sorted(line.strip() for line in output.splitlines() if line.strip())


def _global_max_event_time(repo: EventRepository) -> datetime | None:
    row = repo.db.execute_read('SELECT MAX("event_time") FROM events').fetchone()
    return row[0] if row else None


_LAST_RUN_KEY = "import_last_run_at"


def _get_last_run(repo: EventRepository) -> datetime | None:
    """Return the last recorded heartbeat (when the app was known to be up)."""
    try:
        row = repo.db.execute_read(
            'SELECT "value" FROM app_settings WHERE "key" = ?', [_LAST_RUN_KEY]
        ).fetchone()
    except Exception:  # noqa: BLE001 - best effort
        return None
    if not row or not row[0]:
        return None
    try:
        value = datetime.fromisoformat(row[0])
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def set_last_run(when: datetime | None = None) -> None:
    """Persist a heartbeat so the next startup knows the downtime window."""
    moment = (when or datetime.now(timezone.utc)).astimezone(timezone.utc)
    repo = EventRepository()
    repo.db.execute_write(
        'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
        'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", "updated_at" = now()',
        [_LAST_RUN_KEY, moment.isoformat()],
    )


def _iter_records(ssh: OPNsenseSSH, path: str):
    """Yield complete syslog records from a remote file.

    Records start with a ``<PRI>`` marker and may be concatenated without a
    newline, so the stream is reassembled from chunks and split on ``<PRI>``.
    """
    buffer = ""
    for chunk in ssh.read_chunks(f"cat {path}", CHUNK_SIZE):
        buffer += chunk
        marks = [match.start() for match in _PRI_RE.finditer(buffer)]
        if len(marks) < 2:
            continue
        for index in range(len(marks) - 1):
            yield buffer[marks[index]:marks[index + 1]]
        buffer = buffer[marks[-1]:]
    match = _PRI_RE.search(buffer)
    if match:
        tail = buffer[match.start():].strip()
        if tail:
            yield tail


def _import_file(
    repo: EventRepository,
    ssh: OPNsenseSSH,
    path: str,
    after: datetime | None = None,
    before: datetime | None = None,
    windows: list[tuple[datetime, datetime]] | None = None,
) -> None:
    """Import records from a remote file.

    When ``windows`` is given, only records whose event time falls inside one of
    the ``[start, end)`` windows are kept; otherwise the ``after``/``before``
    bounds are used.
    """
    batch = []
    for record in _iter_records(ssh, path):
        import_job.lines += 1
        stripped = record.strip()
        if not stripped:
            continue
        result = parse_message(stripped)
        event = result.event
        if event is None or event.event_time is None:
            import_job.invalid += 1
            continue
        when = event.event_time
        if windows is not None:
            if not any(start <= when < end for start, end in windows):
                import_job.skipped += 1
                continue
        elif (after is not None and when <= after) or (before is not None and when >= before):
            import_job.skipped += 1
            continue
        batch.append(event)
        import_job.parsed += 1
        if len(batch) >= BATCH_SIZE:
            repo.insert_events(batch)
            import_job.inserted += len(batch)
            batch = []
            # Yield the CPU between batches so a large backfill does not peg a
            # core on low-power firewalls/servers.
            time.sleep(0.05)
    if batch:
        repo.insert_events(batch)
        import_job.inserted += len(batch)


def run_import(full: bool = False) -> dict:
    """Scan all OPNsense filter log files and import what is missing.

    ``full=True`` re-imports every line regardless of the stored watermark
    (may create duplicates); the default mode only fills the gaps.
    """
    import_job.begin()
    try:
        ssh = _build_ssh()
        repo = EventRepository()
        files = _list_log_files(ssh)
        import_job.files_total = len(files)
        logger.info("Filter log import: %d file(s) found", len(files))
        # In gap mode we only fill the downtime window (last heartbeat, now):
        # each day file is intersected with it, so gaps sitting in the middle of
        # a day are filled too, while days already covered are never read. When
        # the database is empty (fresh install) nothing is imported automatically
        # so startup never triggers a heavy multi-day scan.
        overall = None if full else _global_max_event_time(repo)
        last_run = None if full else _get_last_run(repo)
        now = datetime.now(timezone.utc)
        for path in files:
            import_job.current_file = path
            day = _file_day(path)
            if full or day is None:
                _import_file(repo, ssh, path)
                import_job.files_imported += 1
                import_job.files_scanned += 1
                continue
            start, end = _day_window(day)
            if overall is None:
                import_job.files_skipped += 1
                import_job.files_scanned += 1
                continue
            lower = last_run or overall
            window_start = max(start, lower)
            window_end = min(end, now)
            if window_start >= window_end:
                import_job.files_skipped += 1
                import_job.files_scanned += 1
                continue
            _import_file(repo, ssh, path, windows=[(window_start, window_end)])
            import_job.files_imported += 1
            import_job.files_scanned += 1
        if not full:
            # Record that we are up to date so the next restart only re-scans
            # the downtime window.
            try:
                set_last_run(now)
            except Exception:  # noqa: BLE001 - heartbeat must not fail the job
                logger.exception("Could not persist import heartbeat")
        logger.info(
            "Filter log import done: %d file(s), %d line(s), %d inserted",
            import_job.files_imported,
            import_job.lines,
            import_job.inserted,
        )
        import_job.finish()
    except Exception as exc:  # noqa: BLE001 - background job must not raise
        logger.exception("Filter log import failed")
        import_job.finish(str(exc))
    return import_job.snapshot()


def start_import(full: bool = False) -> bool:
    """Start the import in a background thread. Returns False if already running."""
    with import_job._lock:
        if import_job.running:
            return False
    thread = threading.Thread(
        target=run_import, kwargs={"full": full}, name="filterlog-import", daemon=True
    )
    thread.start()
    return True
