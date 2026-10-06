"""RFC3164 (BSD syslog) header parsing.

Format::

    <PRI>MMM dd hh:mm:ss HOSTNAME TAG: MESSAGE
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .tz import source_tz

# <PRI>Mon dd hh:mm:ss host tag: msg
_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<tag>[^:\s]+):?\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def parse_header(message: str, year: int | None = None) -> dict | None:
    """Return header components for an RFC3164 line, or ``None`` if no match."""
    match = _RE.match(message)
    if not match:
        return None
    ts_raw = match.group("timestamp")
    try:
        month_s, day_s, time_s = ts_raw.split()
        month = _MONTHS[month_s]
        hh, mm, ss = (int(x) for x in time_s.split(":"))
        tz = source_tz()
        year = year or datetime.now(tz).year
        # RFC3164 timestamps carry no offset: interpret them in the firewall's
        # local timezone, then normalise to UTC for storage.
        ts = datetime(year, month, int(day_s), hh, mm, ss, tzinfo=tz).astimezone(timezone.utc)
    except (ValueError, KeyError):
        return None
    return {
        "priority": int(match.group("pri")),
        "timestamp": ts,
        "hostname": match.group("host"),
        "tag": match.group("tag"),
        "message": match.group("msg"),
        "format": "rfc3164",
    }
