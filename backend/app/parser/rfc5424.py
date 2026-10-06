"""RFC5424 syslog header parsing.

Format::

    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .tz import source_tz

_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>-|\[.*?\])\s*"
    r"(?P<msg>.*)$",
    re.DOTALL,
)


def parse_header(message: str) -> dict | None:
    match = _RE.match(message)
    if not match:
        return None
    ts_raw = match.group("timestamp")
    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=source_tz())
        ts = ts.astimezone(timezone.utc)
    except ValueError:
        return None
    return {
        "priority": int(match.group("pri")),
        "version": int(match.group("version")),
        "timestamp": ts,
        "hostname": match.group("host"),
        "tag": match.group("app"),
        "message": match.group("msg"),
        "format": "rfc5424",
    }
