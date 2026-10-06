"""Resolve the timezone in which incoming syslog timestamps are expressed.

OPNsense syslog lines carry the firewall's *local* wall-clock time without any
offset. We interpret such naive timestamps in ``SYSLOG_TIMEZONE`` (falling back
to ``DISPLAY_TIMEZONE``) and convert them to UTC before storing them.
"""
from __future__ import annotations

from datetime import timezone, tzinfo
from zoneinfo import ZoneInfo

from ..config import settings


def source_tz() -> tzinfo:
    name = (settings.syslog_timezone or settings.display_timezone or "").strip()
    if not name:
        return timezone.utc
    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - unknown tz name, degrade gracefully
        return timezone.utc
