"""Modular syslog message parser.

The public entry point is :func:`parse_message`. Parsers are intentionally
independent so that a change in the OPNsense wire format only requires touching
one module.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from . import filterlog, rfc3164, rfc5424
from .models import FirewallEvent, ParseResult
from .tz import source_tz

# OPNsense "simplified" format: ISO timestamp, host tag, payload.
# 2025-09-08T20:31:34 filterlog 30,,,...
_CUSTOM_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\s+(?P<tag>\S+)\s+(?P<msg>.*)$",
    re.DOTALL,
)


def _coerce_dt(value: str) -> datetime:
    value = value.strip().replace(" ", "T")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=source_tz())
    return dt.astimezone(timezone.utc)


class BaseParser:
    name = "base"

    def parse(self, message: str, hostname: str = "") -> FirewallEvent | None:  # pragma: no cover
        raise NotImplementedError


class FilterlogParser(BaseParser):
    """Parse a bare filterlog CSV payload."""

    name = "filterlog"

    def parse(self, message: str, hostname: str = "") -> FirewallEvent | None:
        return filterlog.parse_payload(message, hostname=hostname, fmt="filterlog")


class RFC3164Parser(BaseParser):
    name = "rfc3164"

    def parse(self, message: str, hostname: str = "") -> FirewallEvent | None:
        header = rfc3164.parse_header(message)
        if not header:
            return None
        return filterlog.parse_payload(
            header["message"],
            event_time=header["timestamp"],
            hostname=header.get("hostname", hostname),
            fmt="rfc3164",
        )


class RFC5424Parser(BaseParser):
    name = "rfc5424"

    def parse(self, message: str, hostname: str = "") -> FirewallEvent | None:
        header = rfc5424.parse_header(message)
        if not header:
            return None
        return filterlog.parse_payload(
            header["message"],
            event_time=header["timestamp"],
            hostname=header.get("hostname", hostname),
            fmt="rfc5424",
        )


class CustomParser(BaseParser):
    """Parse the OPNsense simplified ``ISO_TIMESTAMP tag payload`` format."""

    name = "custom"

    def parse(self, message: str, hostname: str = "") -> FirewallEvent | None:
        match = _CUSTOM_RE.match(message.strip())
        if not match:
            return None
        tag = match.group("tag")
        if tag.lower() not in {"filterlog", "filterlog:"}:
            return None
        return filterlog.parse_payload(
            match.group("msg"),
            event_time=_coerce_dt(match.group("ts")),
            hostname=hostname,
            fmt="custom",
        )


_PARSERS: list[BaseParser] = [
    RFC5424Parser(),
    RFC3164Parser(),
    CustomParser(),
    FilterlogParser(),
]


def parse_message(message: str, hostname: str = "") -> ParseResult:
    """Try every parser and return the first successful decode."""
    text = message.strip()
    if not text:
        return ParseResult(event=None, status="invalid", error="empty message")

    for parser in _PARSERS:
        try:
            event = parser.parse(text, hostname=hostname)
        except Exception as exc:  # noqa: BLE001 - never let a bad line crash ingestion
            return ParseResult(event=None, status="invalid", error=f"{parser.name}: {exc}")
        if event is not None:
            return ParseResult(event=event, status=event.parse_status)

    return ParseResult(event=None, status="invalid", error="no parser matched")


__all__ = [
    "parse_message",
    "FilterlogParser",
    "RFC3164Parser",
    "RFC5424Parser",
    "CustomParser",
    "FirewallEvent",
    "ParseResult",
]
