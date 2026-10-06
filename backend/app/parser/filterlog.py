"""Decoder for the OPNsense ``filterlog`` CSV payload.

The payload is the text that follows the ``filterlog:`` syslog tag. It is a
comma-separated list whose leading fields are common to every packet and whose
trailing fields depend on the transport protocol.

Example::

    30,,,cd4617bd680a0a5aa4c5694f2eefa56e,vtnet0,match,pass,out,4,0x0,,62,
    35294,0,DF,6,tcp,60,10.13.37.2,191.101.31.14,29397,29376,0,S,1162654291,
    ,64240,,mss;sackOK;TS;nop;wscale
"""
from __future__ import annotations

from datetime import datetime, timezone

from .models import FirewallEvent

_PROTO_ID_TO_NAME = {
    1: "icmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    51: "ah",
    58: "icmpv6",
}


def _int(value: str) -> int | None:
    value = value.strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _field(parts: list[str], index: int) -> str:
    if 0 <= index < len(parts):
        return parts[index].strip()
    return ""


def parse_payload(
    payload: str,
    event_time: datetime | None = None,
    hostname: str = "",
    fmt: str = "filterlog",
) -> FirewallEvent | None:
    """Parse a filterlog CSV payload into a :class:`FirewallEvent`.

    Returns ``None`` when the payload is not a recognisable filterlog line.
    """
    raw = payload.strip()
    if not raw:
        return None

    # Strip a leading "filterlog:" tag if the caller passed the full message.
    lower = raw.lower()
    if lower.startswith("filterlog:"):
        raw = raw[len("filterlog:"):].strip()
    elif lower.startswith("filterlog "):
        raw = raw[len("filterlog "):].strip()

    parts = raw.split(",")
    # A valid filterlog line always carries at least the common prefix and its
    # first field (rule number) is numeric. This guards against other syslog
    # payloads being mis-detected as filterlog.
    if len(parts) < 9 or _int(_field(parts, 0)) is None:
        return None

    protocol = _field(parts, 16).lower()
    protocol_id = _int(_field(parts, 15))
    if not protocol and protocol_id is not None:
        protocol = _PROTO_ID_TO_NAME.get(protocol_id, "")

    event = FirewallEvent(
        event_time=event_time or datetime.now(timezone.utc),
        rule_number=_int(_field(parts, 0)),
        sub_rule=_field(parts, 1),
        anchor=_field(parts, 2),
        rule_id=_field(parts, 3),
        interface=_field(parts, 4),
        reason=_field(parts, 5),
        action=_field(parts, 6).lower(),
        direction=_field(parts, 7).lower(),
        ip_version=_int(_field(parts, 8)),
        tos=_field(parts, 9),
        ecn=_field(parts, 10),
        ttl=_int(_field(parts, 11)),
        packet_id=_int(_field(parts, 12)),
        offset=_int(_field(parts, 13)),
        flags=_field(parts, 14),
        protocol_id=protocol_id,
        protocol=protocol,
        length=_int(_field(parts, 17)),
        src_ip=_field(parts, 18),
        dst_ip=_field(parts, 19),
        hostname=hostname,
        raw=raw,
        format=fmt,
        parse_status="partial",
    )

    _parse_transport(event, parts)
    return event


def _parse_transport(event: FirewallEvent, parts: list[str]) -> None:
    protocol = event.protocol
    if protocol == "tcp":
        event.src_port = _int(_field(parts, 20))
        event.dst_port = _int(_field(parts, 21))
        event.data_length = _int(_field(parts, 22))
        event.tcp_flags = _field(parts, 23)
        event.seq = _field(parts, 24)
        event.ack = _field(parts, 25)
        event.window = _field(parts, 26)
        event.urg = _field(parts, 27)
        event.options = _field(parts, 28)
        event.parse_status = "ok"
    elif protocol == "udp":
        event.src_port = _int(_field(parts, 20))
        event.dst_port = _int(_field(parts, 21))
        event.data_length = _int(_field(parts, 22))
        event.parse_status = "ok"
    elif protocol in {"icmp", "icmpv6"}:
        event.icmp_type = _field(parts, 20)
        event.icmp_code = _field(parts, 21)
        event.icmp_id = _field(parts, 22)
        event.icmp_seq = _field(parts, 23)
        event.src_port = _int(event.icmp_type)
        event.dst_port = _int(event.icmp_code)
        event.parse_status = "ok"
    elif protocol in {"gre", "esp", "ah"}:
        event.src_port = _int(_field(parts, 20))
        event.dst_port = _int(_field(parts, 21))
        event.parse_status = "ok"
    else:
        # Unknown / other protocol: best-effort port extraction.
        event.src_port = _int(_field(parts, 20))
        event.dst_port = _int(_field(parts, 21))
        event.parse_status = "partial"
