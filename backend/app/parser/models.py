"""Domain models for parsed firewall events."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(slots=True)
class FirewallEvent:
    """A single decoded OPNsense ``filterlog`` event.

    Timestamps are stored in UTC. Optional fields default to ``None`` so that
    malformed or partial lines never break ingestion.
    """

    event_time: datetime
    rule_id: str = ""
    rule_number: int | None = None
    sub_rule: str = ""
    anchor: str = ""
    interface: str = ""
    reason: str = ""
    action: str = ""
    direction: str = ""
    ip_version: int | None = None
    tos: str = ""
    ecn: str = ""
    ttl: int | None = None
    packet_id: int | None = None
    offset: int | None = None
    flags: str = ""
    protocol_id: int | None = None
    protocol: str = ""
    length: int | None = None
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    data_length: int | None = None
    tcp_flags: str = ""
    seq: str = ""
    ack: str = ""
    window: str = ""
    urg: str = ""
    options: str = ""
    icmp_type: str = ""
    icmp_code: str = ""
    icmp_id: str = ""
    icmp_seq: str = ""
    # Metadata
    hostname: str = ""
    raw: str = ""
    format: str = "filterlog"  # filterlog | rfc3164 | rfc5424
    parse_status: str = "ok"  # ok | partial | invalid

    def to_row(self) -> dict:
        row = asdict(self)
        row["event_time"] = self.event_time
        return row

    @property
    def is_block(self) -> bool:
        return self.action.lower() in {"block", "reject"}


@dataclass(slots=True)
class ParseResult:
    event: FirewallEvent | None
    status: str  # ok | invalid
    error: str = ""
    extra: dict = field(default_factory=dict)
