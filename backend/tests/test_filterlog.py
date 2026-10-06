from datetime import timezone

from app.parser import parse_message
from app.parser.filterlog import parse_payload

EXAMPLE = (
    "2025-09-08T20:31:34 filterlog 30,,,cd4617bd680a0a5aa4c5694f2eefa56e,vtnet0,"
    "match,pass,out,4,0x0,,62,35294,0,DF,6,tcp,60,10.13.37.2,191.101.31.14,"
    "29397,29376,0,S,1162654291,,64240,,mss;sackOK;TS;nop;wscale"
)


def test_example_line_from_spec():
    result = parse_message(EXAMPLE)
    assert result.status == "ok"
    event = result.event
    assert event.rule_number == 30
    assert event.rule_id == "cd4617bd680a0a5aa4c5694f2eefa56e"
    assert event.interface == "vtnet0"
    assert event.reason == "match"
    assert event.action == "pass"
    assert event.direction == "out"
    assert event.ip_version == 4
    assert event.protocol == "tcp"
    assert event.src_ip == "10.13.37.2"
    assert event.dst_ip == "191.101.31.14"
    assert event.src_port == 29397
    assert event.dst_port == 29376
    assert event.tcp_flags == "S"
    assert event.options == "mss;sackOK;TS;nop;wscale"
    assert event.event_time.year == 2025
    assert event.event_time.tzinfo == timezone.utc
    assert event.format == "custom"


def test_ipv4_udp():
    payload = "5,,,uuid,em0,match,block,in,4,0x0,,64,0,0,DF,17,udp,40,1.1.1.1,2.2.2.2,5353,53,12"
    event = parse_payload(payload)
    assert event.protocol == "udp"
    assert event.src_port == 5353
    assert event.dst_port == 53
    assert event.data_length == 12
    assert event.action == "block"
    assert event.parse_status == "ok"


def test_ipv6_tcp():
    payload = (
        "7,,,uuid,em1,match,pass,in,6,0x0,,64,0,0,,6,tcp,60,"
        "2001:db8::1,2001:db8::2,443,51000,0,SA,,,64240,,mss"
    )
    event = parse_payload(payload)
    assert event.ip_version == 6
    assert event.protocol == "tcp"
    assert event.src_ip == "2001:db8::1"
    assert event.tcp_flags == "SA"


def test_icmp():
    payload = "2,,,uuid,em0,match,pass,out,4,0x0,,64,1,0,,1,icmp,84,10.0.0.1,8.8.8.8,8,0,1234,1"
    event = parse_payload(payload)
    assert event.protocol == "icmp"
    assert event.icmp_type == "8"
    assert event.icmp_code == "0"
    assert event.icmp_id == "1234"
    assert event.icmp_seq == "1"


def test_missing_fields_does_not_raise():
    payload = "1,,,uuid,em0,match,pass,out,4"
    event = parse_payload(payload)
    assert event is not None
    assert event.parse_status == "partial"
    assert event.src_ip == ""


def test_invalid_line():
    result = parse_message("this is not a filterlog line at all")
    assert result.status == "invalid"
    assert result.event is None
