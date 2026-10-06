from app.parser import parse_message
from app.parser.rfc3164 import parse_header as parse3164
from app.parser.rfc5424 import parse_header as parse5424

CSV = (
    "30,,,cd4617bd680a0a5aa4c5694f2eefa56e,vtnet0,match,pass,out,4,0x0,,62,"
    "35294,0,DF,6,tcp,60,10.13.37.2,191.101.31.14,29397,29376,0,S,1162654291,,64240,,mss"
)


def test_rfc3164_header():
    line = f"<134>Sep  8 20:31:34 firewall filterlog: {CSV}"
    header = parse3164(line)
    assert header is not None
    assert header["hostname"] == "firewall"
    assert header["tag"] == "filterlog"
    assert header["timestamp"].month == 9


def test_rfc3164_message_parsed():
    line = f"<134>Sep  8 20:31:34 firewall filterlog: {CSV}"
    result = parse_message(line)
    assert result.status == "ok"
    assert result.event.src_ip == "10.13.37.2"
    assert result.event.format == "rfc3164"


def test_rfc5424_header():
    line = f"<134>1 2025-09-08T20:31:34.000Z firewall filterlog - - - {CSV}"
    header = parse5424(line)
    assert header is not None
    assert header["hostname"] == "firewall"
    assert header["tag"] == "filterlog"


def test_rfc5424_message_parsed():
    line = f"<134>1 2025-09-08T20:31:34.000Z firewall filterlog - - - {CSV}"
    result = parse_message(line)
    assert result.status == "ok"
    assert result.event.rule_id == "cd4617bd680a0a5aa4c5694f2eefa56e"
    assert result.event.format == "rfc5424"
