"""Tests for OPNsense config.xml parsing and rule-label hashing."""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET

from app.opnsense.config_loader import (
    _php_json,
    calc_rule_hash,
    parse_config,
    parse_rules_debug,
    parse_webgui,
    to_array,
)

CONFIG = """<?xml version="1.0"?>
<opnsense>
  <interfaces>
    <lan>
      <if>vtnet0</if>
      <descr>LAN</descr>
      <ipaddr>10.13.37.1</ipaddr>
    </lan>
    <wan>
      <if>vtnet1</if>
      <descr>WAN</descr>
      <ipaddr>191.101.31.1</ipaddr>
    </wan>
  </interfaces>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <descr>Allow outbound web</descr>
      <direction>out</direction>
      <tracker>1605514712</tracker>
      <source><network>lan</network></source>
      <destination><any>1</any><port>443</port></destination>
    </rule>
    <rule>
      <type>block</type>
      <interface>wan</interface>
      <descr>Block telnet</descr>
      <direction>in</direction>
      <tracker>1605514799</tracker>
      <source><any>1</any></source>
      <destination><any>1</any><port>23</port></destination>
      <disabled>1</disabled>
    </rule>
  </filter>
</opnsense>
"""


def test_php_json_matches_php_encoding():
    # json_encode(['any' => '1'])
    assert _php_json({"any": "1"}) == '{"any":"1"}'
    # json_encode(['network' => 'lan', 'port' => '80'])  (sorted keys)
    assert _php_json({"network": "lan", "port": "80"}) == '{"network":"lan","port":"80"}'
    # PHP escapes forward slashes by default
    assert _php_json({"address": "10.0.0.0/8"}) == '{"address":"10.0.0.0\\/8"}'
    # no spaces after separators
    assert " " not in _php_json({"a": "1", "b": {"c": "2"}})


def test_to_array_reproduces_opnsense_structure():
    root = ET.fromstring(CONFIG)
    rule = root.find("filter").find("rule")
    arr = to_array(rule)
    assert arr["type"] == "pass"
    assert arr["descr"] == "Allow outbound web"
    assert arr["tracker"] == "1605514712"
    assert arr["source"] == {"network": "lan"}
    assert arr["destination"] == {"any": "1", "port": "443"}


def test_calc_rule_hash_is_deterministic_md5():
    rule = {
        "type": "pass",
        "interface": "lan",
        "descr": "Allow outbound web",
        "direction": "out",
        "tracker": "1605514712",
        "source": {"network": "lan"},
        "destination": {"port": "443", "any": "1"},
    }
    expected_json = (
        '{"destination":{"any":"1","port":"443"},"direction":"out",'
        '"interface":"lan","source":{"network":"lan"},'
        '"tracker":"1605514712","type":"pass"}'
    )
    expected = hashlib.md5(expected_json.encode("utf-8")).hexdigest()
    got = calc_rule_hash(rule)
    assert got == expected
    assert len(got) == 32 and all(c in "0123456789abcdef" for c in got)


def test_calc_rule_hash_ignores_description_changes():
    base = {"type": "pass", "interface": "lan", "descr": "one", "tracker": "1"}
    changed = {"type": "pass", "interface": "lan", "descr": "two", "tracker": "1"}
    assert calc_rule_hash(base) == calc_rule_hash(changed)


def test_calc_rule_hash_changes_with_matching_fields():
    base = {"type": "pass", "interface": "lan", "destination": {"port": "443"}}
    changed = {"type": "pass", "interface": "lan", "destination": {"port": "80"}}
    assert calc_rule_hash(base) != calc_rule_hash(changed)


def test_parse_config_returns_interfaces_and_rules():
    interfaces, rules = parse_config(CONFIG)
    assert {i["name"] for i in interfaces} == {"lan", "wan"}
    assert interfaces[0]["device"] == "vtnet0"
    assert len(rules) == 2
    descriptions = {r["description"] for r in rules}
    assert descriptions == {"Allow outbound web", "Block telnet"}
    for rule in rules:
        assert len(rule["rule_id"]) == 32
        assert rule["rule_id"] == rule["label"]
    disabled = next(r for r in rules if r["description"] == "Block telnet")
    assert disabled["enabled"] is False
    assert disabled["action"] == "block"
    # "any" sources render as "*"
    assert disabled["source"] == "*"


NEW_MODEL_CONFIG = """<?xml version="1.0"?>
<opnsense>
  <OPNsense>
    <Firewall>
      <Filter>
        <rules>
          <rule uuid="cd4617bd680a0a5aa4c5694f2eefa56e">
            <enabled>1</enabled>
            <action>pass</action>
            <interface>lan</interface>
            <direction>out</direction>
            <protocol>tcp</protocol>
            <source_net>lan</source_net>
            <source_port>any</source_port>
            <destination_net>any</destination_net>
            <destination_port>443</destination_port>
            <description>Allow outbound web</description>
          </rule>
          <rule uuid="AABBCCDD-1122-3344-5566-77889900AABB">
            <enabled>0</enabled>
            <action>block</action>
            <interface>wan</interface>
            <protocol>tcp/udp</protocol>
            <source_not>1</source_not>
            <source_net>wan</source_net>
            <destination_net>any</destination_net>
            <description>Block inbound</description>
          </rule>
        </rules>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>
"""


def test_parse_new_model_rules_uses_uuid_as_label():
    _, rules = parse_config(NEW_MODEL_CONFIG)
    assert len(rules) == 2
    web = next(r for r in rules if r["description"] == "Allow outbound web")
    # filterlog logs the rule uuid -> the label is the normalised uuid
    assert web["rule_id"] == "cd4617bd680a0a5aa4c5694f2eefa56e"
    assert web["label"] == web["rule_id"]
    assert web["action"] == "pass"
    assert web["interface"] == "lan"
    assert web["protocol"] == "tcp"
    assert web["direction"] == "out"
    assert web["enabled"] is True
    assert web["destination"] == "any:443"


def test_parse_new_model_rule_id_is_normalised():
    _, rules = parse_config(NEW_MODEL_CONFIG)
    block = next(r for r in rules if r["description"] == "Block inbound")
    # dashes stripped + lowercased so it matches the logged label
    assert block["rule_id"] == "aabbccdd11223344556677889900aabb"
    assert block["enabled"] is False
    assert block["action"] == "block"
    assert block["source"] == "!wan"


RULES_DEBUG = """
pass in log quick on vlan0.10 inet from any to any flags S/SA keep state tag "abc" label "f1cfa12fd466e923172927c2557b172f" # let out anything from firewall host itself (force gw)
block drop in log quick on vtnet1 inet from any to any label "cd4617bd680a0a5aa4c5694f2eefa56e" # Default allow LAN to any rule
rdr on vtnet1 inet proto tcp from any to any label "aabbccdd11223344556677889900aabb" # nat rule
"""


def test_parse_rules_debug_extracts_label_and_descr():
    rules = parse_rules_debug(RULES_DEBUG)
    assert len(rules) == 3
    force_gw = next(r for r in rules if r["rule_id"] == "f1cfa12fd466e923172927c2557b172f")
    assert force_gw["description"] == "let out anything from firewall host itself (force gw)"
    assert force_gw["action"] == "pass"
    assert force_gw["direction"] == "in"
    assert force_gw["interface"] == "vlan0.10"

    nat = next(r for r in rules if r["rule_id"] == "aabbccdd11223344556677889900aabb")
    assert nat["description"] == "nat rule"
    assert nat["action"] == "pass"
    assert nat["protocol"] == "tcp"


def test_parse_rules_debug_normalises_dashed_uuid():
    rules = parse_rules_debug('pass on vtnet0 label "AABBCCDD-1122-3344-5566-77889900AABB" # X')
    assert rules[0]["rule_id"] == "aabbccdd11223344556677889900aabb"


def test_parse_webgui_detects_protocol_and_port():
    config = "<opnsense><system><webgui><protocol>http</protocol><port>8080</port></webgui></system></opnsense>"
    assert parse_webgui(config) == {"protocol": "http", "port": 8080}


def test_parse_webgui_defaults_when_missing():
    assert parse_webgui("<opnsense><system></system></opnsense>") == {"protocol": "https", "port": 443}
