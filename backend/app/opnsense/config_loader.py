"""Parsing of the OPNsense ``config.xml`` into interfaces and firewall rules.

A single SSH ``cat /conf/config.xml`` gives us everything needed to map
``filterlog`` device names to friendly names and to resolve rule trackers.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET


def _text(element: ET.Element | None, tag: str, default: str = "") -> str:
    if element is None:
        return default
    child = element.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def parse_interfaces(root: ET.Element) -> list[dict]:
    """Return ``[{name, device, description, ipv4, ipv6}]``."""
    interfaces: list[dict] = []
    container = root.find("interfaces")
    if container is None:
        return interfaces
    for iface in container:
        name = iface.tag
        device = _text(iface, "if")
        description = _text(iface, "descr") or name.upper()
        ipv4 = _text(iface, "ipaddr")
        ipv6 = _text(iface, "ipaddrv6")
        interfaces.append(
            {
                "name": name,
                "device": device,
                "description": description,
                "ipv4": ipv4,
                "ipv6": ipv6,
            }
        )
    return interfaces


def parse_rules(root: ET.Element) -> list[dict]:
    """Return ``[{rule_id, description, interface, action, direction, ...}]``."""
    rules: list[dict] = []
    filter_el = root.find("filter")
    if filter_el is None:
        return rules
    for rule in filter_el.findall("rule"):
        tracker = _text(rule, "tracker")
        description = _text(rule, "descr")
        rules.append(
            {
                "rule_id": tracker,
                "rule_number": None,
                "description": description,
                "interface": _text(rule, "interface"),
                "action": _text(rule, "type", "pass"),
                "direction": _text(rule, "direction", "in"),
                "protocol": _text(rule, "protocol", "any"),
                "source": _source_to_str(rule.find("source")),
                "destination": _source_to_str(rule.find("destination")),
                "enabled": _text(rule, "disabled") != "1",
            }
        )
    return rules


def _source_to_str(element: ET.Element | None) -> str:
    if element is None:
        return ""
    network = _text(element, "network")
    address = _text(element, "address")
    port = _text(element, "port")
    value = address or network
    if port:
        value = f"{value}:{port}"
    return value


def parse_config(contents: str) -> tuple[list[dict], list[dict]]:
    root = ET.fromstring(contents)
    return parse_interfaces(root), parse_rules(root)
