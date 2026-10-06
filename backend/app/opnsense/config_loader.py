"""Parsing of the OPNsense ``config.xml`` into interfaces and firewall rules.

A single SSH ``cat /conf/config.xml`` gives us everything needed to map
``filterlog`` device names to friendly names and to resolve rule trackers.

Important: the 4th field of an OPNsense ``filterlog`` line (e.g.
``cd4617bd680a0a5aa4c5694f2eefa56e``) is **not** the numeric ``<tracker>``
element stored in the config. OPNsense labels every pf rule with a hash
computed by ``OPNsense\\Firewall\\Util::calcRuleHash``::

    md5(json_encode($rule_without_descr_updated_created, keys sorted))

The rule description is resolved by computing that same hash for every rule in
``config.xml`` and matching it against the value found in the log line. This
module reproduces the OPNsense XML-to-array conversion (``Config::toArray``)
and the PHP ``calcRuleHash`` byte-for-byte so the mapping works.
"""
from __future__ import annotations

import hashlib
import json
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


def to_array(node: ET.Element) -> dict:
    """Replicate ``OPNsense\\Core\\Config::toArray`` for a single element.

    Text-only children become strings, children with sub-elements become nested
    dicts and repeated sibling tags become lists. All values are strings, exactly
    like the PHP implementation (which casts every leaf to ``(string)``).
    """
    result: dict = {}
    if node.attrib:
        result["@attributes"] = {key: value for key, value in node.attrib.items()}

    for child in list(node):
        name = child.tag
        if len(list(child)) > 0:
            tmp = to_array(child)
            if name in result:
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(tmp)
            else:
                result[name] = tmp
        else:
            value = child.text if child.text is not None else ""
            if name in result:
                if not isinstance(result[name], list):
                    result[name] = [result[name]]
                result[name].append(value)
            else:
                result[name] = value
                for attr_key, attr_value in child.attrib.items():
                    attributes = result.get(f"{name}@attributes") or {}
                    attributes[attr_key] = attr_value
                    result[f"{name}@attributes"] = attributes
    return result


def _php_json(value: object) -> str:
    """``json_encode``-compatible serialisation (no spaces, escaped slashes)."""
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).replace("/", "\\/")


def calc_rule_hash(rule: dict) -> str:
    """Reproduce ``OPNsense\\Firewall\\Util::calcRuleHash`` exactly."""
    filtered = {key: value for key, value in rule.items() if key not in ("updated", "created", "descr")}
    ordered: dict = {}
    for key in sorted(filtered.keys()):
        value = filtered[key]
        if isinstance(value, dict):
            value = {sub_key: value[sub_key] for sub_key in sorted(value.keys())}
        ordered[key] = value
    return hashlib.md5(_php_json(ordered).encode("utf-8")).hexdigest()


def _source_to_str(element: ET.Element | None) -> str:
    if element is None:
        return ""
    if element.find("any") is not None:
        base = "*"
    else:
        base = _text(element, "address") or _text(element, "network")
    port = _text(element, "port")
    value = f"{base}:{port}" if port else base
    if element.find("not") is not None:
        value = f"!{value}"
    return value


def parse_rules(root: ET.Element) -> list[dict]:
    """Return rules keyed by the OPNsense log label (``calcRuleHash``)."""
    rules: list[dict] = []
    filter_el = root.find("filter")
    if filter_el is None:
        return rules
    for rule in filter_el.findall("rule"):
        rule_array = to_array(rule)
        label = calc_rule_hash(rule_array)
        rules.append(
            {
                "rule_id": label,
                "label": label,
                "tracker": _text(rule, "tracker"),
                "rule_number": None,
                "description": _text(rule, "descr"),
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


def parse_config(contents: str) -> tuple[list[dict], list[dict]]:
    root = ET.fromstring(contents)
    return parse_interfaces(root), parse_rules(root)
