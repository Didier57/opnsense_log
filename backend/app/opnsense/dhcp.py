"""Parse OPNsense DHCP leases (ISC dhcpd and Kea) fetched over SSH.

Supports both the legacy ISC lease files
(`/var/dhcpd/var/db/dhcpd.leases`, `dhcpd6.leases`) and the newer Kea memfile
CSV files (`/var/db/kea/kea-leases4.csv`, `kea-leases6.csv`). The SSH command
concatenates the files, each prefixed with a `###<path>` marker line.
"""
from __future__ import annotations

import csv
import io
import re

_LEASE_PATHS = [
    "/var/dhcpd/var/db/dhcpd.leases",
    "/var/dhcpd/var/db/dhcpd6.leases",
    "/var/db/kea/kea-leases4.csv",
    "/var/db/kea/kea-leases6.csv",
]

_BLOCK_RE = re.compile(r"^(lease|ia-na|ia-pd|iaaddr|ia-ta|host)\s+(\S+)\s*\{")
_HOSTNAME_RE = re.compile(r'client-hostname\s+"([^"]*)"')
_MAC_RE = re.compile(r"hardware ethernet\s+([0-9a-fA-F:]+)")


def fetch_script() -> str:
    """Build the remote shell command that dumps all lease files."""
    parts = [f'echo "###{path}"; cat "{path}" 2>/dev/null' for path in _LEASE_PATHS]
    return "; ".join(parts)


def _norm_hostname(value: str) -> str | None:
    value = (value or "").strip().strip('"').rstrip(".")
    return value or None


def _parse_isc(text: str) -> dict[str, dict]:
    """Parse an ISC dhcpd/dhcpd6 lease file (line/brace based)."""
    out: dict[str, dict] = {}
    stack: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        block = _BLOCK_RE.match(line)
        if block:
            kind, ident = block.group(1), block.group(2)
            addrs = [ident] if kind in ("lease", "iaaddr") else []
            if kind == "iaaddr" and stack:
                stack[-1]["addrs"].append(ident)
            stack.append({"kind": kind, "id": ident, "hostname": None, "mac": "", "addrs": addrs})
            continue
        if line == "}":
            if not stack:
                continue
            frame = stack.pop()
            hostname = frame["hostname"] or next(
                (f["hostname"] for f in reversed(stack) if f["hostname"]), None
            )
            mac = frame["mac"] or next((f["mac"] for f in reversed(stack) if f["mac"]), "")
            if hostname:
                for ip in frame["addrs"]:
                    out.setdefault(ip, {"ip": ip, "hostname": hostname, "mac": mac})
            continue
        host_match = _HOSTNAME_RE.search(line)
        if host_match and stack:
            stack[-1]["hostname"] = _norm_hostname(host_match.group(1))
        mac_match = _MAC_RE.search(line)
        if mac_match and stack:
            stack[-1]["mac"] = mac_match.group(1)
    return out


def _parse_kea_csv(text: str) -> dict[str, dict]:
    """Parse a Kea memfile CSV lease file."""
    out: dict[str, dict] = {}
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return out
    for row in reader:
        ip = (row.get("address") or "").strip()
        hostname = _norm_hostname(row.get("hostname") or "")
        if not ip or not hostname:
            continue
        mac = (row.get("hwaddr") or row.get("duid") or "").strip()
        out.setdefault(ip, {"ip": ip, "hostname": hostname, "mac": mac})
    return out


def _split_sections(text: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    current_path: str | None = None
    buffer: list[str] = []
    for line in text.splitlines():
        if line.startswith("###"):
            if current_path is not None:
                sections.append((current_path, "\n".join(buffer)))
            current_path = line[3:].strip()
            buffer = []
        else:
            buffer.append(line)
    if current_path is not None:
        sections.append((current_path, "\n".join(buffer)))
    if not sections:
        sections.append(("", text))
    return sections


def _parse_section(path: str, content: str) -> dict[str, dict]:
    low = path.lower()
    if low.endswith(".csv"):
        return _parse_kea_csv(content)
    if not path and "," in (content.splitlines()[0] if content.splitlines() else ""):
        return _parse_kea_csv(content)
    return _parse_isc(content)


def parse_dhcp_leases(text: str) -> list[dict]:
    """Return a list of `{ip, hostname, mac, source}` from the concatenated dump."""
    leases: dict[str, dict] = {}
    for path, content in _split_sections(text):
        source = "kea" if path.lower().endswith(".csv") else "isc"
        for ip, lease in _parse_section(path, content).items():
            lease["source"] = source
            leases.setdefault(ip, lease)
    return list(leases.values())
