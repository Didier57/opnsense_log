"""Minimal WHOIS client (TCP port 43) with IANA -> RIR referral following.

Used to look up an IP address without any third-party web service, so there is
no captcha and no rate limit beyond the registries' own fair-use policies.
"""
from __future__ import annotations

import ipaddress
import socket

_PORT = 43
_TIMEOUT = 6.0
_MAX_BYTES = 200_000
_MAX_HOPS = 4
_START_SERVERS = ("whois.iana.org", "whois.arin.net")
_USEFUL_MARKERS = (
    "netname",
    "inetnum",
    "inet6num",
    "netrange",
    "org-name",
    "organization",
    "orgname",
    "descr",
    "country",
    "cidr",
)
_EMPTY_MARKERS = (
    "no entries found",
    "no match",
    "not found",
    "no object found",
)


def _query(server: str, query: str) -> str:
    with socket.create_connection((server, _PORT), timeout=_TIMEOUT) as sock:
        sock.settimeout(_TIMEOUT)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        chunks: list[bytes] = []
        total = 0
        while total < _MAX_BYTES:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            total += len(data)
        return b"".join(chunks).decode("utf-8", "replace")


def _refer(text: str) -> str | None:
    """Return the next WHOIS server referenced by ``text`` (or None)."""
    for line in text.splitlines():
        low = line.strip().lower()
        for key in ("refer:", "referralserver:", "whois:"):
            if low.startswith(key):
                value = line.split(":", 1)[1].strip()
                for prefix in ("whois://", "rwhois://", "http://", "https://"):
                    if value.lower().startswith(prefix):
                        value = value[len(prefix):]
                value = value.split("/", 1)[0].strip()
                if value:
                    return value
    return None


def _is_useful(text: str) -> bool:
    low = text.lower()
    if any(marker in low for marker in _EMPTY_MARKERS):
        return False
    return any(marker in low for marker in _USEFUL_MARKERS)


def _follow(server: str, query: str) -> str:
    text = ""
    for _ in range(_MAX_HOPS):
        text = _query(server, query)
        refer = _refer(text)
        if not refer or refer == server:
            break
        server = refer
    return text


def lookup(ip: str) -> str:
    """Return the raw WHOIS text for ``ip`` (raises ValueError if invalid)."""
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError as exc:
        raise ValueError("Adresse IP invalide") from exc
    query = str(address)
    text = ""
    for start in _START_SERVERS:
        try:
            text = _follow(start, query)
        except OSError:
            text = ""
            continue
        if _is_useful(text):
            return text.strip()
    return text.strip()
