"""Tests for DHCP lease parsing (ISC and Kea) and resolver integration."""
import pytest

from app.opnsense.dhcp import (
    discover_script,
    fetch_script,
    parse_dhcp_leases,
    parse_discovered_paths,
)
from app.storage.database import Database
import app.core.hostnames as hn

ISC_V4 = """
lease 192.168.1.100 {
  starts 3 2026/10/06 10:00:00;
  hardware ethernet aa:bb:cc:dd:ee:ff;
  client-hostname "laptop";
}
lease 192.168.1.101 {
  binding state free;
  client-hostname "phone";
}
"""

ISC_V6 = """
ia-na "\\000\\001\\000\\001" {
  iaaddr 2001:db8::50 {
    binding state active;
  }
  client-hostname "nas6";
}
"""

KEA_CSV = """address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
192.168.1.50,11:22:33:44:55:66,,4000,1750000000,1,1,1,desktop,0,,1
192.168.1.51,11:22:33:44:55:67,,4000,1750000000,1,1,1,,0,,1
"""

DNSMASQ = """\
1750000000 aa:bb:cc:11:22:33 192.168.1.120 pc-bureau 01:aa:bb:cc:11:22:33
1750000000 aa:bb:cc:11:22:34 192.168.1.121 * 01:aa:bb:cc:11:22:34
2001:db8::50:aa 00:01:00:01:aa:bb 2001:db8::77 nas6 fd00::1234
"""

DNSMASQ_HOSTS = """\
# OPNsense auto-generated
192.168.1.10 server
192.168.1.11 printer printer.lan
2001:db8::10 nas6
not-a-line
"""

DNSMASQ_LEASES = """\
192.168.1.200 laptop
192.168.1.201 phone.vlan
"""


def test_parse_isc_v4():
    result = {lease["ip"]: lease for lease in parse_dhcp_leases(f"###/var/dhcpd/var/db/dhcpd.leases\n{ISC_V4}")}
    assert result["192.168.1.100"]["hostname"] == "laptop"
    assert result["192.168.1.100"]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["192.168.1.100"]["source"] == "isc"
    assert result["192.168.1.101"]["hostname"] == "phone"


def test_parse_kea_csv():
    result = {lease["ip"]: lease for lease in parse_dhcp_leases(f"###/var/db/kea/kea-leases4.csv\n{KEA_CSV}")}
    assert result["192.168.1.50"]["hostname"] == "desktop"
    assert result["192.168.1.50"]["source"] == "kea"
    assert "192.168.1.51" not in result


def test_parse_isc_v6():
    result = {lease["ip"]: lease for lease in parse_dhcp_leases(f"###/var/dhcpd/var/db/dhcpd6.leases\n{ISC_V6}")}
    assert result["2001:db8::50"]["hostname"] == "nas6"


def test_parse_dnsmasq():
    result = {
        lease["ip"]: lease
        for lease in parse_dhcp_leases(f"###/var/db/dnsmasq.leases\n{DNSMASQ}")
    }
    assert result["192.168.1.120"]["hostname"] == "pc-bureau"
    assert result["192.168.1.120"]["mac"] == "aa:bb:cc:11:22:33"
    assert result["192.168.1.120"]["source"] == "dnsmasq"
    assert result["2001:db8::77"]["hostname"] == "nas6"
    assert "192.168.1.121" not in result


def test_parse_dnsmasq_hosts():
    result = {
        lease["ip"]: lease
        for lease in parse_dhcp_leases(f"###/var/etc/dnsmasq-hosts\n{DNSMASQ_HOSTS}")
    }
    assert result["192.168.1.10"]["hostname"] == "server"
    assert result["192.168.1.11"]["hostname"] == "printer"
    assert result["2001:db8::10"]["hostname"] == "nas6"
    assert result["192.168.1.10"]["source"] == "dnsmasq"


def test_parse_dnsmasq_leases_hosts():
    result = {
        lease["ip"]: lease["hostname"]
        for lease in parse_dhcp_leases(f"###/var/etc/dnsmasq-leases\n{DNSMASQ_LEASES}")
    }
    assert result["192.168.1.200"] == "laptop"
    assert result["192.168.1.201"] == "phone.vlan"


def test_parse_mixed_dump():
    dump = (
        f"###/var/dhcpd/var/db/dhcpd.leases\n{ISC_V4}"
        f"###/var/db/kea/kea-leases4.csv\n{KEA_CSV}"
        f"###/var/db/dnsmasq.leases\n{DNSMASQ}"
        f"###/var/etc/dnsmasq-hosts\n{DNSMASQ_HOSTS}"
    )
    result = {lease["ip"]: lease["hostname"] for lease in parse_dhcp_leases(dump)}
    assert result["192.168.1.100"] == "laptop"
    assert result["192.168.1.50"] == "desktop"
    assert result["192.168.1.120"] == "pc-bureau"
    assert result["192.168.1.10"] == "server"


def test_resolver_prefers_dhcp_lease(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "dhcp.duckdb"))
    monkeypatch.setattr(hn, "get_database", lambda *a, **k: database)
    database.execute_write(
        'INSERT INTO dhcp_leases ("ip", "hostname", "mac", "source", "updated_at") '
        "VALUES ('192.168.1.100', 'laptop', 'aa:bb:cc:dd:ee:ff', 'kea', now())"
    )
    resolver = hn.HostnameResolver()
    monkeypatch.setattr(resolver, "_reverse", lambda ip: pytest.fail("reverse DNS must not be called"))
    out = resolver.resolve(["192.168.1.100"])
    assert out == {"192.168.1.100": "laptop"}
    database.close()


def test_parse_discovered_paths():
    text = (
        "/var/db/dnsmasq.leases\n"
        "/var/db/dnsmasq.leases\n"
        "not-a-path\n"
        "/var/db/kea/kea-leases4.csv\n"
    )
    assert parse_discovered_paths(text) == [
        "/var/db/dnsmasq.leases",
        "/var/db/kea/kea-leases4.csv",
    ]


def test_scripts_are_posix_wrapped():
    """Remote scripts must run under `sh` even when the login shell is csh."""
    for script in (fetch_script(), discover_script()):
        assert script.startswith("sh -c '")
        assert "'" not in script[7:-1]  # single quotes would break the wrapper
    assert "/var/etc/dnsmasq-hosts" in fetch_script()
    assert "sh -c" in discover_script()
