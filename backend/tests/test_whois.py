import pytest

from app import whois


def test_lookup_rejects_invalid_ip():
    with pytest.raises(ValueError):
        whois.lookup("not-an-ip")


def test_refer_parsing():
    text = "NetRange: 8.8.8.0 - 8.8.8.255\nReferralServer: whois://whois.ripe.net\n"
    assert whois._refer(text) == "whois.ripe.net"
    assert whois._refer("refer: whois.apnic.net\n") == "whois.apnic.net"
    assert whois._refer("whois: whois.arin.net\n") == "whois.arin.net"
    assert whois._refer("no refer here") is None


def test_lookup_follows_referral(monkeypatch):
    replies = {
        ("whois.iana.org", "8.8.8.8"): "refer: whois.arin.net\n",
        ("whois.arin.net", "8.8.8.8"): "NetName: GOOGLE\nCountry: US\n",
    }

    def fake_query(server, query):
        return replies[(server, query)]

    monkeypatch.setattr(whois, "_query", fake_query)
    result = whois.lookup("8.8.8.8")
    assert "GOOGLE" in result


def test_lookup_falls_back_to_second_start(monkeypatch):
    calls = []

    def fake_query(server, query):
        calls.append(server)
        if server == "whois.iana.org":
            raise OSError("down")
        return "inetnum: 1.2.3.0 - 1.2.3.255\n"

    monkeypatch.setattr(whois, "_query", fake_query)
    result = whois.lookup("1.2.3.4")
    assert "inetnum" in result
    assert "whois.arin.net" in calls
