import paramiko
import pytest

from app.opnsense.ssh import OPNsenseSSH, SSHError


class _FakeStdin:
    pass


class _FakeChannel:
    def __init__(self, out=b"ok", err=b""):
        self._out = out
        self._err = err

    def read(self):
        return self._out

    def close(self):
        pass


class _FakeStdout(_FakeChannel):
    pass


class _FakeStderr(_FakeChannel):
    pass


def test_valid_connection(monkeypatch):
    class FakeClient:
        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, **kwargs):
            pass

        def exec_command(self, cmd, timeout=None):
            return _FakeChannel(), _FakeStdout(b"ok"), _FakeStderr(b"")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    client = OPNsenseSSH(host="192.0.2.1", username="root", password="secret")
    assert client.run("echo ok") == "ok"
    assert client.test_connection() is True


def test_bad_password(monkeypatch):
    class FakeClient:
        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, **kwargs):
            raise paramiko.AuthenticationException("nope")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    client = OPNsenseSSH(host="192.0.2.1", username="root", password="bad")
    with pytest.raises(SSHError, match="authentication failed"):
        client.run("echo ok")


def test_invalid_key(monkeypatch):
    def fail(*a, **k):
        raise ValueError("bad key")

    for name in ("RSAKey", "Ed25519Key", "ECDSAKey", "DSSKey"):
        cls = getattr(paramiko, name, None)
        if cls is not None:
            monkeypatch.setattr(cls, "from_private_key_file", fail)
    client = OPNsenseSSH(host="192.0.2.1", username="root", auth_type="key", key_path="/nope")
    with pytest.raises(SSHError, match="[Cc]ould not load"):
        client.run("echo ok")


def test_unreachable(monkeypatch):
    class FakeClient:
        def set_missing_host_key_policy(self, *a):
            pass

        def connect(self, **kwargs):
            raise OSError("timed out")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", FakeClient)
    client = OPNsenseSSH(host="192.0.2.1", username="root", password="secret")
    with pytest.raises(SSHError, match="connection failed"):
        client.run("echo ok")
