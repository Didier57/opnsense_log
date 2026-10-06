"""SSH client for OPNsense configuration retrieval.

Passwords and private keys are never written to logs.
"""
from __future__ import annotations

import logging

import paramiko

from ..config import settings

logger = logging.getLogger("opnsense.ssh")


class SSHError(RuntimeError):
    pass


class OPNsenseSSH:
    def __init__(
        self,
        host: str | None = None,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        key_path: str | None = None,
        auth_type: str | None = None,
        timeout: int = 15,
    ) -> None:
        self.host = host or settings.opnsense_host
        self.port = port or settings.opnsense_ssh_port
        self.username = username or settings.opnsense_username
        self.password = password if password is not None else settings.opnsense_password
        self.key_path = key_path if key_path is not None else settings.opnsense_key_path
        self.auth_type = auth_type or settings.opnsense_auth_type
        self.timeout = timeout

    def _connect(self) -> paramiko.SSHClient:
        if not self.host:
            raise SSHError("OPNsense host is not configured")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            if self.auth_type == "key":
                pkey = self._load_key()
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    pkey=pkey,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
            else:
                client.connect(
                    hostname=self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
        except paramiko.AuthenticationException as exc:
            raise SSHError("SSH authentication failed") from exc
        except SSHError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise SSHError(f"SSH connection failed: {exc}") from exc
        return client

    def _load_key(self) -> paramiko.PKey:
        candidates = [
            getattr(paramiko, name, None)
            for name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey")
        ]
        candidates = [c for c in candidates if c is not None]
        for key_cls in candidates:
            try:
                return key_cls.from_private_key_file(self.key_path)
            except paramiko.PasswordRequiredException as exc:
                raise SSHError("SSH key is encrypted and requires a passphrase") from exc
            except Exception:  # noqa: BLE001
                continue
        raise SSHError("Could not load SSH private key")

    def run(self, command: str) -> str:
        client = self._connect()
        try:
            _, stdout, stderr = client.exec_command(command, timeout=self.timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if err.strip() and not out.strip():
                raise SSHError(f"remote command error: {err.strip()[:200]}")
            return out
        finally:
            client.close()

    def test_connection(self) -> bool:
        try:
            self.run("echo ok")
            return True
        except SSHError:
            return False
