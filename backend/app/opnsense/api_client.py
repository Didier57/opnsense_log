"""Minimal OPNsense REST API client (firewall alias management).

Used by the automatic-blocking feature to push alert source IPs into an existing
"Host(s)" firewall alias and to apply the change. Credentials (API key/secret)
are read from the runtime OPNsense settings; they are never written to logs.
"""
from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("opnsense.api")


class APIError(RuntimeError):
    pass


def _split_content(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        parts = [str(v) for v in value]
    else:
        parts = str(value).replace("\r", "\n").split("\n")
    return [p.strip() for p in parts if str(p).strip()]


class OPNsenseAPI:
    def __init__(
        self,
        host: str,
        port: int = 443,
        key: str = "",
        secret: str = "",
        timeout: int = 15,
        verify: bool = False,
    ) -> None:
        self.host = host
        self.port = port or 443
        self.key = key
        self.secret = secret
        self.timeout = timeout
        self.verify = verify

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/api"

    def is_configured(self) -> bool:
        return bool(self.host and self.key and self.secret)

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.base_url,
            auth=(self.key, self.secret),
            verify=self.verify,
            timeout=self.timeout,
            headers={"Accept": "application/json"},
        )

    def _post(self, path: str, json: dict | None = None) -> dict:
        if not self.is_configured():
            raise APIError("OPNsense API credentials are not configured")
        try:
            with self._client() as client:
                response = client.post(path, json=json or {})
        except httpx.HTTPError as exc:
            raise APIError(f"OPNsense API request failed: {exc}") from exc
        if response.status_code == 401:
            raise APIError("OPNsense API authentication failed (check key/secret)")
        if response.status_code >= 400:
            raise APIError(f"OPNsense API returned HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError:
            return {}

    def search_alias(self, name: str) -> dict | None:
        """Return the alias row whose name matches exactly, or None."""
        payload = self._post(
            "/firewall/alias/searchItem",
            {"current": 1, "rowCount": 500, "searchPhrase": name},
        )
        rows = payload.get("rows") or []
        for row in rows:
            if str(row.get("name", "")) == name:
                return row
        return None

    def ensure_host_alias(self, name: str, content: list[str]) -> dict:
        """Create the 'host' alias if missing, otherwise update its content.

        Returns the alias row (with uuid).
        """
        existing = self.search_alias(name)
        joined = "\n".join(content)
        if existing is None:
            self._post(
                "/firewall/alias/addItem",
                {"alias": {"enabled": "1", "name": name, "type": "host", "content": joined}},
            )
            created = self.search_alias(name)
            if created is None:
                raise APIError("Alias creation did not take effect")
            return created
        if str(existing.get("type")) != "host":
            raise APIError(f"Alias '{name}' is not of type Host(s)")
        payload = {k: existing.get(k) for k in ("enabled", "name", "type", "description")}
        payload["enabled"] = existing.get("enabled", "1") or "1"
        payload["content"] = joined
        uuid = existing.get("uuid")
        self._post(f"/firewall/alias/setItem/{uuid}", {"alias": payload})
        return existing

    def get_alias_content(self, name: str) -> tuple[dict | None, list[str]]:
        row = self.search_alias(name)
        if row is None:
            return None, []
        return row, _split_content(row.get("content"))

    def set_alias_content(self, row: dict, content: list[str]) -> None:
        uuid = row.get("uuid")
        payload = {k: row.get(k) for k in ("enabled", "name", "type", "description")}
        payload["enabled"] = row.get("enabled", "1") or "1"
        payload["content"] = "\n".join(content)
        self._post(f"/firewall/alias/setItem/{uuid}", {"alias": payload})

    def reconfigure(self) -> None:
        self._post("/firewall/alias/reconfigure")

    def test_connection(self) -> dict:
        try:
            self._post("/firewall/alias/searchItem", {"current": 1, "rowCount": 1})
            return {"ok": True, "message": "API connection successful"}
        except APIError as exc:
            return {"ok": False, "message": str(exc)}
