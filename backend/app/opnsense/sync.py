"""Synchronisation of OPNsense interfaces and rules over SSH."""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..storage.database import Database, get_database
from .config_loader import parse_config
from .settings_store import get_opnsense_settings
from .ssh import OPNsenseSSH, SSHError

logger = logging.getLogger("opnsense.sync")

CONFIG_PATH = "/conf/config.xml"


class OPNSenseSync:
    def __init__(self, db: Database | None = None, ssh: OPNsenseSSH | None = None) -> None:
        self.db = db or get_database()
        self.ssh = ssh or self._build_ssh()

    @staticmethod
    def _build_ssh() -> OPNsenseSSH:
        cfg = get_opnsense_settings(mask_password=False)
        return OPNsenseSSH(
            host=cfg["opnsense_host"],
            port=cfg["opnsense_ssh_port"],
            username=cfg["opnsense_username"],
            auth_type=cfg["opnsense_auth_type"],
            password=cfg.get("opnsense_password"),
            key_path=cfg["opnsense_key_path"],
        )

    def fetch_config(self) -> str:
        return self.ssh.run(f"cat {CONFIG_PATH}")

    def sync(self) -> dict:
        """Fetch config over SSH and persist interfaces and rules.

        Never raises for remote failures: returns a status dict instead so the
        rest of the application keeps running when OPNsense is unreachable.
        """
        if not self.ssh.host:
            return {"ok": False, "error": "OPNsense host not configured"}

        logger.info(
            "OPNsense sync started (%s@%s:%s, auth=%s)",
            self.ssh.username,
            self.ssh.host,
            self.ssh.port,
            self.ssh.auth_type,
        )
        try:
            contents = self.fetch_config()
        except SSHError as exc:
            logger.warning("OPNsense sync failed: %s", exc)
            return {"ok": False, "error": str(exc)}
        except Exception as exc:  # noqa: BLE001
            logger.exception("OPNsense sync unexpected error")
            return {"ok": False, "error": f"unexpected error: {exc}"}

        try:
            interfaces, rules = parse_config(contents)
        except ET.ParseError as exc:
            logger.error("Failed to parse OPNsense config: %s", exc)
            return {"ok": False, "error": f"config parse error: {exc}"}

        now = datetime.now(timezone.utc)
        try:
            self._store_interfaces(interfaces, now)
            self._store_rules(rules, now)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to store OPNsense config")
            return {"ok": False, "error": f"storage error: {exc}"}

        logger.info("%s interfaces loaded, %s firewall rules loaded", len(interfaces), len(rules))
        return {
            "ok": True,
            "interfaces": len(interfaces),
            "rules": len(rules),
            "synced_at": now.isoformat(),
        }

    def _store_interfaces(self, interfaces: list[dict], now: datetime) -> None:
        for iface in interfaces:
            self.db.execute_write(
                """
                INSERT INTO opnsense_interfaces (name, device, description, ipv4, ipv6, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (name) DO UPDATE SET
                    device = excluded.device,
                    description = excluded.description,
                    ipv4 = excluded.ipv4,
                    ipv6 = excluded.ipv6,
                    updated_at = excluded.updated_at
                """,
                [
                    iface["name"], iface["device"], iface["description"],
                    iface["ipv4"], iface["ipv6"], now,
                ],
            )

    def _store_rules(self, rules: list[dict], now: datetime) -> None:
        for rule in rules:
            previous = self.db.execute_read(
                "SELECT description, interface, action FROM opnsense_rules WHERE rule_id = ?",
                [rule["rule_id"]],
            ).fetchone()
            self.db.execute_write(
                """
                INSERT INTO opnsense_rules
                    (rule_id, rule_number, description, interface, action, direction,
                     protocol, source, destination, enabled, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (rule_id) DO UPDATE SET
                    description = excluded.description,
                    interface = excluded.interface,
                    action = excluded.action,
                    direction = excluded.direction,
                    protocol = excluded.protocol,
                    source = excluded.source,
                    destination = excluded.destination,
                    enabled = excluded.enabled,
                    updated_at = excluded.updated_at
                """,
                [
                    rule["rule_id"], rule["rule_number"], rule["description"],
                    rule["interface"], rule["action"], rule["direction"],
                    rule["protocol"], rule["source"], rule["destination"],
                    rule["enabled"], now,
                ],
            )
            changed = (
                previous is None
                or previous[0] != rule["description"]
                or previous[1] != rule["interface"]
                or previous[2] != rule["action"]
            )
            if changed:
                self.db.execute_write(
                    "INSERT INTO rule_history (rule_id, valid_from, description, interface, action, snapshot) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    [
                        rule["rule_id"], now, rule["description"], rule["interface"],
                        rule["action"], json.dumps(rule),
                    ],
                )
