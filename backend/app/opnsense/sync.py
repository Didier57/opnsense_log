"""Synchronisation of OPNsense interfaces and rules over SSH."""
from __future__ import annotations

import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from ..storage.database import Database, get_database
from .config_loader import parse_config, parse_rules_debug
from .dhcp import (
    discover_script as dhcp_discover_script,
    fetch_script as dhcp_fetch_script,
    parse_dhcp_leases,
    parse_discovered_paths,
    static_lease_paths,
)
from .settings_store import get_opnsense_settings
from .ssh import OPNsenseSSH, SSHError

logger = logging.getLogger("opnsense.sync")

CONFIG_PATH = "/conf/config.xml"
RULES_DEBUG_PATH = "/tmp/rules.debug"


class OPNSenseSync:
    def __init__(self, db: Database | None = None, ssh: OPNsenseSSH | None = None) -> None:
        self.db = db or get_database()
        self.ssh = ssh or self._build_ssh()
        self.lease_paths: list[str] = []

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

    def fetch_rules_debug(self) -> str:
        """Fetch the generated pf ruleset (contains labels + descriptions)."""
        return self.ssh.run(f"cat {RULES_DEBUG_PATH}")

    def fetch_dhcp_leases(self) -> str:
        """Fetch the DHCP lease files (ISC, Kea and/or Dnsmasq).

        The lease file location depends on the DHCP service in use, so the
        actual paths are discovered on the firewall first (dnsmasq config
        directive + a filesystem scan) and merged with the known defaults.
        """
        paths = list(static_lease_paths())
        try:
            discovered = parse_discovered_paths(self.ssh.run(dhcp_discover_script()))
            for path in discovered:
                if path not in paths:
                    paths.append(path)
        except SSHError as exc:
            logger.warning("DHCP lease discovery failed: %s", exc)
        logger.info("Fetching DHCP leases from: %s", ", ".join(paths))
        self.lease_paths = paths
        return self.ssh.run(dhcp_fetch_script(paths))

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

        # Resolve automatic/system/NAT rules that only exist in the loaded
        # ruleset (never in config.xml): each rule line carries
        # `label "<id>"` and a trailing `# <description>`.
        try:
            debug = self.fetch_rules_debug()
            loaded = parse_rules_debug(debug)
            known = {rule["rule_id"] for rule in rules}
            extra = [rule for rule in loaded if rule["rule_id"] not in known]
            rules.extend(extra)
        except SSHError as exc:
            logger.warning("Could not fetch %s: %s", RULES_DEBUG_PATH, exc)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to parse %s", RULES_DEBUG_PATH)

        # DHCP leases give local hostnames (reverse DNS usually cannot resolve
        # private addresses). Best-effort: missing files are simply ignored.
        leases: list[dict] = []
        try:
            leases = parse_dhcp_leases(self.fetch_dhcp_leases())
        except SSHError as exc:
            logger.warning("Could not fetch DHCP leases: %s", exc)
        except Exception:  # noqa: BLE001
            logger.exception("Failed to parse DHCP leases")

        if not leases:
            logger.warning(
                "No DHCP leases found; verify SSH access and that the DHCP "
                "lease file exists on the firewall"
            )

        now = datetime.now(timezone.utc)
        try:
            self._store_interfaces(interfaces, now)
            self._store_rules(rules, now)
            self._store_leases(leases, now)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to store OPNsense config")
            return {"ok": False, "error": f"storage error: {exc}"}

        logger.info(
            "%s interfaces loaded, %s firewall rules loaded, %s DHCP leases loaded",
            len(interfaces), len(rules), len(leases),
        )
        return {
            "ok": True,
            "interfaces": len(interfaces),
            "rules": len(rules),
            "leases": len(leases),
            "lease_paths": self.lease_paths,
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

    def _store_leases(self, leases: list[dict], now: datetime) -> None:
        """Replace the DHCP lease snapshot (used for local hostname lookups)."""
        self.db.execute_write("DELETE FROM dhcp_leases")
        if not leases:
            return
        self.db.executemany_write(
            'INSERT INTO dhcp_leases ("ip", "hostname", "mac", "source", "updated_at") '
            "VALUES (?, ?, ?, ?, ?)",
            [
                [lease["ip"], lease["hostname"], lease.get("mac", ""), lease.get("source", ""), now]
                for lease in leases
            ],
        )
