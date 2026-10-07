"""Country (GeoIP) resolution for public IP addresses.

Uses a local MaxMind-format database (``.mmdb``). By default the free DB-IP
Lite country database is downloaded (no account required); when a MaxMind
account id / licence key is configured (or detected in the OPNsense GeoIP alias
settings) the MaxMind GeoLite2 database is used instead. Results are cached in
memory and in DuckDB (``geoip_cache``).
"""
from __future__ import annotations

import gzip
import io
import ipaddress
import logging
import tarfile
import threading
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from zoneinfo import ZoneInfo

import maxminddb

from ..config import settings
from ..storage.database import get_database
from .store import get_geo_settings

logger = logging.getLogger("geoip")

_NEGATIVE_TTL = 86400  # remember "no country" for a day
_POSITIVE_TTL = 7 * 86400  # remembered results (DB rows expire after a week)
_MAX_BYTES = 200 * 1024 * 1024
_USER_AGENT = "opnsense-log-analyzer/1.0"


@dataclass
class _Entry:
    country: str | None
    name: str | None
    expires: float


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


class GeoResolver:
    def __init__(self) -> None:
        self._reader = None
        self._reader_mtime: float | None = None
        self._reader_lock = threading.Lock()
        self._mem: dict[str, _Entry] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ paths
    @property
    def db_dir(self) -> Path:
        return Path(settings.data_dir) / "geoip"

    @property
    def db_path(self) -> Path:
        return self.db_dir / "country.mmdb"

    def invalidate(self) -> None:
        with self._reader_lock:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception:  # noqa: BLE001
                    pass
            self._reader = None
            self._reader_mtime = None
        with self._lock:
            self._mem.clear()

    # ------------------------------------------------------------------ mmdb
    def _load_reader(self):
        path = self.db_path
        if not path.is_file():
            return None
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return None
        with self._reader_lock:
            if self._reader is not None and self._reader_mtime == mtime:
                return self._reader
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception:  # noqa: BLE001
                    pass
                self._reader = None
            try:
                self._reader = maxminddb.open_database(str(path))
                self._reader_mtime = mtime
            except Exception:  # noqa: BLE001
                logger.exception("Could not open GeoIP database %s", path)
                self._reader = None
        return self._reader

    def _mmdb_lookup(self, ip: str) -> tuple[str | None, str | None]:
        reader = self._load_reader()
        if reader is None:
            return None, None
        try:
            record = reader.get(ip) or {}
        except Exception:  # noqa: BLE001
            return None, None
        country = record.get("country") or record.get("registered_country") or {}
        code = country.get("iso_code")
        if not code:
            return None, None
        name = (country.get("names") or {}).get("en")
        return code, name or code

    # ------------------------------------------------------------------ cache
    def _db_lookup(self, ips: list[str]) -> dict[str, tuple[str, str]]:
        if not ips:
            return {}
        placeholders = ", ".join("?" for _ in ips)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_POSITIVE_TTL)
        try:
            rows = get_database().execute_read(
                'SELECT "ip", "country", "country_name" FROM geoip_cache '
                f'WHERE "ip" IN ({placeholders}) AND "updated_at" >= ?',
                [*ips, cutoff],
            ).fetchall()
        except Exception:  # noqa: BLE001
            return {}
        return {ip: (country, name) for ip, country, name in rows if country}

    def _db_store(self, mapping: dict[str, tuple[str, str]]) -> None:
        if not mapping:
            return
        try:
            get_database().executemany_write(
                'INSERT INTO geoip_cache ("ip", "country", "country_name", "updated_at") '
                "VALUES (?, ?, ?, now()) "
                'ON CONFLICT ("ip") DO UPDATE SET "country" = excluded."country", '
                '"country_name" = excluded."country_name", "updated_at" = excluded."updated_at"',
                [[ip, code, name] for ip, (code, name) in mapping.items()],
            )
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------ lookup
    def resolve(self, ips: list[str]) -> dict[str, dict | None]:
        unique: list[str] = []
        seen: set[str] = set()
        for raw in ips:
            value = (raw or "").strip()
            if not value or value in seen or not is_public_ip(value):
                continue
            seen.add(value)
            unique.append(value)

        now = time.time()
        result: dict[str, dict | None] = {}
        missing: list[str] = []
        with self._lock:
            for ip in unique:
                entry = self._mem.get(ip)
                if entry and entry.expires > now:
                    if entry.country:
                        result[ip] = {"country": entry.country, "name": entry.name}
                    else:
                        result[ip] = None
                else:
                    missing.append(ip)
        if not missing:
            return result

        found: dict[str, tuple[str, str]] = {}
        db_hits = self._db_lookup(missing)
        with self._lock:
            for ip in missing:
                if ip in db_hits:
                    code, name = db_hits[ip]
                    result[ip] = {"country": code, "name": name}
                    self._mem[ip] = _Entry(code, name, now + _POSITIVE_TTL)
                    continue
                code, name = self._mmdb_lookup(ip)
                if code:
                    result[ip] = {"country": code, "name": name}
                    self._mem[ip] = _Entry(code, name, now + _POSITIVE_TTL)
                    found[ip] = (code, name)
                else:
                    result[ip] = None
                    self._mem[ip] = _Entry(None, None, now + _NEGATIVE_TTL)
        self._db_store(found)
        return result

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        geo = get_geo_settings(mask_key=True)
        path = self.db_path
        updated_at = None
        if path.is_file():
            try:
                updated_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
            except OSError:
                updated_at = None
        return {
            "enabled": geo["geoip_enabled"],
            "database": path.is_file(),
            "path": str(path),
            "updated_at": updated_at,
            "updated_at_display": _fmt_local(updated_at),
            "source": "maxmind" if geo["has_license_key"] else "db-ip",
            "has_license_key": geo["has_license_key"],
        }


geo_resolver = GeoResolver()


def _display_tz():
    try:
        from ..settings_store import get_app_settings

        name = get_app_settings().get("display_timezone") or settings.display_timezone or "UTC"
    except Exception:  # noqa: BLE001
        name = settings.display_timezone or "UTC"
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return timezone.utc


def _fmt_local(iso: str | None) -> str | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_display_tz()).strftime("%d/%m/%Y %H:%M:%S")


def _redact(url: str) -> str:
    try:
        parts = urlsplit(url)
        return f"{parts.hostname or 'geoip'}{parts.path}"
    except Exception:  # noqa: BLE001
        return "geoip source"


def _month_candidates() -> list[datetime]:
    now = datetime.now(timezone.utc)
    previous = now.replace(day=1) - timedelta(days=1)
    return [now, previous]


def _download_urls() -> list[str]:
    geo = get_geo_settings(mask_key=False)
    license_key = geo.get("geoip_license_key") or ""
    account_id = geo.get("geoip_account_id") or ""
    if license_key:
        if account_id:
            return [
                "https://"
                f"{account_id}:{license_key}"
                "@download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz"
            ]
        return [
            "https://download.maxmind.com/app/geoip_download"
            f"?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
        ]
    return [
        f"https://download.db-ip.com/free/dbip-country-lite-{month.year:04d}-{month.month:02d}.mmdb.gz"
        for month in _month_candidates()
    ]


def _extract_mmdb(data: bytes) -> bytes | None:
    if data[:2] == b"\x1f\x8b":
        # A tar.gz (MaxMind) or a plain gz (DB-IP). Try the archive first.
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith(".mmdb"):
                        extracted = tar.extractfile(member)
                        if extracted is not None:
                            return extracted.read()
        except (tarfile.TarError, OSError):
            pass
        try:
            return gzip.decompress(data)
        except OSError:
            return None
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for name in archive.namelist():
                    if name.endswith(".mmdb"):
                        return archive.read(name)
        except zipfile.BadZipFile:
            return None
    return None


def download_database() -> dict:
    """Download (or refresh) the country database. Never raises."""
    last_error = "no download source"
    for url in _download_urls():
        label = _redact(url)
        try:
            request = Request(url, headers={"User-Agent": _USER_AGENT})
            with urlopen(request, timeout=60) as response:  # noqa: S310
                data = response.read(_MAX_BYTES + 1)
            if len(data) > _MAX_BYTES:
                last_error = "remote file too large"
                continue
            content = _extract_mmdb(data)
            if not content:
                last_error = "could not extract a .mmdb file"
                continue
            path = geo_resolver.db_path
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(content)
            tmp.replace(path)
            geo_resolver.invalidate()
            logger.info("GeoIP database updated from %s (%s bytes)", label, len(content))
            return {"ok": True, "source": label, "bytes": len(content)}
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            logger.warning("GeoIP download failed for %s: %s", label, exc)
    logger.error("GeoIP database download failed: %s", last_error)
    return {"ok": False, "error": last_error}


async def geo_update_loop() -> None:
    import asyncio

    async def _ensure() -> None:
        try:
            geo = get_geo_settings(mask_key=False)
            if not geo["geoip_enabled"]:
                return
            if not geo_resolver.db_path.is_file():
                await asyncio.to_thread(download_database)
        except Exception:  # noqa: BLE001
            logger.exception("GeoIP update failed")

    await _ensure()
    while True:
        interval = max(24, int(getattr(settings, "geoip_update_interval_hours", 168))) * 3600
        await asyncio.sleep(interval)
        await _ensure()
