# OPNsense Log Analyzer

A self-hosted, Dockerized web application to **continuously collect, store, visualize and
analyze OPNsense firewall `filterlog` logs** in real time.

It is inspired by [Shayano/opnsense-log-viewer](https://github.com/Shayano/opnsense-log-viewer)
but designed for permanent operation: continuous syslog collection, persistent storage,
historical search, a Live View and optional OPNsense configuration synchronisation over SSH.

> **Fundamental principle:** this app never depends on the OPNsense web UI. OPNsense is only
> used as a *log source* and *configuration source*. The app has its own parser, database,
> API, frontend, cache and configuration, and keeps analyzing logs even when OPNsense SSH is
> temporarily unavailable.

## Features

- **Continuous syslog reception** over UDP and/or TCP (`SYSLOG_PROTOCOL=udp|tcp|both`).
- **Modular parser** producing structured events from OPNsense `filterlog` lines:
  RFC3164, RFC5424, custom ISO-timestamp and raw `filterlog` formats.
  Handles IPv4/IPv6, TCP/UDP, ICMP/ICMPv6 and malformed lines.
- **Real-time Live View** over WebSocket with start/pause/resume/clear, configurable buffer
  size and quick filters. Pausing the view **never** stops server-side reception.
- **Historical search** performed server-side (DuckDB) — millions of rows are never loaded
  into the browser. Date/time range, quick filters and advanced filters (AND/OR, operators,
  regex).
- **Dashboard & analysis**: cards (events/blocked/passed/interfaces), time series,
  PASS vs BLOCK, traffic per interface, top source/destination IPs, top ports, top rules,
  top protocols, and a per-dimension analysis section.
- **Interface & rule mapping** fetched from OPNsense over SSH, showing e.g. `LAN (vtnet0)`
  instead of the raw device, with **rule change history** stored over time.
- **Export** of search results to CSV, JSON and Parquet.
- **Retention policy** (`LOG_RETENTION_DAYS`, `0` = unlimited) with a background cleanup task.
- **Saved filters**, pagination, event details.
- **Monitoring & internal logging** with a System → Status page
  (received / parsed / invalid / events-per-second) and a System → Logs page.
- **Authentication** (local, hashed with Argon2) with JWT tokens.
- **Dockerized** single image serving both the API and the frontend, with a healthcheck.

## Architecture

Loss-resistant ingestion pipeline:

```
OPNsense ── syslog ──▶ Syslog receiver ──▶ Receive Queue ──▶ Parser workers ──▶ Batch insert ──▶ DuckDB
                              │                                    │
                              └──────────────▶ WebSocket Live ◀────┘
```

```
backend/
  app/
    api/         FastAPI routers (health, auth, logs, search, statistics, filters,
                 rules, interfaces, settings, system, export, live)
    parser/      filterlog / RFC3164 / RFC5424 / custom parsers
    storage/     DuckDB database, repository, retention
    syslog/      UDP/TCP syslog server with queue + batch workers
    opnsense/    SSH client, config.xml loader, sync, settings store
    websocket/   Live hub
    core/        logging, counters, security
    main.py      FastAPI app + lifespan
  tests/         parser / search / ssh tests
  scripts/       hash_password.py
frontend/
  src/           React + Vite + TypeScript UI
Dockerfile       multi-stage build (frontend + backend in one image)
docker-compose.yml
```

Storage uses **DuckDB** (columnar, analytics-friendly, single-file, no server).

## Quick start

1. Copy the environment file and generate a password hash:

   ```bash
   cp .env.example .env
   docker compose build
   docker compose run --rm opnsense-log-analyzer python scripts/hash_password.py
   # paste the produced hash into AUTH_PASSWORD_HASH in .env
   ```

2. Start the stack:

   ```bash
   docker compose up -d
   ```

3. Open the web UI at <http://SERVER_IP:8080> and log in.

4. Configure OPNsense to send logs to this host:

   **System → Settings → Logging → Remote destinations**
   add a destination `SERVER_IP:5140` (UDP by default), then apply.

Data is stored in the named Docker volume `opnsense_logs` and therefore **persists across
`docker compose down` / `up`**.

### Updating

```bash
docker compose pull && docker compose up -d
```

## Configuration

All configuration is provided through environment variables (see `.env.example`):

| Variable | Default | Description |
| --- | --- | --- |
| `WEB_PORT` | `8080` | HTTP port of the web UI / API |
| `SYSLOG_PORT` | `5140` | syslog listening port |
| `SYSLOG_PROTOCOL` | `udp` | `udp`, `tcp` or `both` |
| `DATA_DIR` | `/data` | data directory (mount a volume here) |
| `LOG_RETENTION_DAYS` | `30` | retention in days (`0` = unlimited) |
| `AUTH_ENABLED` | `true` | enable local authentication |
| `AUTH_USERNAME` | `admin` | login username |
| `AUTH_PASSWORD_HASH` | – | Argon2 password hash |
| `SECRET_KEY` | – | JWT signing secret |
| `DISPLAY_TIMEZONE` | `Europe/Luxembourg` | timezone used for display |
| `LOG_LEVEL` | `INFO` | `INFO`/`WARNING`/`ERROR`/`DEBUG` |
| `OPNSENSE_SYNC_ENABLED` | `false` | enable periodic OPNsense SSH sync |

OPNsense connection (host/port/username/auth/password/key) can also be configured at
runtime from **Settings → OPNsense** in the web UI.

> Timestamps are stored in **UTC** and displayed in the configured timezone.

## Development

Backend:

```bash
cd backend
python -m venv .venv && . .venv/Scripts/activate      # Windows
pip install -r requirements-dev.txt
pytest
uvicorn app.main:app --reload --port 8080
```

Frontend:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8080
```

## Tests

```bash
cd backend && pytest
```

Covers the filterlog parser (the exact OPNsense example line, IPv4 TCP/UDP, IPv6, ICMP,
missing fields, invalid lines), RFC3164/RFC5424 parsing, repository search
(AND/OR/regex/time range/IP/port/rule/interface) and the SSH client
(valid, bad password, invalid key, unreachable).

## Security

- Hashed passwords (Argon2), JWT sessions.
- Parameterized/whitelisted SQL filters (SQL-injection protection).
- Strict validation of filter fields and operators.
- SSH keys are never written to logs.
- Costly requests are limited and large exports are streamed.

## Roadmap

- **V2** — advanced statistics, rule change detection, aliases, geolocation, reverse DNS,
  Excel export, alerts, notifications, webhooks, full API, multi-OPNsense, multi-user,
  LDAP/OIDC.
- **V3** — detection engine: port scans, brute force, traffic spikes, anomalies, IP alerts,
  correlation.

## License

MIT
