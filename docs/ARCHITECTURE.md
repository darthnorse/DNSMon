# DNSMon Architecture

## Overview

DNSMon is a full-stack web application for monitoring multiple Pi-hole (and future AdGuard Home) DNS ad-blocker servers. It provides real-time query ingestion, searchable logs, statistics, alerting via Telegram, and configuration sync across servers.

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11+, FastAPI (async) |
| Frontend | React 18, TypeScript, Vite |
| Database | PostgreSQL 16 |
| ORM | SQLAlchemy (async) |
| Styling | Tailwind CSS |
| Charts | Recharts |
| HTTP Client | httpx (async) |
| Scheduler | APScheduler |
| Notifications | python-telegram-bot |
| Deployment | Docker Compose |

## Directory Structure

```
dnsmon/
├── backend/
│   ├── api.py              # FastAPI routes (all /api/* endpoints)
│   ├── models.py           # SQLAlchemy models
│   ├── database.py         # DB connection setup
│   ├── config.py           # Settings loader (from database)
│   ├── service.py          # DNSMonService - main orchestrator
│   ├── ingestion.py        # Query polling from Pi-hole servers
│   ├── alerts.py           # AlertEngine - pattern matching
│   ├── notifications.py    # TelegramNotifier
│   ├── pihole_client.py    # Pi-hole v6 REST API client
│   ├── sync_service.py     # Config sync between Pi-holes
│   └── main.py             # Entry point
├── frontend/
│   ├── src/
│   │   ├── App.tsx         # Main app + Navigation component
│   │   ├── pages/          # Page components
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Search.tsx
│   │   │   ├── Statistics.tsx
│   │   │   ├── Lists.tsx
│   │   │   ├── AlertRules.tsx
│   │   │   └── Settings.tsx
│   │   ├── types/index.ts  # TypeScript interfaces
│   │   └── utils/api.ts    # API client (axios)
│   ├── index.html
│   └── package.json
├── docs/
│   └── ARCHITECTURE.md     # This file
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── CLAUDE.md               # Coding guidelines
└── README.md
```

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser                                  │
└─────────────────────────────┬───────────────────────────────────┘
                              │ HTTP (port 8000)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FastAPI Application                           │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐  │
│  │ Static Files   │  │  API Routes    │  │ Background Tasks │  │
│  │ (React build)  │  │  /api/*        │  │ (APScheduler)    │  │
│  └────────────────┘  └────────────────┘  └──────────────────┘  │
└───────────┬─────────────────┬─────────────────────┬─────────────┘
            │                 │                     │
            ▼                 ▼                     ▼
┌───────────────────┐ ┌───────────────┐   ┌─────────────────────┐
│   PostgreSQL      │ │  Pi-hole      │   │     Telegram        │
│   - queries       │ │  Servers      │   │     Bot API         │
│   - alert_rules   │ │  (REST API)   │   │                     │
│   - settings      │ └───────────────┘   └─────────────────────┘
│   - servers       │
└───────────────────┘
```

## Data Flow

### 1. Query Ingestion (Every 60s by default)

```
Pi-hole Server                    DNSMon Backend                    PostgreSQL
     │                                  │                                │
     │◄─── GET /api/queries ───────────│                                │
     │     (last 5 min window)          │                                │
     │                                  │                                │
     │────── Query JSON ───────────────►│                                │
     │                                  │                                │
     │                                  │──── INSERT queries ───────────►│
     │                                  │     (dedup by unique index)    │
     │                                  │                                │
     │                                  │──── Check AlertRules ─────────►│
     │                                  │                                │
     │                                  │◄─── Matching rules ────────────│
     │                                  │                                │
     │                                  │──── Send Telegram ────────────►│ (if matches)
```

### 2. Frontend Request Flow

```
React App                         FastAPI                          PostgreSQL
     │                                │                                 │
     │──── GET /api/statistics ──────►│                                 │
     │                                │──── SELECT queries ────────────►│
     │                                │◄─── Result set ─────────────────│
     │◄─── JSON response ─────────────│                                 │
```

### 3. Blocking Control Flow

```
React App                    FastAPI                    Pi-hole Server
     │                           │                            │
     │── POST /api/blocking/1 ──►│                            │
     │   {enabled: false,        │                            │
     │    duration_minutes: 5}   │                            │
     │                           │── POST /api/dns/blocking ─►│
     │                           │   {blocking: false,        │
     │                           │    timer: 300}             │
     │                           │◄── 200 OK ─────────────────│
     │                           │                            │
     │                           │── INSERT BlockingOverride ─►│ (PostgreSQL)
     │◄── {success: true} ───────│                            │
```

## Database Models

### Core Tables

| Table | Purpose |
|-------|---------|
| `queries` | DNS query logs (timestamp, domain, client_ip, status, server) |
| `alert_rules` | Pattern-based alerting configuration |
| `alert_history` | Tracks sent alerts for cooldown logic |
| `app_settings` | Application configuration (key-value) |
| `pihole_servers` | Pi-hole server connection details |
| `settings_changelog` | Audit trail for settings changes |
| `sync_history` | Pi-hole config sync operation logs |
| `blocking_overrides` | Tracks blocking disable events |

### Key Indexes

- `queries`: Indexed on timestamp, domain, client_ip, pihole_server
- Unique constraint: `(timestamp, domain, client_ip, pihole_server)` prevents duplicates

## API Endpoints

### Queries
- `GET /api/queries` - Search with filters (domain, client_ip, date range)
- `GET /api/queries/count` - Count matching queries
- `GET /api/stats` - Dashboard summary statistics
- `GET /api/statistics` - Detailed statistics with time series

### Alert Rules
- `GET /api/alert-rules` - List all rules
- `POST /api/alert-rules` - Create rule
- `PUT /api/alert-rules/{id}` - Update rule
- `DELETE /api/alert-rules/{id}` - Delete rule

### Settings
- `GET /api/settings` - All settings + servers
- `PUT /api/settings/{key}` - Update setting
- `GET /api/settings/pihole-servers` - List servers
- `POST /api/settings/pihole-servers` - Add server
- `PUT /api/settings/pihole-servers/{id}` - Update server
- `DELETE /api/settings/pihole-servers/{id}` - Delete server
- `POST /api/settings/pihole-servers/test` - Test connection
- `POST /api/settings/telegram/test` - Test Telegram
- `POST /api/settings/restart` - Trigger app restart

### Blocking Control
- `GET /api/blocking/status` - Status for all servers
- `POST /api/blocking/{server_id}` - Set blocking for one server
- `POST /api/blocking/all` - Set blocking for all servers

### Domain Lists
- `GET /api/domains/whitelist` - Get whitelist
- `POST /api/domains/whitelist` - Add to whitelist
- `DELETE /api/domains/whitelist/{domain}` - Remove from whitelist
- (Same pattern for blacklist, regex-whitelist, regex-blacklist)

### Sync
- `GET /api/sync/preview` - Preview what would sync
- `POST /api/sync/execute` - Execute sync
- `GET /api/sync/history` - Sync history

### Health
- `GET /api/health` - Health check with DB status

## Key Components

### DNSMonService (service.py)

Main orchestrator that manages:
- **APScheduler**: Runs periodic tasks
- **QueryIngestionService**: Polls Pi-hole servers
- **AlertEngine**: Evaluates queries against rules
- **TelegramNotifier**: Sends notifications
- **PiholeSyncService**: Syncs configs between servers

Scheduled tasks:
- `ingest_and_alert`: Every 60s (configurable)
- `cleanup_task`: Every 24h (removes old queries)
- `sync_task`: Every 3600s (configurable)

### PiholeClient (pihole_client.py)

Async client for Pi-hole v6 REST API:
- Authentication (password or challenge-response)
- Query fetching
- Domain list management (whitelist/blacklist)
- Teleporter (backup/restore)
- Config PATCH
- Blocking control

### AlertEngine (alerts.py)

Pattern matching against DNS queries:
- Wildcard patterns (`*porn*`, `*.adult.*`)
- Client IP patterns (`192.168.1.*`)
- Hostname patterns
- Exclusion patterns
- Cooldown management (prevents alert spam)
- Compiled regex caching for performance

### Frontend State

Navigation component (App.tsx) contains:
- Blocking status polling (every 10s)
- Blocking dropdown with server selection
- Status indicator (green/yellow/red)

Pages manage their own state with `useState` hooks.

## Configuration

All configuration stored in PostgreSQL (no config files needed):

| Setting | Default | Description |
|---------|---------|-------------|
| `poll_interval_seconds` | 60 | Query polling frequency |
| `retention_days` | 60 | Days to keep query logs |
| `sync_interval_seconds` | 3600 | Config sync frequency |
| `telegram_bot_token` | "" | Telegram bot token |
| `telegram_chat_id` | "" | Default chat for alerts |

## Docker Setup

```yaml
services:
  postgres:
    image: postgres:16
    container_name: dnsmon-postgres
    # DB name kept as 'dnsmon' for backwards compatibility

  app:
    build: .
    container_name: dnsmon-app
    depends_on: postgres
    environment:
      DATABASE_URL: postgresql://dnsmon:password@localhost:5432/dnsmon
```

Both containers use `network_mode: host` for simplicity.

## Key Patterns

### Field Naming
- Use `snake_case` everywhere (Python, API responses, TypeScript)
- Keep names identical across layers (e.g., `pihole_server` not `piholeServer`)

### Error Handling
- Backend: HTTPException with appropriate status codes
- Frontend: Try/catch with user-friendly error messages
- Type-safe error handling: `err as { response?: { data?: { detail?: string } } }`

### Async/Await
- All database operations are async
- All HTTP requests (to Pi-hole) are async
- Use `async with` for PiholeClient context management

### Input Validation
- Backend: Pydantic models with Field constraints
- Example: `duration_minutes: Optional[int] = Field(ge=1, le=1440)`

## Future: AdGuard Home Support

Planned abstraction layer:
1. Create `DNSBlockerClient` base class
2. Implement `PiholeClient` and `AdGuardClient`
3. Factory pattern to instantiate correct client based on server type
4. Add `server_type` field to `pihole_servers` table
