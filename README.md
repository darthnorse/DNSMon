# DNSMon - DNS Ad-Blocker Monitor

A comprehensive web-based dashboard for monitoring and managing multiple Pi-hole v6 and AdGuard Home servers with real-time alerts, configuration sync, and multi-channel notifications.

![Dashboard](https://img.shields.io/badge/Dashboard-React-61DAFB?style=flat-square&logo=react)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688?style=flat-square&logo=fastapi)
![Database](https://img.shields.io/badge/Database-PostgreSQL-4169E1?style=flat-square&logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Multi--arch-2496ED?style=flat-square&logo=docker)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=flat-square&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/darthnorse)

## Table of Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Docker Images](#docker-images)
- [API](#api)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Performance](#performance)
- [License](#license)
- [Contributing](#contributing)
- [Support](#support)

## Screenshots

| Dashboard | Statistics |
|-----------|------------|
| ![Dashboard](docs/images/dnsmon_dashboard.png) | ![Statistics](docs/images/dnsmon_statistics.png) |

## Features

### Multi-Server Support
- **Pi-hole v6** - Full REST API integration
- **AdGuard Home** - Native API support
- Monitor unlimited servers from a single dashboard
- Per-server statistics and health monitoring

### Real-time Query Monitoring
- Automatic query ingestion with configurable polling intervals
- Advanced search across domain, client IP, and hostname
- Date range filtering with pagination
- Query status tracking (allowed, blocked, cached)

### Comprehensive Statistics
- Query counts (today, week, month, all-time)
- Block rate percentages
- Hourly/daily query trends with charts
- Top domains and top blocked domains
- Top clients with hostname resolution
- Per-server breakdown with blocked/cached counts
- New client detection

### Flexible Alert System
- Pattern-based rules with wildcard support:
  - Domain patterns (e.g., `*ads*`, `*.gambling.*`)
  - Client IP patterns (e.g., `192.168.1.*`)
  - Client hostname patterns (e.g., `*kids-tablet*`)
- Exclusion patterns to reduce false positives
- Configurable cooldown periods to prevent alert spam
- Batched notifications for multiple matches

### Multi-Channel Notifications
- **Telegram** - Bot integration with chat ID support
- **Pushover** - Priority and sound customization
- **Ntfy** - Self-hosted or ntfy.sh
- **Discord** - Webhook integration
- **Webhook** - Generic HTTP webhooks (POST/PUT/GET)
- Custom message templates with variables
- Per-channel enable/disable and error tracking

### Configuration Sync
Designate a "source" server and sync its configuration to target servers automatically or on-demand.

**Pi-hole syncs:**
- Gravity database (via Teleporter):
  - Adlists (blocklists/subscriptions)
  - Whitelist and blacklist domains
  - Regex whitelist and blacklist
  - Groups and group assignments
  - Client definitions and group memberships
- DNS settings:
  - Local DNS records (A/AAAA)
  - CNAME records
  - Upstream DNS servers
  - Conditional forwarding rules

**AdGuard Home syncs:**
- User filtering rules
- DNS configuration and upstream servers
- DNS rewrites
- Blocklist and allowlist subscriptions
- Persistent client settings

Includes sync history with detailed logs and error tracking.

### Blocking Control
- Enable/disable blocking per server or globally
- Timed disable with automatic re-enable
- Real-time blocking status display

### Domain Management
- View and manage whitelist/blacklist across all servers
- Quick whitelist/blacklist actions from query results
- Regex list support (Pi-hole)

### API Keys & Programmatic Access
- Create API keys for scripting and automation
- Read-only or admin-level key permissions
- Optional expiration dates
- All REST endpoints accessible via `Authorization: Bearer <key>`

### Security
- Built-in authentication with session management
- Admin and regular user roles
- API key authentication for programmatic access
- OIDC/SSO integration (Google, Authentik, Keycloak, etc.)
- Rate-limited login attempts
- Secure password hashing (bcrypt)

## Installation

### Requirements
- Docker and Docker Compose
- Pi-hole v6 and/or AdGuard Home server(s)

### Quick Start

1. Create a directory and `docker-compose.yml`:

```bash
mkdir dnsmon && cd dnsmon
```

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    container_name: dnsmon-postgres
    environment:
      POSTGRES_DB: dnsmon
      POSTGRES_USER: dnsmon
      POSTGRES_PASSWORD: changeme  # Change this!
    volumes:
      - dnsmon_postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U dnsmon"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  app:
    image: ghcr.io/darthnorse/dnsmon:latest
    container_name: dnsmon-app
    depends_on:
      postgres:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://dnsmon:changeme@postgres:5432/dnsmon  # Match password above
      TZ: America/Denver  # Your timezone
    ports:
      - "8000:8000"
    restart: unless-stopped

volumes:
  dnsmon_postgres_data:
```

2. Start the services:

```bash
docker compose up -d
```

3. Open `http://localhost:8000` and create your admin account

4. Go to **Settings** → **DNS Servers** to add your Pi-hole/AdGuard servers

That's it! DNSMon will start monitoring your DNS servers immediately.

## Configuration

All configuration is done through the web UI - no config files needed!

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `POSTGRES_PASSWORD` | PostgreSQL password | `changeme` |
| `TZ` | Timezone for display | `UTC` |
| `DNSMON_SECRET_KEY` | Session signing key (recommended for production) | Auto-generated |
| `DNSMON_COOKIE_SECURE` | Set to `true` if behind HTTPS | `false` |

### Adding DNS Servers

1. Go to **Settings** → **DNS Servers**
2. Click **Add Server**
3. Enter:
   - **Name**: Friendly name (e.g., "Primary Pi-hole")
   - **Type**: Pi-hole or AdGuard Home
   - **URL**: Server URL (e.g., `http://192.168.1.100`)
   - **Password/API Key**: Your server's password
4. Click **Test Connection** to verify
5. Save and the server will start being monitored

### Setting Up Notifications

1. Go to **Settings** → **Notifications**
2. Click **Add Channel**
3. Choose your notification type and configure:

#### Telegram
1. Create a bot via [@BotFather](https://t.me/botfather)
2. Get your chat ID by messaging [@userinfobot](https://t.me/userinfobot)
3. Enter bot token and chat ID

#### Pushover
1. Create an application at [pushover.net](https://pushover.net)
2. Enter your app token and user key

#### Discord
1. Create a webhook in your Discord channel settings
2. Paste the webhook URL

#### Ntfy
1. Choose a topic name
2. Optionally specify a self-hosted server URL

### Creating Alert Rules

1. Go to **Alert Rules**
2. Click **Create Rule**
3. Configure patterns:
   - **Domain Pattern**: `*ads*,*tracker*,*malware*` (comma-separated)
   - **Client IP Pattern**: `192.168.1.100` or `192.168.1.*`
   - **Exclude Domains**: `safe-site.com,another-safe.com`
4. Set cooldown period (minutes between alerts)
5. Save - alerts will be sent to all enabled notification channels

## Architecture

```
┌─────────────────┐
│     Browser     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐      ┌─────────────────┐
│   DNSMon App    │◄────►│   PostgreSQL    │
│  (FastAPI +     │      │   (Data Store)  │
│   React SPA)    │      └─────────────────┘
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│         DNS Ad-Blockers             │
│  ┌─────────┐  ┌─────────┐          │
│  │ Pi-hole │  │ AdGuard │  • • •   │
│  │   v6    │  │  Home   │          │
│  └─────────┘  └─────────┘          │
└─────────────────────────────────────┘
```

- **Backend**: Python FastAPI with async SQLAlchemy
- **Frontend**: React 18 with TypeScript and Tailwind CSS
- **Database**: PostgreSQL 16 with timezone-aware timestamps
- **Scheduler**: APScheduler for background tasks

## Docker Images

Pre-built multi-architecture images are available on GitHub Container Registry:

```bash
docker pull ghcr.io/darthnorse/dnsmon:latest
```

Supported architectures:
- `linux/amd64` (x86 64-bit)
- `linux/arm64` (ARM 64-bit, e.g., Raspberry Pi 4+)

## API

Full interactive API documentation is available at `/docs` (Swagger UI) or `/redoc` (ReDoc) on your DNSMon instance.

All endpoints support API key authentication via the `Authorization: Bearer <key>` header. Create keys in **Settings** → **API Keys**.

### Quick Examples

```bash
# Get dashboard statistics
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/stats

# Search queries
curl -H "Authorization: Bearer YOUR_API_KEY" "http://localhost:8000/api/queries?domain=example.com&limit=10"

# Get blocking status
curl -H "Authorization: Bearer YOUR_API_KEY" http://localhost:8000/api/blocking/status

# Disable blocking on all servers for 5 minutes
curl -X POST -H "Authorization: Bearer YOUR_API_KEY" -H "Content-Type: application/json" \
  -d '{"enabled": false, "duration": 300}' http://localhost:8000/api/blocking/all
```

### Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/check` - Check auth status

### Queries
- `GET /api/queries` - Search queries with filters
- `GET /api/queries/count` - Count matching queries

### Statistics
- `GET /api/stats` - Dashboard statistics
- `GET /api/statistics` - Detailed statistics with time series

### Alert Rules
- `GET /api/alert-rules` - List rules
- `POST /api/alert-rules` - Create rule
- `PUT /api/alert-rules/{id}` - Update rule
- `DELETE /api/alert-rules/{id}` - Delete rule

### Notification Channels
- `GET /api/notification-channels` - List channels
- `POST /api/notification-channels` - Create channel
- `POST /api/notification-channels/{id}/test` - Send test notification

### Settings
- `GET /api/settings` - Get all settings
- `POST /api/settings/pihole-servers` - Add DNS server
- `POST /api/settings/pihole-servers/test` - Test connection

### Blocking Control
- `GET /api/blocking/status` - Get blocking status
- `POST /api/blocking/{server_id}` - Set blocking for server
- `POST /api/blocking/all` - Set blocking for all servers

### Domain Management
- `GET /api/domains/whitelist` - Get whitelist
- `POST /api/domains/whitelist` - Add to whitelist
- `POST /api/domains/blacklist` - Add to blacklist

### Sync
- `GET /api/sync/preview` - Preview sync changes
- `POST /api/sync/execute` - Execute sync
- `GET /api/sync/history` - Get sync history

## Development

For contributors who want to modify DNSMon:

```bash
# Clone repository
git clone https://github.com/darthnorse/DNSMon.git
cd DNSMon

# Start PostgreSQL
docker run -d -p 5432:5432 \
  -e POSTGRES_DB=dnsmon \
  -e POSTGRES_USER=dnsmon \
  -e POSTGRES_PASSWORD=changeme \
  postgres:16

# Backend
pip install -r requirements.txt
export DATABASE_URL=postgresql://dnsmon:changeme@localhost:5432/dnsmon
python -m backend.main

# Frontend (separate terminal)
cd frontend
npm install
npm run dev
```

To build a local Docker image:

```bash
docker build -t dnsmon .
```

## Troubleshooting

### No queries appearing
1. Check server configuration in Settings → DNS Servers
2. Verify credentials with "Test Connection"
3. Check logs: `docker compose logs app`
4. Ensure your DNS server's API is accessible

### Notifications not working
1. Verify channel configuration in Settings → Notifications
2. Use "Send Test" to verify connectivity
3. Check for error messages on the channel card
4. Ensure your notification service credentials are correct

### Login issues
1. Clear browser cookies and try again
2. Check if rate limiting is active (wait 60 seconds)
3. Reset password via database if needed

### Database connection errors
1. Ensure PostgreSQL is running: `docker compose ps`
2. Check password matches in `.env` and compose file
3. Restart services: `docker compose restart`

## Performance

- Tested with 250k+ queries/day
- Efficient bulk insert with duplicate detection
- Configurable data retention (default 60 days)
- Connection pooling for database efficiency
- Background task scheduling with overlap prevention

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Credits

Built with:
- [FastAPI](https://fastapi.tiangolo.com/) - Modern Python web framework
- [React](https://react.dev/) - UI library
- [PostgreSQL](https://www.postgresql.org/) - Database
- [Tailwind CSS](https://tailwindcss.com/) - Styling
- [Recharts](https://recharts.org/) - Charts
- [SQLAlchemy](https://www.sqlalchemy.org/) - ORM

## Support

If you find DNSMon useful, consider buying me a coffee!

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/darthnorse)

## Acknowledgments

This project has been developed with vibe coding and AI assistance using [Claude Code](https://docs.anthropic.com/en/docs/claude-code). The codebase includes clean, well-documented code with proper error handling, comprehensive testing considerations, modern async/await patterns, robust database design, and production-ready deployment configurations.
