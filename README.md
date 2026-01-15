# DNSMon - DNS Ad-Blocker Monitor

A comprehensive web-based dashboard for monitoring multiple Pi-hole v6 (and soon AdGuard Home) servers with advanced search capabilities and customizable alerting to Telegram.

## Features

- **Multi-Server Support**: Monitor multiple Pi-hole v6 servers from a single dashboard
- **Real-time Ingestion**: Polls Pi-hole REST APIs every 5 minutes for DNS query logs
- **Advanced Search**: Search queries by domain, client IP, client hostname, with date range filtering
- **Statistics Dashboard**: View query counts, top domains, top clients, and server breakdowns with charts
- **Flexible Alerting**: Create custom alert rules with wildcard pattern matching
  - Match on domain patterns (e.g., `*porn*`, `*.adult.*`)
  - Match on client IP patterns (e.g., `192.168.1.*`)
  - Match on client hostname patterns (e.g., `*laptop*`)
  - Exclude specific domains from alerts
  - Configurable cooldown periods to prevent alert spam
- **Telegram Notifications**: Receive instant alerts via Telegram bot
- **Data Retention**: Configurable retention period (default 60 days)
- **Modern UI**: React-based frontend with charts and responsive design

## Architecture

- **Backend**: Python FastAPI with async support
- **Database**: PostgreSQL for query storage
- **Frontend**: React with TypeScript, Recharts for visualization
- **Deployment**: Docker Compose (2 containers: app + postgres)

## Requirements

- Docker and Docker Compose
- Pi-hole v6 server(s) with REST API enabled
- (Optional) Telegram bot token and chat ID for notifications

## Setup

### 1. Clone or Download

```bash
git clone <your-repo-url>
cd dnsmon
```

### 2. Create Configuration Files

Copy the example files:

```bash
cp config.yml.example config.yml
cp .env.example .env
```

### 3. Configure Pi-hole Servers

Edit `config.yml`:

```yaml
poll_interval_seconds: 300  # 5 minutes
retention_days: 60

pihole_servers:
  - name: "pihole1"
    url: "http://192.168.1.100"
    password: "your-pihole-password"
    enabled: true

  - name: "pihole2"
    url: "http://192.168.1.101"
    password: "your-pihole-password"
    enabled: true
```

### 4. Configure Environment Variables

Edit `.env`:

```bash
# Postgres password (change this!)
POSTGRES_PASSWORD=your_secure_password_here

# Telegram configuration (optional)
TELEGRAM_BOT_TOKEN=your-bot-token-here
TELEGRAM_CHAT_ID=your-chat-id-here
```

### 5. Build and Start

```bash
# Build the Docker images
docker-compose build

# Start the services
docker-compose up -d
```

The application will be available at `http://localhost:8000`

### 6. Access the Dashboard

Open your browser and navigate to:
- Dashboard: `http://localhost:8000/`
- Search: `http://localhost:8000/search`
- Alert Rules: `http://localhost:8000/alerts`

## Getting Telegram Bot Credentials

### Create a Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the instructions
3. Copy the bot token (format: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

### Get Your Chat ID

1. Start a conversation with your bot
2. Send any message to the bot
3. Visit: `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates`
4. Find the `"chat":{"id":` field - this is your chat ID

## Usage

### Creating Alert Rules

1. Navigate to the "Alert Rules" page
2. Click "Create Rule"
3. Configure your rule:
   - **Name**: Descriptive name for the rule
   - **Domain Pattern**: Match domains with wildcards (e.g., `*porn*`, `*.gambling.*`)
   - **Client IP Pattern**: Match specific clients (e.g., `192.168.1.100` or `192.168.1.*`)
   - **Client Hostname Pattern**: Match by hostname (e.g., `*kids-laptop*`)
   - **Exclude Domains**: JSON array of domains to exclude from alerts
   - **Cooldown**: Minutes to wait between alerts for the same rule
4. Click "Create Rule"

### Searching Queries

1. Navigate to the "Search" page
2. Enter search criteria:
   - Domain (partial match supported)
   - Client IP (partial match supported)
   - Client Hostname (partial match supported)
   - Pi-hole Server
   - Date range
3. Click "Search"

Results show all matching queries with pagination support.

## Development

### Running Locally (without Docker)

#### Backend

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://dnsmon:changeme@localhost:5432/dnsmon
export TELEGRAM_BOT_TOKEN=your-token
export TELEGRAM_CHAT_ID=your-chat-id

# Start PostgreSQL (via Docker or locally)
docker run -d -p 5432:5432 -e POSTGRES_DB=dnsmon -e POSTGRES_USER=dnsmon -e POSTGRES_PASSWORD=changeme postgres:16-alpine

# Run the application
python -m backend.main
```

#### Frontend

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at `http://localhost:3000` and will proxy API requests to `http://localhost:8000`.

### Building Frontend for Production

```bash
cd frontend
npm run build
```

The built files will be in `frontend/build/` and will be served by the FastAPI app.

## Database Schema

### Queries Table
- Stores all DNS queries with timestamp, domain, client IP, client hostname
- Indexed for fast searching on domain, client_ip, client_hostname, timestamp

### Alert Rules Table
- Stores alert rule configurations with patterns and notification settings

### Alert History Table
- Tracks when alerts were triggered to implement cooldown logic

## API Endpoints

- `GET /api/queries` - Search queries with filters
- `GET /api/queries/count` - Count matching queries
- `GET /api/stats` - Dashboard statistics
- `GET /api/alert-rules` - List all alert rules
- `POST /api/alert-rules` - Create alert rule
- `PUT /api/alert-rules/{id}` - Update alert rule
- `DELETE /api/alert-rules/{id}` - Delete alert rule
- `GET /api/health` - Health check

## Troubleshooting

### No queries appearing

1. Check Pi-hole server configuration in `config.yml`
2. Verify Pi-hole password is correct
3. Check logs: `docker-compose logs app`
4. Ensure Pi-hole v6 REST API is accessible

### Telegram notifications not working

1. Verify bot token and chat ID in `.env`
2. Ensure bot is started (send `/start` to your bot)
3. Check logs for errors: `docker-compose logs app`

### Database connection errors

1. Ensure PostgreSQL container is running: `docker-compose ps`
2. Check database password matches in `.env` and `docker-compose.yml`
3. Restart services: `docker-compose restart`

## Performance Notes

- With 250k queries/day, the database will store approximately 15M queries over 60 days
- PostgreSQL handles this easily with proper indexing
- Consider adjusting retention period based on your needs and disk space

## License

MIT License - See LICENSE file for details

## Credits

Built with:
- FastAPI
- PostgreSQL
- React
- Recharts
- Tailwind CSS
