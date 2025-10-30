# Floaty - Number Tracker with Automatic Monthly Additions

A simple web application that tracks multiple running totals with manual additions/subtractions and automatic monthly recurring values.

## TODOs

- [x] Fix Github actions

=======

## Features

- **Multiple trackers** - Configure multiple independent number trackers
- **Add/Subtract values** with optional notes
- **Delete transactions** - Remove manual transactions with soft deletes
- **Automatic monthly recurring additions** (100 on the 1st of each month)
- **Event-sourced storage** - all changes logged to append-only files
- **Catch-up mechanism** - if server is offline, recurring events are generated when data is read
- **Minimal UI** - text-only design with serif fonts
- **Mobile-friendly** - responsive design that works on all devices
- **Dockerized** - fully self-contained deployment

## Quick Start

### Inner Workings

Each tracker gets:

- Its own URL: `/{slug}`
- Its own log file: `data/{slug}.log`
- Its own API endpoints: `/api/{slug}/*`

### Run Locally (Development)

```bash
# Run the server
go run main.go
```

Access the app at http://localhost:8080

### Build and Run with Docker

```bash
# Build the image
docker build -t floaty .

# Run with config and data mounted
docker run -d -p 8080:8080 \
  -v $(pwd)/config.json:/root/config.json \
  -v $(pwd)/data:/data \
  --name floaty \
  floaty
```

**Important mounts:**

- `data/` - Directory where event logs are stored

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: "3"
services:
  floaty:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./config.json:/root/config.json
      - ./data:/data
    restart: unless-stopped
```

Run with `docker-compose up -d`

## Configuration

### Tracker Configuration

The `config.json` file defines your trackers:

```json
[
  {
    "title": "Display Name",
    "slug": "url-slug"
  }
]
```

- `title` - Display name shown in the UI
- `slug` - URL-safe identifier (lowercase, no spaces)

### Environment Variables

- `FLOATY_CONFIG` - Path to config file (default: `config.json`)
- `PORT` - HTTP port (default: `8080`)

### Application Constants

Edit in `main.go`:

- `recurringValue` - Amount added monthly (default: 100.0)
- `recurringDayOfMonth` - Day of month for recurring addition (default: 1)

## How It Works

### Event Sourcing

All changes are stored as events in `data/{slug}.log` as JSON lines:

```json
{"id":"abc123","timestamp":"2025-10-29T10:00:00Z","type":"manual","value":50.0,"note":"Initial deposit"}
{"id":"def456","timestamp":"2025-11-01T00:00:00Z","type":"recurring","value":100.0,"note":"Monthly recurring addition"}
```

### Automatic Recurring Events

When data is requested:

1. Load all events from log file
2. Check time gap between last event and current time
3. Generate synthetic recurring events for each month boundary crossed
4. Persist synthetic events to log
5. Calculate total from all events

If the server is offline for 3 months, it will automatically generate and persist 3 monthly recurring events when it comes back online.

### Soft Deletes

Deleting a transaction appends a deletion marker to the log. The event remains in the file but is filtered out when reading.

## API Endpoints

### Homepage

- `GET /` - List of all trackers

### Per-Tracker Endpoints

- `GET /{slug}` - Tracker UI
- `GET /api/{slug}/total` - Get current total
- `GET /api/{slug}/events` - Get all events
- `POST /api/{slug}/add` - Add value `{"value": 50.0, "note": "optional"}`
- `POST /api/{slug}/subtract` - Subtract value `{"value": 25.0, "note": "optional"}`
- `POST /api/{slug}/delete` - Delete transaction `{"id": "event-id"}`

## Data Persistence

Event logs are stored in the `data/` directory:

- `data/personal.log`
- `data/business.log`
- etc.

**Always mount the data directory** to persist data across container restarts.

## Development

### Project Structure

```
floaty/
├── main.go                 # Go backend
├── config.json            # Tracker configuration
├── config.json.example    # Example configuration
├── static/
│   ├── index.html         # Homepage template
│   ├── tracker.html       # Tracker page template
│   ├── style.css          # Shared styles
│   └── 404.html           # 404 page
├── data/                  # Event logs (created at runtime)
├── Dockerfile
└── README.md
```

### Adding a New Tracker

1. Edit `config.json`
2. Add new tracker object with `title` and `slug`
3. Restart the server
4. New tracker available at `/{slug}`

### Recurring Event Logic

Recurring events are generated on-demand when data is read. The system:

1. Finds the last event timestamp
2. Calculates how many months have passed
3. Generates events for the 1st of each missed month
4. Writes them to the log file

All timestamps are stored in UTC to avoid timezone issues.
