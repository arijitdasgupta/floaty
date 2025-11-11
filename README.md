# Floaty

## Multiple Numbers Rolling Totals

_THIS IS NOT A PRODUCTION GRADE APP, ONLY MEANT FOR (my own) PERSONAL USAGE_

_Almost entirely written with Claude Sonnet 4.5 (including this README)._

A simple web application that tracks multiple rolling totals with manual additions/subtractions.

This is entirely a personal tool I made to keep track of my things.
I have zero plans to improve this as of now.
That being said, if you do want to use it, feel free. It's decent looking, it's tiny and it works!

## Code Structure

The codebase is now modularized into separate packages for better maintainability:

- **`models/`** - Data models (Event, Tracker, EventType) and validation logic
- **`storage/`** - Event storage operations (file I/O, event loading, calculations)
- **`auth/`** - Authentication logic (session management, token generation)
- **`handlers/`** - HTTP handlers for web routes and API endpoints
- **`middleware/`** - HTTP middleware (logging, authentication, slug validation)
- **`main.go`** - Application entry point and server configuration (115 lines)

## Testing

The project includes comprehensive unit tests for all packages:

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./...
```

**Test Coverage:**
- `auth/` - 100% coverage (session management, token generation)
- `models/` - 100% coverage (slug validation, ID generation)
- `storage/` - 61.2% coverage (event loading, appending, calculations)
- `handlers/` - 50.6% coverage (API endpoints, login flow)

All 38 tests passing.

## TODOs
 - Edit function is wonky!

## Screenshots

![Screenshot 1](./images/shot1.jpg)
![Screenshot 2](./images/shot2.jpg)

## Features

- **Multiple trackers** - Configure multiple independent number trackers
- **Add/Subtract values** with optional notes
- **Edit transactions** - Modify existing entries inline with full history preservation
- **Delete transactions** - Remove manual transactions with soft deletes
- **Event-sourced storage** - All changes logged to append-only files
- **Mobile-friendly** - Responsive design that works on all devices
- **Cookie-based authentication** - Simple username/password protection with configurable session duration
- **Dockerized** - Fully self-contained deployment

## Quick Start

### Inner Workings

Each tracker gets:

- Its own URL: `/{slug}`
- Its own log file: `data/{slug}.log`
- Its own API endpoints: `/api/{slug}/*`

### Run Locally (Development)

```bash
# Run the server (uses default username "admin" and password "floaty")
go run main.go

# Run with custom credentials
FLOATY_USERNAME=myuser FLOATY_PASSWORD=mysecretpassword go run main.go

# Run with custom cookie expiration (e.g., 1 hour = 3600 seconds)
FLOATY_COOKIE_MAX_AGE=3600 go run main.go

# Run without authentication (public access - use with caution!)
FLOATY_NO_AUTH=true go run main.go
```

Access the app at http://localhost:8080

**Default login:** Username: `admin`, Password: `floaty` (change via `FLOATY_USERNAME` and `FLOATY_PASSWORD` environment variables)

**No-auth mode:** Set `FLOATY_NO_AUTH=true` to disable authentication entirely. This makes the application publicly accessible without any login.

### Build and Run with Docker

```bash
# Build the image
docker build -t floaty .

# Run with authentication
docker run -d -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e FLOATY_USERNAME=myuser \
  -e FLOATY_PASSWORD=mysecretpassword \
  -e FLOATY_COOKIE_MAX_AGE=259200 \
  --name floaty \
  floaty

# Run without authentication (public access)
docker run -d -p 8080:8080 \
  -v $(pwd)/data:/data \
  -e FLOATY_NO_AUTH=true \
  --name floaty \
  floaty
```

**Important mounts:**

- `data/` - Directory where event logs are stored

## Configuration

### Environment Variables

- `PORT` - HTTP port (default: `8080`)
- `FLOATY_USERNAME` - Username for login (default: `admin` - **change this in production!**)
- `FLOATY_PASSWORD` - Password for login (default: `floaty` - **change this in production!**)
- `FLOATY_COOKIE_MAX_AGE` - Cookie expiration time in seconds (default: `259200` = 3 days)
- `FLOATY_NO_AUTH` - Disable authentication when set to `true` (default: `false` - **use with caution!**)

## How It Works

### Event Sourcing

All changes are stored as events in `data/{slug}.log` as JSON lines. This includes:
- Manual additions and subtractions
- Deletions (soft deletes with markers)
- Edits (new events referencing original event IDs)

Each event has a unique ID and timestamp, creating an immutable audit trail.

### Soft Deletes

Deleting a transaction appends a deletion marker to the log. The event remains in the file but is filtered out when reading.

### Event Editing

Editing a transaction creates a new event with an `edited_id` field pointing to the original event. The system follows edit chains to display only the latest version while preserving the original timestamp and maintaining the full history in the log.

## API Endpoints

### Authentication

- `GET /login` - Login page
- `POST /login` - Login with credentials `{"username": "admin", "password": "your-password"}`

All endpoints below require authentication via cookie (unless `FLOATY_NO_AUTH=true` is set).

### Homepage

- `GET /` - List of all trackers

### Tracker Management

- `POST /api/trackers/create` - Create new tracker `{"title": "My Tracker", "slug": "my-tracker"}`
- `POST /api/trackers/delete` - Delete tracker `{"slug": "my-tracker"}`

### Per-Tracker Endpoints

- `GET /{slug}` - Tracker UI
- `GET /api/{slug}/total` - Get current total
- `GET /api/{slug}/events` - Get all events (filtered to show latest versions after edits)
- `POST /api/{slug}/add` - Add value `{"value": 50.0, "note": "optional"}`
- `POST /api/{slug}/subtract` - Subtract value `{"value": 25.0, "note": "optional"}`
- `POST /api/{slug}/edit` - Edit transaction `{"id": "event-id", "value": 75.0, "note": "updated note"}`
- `POST /api/{slug}/delete` - Delete transaction `{"id": "event-id"}`

## Data Persistence

Event logs are stored in the `data/` directory:

- `data/personal.log`
- `data/business.log`
- etc.

**Always mount the data directory** to persist data across container restarts.

## Forking

If you choose to fork this repository, ensure you set the secrets for the Github actions to work.
