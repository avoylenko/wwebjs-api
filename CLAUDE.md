# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WWebJS REST API is a REST API wrapper for the whatsapp-web.js library. It runs multiple WhatsApp Web client sessions simultaneously via Docker, each session identified by a unique `sessionId`. The architecture supports both webhook and websocket delivery of events.

## Development Commands

### Running Locally
```bash
npm install                  # Install dependencies
cp .env.example .env         # Configure environment variables
npm start                    # Start the server (runs server.js)
```

### Docker
```bash
docker-compose pull && docker-compose up    # Start with Docker
```

### Testing
```bash
npm test                     # Run test suite with Jest (runs in band)
```

### Documentation
```bash
npm run swagger              # Generate Swagger documentation
```

Server runs on `http://localhost:3000` by default (configurable via `PORT` env var).

## Architecture

### Core Components

**Session Management (`src/sessions.js`)**
- Central module managing WhatsApp client instances via a `Map<sessionId, Client>`
- `setupSession(sessionId)`: Creates new whatsapp-web.js Client with Puppeteer config
- `restoreSessions()`: Called on startup to restore all sessions from `./sessions` folder
- `validateSession(sessionId)`: Checks if session is connected and browser page is responsive
- `deleteSession()`: Logs out/destroys client and removes session folder
- Session data persists in `sessionFolderPath` (default: `./sessions/session-{sessionId}/`)

**Webhook System (`src/webhookManager.js`, `src/utils.js`)**
- Dynamic multi-webhook support: each session can have multiple webhook endpoints
- Webhooks stored in `sessions/webhooks.json` with event filtering per webhook
- `triggerWebhook(sessionId, dataType, data)`: Sends events to all matching webhooks
- `getWebhooksForEvent(sessionId, eventType)`: Returns webhook URLs filtered by event type
- Falls back to environment variables (`{SESSIONID}_WEBHOOK_URL` or `BASE_WEBHOOK_URL`) if no webhooks configured
- See `WEBHOOK_API.md` for full webhook management API documentation

**WebSocket System (`src/websocket.js`)**
- Real-time event delivery via WebSocket connections at `/ws/:sessionId`
- One WebSocket server instance per active session
- Supports ping/pong for connection keep-alive
- Enable via `ENABLE_WEBSOCKET=TRUE` environment variable

**Event Handling (`src/sessions.js:initializeEvents()`)**
- WhatsApp events: `qr`, `authenticated`, `ready`, `message`, `message_ack`, `group_join`, etc.
- Events trigger both webhooks and websockets
- Filtered by `DISABLED_CALLBACKS` env var (pipe-separated list)
- `isEventEnabled(event)` checks if event should be dispatched

**Application Bootstrap (`server.js`, `src/app.js`)**
- `server.js`: Entry point, starts Express server, calls `restoreSessions()` if `AUTO_START_SESSIONS=true`
- `src/app.js`: Express app setup with JSON body parsing, routing, and optional base path mounting
- Routes defined in `src/routes.js` with middleware chains

### Route Structure

Routes are organized by resource type with middleware applied:
- **Session routes** (`/session/*`): Start/stop sessions, QR codes, status
- **Client routes** (`/client/*`): Client-level operations (getContacts, sendMessage, createGroup, etc.)
- **Chat routes** (`/chat/*`): Chat-specific operations (fetchMessages, sendSeen, clearMessages)
- **GroupChat routes** (`/groupChat/*`): Group management (addParticipants, promoteParticipants, setDescription)
- **Message routes** (`/message/*`): Message operations (downloadMedia, forward, react, edit)
- **Contact routes** (`/contact/*`): Contact operations (block, getAbout, getProfilePicUrl)
- **Channel routes** (`/channel/*`): Channel operations (sendMessage, mute, sendChannelAdminInvite)
- **Webhook routes** (`/webhook/*`): Dynamic webhook management (add, update, delete, list)

All routes (except `/ping`) require:
1. `middleware.apikey`: Validates `x-api-key` header against `API_KEY` env var
2. `middleware.sessionNameValidation`: Validates sessionId format
3. `middleware.sessionValidation`: Ensures session exists and is connected

### Controllers

Controllers in `src/controllers/` handle business logic:
- Each controller exports functions matching route handlers
- Use `validateSession()` to check session state before operations
- Return standardized responses: `{ success: true/false, data/error }`
- Controllers access client via `sessions.get(sessionId)`

### Key Files

- `src/config.js`: Centralized environment variable parsing and exports
- `src/logger.js`: Pino logger with configurable log level (`LOG_LEVEL` env var)
- `src/middleware.js`: Authentication, rate limiting, session validation
- `src/utils.js`: Helper functions including `triggerWebhook()`, `waitForNestedObject()`, `patchWWebLibrary()`
- `swagger.json`: OpenAPI specification (view at `/api-docs` if `ENABLE_SWAGGER_ENDPOINT=TRUE`)

## Important Implementation Details

### Session Lifecycle
1. **Start**: `GET /session/start/:sessionId` → `setupSession()` → Creates Client with Puppeteer → Emits `qr` event
2. **QR Scan**: Client emits `authenticated` → `ready` events when connected
3. **Active**: Session processes messages and events
4. **Stop**: `GET /session/stop/:sessionId` → `destroySession()` → Keeps session data
5. **Terminate**: `GET /session/terminate/:sessionId` → `deleteSession()` → Removes session folder

### Browser Configuration
- Uses Chromium via Puppeteer with extensive args for Docker compatibility (see `src/sessions.js:setupSession()`)
- `CHROME_BIN` env var specifies executable path (default: `/usr/bin/chromium` in Docker)
- `HEADLESS=TRUE` runs browser headlessly
- `RELEASE_BROWSER_LOCK=TRUE` removes Singleton lock file on startup to prevent lock issues
- `RECOVER_SESSIONS=TRUE` automatically restarts sessions on browser page close/error

### Session Recovery
When `RECOVER_SESSIONS=TRUE`:
- Listens to `pupPage` 'close' and 'error' events
- Automatically destroys and recreates sessions on failures
- Prevents sessions from becoming permanently stuck

### Message Handling
- All messages emit `message` event
- If `message.hasMedia` and size < `MAX_ATTACHMENT_SIZE`, automatically downloads media and emits `media` event
- If `SET_MESSAGES_AS_SEEN=TRUE`, automatically marks messages as seen after 1s delay

### WWebJS Library Patching
`patchWWebLibrary()` in `src/utils.js` overrides whatsapp-web.js methods to add custom functionality:
- `Client.prototype.getChats()`: Adds search/filter options
- `Chat.prototype.fetchMessages()`: Adds pagination and filtering
- Called once per session after 'ready' event fires

### Environment Variables
Critical variables (see `.env.example` for full list):
- `API_KEY`: Protects all endpoints (production required)
- `BASE_WEBHOOK_URL`: Default webhook endpoint
- `SESSIONS_PATH`: Session storage location (default: `./sessions`)
- `WEB_VERSION`: WhatsApp Web version to use (e.g., '2.2328.5')
- `DISABLED_CALLBACKS`: Events to disable (pipe-separated, e.g., `message_ack|unread_count`)
- `AUTO_START_SESSIONS=TRUE`: Restore sessions on startup
- `BASE_PATH`: Mount all routes under a base path (e.g., `/api/v1/whatsapp`)
- `TRUST_PROXY=TRUE`: Enable when behind reverse proxy/load balancer

## Testing Strategy

Tests use Jest with Supertest for API endpoint testing. When writing tests:
- Use `--runInBand` flag to run tests sequentially (prevents session conflicts)
- Mock whatsapp-web.js Client when testing session logic
- Test controllers independently by mocking `sessions.get()`

## Common Patterns

### Adding New Endpoints
1. Define route in `src/routes.js` with appropriate middleware
2. Create controller function in corresponding controller file
3. Validate session with `validateSession(sessionId)`
4. Access client via `sessions.get(sessionId)`
5. Update `swagger.json` for documentation

### Adding New Events
1. Add event name to `VALID_EVENT_TYPES` in `src/webhookManager.js`
2. Add listener in `initializeEvents()` in `src/sessions.js`
3. Call `triggerWebhook()` and `triggerWebSocket()` with event data
4. Check `isEventEnabled()` before triggering

### Debugging Sessions
- Check logs with `LOG_LEVEL=debug`
- Use `GET /session/status/:sessionId` to check session state
- Use `GET /session/getPageScreenshot/:sessionId` to capture browser screenshot
- Session folders in `./sessions/session-{sessionId}/` contain Chrome profile data

## Production Considerations

- Set `API_KEY` to protect endpoints
- Disable `ENABLE_LOCAL_CALLBACK_EXAMPLE` in production
- Use `GET /session/terminateInactive` periodically to cleanup stale sessions
- Monitor session storage disk usage (`SESSIONS_PATH` directory)
- Consider setting `DISABLED_CALLBACKS` to reduce webhook noise
- Use `TRUST_PROXY=TRUE` when behind nginx/load balancer
- Configure `BASE_PATH` when deploying behind reverse proxy with path prefix

## Recent Changes

The project recently implemented a dynamic webhook management system (see `WEBHOOK_API.md`) that allows:
- Multiple webhooks per session via REST API
- Per-webhook event filtering
- Runtime webhook configuration without container restart
- Backward compatibility with environment variable configuration
