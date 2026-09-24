# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

REST API wrapper around [whatsapp-web.js](https://docs.wwebjs.dev/) (Express, CommonJS, Node >= 20). Each WhatsApp session is a headless Chromium instance driven by puppeteer.

## Commands

- `npm start` — run the server (`server.js`), reads `.env` (or the file at `ENV_PATH`). Copy `.env.example` to start.
- `npm test` — Jest with `--runInBand` (required: tests share port 3000 and the `./sessions_test` folder).
- Single test: `npx jest tests/api.test.js -t "should return valid health check"`
- Lint: `npx eslint .` (eslint-config-standard; no npm script, not run in CI).
- `npm run swagger` — regenerate `swagger.json` from `src/routes.js` via swagger-autogen.
- `docker compose up` — run in Docker; sessions persist in a named volume.

Some tests in `tests/api.test.js` start real sessions (launch Chromium and wait for a QR), so they are slow and need a working browser.

## Architecture

- `server.js` — starts the HTTP server, calls `restoreSessions()` when `AUTO_START_SESSIONS` is on, and wires WebSocket upgrades. `src/app.js` builds the Express app (no listen) and is what tests import.
- `src/config.js` — every env var is parsed here into a constant; add new settings here rather than reading `process.env` elsewhere. Exception: per-session webhook override `<SESSIONID>_WEBHOOK_URL` is read in `sessions.js`.
- `src/routes.js` — one Express sub-router per domain (`/session`, `/client`, `/chat`, `/groupChat`, `/message`, `/contact`, `/channel`), all mounted under `BASE_PATH`. Almost every endpoint is `/<domain>/<action>/:sessionId`, with middleware chain `[sessionNameValidation, sessionValidation]`. Optional `/api-docs` (Swagger) and `/dashboard` (static files from `public/dashboard`) are gated by env flags.
- `src/middleware.js` — API key check (`x-api-key` vs `API_KEY`), sessionId format check, `sessionValidation` (404 unless the client is `CONNECTED`), rate limiter, and no-op `*Swagger` middlewares that exist only to carry swagger-autogen tag comments.
- `src/controllers/*` — thin handlers: get the client with `sessions.get(req.params.sessionId)`, call the whatsapp-web.js API, return `{ success: true, ... }`, and on error call `sendErrorResponse(res, 500, error)`.
- `src/sessions.js` — the in-memory `sessions` Map (sessionId → `Client`) and the session lifecycle: `setupSession`, `validateSession`, `reloadSession`, `destroySession`, `deleteSession`, `flushSessions`. Auth uses `LocalAuth` with data in `SESSIONS_PATH/session-<id>`; `restoreSessions` finds sessions by scanning for those folders. `initializeEvents` forwards every client event to the webhook and WebSocket, unless it is listed in `DISABLED_CALLBACKS`.
- `src/utils.js` — `triggerWebhook` (POST `{ dataType, data, sessionId }` with the API key header), `sendErrorResponse`, and `patchWWebLibrary`, which monkey-patches `Client.getChats`, `Chat.fetchMessages`, and `window.WWebJS.getChats` inside the page after `ready`. Check it when upgrading whatsapp-web.js.
- `src/websocket.js` — one `ws` server per session (`noServer` mode), reached at `<BASE_PATH>/ws/:sessionId`.

## Swagger docs

`swagger.json` is generated and committed. API docs live in `#swagger.*` comment blocks inside controllers and middleware. After adding or changing an endpoint or its `#swagger` comments, run `npm run swagger` and commit the updated `swagger.json`.

## CI

PRs to `main` run `npm ci && npm test` on Node 24. Pushing a `v*` or `edge` tag builds and publishes the Docker image; `edge` first installs whatsapp-web.js from GitHub `main`.
