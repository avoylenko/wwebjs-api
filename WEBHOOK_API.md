# Dynamic Webhook Management API

This document describes the new dynamic webhook management system that allows you to configure multiple webhooks per session without restarting the container.

## Overview

The new webhook system provides:
- **Multiple webhooks per session**: Each session can have multiple webhook endpoints
- **Per-webhook event filtering**: Each webhook can listen to specific events or all events
- **Dynamic configuration**: Add, update, or delete webhooks via REST API without restart
- **Backward compatibility**: Environment variable configuration still works as fallback

## API Endpoints

All endpoints require the `x-api-key` header for authentication.

### 1. Get Valid Event Types

Get a list of all valid event types that can be used in webhook filters.

```http
GET /webhook/events
```

**Response:**
```json
{
  "success": true,
  "eventTypes": [
    "auth_failure",
    "authenticated",
    "call",
    "change_state",
    "disconnected",
    "group_join",
    "group_leave",
    "group_admin_changed",
    "group_membership_request",
    "group_update",
    "loading_screen",
    "media_uploaded",
    "message",
    "message_ack",
    "message_create",
    "message_reaction",
    "message_edit",
    "message_ciphertext",
    "message_revoke_everyone",
    "message_revoke_me",
    "qr",
    "ready",
    "contact_changed",
    "chat_removed",
    "chat_archived",
    "unread_count",
    "vote_update",
    "code",
    "media"
  ]
}
```

### 2. Get All Sessions with Webhooks

Get all active sessions and their configured webhooks.

```http
GET /webhook/sessions
```

**Response:**
```json
{
  "success": true,
  "sessions": [
    {
      "sessionId": "main",
      "webhooks": [
        {
          "id": "webhook-uuid",
          "url": "https://example.com/webhook",
          "events": ["message", "qr"],
          "enabled": true,
          "createdAt": "2025-01-01T00:00:00.000Z"
        }
      ]
    },
    {
      "sessionId": "support",
      "webhooks": []
    }
  ]
}
```

### 3. Get Webhooks for a Session

Get all webhooks configured for a specific session.

```http
GET /webhook/session/:sessionId
```

**Response:**
```json
{
  "success": true,
  "webhooks": [
    {
      "id": "webhook-uuid",
      "url": "https://example.com/webhook",
      "events": ["message", "qr"],
      "enabled": true,
      "createdAt": "2025-01-01T00:00:00.000Z"
    }
  ]
}
```

### 4. Add Webhook to Session

Add a new webhook to a session.

```http
POST /webhook/session/:sessionId
Content-Type: application/json

{
  "url": "https://example.com/webhook",
  "events": ["message", "qr", "ready"],
  "enabled": true
}
```

**Parameters:**
- `url` (required): Webhook URL (must start with `http://` or `https://`)
- `events` (optional): Array of event types to send to this webhook. Empty array or omitted = all events
- `enabled` (optional): Whether webhook is enabled. Default: `true`

**Response:**
```json
{
  "success": true,
  "webhook": {
    "id": "webhook-uuid",
    "url": "https://example.com/webhook",
    "events": ["message", "qr", "ready"],
    "enabled": true,
    "createdAt": "2025-01-01T00:00:00.000Z"
  }
}
```

### 5. Update Webhook

Update an existing webhook's configuration.

```http
PUT /webhook/session/:sessionId/:webhookId
Content-Type: application/json

{
  "url": "https://new-url.com/webhook",
  "events": ["message"],
  "enabled": false
}
```

**Parameters:**
All parameters are optional. Only provided fields will be updated.
- `url`: New webhook URL
- `events`: New event filter array
- `enabled`: Enable/disable the webhook

**Response:**
```json
{
  "success": true,
  "webhook": {
    "id": "webhook-uuid",
    "url": "https://new-url.com/webhook",
    "events": ["message"],
    "enabled": false,
    "createdAt": "2025-01-01T00:00:00.000Z",
    "updatedAt": "2025-01-01T01:00:00.000Z"
  }
}
```

### 6. Delete Webhook

Delete a webhook from a session.

```http
DELETE /webhook/session/:sessionId/:webhookId
```

**Response:**
```json
{
  "success": true,
  "message": "Webhook deleted successfully"
}
```

## Event Filtering

Each webhook can specify which events it wants to receive:

- **Empty array `[]` or omitted**: Receives ALL events
- **Specific events**: Only receives the specified event types

**Example:**
```json
{
  "url": "https://example.com/webhook",
  "events": ["message", "qr", "ready"]
}
```
This webhook will ONLY receive `message`, `qr`, and `ready` events.

## Multiple Webhooks

You can configure multiple webhooks for a single session. Each webhook will receive events according to its filter:

**Example Scenario:**
```javascript
// Webhook 1: Only messages
{
  "url": "https://messages.example.com/webhook",
  "events": ["message", "message_ack"]
}

// Webhook 2: Only QR codes and status
{
  "url": "https://auth.example.com/webhook",
  "events": ["qr", "ready", "authenticated", "disconnected"]
}

// Webhook 3: Everything
{
  "url": "https://logger.example.com/webhook",
  "events": []
}
```

When a `message` event occurs:
- Webhook 1: ✅ Receives event
- Webhook 2: ❌ Doesn't receive event
- Webhook 3: ✅ Receives event (receives all)

## Backward Compatibility

The system maintains backward compatibility with environment variable configuration:

1. If no webhooks are configured via API, the system falls back to:
   - `{SESSIONID}_WEBHOOK_URL` environment variable
   - `BASE_WEBHOOK_URL` environment variable

2. Environment variable webhooks receive all events (equivalent to empty events array)

3. The global `DISABLED_CALLBACKS` environment variable still works to disable events globally

## Storage

Webhook configurations are stored in `sessions/webhooks.json` and persist across restarts.

**Note:** This file is added to `.gitignore` by default.

## Usage Examples

### Example 1: Add a webhook for message events only

```bash
curl -X POST http://localhost:3000/webhook/session/main \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/messages",
    "events": ["message", "media"]
  }'
```

### Example 2: Add a webhook for all events

```bash
curl -X POST http://localhost:3000/webhook/session/main \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/all-events",
    "events": []
  }'
```

### Example 3: Temporarily disable a webhook

```bash
curl -X PUT http://localhost:3000/webhook/session/main/webhook-uuid \
  -H "x-api-key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false
  }'
```

### Example 4: List all webhooks for a session

```bash
curl -X GET http://localhost:3000/webhook/session/main \
  -H "x-api-key: your-api-key"
```

### Example 5: Get all valid event types

```bash
curl -X GET http://localhost:3000/webhook/events \
  -H "x-api-key: your-api-key"
```

## Migration from Environment Variables

If you're currently using `BASE_WEBHOOK_URL` or session-specific environment variables, you can:

1. **Keep using them**: The system will continue to work as before
2. **Migrate to API**: Add webhooks via API - they will take precedence over env vars
3. **Use both**: API-configured webhooks + env var fallback for sessions without API config

No restart required for migration!

