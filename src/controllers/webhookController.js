const { sendErrorResponse } = require('../utils')
const { logger } = require('../logger')
const { sessions } = require('../sessions')
const {
  getSessionWebhooks,
  getAllWebhooks,
  addWebhook,
  updateWebhook,
  deleteWebhook,
  getValidEventTypes
} = require('../webhookManager')

/**
 * Get webhooks for a specific session
 *
 * @function getSessionWebhooksEndpoint
 * @async
 * @param {Object} req - Express request object
 * @param {string} req.params.sessionId - Session identifier
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const getSessionWebhooksEndpoint = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Get webhooks for session'
    #swagger.description = 'Retrieve all webhooks configured for a specific session'
    #swagger.responses[200] = {
      description: "Webhooks retrieved successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            webhooks: [
              {
                id: "webhook-uuid",
                url: "https://example.com/webhook",
                events: ["message", "qr"],
                enabled: true,
                createdAt: "2025-01-01T00:00:00.000Z"
              }
            ]
          }
        }
      }
    }
  */
  try {
    const { sessionId } = req.params
    const webhooks = getSessionWebhooks(sessionId)
    res.json({ success: true, webhooks })
  } catch (error) {
    /* #swagger.responses[500] = {
      description: "Server Failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
    */
    logger.error({ err: error, sessionId: req.params.sessionId }, 'Failed to get session webhooks')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get all sessions with their webhooks
 *
 * @function getAllSessionWebhooks
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const getAllSessionWebhooks = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Get all sessions with webhooks'
    #swagger.description = 'Retrieve all sessions and their configured webhooks'
    #swagger.responses[200] = {
      description: "Sessions retrieved successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            sessions: [
              {
                sessionId: "main",
                webhooks: [
                  {
                    id: "webhook-uuid",
                    url: "https://example.com/webhook",
                    events: ["message"],
                    enabled: true
                  }
                ]
              },
              {
                sessionId: "support",
                webhooks: []
              }
            ]
          }
        }
      }
    }
  */
  try {
    const allWebhooks = getAllWebhooks()
    const activeSessions = Array.from(sessions.keys())
    
    // Build response with all sessions
    const sessionsList = activeSessions.map(sessionId => ({
      sessionId,
      webhooks: allWebhooks[sessionId]?.webhooks || []
    }))

    res.json({ success: true, sessions: sessionsList })
  } catch (error) {
    /* #swagger.responses[500] = {
      description: "Server Failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
    */
    logger.error({ err: error }, 'Failed to get all session webhooks')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Add a webhook to a session
 *
 * @function addSessionWebhook
 * @async
 * @param {Object} req - Express request object
 * @param {string} req.params.sessionId - Session identifier
 * @param {Object} req.body - Request body
 * @param {string} req.body.url - Webhook URL
 * @param {Array<string>} req.body.events - Event types to filter (optional, empty = all events)
 * @param {boolean} req.body.enabled - Whether webhook is enabled (optional, default: true)
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const addSessionWebhook = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Add webhook to session'
    #swagger.description = 'Add a new webhook to a session with optional event filtering. Valid event types: auth_failure, authenticated, call, change_state, disconnected, group_join, group_leave, group_admin_changed, group_membership_request, group_update, loading_screen, media_uploaded, message, message_ack, message_create, message_reaction, message_edit, message_ciphertext, message_revoke_everyone, message_revoke_me, qr, ready, contact_changed, chat_removed, chat_archived, unread_count, vote_update, code, media'
    #swagger.requestBody = {
      required: true,
      content: {
        "application/json": {
          schema: {
            type: 'object',
            required: ['url'],
            properties: {
              url: {
                type: 'string',
                description: 'Webhook URL (must start with http:// or https://)',
                example: 'https://example.com/webhook'
              },
              events: {
                type: 'array',
                description: 'Event types to send to this webhook. Empty array means all events. Valid events: auth_failure, authenticated, call, change_state, disconnected, group_join, group_leave, group_admin_changed, group_membership_request, group_update, loading_screen, media_uploaded, message, message_ack, message_create, message_reaction, message_edit, message_ciphertext, message_revoke_everyone, message_revoke_me, qr, ready, contact_changed, chat_removed, chat_archived, unread_count, vote_update, code, media',
                items: { 
                  type: 'string',
                  enum: ['auth_failure', 'authenticated', 'call', 'change_state', 'disconnected', 'group_join', 'group_leave', 'group_admin_changed', 'group_membership_request', 'group_update', 'loading_screen', 'media_uploaded', 'message', 'message_ack', 'message_create', 'message_reaction', 'message_edit', 'message_ciphertext', 'message_revoke_everyone', 'message_revoke_me', 'qr', 'ready', 'contact_changed', 'chat_removed', 'chat_archived', 'unread_count', 'vote_update', 'code', 'media']
                },
                example: ['message', 'qr', 'ready']
              },
              enabled: {
                type: 'boolean',
                description: 'Whether webhook is enabled',
                example: true
              }
            }
          }
        }
      }
    }
    #swagger.responses[201] = {
      description: "Webhook created successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            webhook: {
              id: "webhook-uuid",
              url: "https://example.com/webhook",
              events: ["message", "qr"],
              enabled: true,
              createdAt: "2025-01-01T00:00:00.000Z"
            }
          }
        }
      }
    }
  */
  try {
    const { sessionId } = req.params
    const { url, events = [], enabled = true } = req.body

    if (!url) {
      return sendErrorResponse(res, 400, 'URL is required')
    }

    const webhook = await addWebhook(sessionId, url, events, enabled)
    res.status(201).json({ success: true, webhook })
  } catch (error) {
    /* #swagger.responses[400] = {
      description: "Bad Request.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
    */
    logger.error({ err: error, sessionId: req.params.sessionId }, 'Failed to add webhook')
    sendErrorResponse(res, 400, error.message)
  }
}

/**
 * Update a webhook
 *
 * @function updateSessionWebhook
 * @async
 * @param {Object} req - Express request object
 * @param {string} req.params.sessionId - Session identifier
 * @param {string} req.params.webhookId - Webhook identifier
 * @param {Object} req.body - Request body with updates
 * @param {string} req.body.url - Webhook URL (optional)
 * @param {Array<string>} req.body.events - Event types to filter (optional)
 * @param {boolean} req.body.enabled - Whether webhook is enabled (optional)
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const updateSessionWebhook = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Update webhook'
    #swagger.description = 'Update an existing webhook configuration. Valid event types: auth_failure, authenticated, call, change_state, disconnected, group_join, group_leave, group_admin_changed, group_membership_request, group_update, loading_screen, media_uploaded, message, message_ack, message_create, message_reaction, message_edit, message_ciphertext, message_revoke_everyone, message_revoke_me, qr, ready, contact_changed, chat_removed, chat_archived, unread_count, vote_update, code, media'
    #swagger.requestBody = {
      required: true,
      content: {
        "application/json": {
          schema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'Webhook URL (must start with http:// or https://)',
                example: 'https://example.com/webhook'
              },
              events: {
                type: 'array',
                description: 'Event types to send to this webhook. Empty array means all events. Valid events: auth_failure, authenticated, call, change_state, disconnected, group_join, group_leave, group_admin_changed, group_membership_request, group_update, loading_screen, media_uploaded, message, message_ack, message_create, message_reaction, message_edit, message_ciphertext, message_revoke_everyone, message_revoke_me, qr, ready, contact_changed, chat_removed, chat_archived, unread_count, vote_update, code, media',
                items: { 
                  type: 'string',
                  enum: ['auth_failure', 'authenticated', 'call', 'change_state', 'disconnected', 'group_join', 'group_leave', 'group_admin_changed', 'group_membership_request', 'group_update', 'loading_screen', 'media_uploaded', 'message', 'message_ack', 'message_create', 'message_reaction', 'message_edit', 'message_ciphertext', 'message_revoke_everyone', 'message_revoke_me', 'qr', 'ready', 'contact_changed', 'chat_removed', 'chat_archived', 'unread_count', 'vote_update', 'code', 'media']
                },
                example: ['message', 'ready']
              },
              enabled: {
                type: 'boolean',
                description: 'Whether webhook is enabled',
                example: true
              }
            }
          }
        }
      }
    }
    #swagger.responses[200] = {
      description: "Webhook updated successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            webhook: {
              id: "webhook-uuid",
              url: "https://example.com/webhook",
              events: ["message"],
              enabled: true,
              updatedAt: "2025-01-01T00:00:00.000Z"
            }
          }
        }
      }
    }
  */
  try {
    const { sessionId, webhookId } = req.params
    const updates = req.body

    if (Object.keys(updates).length === 0) {
      return sendErrorResponse(res, 400, 'No updates provided')
    }

    const webhook = await updateWebhook(sessionId, webhookId, updates)
    res.json({ success: true, webhook })
  } catch (error) {
    /* #swagger.responses[404] = {
      description: "Not Found.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/NotFoundResponse" }
        }
      }
    }
    */
    logger.error({ err: error, sessionId: req.params.sessionId, webhookId: req.params.webhookId }, 'Failed to update webhook')
    const statusCode = error.message.includes('not found') ? 404 : 400
    sendErrorResponse(res, statusCode, error.message)
  }
}

/**
 * Delete a webhook
 *
 * @function deleteSessionWebhook
 * @async
 * @param {Object} req - Express request object
 * @param {string} req.params.sessionId - Session identifier
 * @param {string} req.params.webhookId - Webhook identifier
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const deleteSessionWebhook = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Delete webhook'
    #swagger.description = 'Delete a webhook from a session'
    #swagger.responses[200] = {
      description: "Webhook deleted successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            message: "Webhook deleted successfully"
          }
        }
      }
    }
  */
  try {
    const { sessionId, webhookId } = req.params
    await deleteWebhook(sessionId, webhookId)
    res.json({ success: true, message: 'Webhook deleted successfully' })
  } catch (error) {
    /* #swagger.responses[404] = {
      description: "Not Found.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/NotFoundResponse" }
        }
      }
    }
    */
    logger.error({ err: error, sessionId: req.params.sessionId, webhookId: req.params.webhookId }, 'Failed to delete webhook')
    const statusCode = error.message.includes('not found') ? 404 : 500
    sendErrorResponse(res, statusCode, error.message)
  }
}

/**
 * Get list of valid event types
 *
 * @function getEventTypes
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>}
 */
const getEventTypes = async (req, res) => {
  /*
    #swagger.tags = ['Webhook']
    #swagger.summary = 'Get valid event types'
    #swagger.description = 'Retrieve list of all valid event types that can be used in webhook filters'
    #swagger.responses[200] = {
      description: "Event types retrieved successfully",
      content: {
        "application/json": {
          example: {
            success: true,
            eventTypes: ["message", "qr", "ready", "authenticated", "disconnected"]
          }
        }
      }
    }
  */
  try {
    const eventTypes = getValidEventTypes()
    res.json({ success: true, eventTypes })
  } catch (error) {
    logger.error({ err: error }, 'Failed to get event types')
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getSessionWebhooksEndpoint,
  getAllSessionWebhooks,
  addSessionWebhook,
  updateSessionWebhook,
  deleteSessionWebhook,
  getEventTypes
}

