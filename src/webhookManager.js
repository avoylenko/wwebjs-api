const fsp = require('fs').promises
const path = require('path')
const { v4: uuidv4 } = require('uuid')
const { sessionFolderPath, baseWebhookURL } = require('./config')
const { logger } = require('./logger')

const WEBHOOKS_FILE = path.join(sessionFolderPath, 'webhooks.json')

// Known event types for validation
const VALID_EVENT_TYPES = [
  'auth_failure',
  'authenticated',
  'call',
  'change_state',
  'disconnected',
  'group_join',
  'group_leave',
  'group_admin_changed',
  'group_membership_request',
  'group_update',
  'loading_screen',
  'media_uploaded',
  'message',
  'message_ack',
  'message_create',
  'message_reaction',
  'message_edit',
  'message_ciphertext',
  'message_revoke_everyone',
  'message_revoke_me',
  'qr',
  'ready',
  'contact_changed',
  'chat_removed',
  'chat_archived',
  'unread_count',
  'vote_update',
  'code',
  'media'
]

// In-memory cache of webhook configurations
let webhookCache = {}
let isLoaded = false
let saveQueue = Promise.resolve()

/**
 * Load webhook configurations from file
 * @returns {Promise<Object>} Webhook configurations
 */
const loadWebhooks = async () => {
  if (isLoaded) return webhookCache
  
  try {
    const data = await fsp.readFile(WEBHOOKS_FILE, 'utf-8')
    webhookCache = JSON.parse(data)
    isLoaded = true
    logger.info('Loaded webhook configurations from file')
    return webhookCache
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist, initialize empty cache
      webhookCache = {}
      isLoaded = true
      logger.info('No webhook configuration file found, starting with empty cache')
      return webhookCache
    }
    logger.error({ err: error }, 'Failed to load webhook configurations')
    throw error
  }
}

/**
 * Save webhook configurations to file
 * Serializes saves to prevent race conditions
 * @returns {Promise<void>}
 */
const saveWebhooks = async () => {
  // Queue saves to prevent race conditions
  saveQueue = saveQueue.then(async () => {
    try {
      // Ensure directory exists
      await fsp.mkdir(sessionFolderPath, { recursive: true })
      await fsp.writeFile(WEBHOOKS_FILE, JSON.stringify(webhookCache, null, 2), 'utf-8')
      logger.debug('Saved webhook configurations to file')
    } catch (error) {
      logger.error({ err: error }, 'Failed to save webhook configurations')
      throw error
    }
  })
  return saveQueue
}

/**
 * Validate webhook URL format
 * @param {string} url - URL to validate
 * @returns {boolean} True if valid
 */
const isValidUrl = (url) => {
  try {
    const parsedUrl = new URL(url)
    return parsedUrl.protocol === 'http:' || parsedUrl.protocol === 'https:'
  } catch {
    return false
  }
}

/**
 * Validate event types
 * @param {Array<string>} events - Array of event types
 * @returns {Object} { valid: boolean, invalidEvents: Array<string> }
 */
const validateEvents = (events) => {
  if (!Array.isArray(events)) {
    return { valid: false, invalidEvents: [] }
  }
  
  const invalidEvents = events.filter(event => !VALID_EVENT_TYPES.includes(event))
  return {
    valid: invalidEvents.length === 0,
    invalidEvents
  }
}

/**
 * Get webhooks for a session
 * @param {string} sessionId - Session identifier
 * @returns {Array} Array of webhook configurations
 */
const getSessionWebhooks = (sessionId) => {
  const session = webhookCache[sessionId]
  if (!session || !session.webhooks) {
    return []
  }
  return session.webhooks
}

/**
 * Get all sessions with their webhooks
 * @returns {Object} Object with sessionIds as keys and webhook arrays as values
 */
const getAllWebhooks = () => {
  return { ...webhookCache }
}

/**
 * Add a webhook to a session
 * @param {string} sessionId - Session identifier
 * @param {string} url - Webhook URL
 * @param {Array<string>} events - Event types to filter (empty = all events)
 * @param {boolean} enabled - Whether webhook is enabled
 * @returns {Object} Created webhook object
 * @throws {Error} If validation fails
 */
const addWebhook = async (sessionId, url, events = [], enabled = true) => {
  // Ensure cache is loaded
  await loadWebhooks()
  
  // Validate URL
  if (!isValidUrl(url)) {
    throw new Error('Invalid URL format. URL must start with http:// or https://')
  }

  // Validate events
  const eventValidation = validateEvents(events)
  if (!eventValidation.valid) {
    throw new Error(`Invalid event types: ${eventValidation.invalidEvents.join(', ')}`)
  }

  // Create webhook object
  const webhook = {
    id: uuidv4(),
    url,
    events,
    enabled,
    createdAt: new Date().toISOString()
  }

  // Initialize session if doesn't exist
  if (!webhookCache[sessionId]) {
    webhookCache[sessionId] = { webhooks: [] }
  }

  // Add webhook
  webhookCache[sessionId].webhooks.push(webhook)

  // Save to file
  await saveWebhooks()

  logger.info({ sessionId, webhookId: webhook.id, url }, 'Added webhook')
  return webhook
}

/**
 * Update a webhook
 * @param {string} sessionId - Session identifier
 * @param {string} webhookId - Webhook identifier
 * @param {Object} updates - Updates to apply (url, events, enabled)
 * @returns {Object} Updated webhook object
 * @throws {Error} If webhook not found or validation fails
 */
const updateWebhook = async (sessionId, webhookId, updates) => {
  // Ensure cache is loaded
  await loadWebhooks()
  
  const session = webhookCache[sessionId]
  if (!session || !session.webhooks) {
    throw new Error('Session not found')
  }

  const webhookIndex = session.webhooks.findIndex(w => w.id === webhookId)
  if (webhookIndex === -1) {
    throw new Error('Webhook not found')
  }

  const webhook = session.webhooks[webhookIndex]

  // Validate URL if provided
  if (updates.url !== undefined) {
    if (!isValidUrl(updates.url)) {
      throw new Error('Invalid URL format. URL must start with http:// or https://')
    }
    webhook.url = updates.url
  }

  // Validate events if provided
  if (updates.events !== undefined) {
    const eventValidation = validateEvents(updates.events)
    if (!eventValidation.valid) {
      throw new Error(`Invalid event types: ${eventValidation.invalidEvents.join(', ')}`)
    }
    webhook.events = updates.events
  }

  // Update enabled status if provided
  if (updates.enabled !== undefined) {
    webhook.enabled = updates.enabled
  }

  webhook.updatedAt = new Date().toISOString()

  // Save to file
  await saveWebhooks()

  logger.info({ sessionId, webhookId, updates }, 'Updated webhook')
  return webhook
}

/**
 * Delete a webhook
 * @param {string} sessionId - Session identifier
 * @param {string} webhookId - Webhook identifier
 * @returns {boolean} True if deleted
 * @throws {Error} If webhook not found
 */
const deleteWebhook = async (sessionId, webhookId) => {
  // Ensure cache is loaded
  await loadWebhooks()
  
  const session = webhookCache[sessionId]
  if (!session || !session.webhooks) {
    throw new Error('Session not found')
  }

  const webhookIndex = session.webhooks.findIndex(w => w.id === webhookId)
  if (webhookIndex === -1) {
    throw new Error('Webhook not found')
  }

  session.webhooks.splice(webhookIndex, 1)

  // Remove session if no webhooks left
  if (session.webhooks.length === 0) {
    delete webhookCache[sessionId]
  }

  // Save to file
  await saveWebhooks()

  logger.info({ sessionId, webhookId }, 'Deleted webhook')
  return true
}

/**
 * Get webhooks that should receive a specific event
 * @param {string} sessionId - Session identifier
 * @param {string} eventType - Event type
 * @returns {Array} Array of webhook URLs that should receive this event
 */
const getWebhooksForEvent = (sessionId, eventType) => {
  const session = webhookCache[sessionId]
  if (!session || !session.webhooks) {
    // Fall back to environment variable if no webhooks configured
    const envWebhook = process.env[sessionId.toUpperCase() + '_WEBHOOK_URL'] || baseWebhookURL
    return envWebhook ? [envWebhook] : []
  }

  // Filter enabled webhooks that accept this event type
  const matchingWebhooks = session.webhooks
    .filter(webhook => {
      if (!webhook.enabled) return false
      // Empty events array means all events
      if (webhook.events.length === 0) return true
      // Check if event is in the filter
      return webhook.events.includes(eventType)
    })
    .map(webhook => webhook.url)

  // If no webhooks configured but env var exists, use env var as fallback
  if (matchingWebhooks.length === 0) {
    const envWebhook = process.env[sessionId.toUpperCase() + '_WEBHOOK_URL'] || baseWebhookURL
    return envWebhook ? [envWebhook] : []
  }

  return matchingWebhooks
}

/**
 * Get list of valid event types
 * @returns {Array<string>} Array of valid event types
 */
const getValidEventTypes = () => {
  return [...VALID_EVENT_TYPES]
}

// Initialize webhook cache on module load
loadWebhooks().catch(err => {
  logger.error({ err }, 'Failed to initialize webhook manager')
})

module.exports = {
  loadWebhooks,
  saveWebhooks,
  getSessionWebhooks,
  getAllWebhooks,
  addWebhook,
  updateWebhook,
  deleteWebhook,
  getWebhooksForEvent,
  getValidEventTypes,
  isValidUrl,
  validateEvents
}

