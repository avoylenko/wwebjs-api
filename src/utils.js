const axios = require('axios')
const { globalApiKey, disabledCallbacks, enableWebHook } = require('./config')
const { logger } = require('./logger')
const ChatFactory = require('whatsapp-web.js/src/factories/ChatFactory')
const Client = require('whatsapp-web.js').Client
const { Chat, Message } = require('whatsapp-web.js/src/structures')
const { getWebhooksForEvent } = require('./webhookManager')

// Trigger webhook endpoint
const triggerWebhook = (sessionId, dataType, data) => {
  if (enableWebHook) {
    // Get all webhooks that should receive this event
    const webhookURLs = getWebhooksForEvent(sessionId, dataType)
    
    // Send to all matching webhooks in parallel
    webhookURLs.forEach(webhookURL => {
      axios.post(webhookURL, { dataType, data, sessionId }, { headers: { 'x-api-key': globalApiKey } })
        .then(() => logger.debug({ sessionId, dataType, data: data || '' }, `Webhook message sent to ${webhookURL}`))
        .catch(error => logger.error({ sessionId, dataType, err: error, data: data || '' }, `Failed to send webhook message to ${webhookURL}`))
    })
  }
}

// Function to send a response with error status and message
const sendErrorResponse = (res, status, message) => {
  res.status(status).json({ success: false, error: message })
}

// Function to wait for a specific item not to be null
const waitForNestedObject = (rootObj, nestedPath, maxWaitTime = 10000, interval = 100) => {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const checkObject = () => {
      const nestedObj = nestedPath.split('.').reduce((obj, key) => obj ? obj[key] : undefined, rootObj)
      if (nestedObj) {
        // Nested object exists, resolve the promise
        resolve()
      } else if (Date.now() - start > maxWaitTime) {
        // Maximum wait time exceeded, reject the promise
        logger.error('Timed out waiting for nested object')
        reject(new Error('Timeout waiting for nested object'))
      } else {
        // Nested object not yet created, continue waiting
        setTimeout(checkObject, interval)
      }
    }
    checkObject()
  })
}

const isEventEnabled = (event) => {
  return !disabledCallbacks.includes(event)
}

const sendMessageSeenStatus = async (message) => {
  try {
    const chat = await message.getChat()
    await chat.sendSeen()
  } catch (error) {
    logger.error(error, 'Failed to send seen status')
  }
}

const decodeBase64 = function * (base64String) {
  const chunkSize = 1024
  for (let i = 0; i < base64String.length; i += chunkSize) {
    const chunk = base64String.slice(i, i + chunkSize)
    yield Buffer.from(chunk, 'base64')
  }
}

/**
 * Normalize a chatId into a best-effort canonical form.
 * - Trims whitespace
 * - If given a plain phone number, appends '@c.us'
 * - If given '+<digits>', strips non-digits and appends '@c.us'
 */
const normalizeChatId = (chatId) => {
  if (typeof chatId !== 'string') return chatId
  const trimmed = chatId.trim()
  // Already a JID-like value (group/channel/broadcast/contact)
  if (trimmed.includes('@')) return trimmed

  // Treat as phone number
  const digits = trimmed.replace(/[^\d]/g, '')
  if (!digits) return trimmed
  return `${digits}@c.us`
}

/**
 * Normalize base64 payloads.
 * - Accepts either raw base64 or a data-uri: "data:<mimetype>;base64,<data>"
 * - Strips whitespace/newlines
 */
const normalizeBase64Media = ({ mimetype, data, filename = null, filesize = null } = {}) => {
  if (typeof data !== 'string') {
    return { mimetype, data, filename, filesize }
  }

  let nextMimetype = mimetype
  let nextData = data.trim().replace(/\s+/g, '')

  const dataUriMatch = nextData.match(/^data:([^;]+);base64,(.+)$/i)
  if (dataUriMatch) {
    nextMimetype = nextMimetype || dataUriMatch[1]
    nextData = dataUriMatch[2]
  }

  return { mimetype: nextMimetype, data: nextData, filename, filesize }
}

/**
 * Resolve a recipient id for sending messages.
 * For contacts, uses getNumberId to canonicalize + validate registration.
 * For other ids, returns normalized id as-is.
 */
const resolveSendChatId = async (client, chatId) => {
  const normalized = normalizeChatId(chatId)
  if (typeof normalized !== 'string') return normalized

  // For contact JIDs, try to canonicalize/validate registration to avoid WA Web crashes.
  if (normalized.endsWith('@c.us')) {
    const number = normalized.slice(0, -'@c.us'.length)
    try {
      const numberId = await client.getNumberId(number)
      if (!numberId || !numberId._serialized) return normalized
      return numberId._serialized
    } catch (_) {
      // If getNumberId fails (e.g. transient), fall back to normalized input.
      return normalized
    }
  }

  return normalized
}

const sleep = function (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

const exposeFunctionIfAbsent = async (page, name, fn) => {
  const exist = await page.evaluate((name) => {
    return !!window[name]
  }, name)
  if (exist) {
    return
  }
  await page.exposeFunction(name, fn)
}

const patchWWebLibrary = async (client) => {
  // MUST be run after the 'ready' event fired
  Client.prototype.getChats = async function (searchOptions = {}) {
    const chats = await this.pupPage.evaluate(async (searchOptions) => {
      return await window.WWebJS.getChats({ ...searchOptions })
    }, searchOptions)

    return chats.map(chat => ChatFactory.create(this, chat))
  }

  Chat.prototype.fetchMessages = async function (searchOptions) {
    const messages = await this.client.pupPage.evaluate(async (chatId, searchOptions) => {
      const msgFilter = (m) => {
        if (m.isNotification) {
          return false
        }
        if (searchOptions && searchOptions.fromMe !== undefined && m.id.fromMe !== searchOptions.fromMe) {
          return false
        }
        if (searchOptions && searchOptions.since !== undefined && Number.isFinite(searchOptions.since) && m.t < searchOptions.since) {
          return false
        }
        return true
      }

      const chat = await window.WWebJS.getChat(chatId, { getAsModel: false })
      let msgs = chat.msgs.getModelsArray().filter(msgFilter)

      if (searchOptions && searchOptions.limit > 0) {
        while (msgs.length < searchOptions.limit) {
          const loadedMessages = await window.Store.ConversationMsgs.loadEarlierMsgs(chat)
          if (!loadedMessages || !loadedMessages.length) break
          msgs = [...loadedMessages.filter(msgFilter), ...msgs]
        }

        if (msgs.length > searchOptions.limit) {
          msgs.sort((a, b) => (a.t > b.t) ? 1 : -1)
          msgs = msgs.splice(msgs.length - searchOptions.limit)
        }
      }

      return msgs.map(m => window.WWebJS.getMessageModel(m))
    }, this.id._serialized, searchOptions)

    return messages.map(m => new Message(this.client, m))
  }

  await client.pupPage.evaluate(() => {
    // hotfix for https://github.com/pedroslopez/whatsapp-web.js/pull/3643
    window.WWebJS.getChats = async (searchOptions = {}) => {
      const chatFilter = (c) => {
        if (searchOptions && searchOptions.unread === true && c.unreadCount === 0) {
          return false
        }
        if (searchOptions && searchOptions.since !== undefined && Number.isFinite(searchOptions.since) && c.t < searchOptions.since) {
          return false
        }
        return true
      }

      const allChats = window.Store.Chat.getModelsArray()

      const filteredChats = allChats.filter(chatFilter)

      return await Promise.all(
        filteredChats.map(chat => window.WWebJS.getChatModel(chat))
      )
    }
  })
}

module.exports = {
  triggerWebhook,
  sendErrorResponse,
  waitForNestedObject,
  isEventEnabled,
  sendMessageSeenStatus,
  decodeBase64,
  normalizeChatId,
  normalizeBase64Media,
  resolveSendChatId,
  sleep,
  exposeFunctionIfAbsent,
  patchWWebLibrary
}
