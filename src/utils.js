const axios = require('axios')
const { globalApiKey, disabledCallbacks, enableWebHook } = require('./config')
const { logger } = require('./logger')
const ChatFactory = require('whatsapp-web.js/src/factories/ChatFactory')
const Client = require('whatsapp-web.js').Client
const { Chat, Message } = require('whatsapp-web.js/src/structures')

// Trigger webhook endpoint
const triggerWebhook = (webhookURL, sessionId, dataType, data) => {
  if (enableWebHook) {
    axios.post(webhookURL, { dataType, data, sessionId }, { headers: { 'x-api-key': globalApiKey } })
      .then(() => logger.debug({ sessionId, dataType, data: data || '' }, `Webhook message sent to ${webhookURL}`))
      .catch(error => logger.error({ sessionId, dataType, err: error, data: data || '' }, `Failed to send webhook message to ${webhookURL}`))
  }
}

// Function to send a response with error status and message
const sendErrorResponse = (res, status, error) => {
  const message = error instanceof Error ? error.message : error
  if (error instanceof Error) {
    logger.error({ err: error }, message)
  }
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

// Called when the library sends a message but hands nothing back. Reports what the page looks
// like at that moment so the failure can be told apart from a plain rename: whether a fresh
// MsgKey exposes `_serialized`, and how the keys of the messages already in the chat are shaped.
const logMissingMessage = async (client, chatId) => {
  try {
    const snapshot = await client.pupPage.evaluate(async (chatId) => {
      const probe = (() => {
        try {
          const MsgKey = window.require('WAWebMsgKey')
          const wid = window.require('WAWebWidFactory').createWid('0@c.us')
          const key = new MsgKey({ from: wid, to: wid, id: 'WWEBJSAPIPROBE', selfDir: 'out' })
          return { serialized: key._serialized, fields: Object.keys(key) }
        } catch (error) {
          return { error: error.message }
        }
      })()

      const lastOutgoing = await (async () => {
        try {
          const chat = await window.WWebJS.getChat(chatId, { getAsModel: false })
          const msgs = (chat && chat.msgs && chat.msgs.getModelsArray()) || []
          for (let i = msgs.length - 1; i >= 0; i--) {
            const id = msgs[i] && msgs[i].id
            if (!id || !id.fromMe) { continue }
            return {
              serialized: id._serialized,
              fields: Object.keys(id),
              foundInCollection: !!window.require('WAWebCollections').Msg.get(id._serialized)
            }
          }
          return { error: 'no outgoing message in this chat' }
        } catch (error) {
          return { error: error.message }
        }
      })()

      return { waVersion: window.Debug && window.Debug.VERSION, probe, lastOutgoing }
    }, chatId)
    logger.warn({ chatId, ...snapshot }, 'Sent message was not returned by the library')
  } catch (error) {
    logger.warn({ chatId, err: error }, 'Sent message was not returned by the library')
  }
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
        if (searchOptions && searchOptions.messageId !== undefined && m.id.id !== searchOptions.messageId) {
          return false
        }
        return true
      }

      const chat = await window.WWebJS.getChat(chatId, { getAsModel: false })
      let msgs = chat.msgs.getModelsArray().filter(msgFilter)

      if (searchOptions && searchOptions.limit > 0) {
        while (msgs.length < searchOptions.limit) {
          const loadedMessages = await (window.require('WAWebChatLoadMessages')).loadEarlierMsgs({ chat })

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

      const allChats = window.require('WAWebCollections').Chat.getModelsArray()

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
  sleep,
  exposeFunctionIfAbsent,
  logMissingMessage,
  patchWWebLibrary
}
