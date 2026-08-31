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

// WhatsApp Web 2.3000.x builds (rolled out since July 2026) minify the serialized id field of
// Wid/MsgKey objects away from `_serialized` - `$1` in the builds reported upstream. Every
// `id._serialized` read then yields undefined: WWebJS.sendMessage ends with `Msg.get(undefined)`
// and returns nothing, so `client.sendMessage()` resolves to undefined and this API answers
// `{ success: true }` without the message. The same rename strips ids from the message, chat and
// contact payloads and from the webhooks.
// Upstream issue: https://github.com/wwebjs/whatsapp-web.js/issues/201830
// Wid and MsgKey are renamed independently and the alias is minifier output, so each class is
// probed on its own and the alias is discovered by value rather than assumed to be named `$1`.
// NOTE: the callback is serialized and evaluated in the browser - it must not reference module scope.
const patchSerializedIds = async (client) => {
  return await client.pupPage.evaluate(() => {
    if (window.__wwebjsApiSerializedIds) {
      return { applied: false, reason: 'already applied' }
    }

    // The alias holds the same value `_serialized` used to hold, so the probe finds it by
    // recognising the serialized value instead of relying on a name the minifier picked.
    const findAlias = (probe, isSerialized) => {
      const names = Object.keys(probe).concat(Object.getOwnPropertyNames(Object.getPrototypeOf(probe) || {}))
      for (const name of names) {
        if (name === '_serialized' || name === 'constructor') { continue }
        let value
        try { value = probe[name] } catch (error) { continue }
        if (typeof value === 'string' && isSerialized(value)) { return name }
      }
      return null
    }

    const defineSerialized = (prototype, alias) => {
      Object.defineProperty(prototype, '_serialized', {
        configurable: true,
        get () { return this[alias] },
        set (value) {
          Object.defineProperty(this, '_serialized', { value, writable: true, enumerable: true, configurable: true })
        }
      })
    }

    // Returns what happened to one class, so a build that renamed only one of them is visible
    const restoreClass = (buildProbe, isSerialized) => {
      let probe
      try {
        probe = buildProbe()
      } catch (error) {
        return { patched: false, reason: `unable to probe: ${error.message}` }
      }
      if (typeof probe._serialized === 'string') {
        return { patched: false, reason: 'exposes _serialized' }
      }
      const alias = findAlias(probe, isSerialized)
      if (!alias) {
        return { patched: false, reason: 'no _serialized and no alias found' }
      }
      const prototype = Object.getPrototypeOf(probe)
      if (!prototype || Object.getOwnPropertyDescriptor(prototype, '_serialized')) {
        return { patched: false, reason: 'prototype is not patchable' }
      }
      defineSerialized(prototype, alias)
      return { patched: true, alias }
    }

    const createWid = (jid) => window.require('WAWebWidFactory').createWid(jid)
    const wid = restoreClass(
      () => createWid('0@c.us'),
      (value) => value === '0@c.us'
    )
    // The probe id is also the value of the key's own `id` field, so the serialized one is the
    // field that carries the id inside a longer string
    const msgKey = restoreClass(
      () => {
        const MsgKey = window.require('WAWebMsgKey')
        return new MsgKey({ from: createWid('0@c.us'), to: createWid('0@c.us'), id: 'WWEBJSAPIPROBE', selfDir: 'out' })
      },
      (value) => value.includes('WWEBJSAPIPROBE') && value.length > 'WWEBJSAPIPROBE'.length
    )

    const aliases = [wid.alias, msgKey.alias].filter(Boolean)
    if (!aliases.length) {
      return { applied: false, reason: 'nothing to restore', wid, msgKey }
    }

    // Models are plain copies handed over to node, so they need the field set explicitly
    const restoreSerialized = (value, depth) => {
      if (!value || typeof value !== 'object' || depth > 6) { return value }
      if (Array.isArray(value)) {
        for (const item of value) { restoreSerialized(item, depth + 1) }
        return value
      }
      if (typeof value._serialized !== 'string') {
        for (const alias of aliases) {
          if (typeof value[alias] === 'string') {
            value._serialized = value[alias]
            break
          }
        }
      }
      for (const key of Object.keys(value)) { restoreSerialized(value[key], depth + 1) }
      return value
    }

    const models = []
    for (const name of ['getMessageModel', 'getChatModel', 'getContactModel']) {
      const getModel = window.WWebJS[name]
      if (typeof getModel !== 'function') { continue }
      window.WWebJS[name] = function (...args) {
        const model = getModel.apply(this, args)
        return model instanceof Promise
          ? model.then((resolved) => restoreSerialized(resolved, 0))
          : restoreSerialized(model, 0)
      }
      models.push(name)
    }

    window.__wwebjsApiSerializedIds = true
    return { applied: true, wid, msgKey, models }
  })
}

const patchWWebLibrary = async (client, sessionId) => {
  // MUST be run after the 'ready' event fired
  try {
    logger.info({ sessionId, ...await patchSerializedIds(client) }, 'Serialized id patch')
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to patch serialized ids')
  }

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
  patchSerializedIds,
  patchWWebLibrary
}
