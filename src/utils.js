const axios = require('axios')
const { globalApiKey, disabledCallbacks, enableWebHook, mediaResolveTimeoutMs } = require('./config')
const { logger } = require('./logger')
const ChatFactory = require('whatsapp-web.js/src/factories/ChatFactory')
const Client = require('whatsapp-web.js').Client
const { Chat, Message } = require('whatsapp-web.js/src/structures')
const MessageMedia = require('whatsapp-web.js/src/structures/MessageMedia')

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

// WhatsApp Web 2.3000.x indexes the Msg collection under a key whatsapp-web.js no longer agrees
// on, so `Msg.get(serializedId)` misses for every message that is not already in memory. The
// library then falls back to `Msg.getMessagesById()`, whose IndexedDB lookup rejects the id with
// `DataError: Failed to execute 'get' on 'IDBObjectStore'`. That class is minified, so puppeteer
// recovers nothing but its name and the whole thing reaches the API as the opaque `t: t`, which
// is what every failing attachment download in production looks like.
// Upstream: wwebjs/whatsapp-web.js#201830, #201828, #201833
// Resolve the message ourselves - never reaching the IndexedDB fallback - and report what
// actually went wrong when the media still cannot be fetched.
const patchMediaDownload = (resolveTimeoutMs = mediaResolveTimeoutMs) => {
  Message.prototype.downloadMedia = async function () {
    if (!this.hasMedia) { return undefined }

    const result = await this.client.pupPage.evaluate(async (id, resolveTimeoutMs) => {
      const attempt = (read) => { try { return read() } catch (error) { return null } }
      const { Msg } = window.require('WAWebCollections')

      // The serialized form changed shape between builds (a trailing `_out`, a participant for
      // group messages), so try what the page handed us and the classic three-part key before
      // giving up on the index.
      let msg = null
      let resolvedBy = null
      for (const [via, key] of [['serialized', id._serialized], ['threePart', `${id.fromMe}_${id.remote}_${id.id}`]]) {
        if (!key) { continue }
        msg = attempt(() => Msg.get(key))
        if (msg) { resolvedBy = via; break }
      }
      // The chat keeps its own collection, and that is the one `_getMessageById` already reads to
      // hand this message to the caller - so it holds the message even when the global index does
      // not. Match on the raw id, which no build has renamed.
      // ponytail: linear scan, bounded by the messages loaded for one chat. Narrow it if a chat
      // ever holds enough history for this to show up in a profile.
      if (!msg) {
        const chat = await (async () => {
          try { return await window.WWebJS.getChat(id.remote, { getAsModel: false }) } catch (error) { return null }
        })()
        const msgs = (chat && chat.msgs && attempt(() => chat.msgs.getModelsArray())) || []
        msg = msgs.find((m) => m && m.id && m.id.id === id.id) || null
        if (msg) { resolvedBy = 'chatScan' }
      }
      if (!msg) { return { failed: { reason: 'message is not in the page collection' } } }
      if (!msg.mediaData) { return { failed: { reason: 'message carries no mediaData', resolvedBy } } }

      // The page drops `mediaData` off the message while it is working on it - reading the stage
      // straight through crashed one download on 2026-08-25 with `Cannot read properties of
      // undefined (reading 'mediaStage')`. Treat it as a stage like any other and keep waiting.
      const stageOf = () => (msg.mediaData && msg.mediaData.mediaStage) || 'GONE'

      const describe = (error) => ({
        name: error && error.name,
        message: error && error.message,
        status: (error && error.status) || null
      })

      // Never re-decrypt the media ourselves. `downloadManager.downloadAndMaybeDecrypt` has to be
      // fed `directPath`/`encFilehash`/`mediaKey`, and once the page has run a media retry those
      // live on `msg.mediaObject`, not on the message - so the stale key off `msg` decrypts to
      // garbage and WhatsApp's own sniffer answers `InvalidMediaFileType: Unexpected mimetype
      // application/octet-stream for media type image` (169 of 169 attachments on 2026-08-24), or
      // `MediaDecryptionError: decryptMedia: hmac mismatch` when it gets that far.
      // `msg.downloadMedia()` already decrypts and parks the blob in WhatsApp's own cache, so take
      // it from there and let the page own the crypto. That is what upstream switched to in
      // wwebjs/whatsapp-web.js#201697, which is on main but not in any release yet.
      const readBlob = () => {
        // the cache stores upload FormData under the same key, so only take an entry we can read
        const cached = attempt(() => window.require('WAWebMediaInMemoryBlobCache')
          .InMemoryMediaBlobCache.get(msg.mediaObject && msg.mediaObject.filehash))
        if (cached && typeof cached.arrayBuffer === 'function') { return cached }
        const mediaBlob = msg.mediaObject && msg.mediaObject.mediaBlob
        return (mediaBlob && attempt(() => mediaBlob.forceToBlob())) || null
      }

      // Asking once is not enough: when several media arrive in one batch - the only condition that
      // correlated with the failures in production, every one of them stuck at `INIT` for the whole
      // wait - the request goes nowhere and the stage never moves, so passively polling can only
      // time out. Ask again on every round instead. A single cold download resolves in well under a
      // second, so a still-`INIT` stage means the request was dropped, not that it is slow.
      // The stage is never used to skip the call: cache eviction leaves `RESOLVED` behind with no
      // blob to read.
      let resolveAttempts = 0
      let lastResolveError = null
      let blob = readBlob()
      const deadline = Date.now() + resolveTimeoutMs
      while (!blob) {
        if (Date.now() > deadline) {
          return {
            failed: {
              reason: 'media did not resolve in time',
              mediaStage: stageOf(),
              resolvedBy,
              resolveAttempts,
              ...(lastResolveError ? describe(lastResolveError) : {})
            }
          }
        }
        // `REUPLOADING` means the media expired and the sender is uploading it again - the page is
        // already on it and a second ask would only pile on, so wait that stage out instead.
        if (stageOf() !== 'REUPLOADING') {
          resolveAttempts++
          try {
            await msg.downloadMedia({ downloadEvenIfExpensive: true, rmrReason: 1, isUserInitiated: true })
          } catch (error) {
            lastResolveError = error
          }
        }
        if (stageOf().includes('ERROR')) {
          return {
            failed: {
              reason: 'the page could not fetch the media',
              mediaStage: stageOf(),
              resolvedBy,
              resolveAttempts,
              ...(lastResolveError ? describe(lastResolveError) : {})
            }
          }
        }
        blob = readBlob()
        if (blob) { break }
        await new Promise((resolve) => setTimeout(resolve, 500))
      }

      try {
        return {
          media: {
            data: await window.WWebJS.arrayBufferToBase64Async(await blob.arrayBuffer()),
            mimetype: msg.mimetype,
            filename: msg.filename,
            filesize: msg.size
          }
        }
      } catch (error) {
        return { failed: { reason: 'reading the decrypted media failed', mediaStage: stageOf(), resolvedBy, resolveAttempts, ...describe(error) } }
      }
    }, this.id, resolveTimeoutMs)

    if (result.failed) {
      const { reason, ...details } = result.failed
      logger.warn({ messageId: this.id._serialized, ...details }, `Media download failed: ${reason}`)
      // 404 is how the library reports media the server no longer holds - keep that answering
      // "no media" rather than an error.
      if (details.status === 404) { return undefined }
      throw new Error(`media download failed: ${reason}`)
    }
    const { data, mimetype, filename, filesize } = result.media
    return new MessageMedia(mimetype, data, filename, filesize)
  }
}

const patchWWebLibrary = async (client) => {
  // MUST be run after the 'ready' event fired
  patchMediaDownload()

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
  patchMediaDownload,
  patchWWebLibrary
}
