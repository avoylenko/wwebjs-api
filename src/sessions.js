const { Client, LocalAuth } = require('whatsapp-web.js')
const fs = require('fs')
const path = require('path')
const sessions = new Map()
const { 
  baseWebhookURL, 
  sessionFolderPath, 
  maxAttachmentSize, 
  setMessagesAsSeen, 
  webVersion, 
  webVersionCacheType, 
  recoverSessions, 
  chromeBin, 
  headless, 
  releaseBrowserLock 
} = require('./config')
const { triggerWebhook, waitForNestedObject, checkIfEventisEnabled, sendMessageSeenStatus } = require('./utils')
const { logger } = require('./logger')
const { initWebSocketServer, terminateWebSocketServer, triggerWebSocket } = require('./websocket')
const QRCode = require('qrcode');

/**
 * Validates if the session is ready by checking:
 *  - The session exists in our map
 *  - The puppeteer page is available and evaluable.
 *  - The session state is "CONNECTED"
 */
const validateSession = async (sessionId) => {
  try {
    const returnData = { success: false, state: null, message: '' }

    // Session not found in our sessions map
    if (!sessions.has(sessionId) || !sessions.get(sessionId)) {
      returnData.message = 'session_not_found'
      return returnData
    }

    const client = sessions.get(sessionId)
    // Wait until the client has a pupPage object
    await waitForNestedObject(client, 'pupPage')
      .catch((err) => { 
        return { success: false, state: null, message: err.message } 
      })

    // Validate the page is not closed and evaluable
    let maxRetry = 0
    while (true) {
      try {
        if (!client.pupPage || client.pupPage.isClosed()) {
          return { success: false, state: null, message: 'browser tab closed' }
        }
        // Attempt a simple evaluation with a timeout fallback
        await Promise.race([
          client.pupPage.evaluate(() => 1),
          new Promise(resolve => setTimeout(resolve, 1000))
        ])
        break
      } catch (error) {
        logger.warn({ sessionId, error }, 'Evaluation error during session validation.')
        if (maxRetry === 2) {
          return { success: false, state: null, message: 'session closed' }
        }
        maxRetry++
      }
    }

    const state = await client.getState()
    returnData.state = state
    if (state !== 'CONNECTED') {
      returnData.message = 'session_not_connected'
      return returnData
    }

    // Session is successfully connected
    returnData.success = true
    returnData.message = 'session_connected'
    return returnData
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to validate session')
    return { success: false, state: null, message: error.message }
  }
}

/**
 * Restores any sessions from the session folder. This scans the session folder
 * for directories matching "session-*" and reinitializes them.
 */
const restoreSessions = () => {
  try {
    if (!fs.existsSync(sessionFolderPath)) {
      fs.mkdirSync(sessionFolderPath) // Create the session directory if it doesn't exist
    }
    // Read the contents of the folder
    fs.readdir(sessionFolderPath, async (_, files) => {
      // Iterate through each folder in the session folder
      for (const file of files) {
        // Extract sessionId from folder name
        const match = file.match(/^session-(.+)$/)
        if (match) {
          const sessionId = match[1]
          logger.warn({ sessionId }, 'Existing session detected; attempting restoration.')
          await setupSession(sessionId)
        }
      }
    })
  } catch (error) {
    logger.error(error, 'Failed to restore sessions')
  }
}

/**
 * Sets up a new client session.
 */
const setupSession = async (sessionId) => {
  try {
    if (sessions.has(sessionId)) {
      return { success: false, message: `Session already exists for: ${sessionId}`, client: sessions.get(sessionId) }
    }

    // Use LocalAuth for session data; disable logout from LocalAuth (to avoid deletion of files during logout)
    const localAuth = new LocalAuth({ clientId: sessionId, dataPath: sessionFolderPath })
    delete localAuth.logout
    localAuth.logout = () => { }

    const clientOptions = {
      puppeteer: {
        executablePath: chromeBin,
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-gpu',
          '--disable-dev-shm-usage',
          '--single-process' // Reduces resource usage
        ],
        timeout: 30000 // Increase launch timeout if needed
      },
      authStrategy: localAuth,
      takeoverOnConflict: true, // Handle session conflicts
      qrMaxRetries: 5, // Limit QR regeneration attempts
    };
    if (webVersion) {
      clientOptions.webVersion = webVersion
      switch (webVersionCacheType.toLowerCase()) {
        case 'local':
          clientOptions.webVersionCache = {
            type: 'local'
          }
          break
        case 'remote':
          clientOptions.webVersionCache = {
            type: 'remote',
            remotePath: 'https://raw.githubusercontent.com/wppconnect-team/wa-version/main/html/' + webVersion + '.html'
          }
          break
        default:
          clientOptions.webVersionCache = {
            type: 'none'
          }
      }
    }

    const client = new Client(clientOptions)
    if (releaseBrowserLock) {
      // Remove the SingletonLock file if it exists to avoid lock issues (see Puppeteer issue #4860)
      const singletonLockPath = path.resolve(path.join(sessionFolderPath, `session-${sessionId}`, 'SingletonLock'))
      const singletonLockExists = await fs.promises.lstat(singletonLockPath).then(() => true).catch(() => false)
      if (singletonLockExists) {
        logger.warn({ sessionId }, 'Browser lock file exists, removing.')
        await fs.promises.unlink(singletonLockPath)
      }
    }

    try {
      await client.initialize()
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Initialize error')
      throw error
    }

    // Start the WebSocket server for this session
    initWebSocketServer(sessionId)
    // Initialize client event listeners
    initializeEvents(client, sessionId)

    // Save the session to the Map
    sessions.set(sessionId, client)
    return { success: true, message: 'Session initiated successfully', client }
  } catch (error) {
    return { success: false, message: error.message, client: null }
  }
}

/**
 * Initializes events for the client.
 * Events include handling page closure, errors, and various WhatsApp events.
 */
const initializeEvents = (client, sessionId) => {
  // Set the webhook URL; allow for environment override per session
  const sessionWebhook = process.env[sessionId.toUpperCase() + '_WEBHOOK_URL'] || baseWebhookURL

  if (recoverSessions) {
    waitForNestedObject(client, 'pupPage').then(() => {
      const restartSession = async (sessionId) => {
        sessions.delete(sessionId)
        await client.destroy().catch(e => { logger.error({ sessionId, err: e }, 'Error during client destroy'); })
        await setupSession(sessionId)
      }
      // Listen for page close and error events to restart session
      client.pupPage.once('close', function () {
        logger.warn({ sessionId }, 'Browser page closed. Restoring session.')
        restartSession(sessionId)
      })
      client.pupPage.once('error', function () {
        logger.warn({ sessionId }, 'Browser page error occurred. Restoring session.')
        restartSession(sessionId)
      })
    }).catch(e => { 
      logger.error({ sessionId, err: e }, 'Error waiting for pupPage.') 
    })
  }

  // Register events only if enabled
  checkIfEventisEnabled('auth_failure')
    .then(_ => {
      client.on('auth_failure', (msg) => {
        triggerWebhook(sessionWebhook, sessionId, 'status', { msg })
        triggerWebSocket(sessionId, 'status', { msg })
      })
    })

  checkIfEventisEnabled('authenticated')
    .then(_ => {
      client.qr = null
      client.on('authenticated', () => {
        triggerWebhook(sessionWebhook, sessionId, 'authenticated')
        triggerWebSocket(sessionId, 'authenticated')
      })
    })

  checkIfEventisEnabled('call')
    .then(_ => {
      client.on('call', async (call) => {
        triggerWebhook(sessionWebhook, sessionId, 'call', { call })
        triggerWebSocket(sessionId, 'call', { call })
      })
    })

  checkIfEventisEnabled('change_state')
    .then(_ => {
      client.on('change_state', state => {
        triggerWebhook(sessionWebhook, sessionId, 'change_state', { state })
        triggerWebSocket(sessionId, 'change_state', { state })
      })
    })

  checkIfEventisEnabled('disconnected')
    .then(_ => {
      client.on('disconnected', (reason) => {
        triggerWebhook(sessionWebhook, sessionId, 'disconnected', { reason })
        triggerWebSocket(sessionId, 'disconnected', { reason })
      })
    })

  checkIfEventisEnabled('group_join')
    .then(_ => {
      client.on('group_join', (notification) => {
        triggerWebhook(sessionWebhook, sessionId, 'group_join', { notification })
        triggerWebSocket(sessionId, 'group_join', { notification })
      })
    })

  checkIfEventisEnabled('group_leave')
    .then(_ => {
      client.on('group_leave', (notification) => {
        triggerWebhook(sessionWebhook, sessionId, 'group_leave', { notification })
        triggerWebSocket(sessionId, 'group_leave', { notification })
      })
    })

  checkIfEventisEnabled('group_admin_changed')
    .then(_ => {
      client.on('group_admin_changed', (notification) => {
        triggerWebhook(sessionWebhook, sessionId, 'group_admin_changed', { notification })
        triggerWebSocket(sessionId, 'group_admin_changed', { notification })
      })
    })

  checkIfEventisEnabled('group_membership_request')
    .then(_ => {
      client.on('group_membership_request', (notification) => {
        triggerWebhook(sessionWebhook, sessionId, 'group_membership_request', { notification })
        triggerWebSocket(sessionId, 'group_membership_request', { notification })
      })
    })

  checkIfEventisEnabled('group_update')
    .then(_ => {
      client.on('group_update', (notification) => {
        triggerWebhook(sessionWebhook, sessionId, 'group_update', { notification })
        triggerWebSocket(sessionId, 'group_update', { notification })
      })
    })

  checkIfEventisEnabled('loading_screen')
    .then(_ => {
      client.on('loading_screen', (percent, message) => {
        triggerWebhook(sessionWebhook, sessionId, 'loading_screen', { percent, message })
        triggerWebSocket(sessionId, 'loading_screen', { percent, message })
      })
    })

  checkIfEventisEnabled('media_uploaded')
    .then(_ => {
      client.on('media_uploaded', (message) => {
        triggerWebhook(sessionWebhook, sessionId, 'media_uploaded', { message })
        triggerWebSocket(sessionId, 'media_uploaded', { message })
      })
    })

  checkIfEventisEnabled('message')
    .then(_ => {
      client.on('message', async (message) => {
        triggerWebhook(sessionWebhook, sessionId, 'message', { message })
        triggerWebSocket(sessionId, 'message', { message })
        if (message.hasMedia && message._data?.size < maxAttachmentSize) {
          checkIfEventisEnabled('media').then(_ => {
            message.downloadMedia().then(messageMedia => {
              triggerWebhook(sessionWebhook, sessionId, 'media', { messageMedia, message })
              triggerWebSocket(sessionId, 'media', { messageMedia, message })
            }).catch(error => {
              logger.error({ sessionId, err: error }, 'Failed to download media')
            })
          })
        }
        if (setMessagesAsSeen) {
          sendMessageSeenStatus(message)
        }
      })
    })

  checkIfEventisEnabled('message_ack')
    .then(_ => {
      client.on('message_ack', async (message, ack) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_ack', { message, ack })
        triggerWebSocket(sessionId, 'message_ack', { message, ack })
        if (setMessagesAsSeen) {
          sendMessageSeenStatus(message)
        }
      })
    })

  checkIfEventisEnabled('message_create')
    .then(_ => {
      client.on('message_create', async (message) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_create', { message })
        triggerWebSocket(sessionId, 'message_create', { message })
        if (setMessagesAsSeen) {
          sendMessageSeenStatus(message)
        }
      })
    })

  checkIfEventisEnabled('message_reaction')
    .then(_ => {
      client.on('message_reaction', (reaction) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_reaction', { reaction })
        triggerWebSocket(sessionId, 'message_reaction', { reaction })
      })
    })

  checkIfEventisEnabled('message_edit')
    .then(_ => {
      client.on('message_edit', (message, newBody, prevBody) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_edit', { message, newBody, prevBody })
        triggerWebSocket(sessionId, 'message_edit', { message, newBody, prevBody })
      })
    })

  checkIfEventisEnabled('message_ciphertext')
    .then(_ => {
      client.on('message_ciphertext', (message) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_ciphertext', { message })
        triggerWebSocket(sessionId, 'message_ciphertext', { message })
      })
    })

  checkIfEventisEnabled('message_revoke_everyone')
    .then(_ => {
      client.on('message_revoke_everyone', async (message) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_revoke_everyone', { message })
        triggerWebSocket(sessionId, 'message_revoke_everyone', { message })
      })
    })

  checkIfEventisEnabled('message_revoke_me')
    .then(_ => {
      client.on('message_revoke_me', async (message, revokedMsg) => {
        triggerWebhook(sessionWebhook, sessionId, 'message_revoke_me', { message, revokedMsg })
        triggerWebSocket(sessionId, 'message_revoke_me', { message, revokedMsg })
      })
    })

  // QR code events
  client.on('qr', async (qrData) => {
    try {
      // Generate QR code as a buffer
      const qrImageBuffer = await QRCode.toBuffer(qrData, { type: 'png' });
      client.qrImage = qrImageBuffer; // Cache the image buffer
      client.qr = qrData;
  
      // Clear previous timeout and set new expiration (60 seconds)
      if (client.qrClearTimeout) clearTimeout(client.qrClearTimeout);
      client.qrClearTimeout = setTimeout(() => {
        client.qr = null;
        client.qrImage = null;
        logger.warn({ sessionId }, 'QR code expired');
      }, 60000);
  
      // Emit QR via webhook/websocket
      if (await checkIfEventisEnabled('qr')) {
        triggerWebhook(sessionWebhook, sessionId, 'qr', { qr: qrData });
        triggerWebSocket(sessionId, 'qr', { qr: qrData });
      }
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Failed to generate QR image');
    }
  });
  
  checkIfEventisEnabled('ready')
    .then(_ => {
      client.on('ready', () => {
        triggerWebhook(sessionWebhook, sessionId, 'ready')
        triggerWebSocket(sessionId, 'ready')
      })
    })

  checkIfEventisEnabled('contact_changed')
    .then(_ => {
      client.on('contact_changed', async (message, oldId, newId, isContact) => {
        triggerWebhook(sessionWebhook, sessionId, 'contact_changed', { message, oldId, newId, isContact })
        triggerWebSocket(sessionId, 'contact_changed', { message, oldId, newId, isContact })
      })
    })

  checkIfEventisEnabled('chat_removed')
    .then(_ => {
      client.on('chat_removed', async (chat) => {
        triggerWebhook(sessionWebhook, sessionId, 'chat_removed', { chat })
        triggerWebSocket(sessionId, 'chat_removed', { chat })
      })
    })

  checkIfEventisEnabled('chat_archived')
    .then(_ => {
      client.on('chat_archived', async (chat, currState, prevState) => {
        triggerWebhook(sessionWebhook, sessionId, 'chat_archived', { chat, currState, prevState })
        triggerWebSocket(sessionId, 'chat_archived', { chat, currState, prevState })
      })
    })

  checkIfEventisEnabled('unread_count')
    .then(_ => {
      client.on('unread_count', async (chat) => {
        triggerWebhook(sessionWebhook, sessionId, 'unread_count', { chat })
        triggerWebSocket(sessionId, 'unread_count', { chat })
      })
    })

  checkIfEventisEnabled('vote_update')
    .then(_ => {
      client.on('vote_update', async (vote) => {
        triggerWebhook(sessionWebhook, sessionId, 'vote_update', { vote })
        triggerWebSocket(sessionId, 'vote_update', { vote })
      })
    })
}

/**
 * Deletes the client session folder safely, ensuring no directory traversal is possible.
 */
const deleteSessionFolder = async (sessionId) => {
  try {
    const targetDirPath = path.join(sessionFolderPath, `session-${sessionId}`)
    const resolvedTargetDirPath = await fs.promises.realpath(targetDirPath)
    const resolvedSessionPath = await fs.promises.realpath(sessionFolderPath)

    // Ensure the target directory path is a subdirectory of the session folder
    const safeSessionPath = `${resolvedSessionPath}${path.sep}`
    if (!resolvedTargetDirPath.startsWith(safeSessionPath)) {
      throw new Error('Invalid path: Directory traversal detected')
    }
    await fs.promises.rm(resolvedTargetDirPath, { recursive: true, force: true })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Folder deletion error')
    throw error
  }
}

/**
 * Reloads the session without removing the browser cache.
 */
const reloadSession = async (sessionId) => {
  try {
    const client = sessions.get(sessionId)
    if (!client) {
      return
    }
    // Remove page event listeners to avoid duplicate calls
    client.pupPage?.removeAllListeners('close')
    client.pupPage?.removeAllListeners('error')
    try {
      const pages = await client.pupBrowser.pages()
      await Promise.all(pages.map((page) => page.close()))
      await Promise.race([
        client.pupBrowser.close(),
        new Promise(resolve => setTimeout(resolve, 5000))
      ])
    } catch (e) {
      const childProcess = client.pupBrowser.process()
      if (childProcess) {
        childProcess.kill(9)
      }
    }
    sessions.delete(sessionId)
    await setupSession(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to reload session')
    throw error
  }
}

/**
 * Deletes the session. It first attempts to gracefully logout/destroy the client,
 * then waits a few seconds for the browser process to disconnect before deleting the session folder.
 */
const deleteSession = async (sessionId, validation) => {
  try {
    const client = sessions.get(sessionId)
    if (!client) {
      return
    }
    client.pupPage?.removeAllListeners('close')
    client.pupPage?.removeAllListeners('error')
    try {
      await terminateWebSocketServer(sessionId)
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Failed to terminate WebSocket server')
    }
    if (validation.success) {
      logger.info({ sessionId }, 'Logging out session')
      await client.logout()
    } else if (validation.message === 'session_not_connected') {
      logger.info({ sessionId }, 'Destroying session')
      await client.destroy()
    }
    // Wait for up to 10 seconds for the browser to disconnect
    let maxDelay = 0
    while (client.pupBrowser.isConnected() && (maxDelay < 10)) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      maxDelay++
    }
    sessions.delete(sessionId)
    await deleteSessionFolder(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to delete session')
    throw error
  }
}

/**
 * Flushes sessions by iterating through the session folder and deleting sessions
 * that are either inactive or all sessions (depending on the deleteOnlyInactive flag).
 */
const flushSessions = async (deleteOnlyInactive) => {
  try {
    const files = await fs.promises.readdir(sessionFolderPath)
    for (const file of files) {
      const match = file.match(/^session-(.+)$/)
      if (match) {
        const sessionId = match[1]
        const validation = await validateSession(sessionId)
        if (!deleteOnlyInactive || !validation.success) {
          await deleteSession(sessionId, validation)
        }
      }
    }
  } catch (error) {
    logger.error(error, 'Failed to flush sessions')
    throw error
  }
}

module.exports = {
  sessions,
  setupSession,
  restoreSessions,
  validateSession,
  deleteSession,
  reloadSession,
  flushSessions
}
