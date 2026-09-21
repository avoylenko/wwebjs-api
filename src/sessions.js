const { Client, LocalAuth } = require('whatsapp-web.js')
const fs = require('fs')
const path = require('path')
const sessions = new Map()
const { baseWebhookURL, sessionFolderPath, maxAttachmentSize, setMessagesAsSeen, webVersion, webVersionCacheType, recoverSessions, chromeBin, headless, releaseBrowserLock, proxyUrl, proxyUsername, proxyPassword, protocolTimeoutMs, browserDestroyTimeoutMs, sessionHealthcheckIntervalMs, sessionHealthcheckTimeoutMs, sessionHealthcheckFailures } = require('./config')
const { triggerWebhook, waitForNestedObject, isEventEnabled, sendMessageSeenStatus, sleep, patchWWebLibrary } = require('./utils')
const { logger } = require('./logger')
const { initWebSocketServer, terminateWebSocketServer, triggerWebSocket } = require('./websocket')

// `getState()` is a round trip into the page, so on a wedged browser it never comes back. Every
// caller needs a deadline, and needs to tell "not connected" apart from "not answering".
const getStateWithDeadline = async (client, sessionId) => {
  try {
    return await Promise.race([
      client.getState(),
      sleep(sessionHealthcheckTimeoutMs).then(() => 'unresponsive')
    ])
  } catch (error) {
    logger.debug({ sessionId, err: error }, 'Failed to read session state')
    return null
  }
}

// Function to validate if the session is ready
const validateSession = async (sessionId) => {
  try {
    const returnData = { success: false, state: null, message: '' }

    // Session not Connected 😢
    if (!sessions.has(sessionId) || !sessions.get(sessionId)) {
      returnData.message = 'session_not_found'
      return returnData
    }

    const client = sessions.get(sessionId)
    // wait until the client is created
    await waitForNestedObject(client, 'pupPage')
      .catch((err) => { return { success: false, state: null, message: err.message } })

    if (client.pupPage.isClosed()) {
      return { success: false, state: null, message: 'browser tab closed' }
    }

    const state = await getStateWithDeadline(client, sessionId)
    returnData.state = state
    if (state !== 'CONNECTED') {
      returnData.message = 'session_not_connected'
      return returnData
    }

    // Session Connected 🎉
    returnData.success = true
    returnData.message = 'session_connected'
    return returnData
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to validate session')
    return { success: false, state: null, message: error.message }
  }
}

// Function to handle client session restoration
const restoreSessions = () => {
  try {
    if (!fs.existsSync(sessionFolderPath)) {
      fs.mkdirSync(sessionFolderPath) // Create the session directory if it doesn't exist
    }
    // Read the contents of the folder
    fs.readdir(sessionFolderPath, async (_, files) => {
      // Iterate through the files in the parent folder
      for (const file of files) {
        // Use regular expression to extract the string from the folder name
        const match = file.match(/^session-(.+)$/)
        if (match) {
          const sessionId = match[1]
          logger.warn({ sessionId }, 'Existing session detected')
          await setupSession(sessionId)
        }
      }
    })
  } catch (error) {
    logger.error(error, 'Failed to restore sessions')
  }
}

// Resolves the webhook a session reports to, honouring the per-session override.
const webhookFor = (sessionId) => process.env[sessionId.toUpperCase() + '_WEBHOOK_URL'] || baseWebhookURL

// `client.destroy()` shuts the browser down over CDP, so a wedged browser hangs it forever and
// the chromium process outlives the client that owned it. Give the polite path a deadline, then
// take the process out directly.
// `killed` on a ChildProcess means "a signal was delivered", not "the process is gone", so it
// stays false after a perfectly clean shutdown. Exit status is the only honest answer.
const hasExited = (browserProcess) =>
  browserProcess.exitCode !== null || browserProcess.signalCode !== null

const hardDestroy = async (client, sessionId) => {
  if (!client) { return }
  const browserProcess = client.pupBrowser?.process?.()
  await Promise.race([
    Promise.resolve().then(() => client.destroy()).catch(() => {}),
    sleep(browserDestroyTimeoutMs)
  ])
  if (browserProcess && !hasExited(browserProcess)) {
    logger.warn({ sessionId }, 'Browser did not shut down in time, killing it')
    try {
      browserProcess.kill('SIGKILL')
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Failed to kill browser process')
    }
  }
}

// Sessions whose lifecycle is mid-flight: being rebuilt, reloaded or deleted. A crashing page
// emits both 'close' and 'error', and the watchdog can fire on top of either, so without this
// every crash started two setupSession runs - and since `sessions` is only written after
// initialize() resolves, the second one sailed past the "already exists" check and put a second
// chromium on the same profile. It also keeps the watchdog off sessions an operator is already
// reloading or deleting.
const inTransition = new Set()

const restartSession = async (sessionId, client, reason) => {
  const current = sessions.get(sessionId)
  if (client && current && current !== client) {
    // A browser left over from an earlier generation. Bury it, but leave the live one alone -
    // restarting here is what turned one crash into a cascade of restarts.
    logger.warn({ sessionId, reason }, 'Stale client reported a failure, discarding it')
    await hardDestroy(client, sessionId)
    return
  }
  if (inTransition.has(sessionId)) { return }
  inTransition.add(sessionId)
  try {
    logger.warn({ sessionId, reason }, 'Restarting session')
    sessions.delete(sessionId)
    sessionHealth.delete(sessionId)
    await hardDestroy(client || current, sessionId)
    await setupSession(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to restart session')
  } finally {
    inTransition.delete(sessionId)
  }
}

// Setup Session
const setupSession = async (sessionId) => {
  try {
    if (sessions.has(sessionId)) {
      return { success: false, message: `Session already exists for: ${sessionId}`, client: sessions.get(sessionId) }
    }
    logger.info({ sessionId }, 'Session is being initiated')
    // Disable the delete folder from the logout function (will be handled separately)
    const localAuth = new LocalAuth({ clientId: sessionId, dataPath: sessionFolderPath })
    delete localAuth.logout
    localAuth.logout = () => { }

    const clientOptions = {
      puppeteer: {
        executablePath: chromeBin,
        headless,
        protocolTimeout: protocolTimeoutMs,
        // puppeteer's own signal handlers do not close the browser, they SIGKILL its whole
        // process group - which leaves WhatsApp Web's IndexedDB unflushed and the profile
        // unreadable on the next boot. Shutdown is handled in server.js instead.
        handleSIGINT: false,
        handleSIGTERM: false,
        handleSIGHUP: false,
        args: [
          '--autoplay-policy=user-gesture-required',
          '--disable-background-networking',
          '--disable-background-timer-throttling',
          '--disable-backgrounding-occluded-windows',
          '--disable-breakpad',
          '--disable-client-side-phishing-detection',
          '--disable-component-update',
          '--disable-default-apps',
          '--disable-dev-shm-usage',
          '--disable-domain-reliability',
          '--disable-extensions',
          '--disable-features=AudioServiceOutOfProcess',
          '--disable-hang-monitor',
          '--disable-ipc-flooding-protection',
          '--disable-notifications',
          '--disable-offer-store-unmasked-wallet-cards',
          '--disable-popup-blocking',
          '--disable-print-preview',
          '--disable-prompt-on-repost',
          '--disable-renderer-backgrounding',
          '--disable-speech-api',
          '--disable-sync',
          '--disable-gpu',
          '--disable-accelerated-2d-canvas',
          '--hide-scrollbars',
          '--ignore-gpu-blacklist',
          '--metrics-recording-only',
          '--mute-audio',
          '--no-default-browser-check',
          '--no-first-run',
          '--no-pings',
          '--no-zygote',
          '--password-store=basic',
          '--use-gl=swiftshader',
          '--use-mock-keychain',
          '--disable-setuid-sandbox',
          '--no-sandbox',
          '--disable-blink-features=AutomationControlled',
          // Route Chromium outbound traffic through PROXY_URL when configured.
          ...(proxyUrl ? [`--proxy-server=${proxyUrl}`] : [])
        ]
      },
      authStrategy: localAuth
    }

    if (proxyUrl && proxyUsername != null && proxyPassword != null) {
      clientOptions.proxyAuthentication = { username: proxyUsername, password: proxyPassword }
    }

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
      // See https://github.com/puppeteer/puppeteer/issues/4860
      const singletonLockPath = path.resolve(path.join(sessionFolderPath, `session-${sessionId}`, 'SingletonLock'))
      const singletonLockExists = await fs.promises.lstat(singletonLockPath).then(() => true).catch(() => false)
      if (singletonLockExists) {
        logger.warn({ sessionId }, 'Browser lock file exists, removing')
        await fs.promises.unlink(singletonLockPath)
      }
    }

    try {
      client.once('ready', () => {
        patchWWebLibrary(client).catch((err) => {
          logger.error({ sessionId, err }, 'Failed to patch WWebJS library')
        })
      })
      initWebSocketServer(sessionId)
      initializeEvents(client, sessionId)
      await client.initialize()
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Initialize error')
      // The client never reached `sessions`, so nothing else holds a reference to its browser.
      // Without this every failed restore left a chromium process behind.
      await hardDestroy(client, sessionId)
      throw error
    }

    // Save the session to the Map
    sessions.set(sessionId, client)
    return { success: true, message: 'Session initiated successfully', client }
  } catch (error) {
    return { success: false, message: error.message, client: null }
  }
}

const initializeEvents = (client, sessionId) => {
  // check if the session webhook is overridden
  const sessionWebhook = webhookFor(sessionId)

  if (recoverSessions) {
    waitForNestedObject(client, 'pupPage').then(() => {
      client.pupPage.once('close', function () {
        // emitted when the page closes
        restartSession(sessionId, client, 'browser page closed')
      })
      client.pupPage.once('error', function () {
        // emitted when the page crashes
        restartSession(sessionId, client, 'error on browser page')
      })
      client.pupPage
        .on('console', message => {
          const type = message.type().substr(0, 3).toUpperCase()
          logger.debug({ sessionId, type }, `Page console log: ${message.text()}`)
        })
        .on('requestfailed', request => {
          const failure = request.failure()
          if (failure) {
            logger.error({ sessionId, url: request.url() }, `Page request failed: ${failure.errorText}`)
          } else {
            logger.error({ sessionId, url: request.url() }, 'Page request failed but no failure reason provided')
          }
        })
        .on('pageerror', ({ message }) => logger.error({ sessionId, message }, 'Page error occurred'))
    }).catch(e => { })
  }

  if (isEventEnabled('auth_failure')) {
    client.on('auth_failure', (msg) => {
      triggerWebhook(sessionWebhook, sessionId, 'status', { msg })
      triggerWebSocket(sessionId, 'status', { msg })
    })
  }

  client.on('authenticated', () => {
    client.qr = null
    if (isEventEnabled('authenticated')) {
      triggerWebhook(sessionWebhook, sessionId, 'authenticated')
      triggerWebSocket(sessionId, 'authenticated')
    }
  })

  if (isEventEnabled('call')) {
    client.on('call', (call) => {
      triggerWebhook(sessionWebhook, sessionId, 'call', { call })
      triggerWebSocket(sessionId, 'call', { call })
    })
  }

  if (isEventEnabled('change_state')) {
    client.on('change_state', state => {
      triggerWebhook(sessionWebhook, sessionId, 'change_state', { state })
      triggerWebSocket(sessionId, 'change_state', { state })
    })
  }

  if (isEventEnabled('disconnected')) {
    client.on('disconnected', (reason) => {
      triggerWebhook(sessionWebhook, sessionId, 'disconnected', { reason })
      triggerWebSocket(sessionId, 'disconnected', { reason })
    })
  }

  if (isEventEnabled('group_join')) {
    client.on('group_join', (notification) => {
      triggerWebhook(sessionWebhook, sessionId, 'group_join', { notification })
      triggerWebSocket(sessionId, 'group_join', { notification })
    })
  }

  if (isEventEnabled('group_leave')) {
    client.on('group_leave', (notification) => {
      triggerWebhook(sessionWebhook, sessionId, 'group_leave', { notification })
      triggerWebSocket(sessionId, 'group_leave', { notification })
    })
  }

  if (isEventEnabled('group_admin_changed')) {
    client.on('group_admin_changed', (notification) => {
      triggerWebhook(sessionWebhook, sessionId, 'group_admin_changed', { notification })
      triggerWebSocket(sessionId, 'group_admin_changed', { notification })
    })
  }

  if (isEventEnabled('group_membership_request')) {
    client.on('group_membership_request', (notification) => {
      triggerWebhook(sessionWebhook, sessionId, 'group_membership_request', { notification })
      triggerWebSocket(sessionId, 'group_membership_request', { notification })
    })
  }

  if (isEventEnabled('group_update')) {
    client.on('group_update', (notification) => {
      triggerWebhook(sessionWebhook, sessionId, 'group_update', { notification })
      triggerWebSocket(sessionId, 'group_update', { notification })
    })
  }

  if (isEventEnabled('loading_screen')) {
    client.on('loading_screen', (percent, message) => {
      triggerWebhook(sessionWebhook, sessionId, 'loading_screen', { percent, message })
      triggerWebSocket(sessionId, 'loading_screen', { percent, message })
    })
  }

  if (isEventEnabled('media_uploaded')) {
    client.on('media_uploaded', (message) => {
      triggerWebhook(sessionWebhook, sessionId, 'media_uploaded', { message })
      triggerWebSocket(sessionId, 'media_uploaded', { message })
    })
  }

  client.on('message', async (message) => {
    if (isEventEnabled('message')) {
      triggerWebhook(sessionWebhook, sessionId, 'message', { message })
      triggerWebSocket(sessionId, 'message', { message })
      if (message.hasMedia && message._data?.size < maxAttachmentSize) {
      // custom service event
        if (isEventEnabled('media')) {
          message.downloadMedia().then(messageMedia => {
            triggerWebhook(sessionWebhook, sessionId, 'media', { messageMedia, message })
            triggerWebSocket(sessionId, 'media', { messageMedia, message })
          }).catch(error => {
            logger.error({ sessionId, err: error }, 'Failed to download media')
          })
        }
      }
    }
    if (setMessagesAsSeen) {
      // small delay to ensure the message is processed before sending seen status
      await sleep(1000)
      sendMessageSeenStatus(message)
    }
  })

  if (isEventEnabled('message_ack')) {
    client.on('message_ack', (message, ack) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_ack', { message, ack })
      triggerWebSocket(sessionId, 'message_ack', { message, ack })
    })
  }

  if (isEventEnabled('message_create')) {
    client.on('message_create', (message) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_create', { message })
      triggerWebSocket(sessionId, 'message_create', { message })
    })
  }

  if (isEventEnabled('message_reaction')) {
    client.on('message_reaction', (reaction) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_reaction', { reaction })
      triggerWebSocket(sessionId, 'message_reaction', { reaction })
    })
  }

  if (isEventEnabled('message_edit')) {
    client.on('message_edit', (message, newBody, prevBody) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_edit', { message, newBody, prevBody })
      triggerWebSocket(sessionId, 'message_edit', { message, newBody, prevBody })
    })
  }

  if (isEventEnabled('message_ciphertext')) {
    client.on('message_ciphertext', (message) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_ciphertext', { message })
      triggerWebSocket(sessionId, 'message_ciphertext', { message })
    })
  }

  if (isEventEnabled('message_revoke_everyone')) {
    client.on('message_revoke_everyone', (message) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_revoke_everyone', { message })
      triggerWebSocket(sessionId, 'message_revoke_everyone', { message })
    })
  }

  if (isEventEnabled('message_revoke_me')) {
    client.on('message_revoke_me', (message, revokedMsg) => {
      triggerWebhook(sessionWebhook, sessionId, 'message_revoke_me', { message, revokedMsg })
      triggerWebSocket(sessionId, 'message_revoke_me', { message, revokedMsg })
    })
  }

  client.on('qr', (qr) => {
    // inject qr code into session
    client.qr = qr
    if (isEventEnabled('qr')) {
      triggerWebhook(sessionWebhook, sessionId, 'qr', { qr })
      triggerWebSocket(sessionId, 'qr', { qr })
    }
  })

  if (isEventEnabled('ready')) {
    client.on('ready', () => {
      triggerWebhook(sessionWebhook, sessionId, 'ready')
      triggerWebSocket(sessionId, 'ready')
    })
  }

  if (isEventEnabled('contact_changed')) {
    client.on('contact_changed', (message, oldId, newId, isContact) => {
      triggerWebhook(sessionWebhook, sessionId, 'contact_changed', { message, oldId, newId, isContact })
      triggerWebSocket(sessionId, 'contact_changed', { message, oldId, newId, isContact })
    })
  }

  if (isEventEnabled('chat_removed')) {
    client.on('chat_removed', (chat) => {
      triggerWebhook(sessionWebhook, sessionId, 'chat_removed', { chat })
      triggerWebSocket(sessionId, 'chat_removed', { chat })
    })
  }

  if (isEventEnabled('chat_archived')) {
    client.on('chat_archived', (chat, currState, prevState) => {
      triggerWebhook(sessionWebhook, sessionId, 'chat_archived', { chat, currState, prevState })
      triggerWebSocket(sessionId, 'chat_archived', { chat, currState, prevState })
    })
  }

  if (isEventEnabled('unread_count')) {
    client.on('unread_count', (chat) => {
      triggerWebhook(sessionWebhook, sessionId, 'unread_count', { chat })
      triggerWebSocket(sessionId, 'unread_count', { chat })
    })
  }

  if (isEventEnabled('vote_update')) {
    client.on('vote_update', (vote) => {
      triggerWebhook(sessionWebhook, sessionId, 'vote_update', { vote })
      triggerWebSocket(sessionId, 'vote_update', { vote })
    })
  }

  if (isEventEnabled('code')) {
    client.on('code', (code) => {
      triggerWebhook(sessionWebhook, sessionId, 'code', { code })
      triggerWebSocket(sessionId, 'code', { code })
    })
  }
}

// Function to delete client session folder
const deleteSessionFolder = async (sessionId) => {
  try {
    const targetDirPath = path.join(sessionFolderPath, `session-${sessionId}`)
    const resolvedTargetDirPath = await fs.promises.realpath(targetDirPath)
    const resolvedSessionPath = await fs.promises.realpath(sessionFolderPath)

    // Ensure the target directory path ends with a path separator
    const safeSessionPath = `${resolvedSessionPath}${path.sep}`

    // Validate the resolved target directory path is a subdirectory of the session folder path
    if (!resolvedTargetDirPath.startsWith(safeSessionPath)) {
      throw new Error('Invalid path: Directory traversal detected')
    }
    await fs.promises.rm(resolvedTargetDirPath, { recursive: true, force: true })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Folder deletion error')
    throw error
  }
}

// Function to reload client session without removing browser cache
const reloadSession = async (sessionId) => {
  const client = sessions.get(sessionId)
  if (!client) {
    return
  }
  // An automatic restart is already rebuilding this one. Stacking a manual reload on top is the
  // same double-launch the rest of this module exists to prevent.
  if (inTransition.has(sessionId)) {
    logger.warn({ sessionId }, 'Session is already being rebuilt, skipping reload')
    return
  }
  inTransition.add(sessionId)
  try {
    client.pupPage?.removeAllListeners('close')
    client.pupPage?.removeAllListeners('error')
    sessions.delete(sessionId)
    await hardDestroy(client, sessionId)
    await setupSession(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to reload session')
    throw error
  } finally {
    inTransition.delete(sessionId)
  }
}

const destroySession = async (sessionId) => {
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
    await client.destroy()
    // Wait 10 secs for client.pupBrowser to be disconnected
    let maxDelay = 0
    while (client.pupBrowser?.isConnected() && (maxDelay < 10)) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      maxDelay++
    }
    sessions.delete(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to stop session')
    throw error
  }
}

const deleteSession = async (sessionId, validation) => {
  const client = sessions.get(sessionId)
  if (!client) {
    return
  }
  // Unlike a reload, a delete always wins - it only has to stay invisible to the watchdog while
  // the session sits in the Map waiting for its browser to go away.
  inTransition.add(sessionId)
  try {
    client.pupPage?.removeAllListeners('close')
    client.pupPage?.removeAllListeners('error')
    try {
      await terminateWebSocketServer(sessionId)
    } catch (error) {
      logger.error({ sessionId, err: error }, 'Failed to terminate WebSocket server')
    }
    if (validation.success) {
      // Client Connected, request logout
      logger.info({ sessionId }, 'Logging out session')
      await client.logout()
    }
    // The browser has to go either way: logout does not close it, and matching on one exact
    // message left it running for every unhealthy verdict other than 'session_not_connected'.
    // hardDestroy waits for the process, so the folder is only removed once nothing holds it.
    logger.info({ sessionId, reason: validation.message }, 'Destroying session')
    await hardDestroy(client, sessionId)
    sessions.delete(sessionId)
    await deleteSessionFolder(sessionId)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to delete session')
    throw error
  } finally {
    inTransition.delete(sessionId)
  }
}

// Function to handle session flush
const flushSessions = async (deleteOnlyInactive) => {
  try {
    // Read the contents of the sessions folder
    const files = await fs.promises.readdir(sessionFolderPath)
    // Iterate through the files in the parent folder
    for (const file of files) {
      // Use regular expression to extract the string from the folder name
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

// The in-process session watchdog.
//
// A container liveness probe is the wrong instrument here: Express keeps answering /ping long
// after a session's browser has stopped responding, so the probe reports a healthy pod wrapped
// around a dead WhatsApp session. The only check worth anything is one that talks to the
// session itself, and the only repair worth anything rebuilds that one session rather than
// restarting the whole process and every other session with it.
const sessionHealth = new Map()
let healthCheckTimer = null

const probeSession = async (sessionId, client) => {
  let health = sessionHealth.get(sessionId)
  if (!health) {
    health = { failures: 0, everConnected: false, reported: false }
    sessionHealth.set(sessionId, health)
  }

  const state = await getStateWithDeadline(client, sessionId)

  if (state === 'CONNECTED') {
    health.everConnected = true
    health.failures = 0
    health.reported = false
    return
  }

  health.failures++
  if (health.failures < sessionHealthcheckFailures) { return }

  if (!health.everConnected) {
    // Either the session was never paired, or the phone logged it out. A fresh browser cannot
    // fix either one - it only throws away the QR code someone is about to scan. Say so once
    // and leave it alone. The flag is cleared on restart, so a session that comes back up
    // unpaired settles here too instead of looping.
    if (!health.reported) {
      health.reported = true
      logger.warn({ sessionId, state }, 'Session is not connected and never has been, leaving it alone')
      triggerWebhook(webhookFor(sessionId), sessionId, 'status', { msg: 'session_not_connected', state })
      triggerWebSocket(sessionId, 'status', { msg: 'session_not_connected', state })
    }
    return
  }

  await restartSession(sessionId, client, `health check failed ${health.failures}x, last state ${state}`)
}

// One pass over every live session. Exported so it can be driven directly in tests.
const runHealthChecks = async () => {
  for (const sessionId of [...sessionHealth.keys()]) {
    if (!sessions.has(sessionId)) { sessionHealth.delete(sessionId) }
  }
  for (const [sessionId, client] of [...sessions]) {
    if (inTransition.has(sessionId)) { continue }
    await probeSession(sessionId, client)
  }
}

const startHealthChecks = () => {
  if (healthCheckTimer || sessionHealthcheckIntervalMs <= 0) { return }
  healthCheckTimer = setInterval(() => {
    runHealthChecks().catch((error) => logger.error({ err: error }, 'Session health check pass failed'))
  }, sessionHealthcheckIntervalMs)
  healthCheckTimer.unref?.()
  logger.info({ intervalMs: sessionHealthcheckIntervalMs, failuresBeforeRestart: sessionHealthcheckFailures }, 'Session health checks enabled')
}

const stopHealthChecks = () => {
  if (!healthCheckTimer) { return }
  clearInterval(healthCheckTimer)
  healthCheckTimer = null
}

// Closing the browsers over CDP is what lets chromium flush WhatsApp Web's IndexedDB. Skip it
// and the next boot finds an unreadable profile and reports the session as disconnected, even
// though nobody ever logged out.
const shutdownSessions = async () => {
  stopHealthChecks()
  await Promise.all([...sessions].map(async ([sessionId, client]) => {
    // Closing a browser closes its page, and the page-close handler is the restore path. Left
    // alone it would launch a fresh browser on the way out of the process.
    inTransition.add(sessionId)
    client.pupPage?.removeAllListeners('close')
    client.pupPage?.removeAllListeners('error')
    await hardDestroy(client, sessionId)
  }))
  sessions.clear()
}

module.exports = {
  sessions,
  setupSession,
  restoreSessions,
  validateSession,
  deleteSession,
  reloadSession,
  flushSessions,
  destroySession,
  restartSession,
  runHealthChecks,
  startHealthChecks,
  stopHealthChecks,
  shutdownSessions
}
