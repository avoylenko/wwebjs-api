const app = require('./src/app')
const { servicePort, baseWebhookURL, enableWebHook, enableWebSocket, autoStartSessions, shutdownTimeoutMs } = require('./src/config')
const { logger } = require('./src/logger')
const { handleUpgrade } = require('./src/websocket')
const { restoreSessions, startHealthChecks, shutdownSessions } = require('./src/sessions')

// Check if BASE_WEBHOOK_URL environment variable is available when WebHook is enabled
if (!baseWebhookURL && enableWebHook) {
  logger.error('BASE_WEBHOOK_URL environment variable is not set. Exiting...')
  process.exit(1) // Terminate the application with an error code
}

const server = app.listen(servicePort, () => {
  logger.info(`Server running on port ${servicePort}`)
  logger.debug({ configuration: require('./src/config') }, 'Service configuration')
  if (autoStartSessions) {
    logger.info('Starting all sessions')
    restoreSessions()
  }
  startHealthChecks()
})

if (enableWebSocket) {
  server.on('upgrade', (request, socket, head) => {
    handleUpgrade(request, socket, head)
  })
}

// Browsers are shut down here rather than by puppeteer, whose signal handlers SIGKILL the
// chromium process group. That never flushes WhatsApp Web's IndexedDB, so the next boot finds
// an unreadable profile and the session comes back as if it had been logged out.
let shuttingDown = false

const shutdown = async (signal) => {
  if (shuttingDown) { return }
  shuttingDown = true
  logger.info({ signal }, 'Shutting down, closing sessions')
  server.close()
  try {
    await Promise.race([
      shutdownSessions(),
      new Promise(resolve => setTimeout(resolve, shutdownTimeoutMs))
    ])
  } catch (error) {
    logger.error({ err: error }, 'Failed to close sessions cleanly')
  }
  process.exit(0)
}

process.on('SIGTERM', () => { shutdown('SIGTERM') })
process.on('SIGINT', () => { shutdown('SIGINT') })

// Allows more than 10 browser instances without a listener warning
process.setMaxListeners(0)
