// Load environment variables from .env file
require('dotenv').config({ path: process.env.ENV_PATH || '.env' })

// setup global const
const servicePort = process.env.PORT || 3000
const sessionFolderPath = process.env.SESSIONS_PATH || './sessions'
const enableLocalCallbackExample = (process.env.ENABLE_LOCAL_CALLBACK_EXAMPLE || '').toLowerCase() === 'true'
const globalApiKey = process.env.API_KEY
const baseWebhookURL = process.env.BASE_WEBHOOK_URL
const maxAttachmentSize = parseInt(process.env.MAX_ATTACHMENT_SIZE) || 10000000
const setMessagesAsSeen = (process.env.SET_MESSAGES_AS_SEEN || '').toLowerCase() === 'true'
const disabledCallbacks = process.env.DISABLED_CALLBACKS ? process.env.DISABLED_CALLBACKS.split('|') : []
const enableSwaggerEndpoint = (process.env.ENABLE_SWAGGER_ENDPOINT || '').toLowerCase() === 'true'
const enableWebUI = (process.env.ENABLE_WEB_UI || '').toLowerCase() === 'true'
const webVersion = process.env.WEB_VERSION
const webVersionCacheType = process.env.WEB_VERSION_CACHE_TYPE || 'none'
const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX) || 1000
const rateLimitWindowMs = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 1000
const recoverSessions = (process.env.RECOVER_SESSIONS || '').toLowerCase() === 'true'
const chromeBin = process.env.CHROME_BIN || null
const headless = process.env.HEADLESS ? (process.env.HEADLESS).toLowerCase() === 'true' : true
const releaseBrowserLock = process.env.RELEASE_BROWSER_LOCK ? (process.env.RELEASE_BROWSER_LOCK).toLowerCase() === 'true' : true
const logLevel = process.env.LOG_LEVEL || 'info'
const enableWebHook = process.env.ENABLE_WEBHOOK ? (process.env.ENABLE_WEBHOOK).toLowerCase() === 'true' : true
const enableWebSocket = process.env.ENABLE_WEBSOCKET ? (process.env.ENABLE_WEBSOCKET).toLowerCase() === 'true' : false
const autoStartSessions = process.env.AUTO_START_SESSIONS ? (process.env.AUTO_START_SESSIONS).toLowerCase() === 'true' : true
const basePath = process.env.BASE_PATH || '/'
const trustProxy = process.env.TRUST_PROXY ? (process.env.TRUST_PROXY).toLowerCase() === 'true' : false
// Puppeteer's own default is 180s, which means a wedged page holds a REST request open for
// three minutes before anyone finds out. One minute is long enough for a slow evaluate and
// short enough that a stuck browser surfaces while the caller is still listening.
const protocolTimeoutMs = parseInt(process.env.PROTOCOL_TIMEOUT_MS) || 60000
// How long `client.destroy()` gets to shut chromium down politely before it is killed.
const browserDestroyTimeoutMs = parseInt(process.env.BROWSER_DESTROY_TIMEOUT_MS) || 10000
// How long a graceful shutdown gets before the process exits anyway. Must stay under the
// pod's terminationGracePeriodSeconds (30s by default) or kubernetes kills us mid-flush.
const shutdownTimeoutMs = parseInt(process.env.SHUTDOWN_TIMEOUT_MS) || 20000
// The in-process session watchdog. A container probe cannot see this: the HTTP server keeps
// answering long after a session's browser has stopped responding, so the check has to talk
// to the session itself. Set the interval to 0 to turn the watchdog off.
const sessionHealthcheckIntervalMs = Number.isFinite(parseInt(process.env.SESSION_HEALTHCHECK_INTERVAL_MS))
  ? parseInt(process.env.SESSION_HEALTHCHECK_INTERVAL_MS)
  : 60000
const sessionHealthcheckTimeoutMs = parseInt(process.env.SESSION_HEALTHCHECK_TIMEOUT_MS) || 15000
// Consecutive failed probes before a session is recycled. WhatsApp Web dips out of CONNECTED
// during ordinary reconnects, so a single bad reading means nothing.
const sessionHealthcheckFailures = parseInt(process.env.SESSION_HEALTHCHECK_FAILURES) || 3

const proxyUrl = process.env.PROXY_URL || null
const proxyUsername = process.env.PROXY_USERNAME ?? null
const proxyPassword = process.env.PROXY_PASSWORD ?? null

module.exports = {
  servicePort,
  sessionFolderPath,
  enableLocalCallbackExample,
  globalApiKey,
  baseWebhookURL,
  maxAttachmentSize,
  setMessagesAsSeen,
  disabledCallbacks,
  enableSwaggerEndpoint,
  enableWebUI,
  webVersion,
  webVersionCacheType,
  rateLimitMax,
  rateLimitWindowMs,
  recoverSessions,
  chromeBin,
  headless,
  releaseBrowserLock,
  logLevel,
  enableWebHook,
  enableWebSocket,
  autoStartSessions,
  basePath,
  trustProxy,
  protocolTimeoutMs,
  shutdownTimeoutMs,
  browserDestroyTimeoutMs,
  sessionHealthcheckIntervalMs,
  sessionHealthcheckTimeoutMs,
  sessionHealthcheckFailures,
  proxyUrl,
  proxyUsername,
  proxyPassword
}
