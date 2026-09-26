const fs = require('fs')
const os = require('os')
const path = require('path')

// Every knob the recovery code reads has to be set before `src/config` is first required,
// because config snapshots the environment at require time.
process.env.SESSIONS_PATH = fs.mkdtempSync(path.join(os.tmpdir(), 'wwebjs-sessions-'))
process.env.RECOVER_SESSIONS = 'TRUE'
process.env.BASE_WEBHOOK_URL = 'http://127.0.0.1:1/hook'
process.env.ENABLE_WEBHOOK = 'FALSE'
// The watchdog's timer stays off; the tests drive `runHealthChecks` by hand so they never
// have to wait on wall-clock time.
process.env.SESSION_HEALTHCHECK_INTERVAL_MS = '0'
process.env.SESSION_HEALTHCHECK_TIMEOUT_MS = '50'
process.env.SESSION_HEALTHCHECK_FAILURES = '3'
process.env.BROWSER_DESTROY_TIMEOUT_MS = '50'

// Collects every Client the code under test constructed, so a test can assert on how many
// browsers were launched - which is the whole point of the restart guard.
const mockClients = []
// Per-test overrides for the three calls that reach into puppeteer.
const mockHooks = {}

jest.mock('whatsapp-web.js', () => {
  const MockEventEmitter = require('events')

  class FakeClient extends MockEventEmitter {
    constructor (options) {
      super()
      this.options = options
      this.browserProcess = {
        exitCode: null,
        signalCode: null,
        kill (signal) {
          this.signalCode = signal
        }
      }
      this.pupPage = new MockEventEmitter()
      this.pupPage.isClosed = () => false
      this.pupPage.evaluate = async () => 1
      this.pupBrowser = { process: () => this.browserProcess, isConnected: () => false }
      this.destroyCalls = 0
      this.state = 'CONNECTED'
      mockClients.push(this)
    }

    async initialize () {
      return mockHooks.initialize ? mockHooks.initialize(this) : undefined
    }

    async destroy () {
      this.destroyCalls++
      if (mockHooks.destroy) { await mockHooks.destroy(this) }
      // The real destroy() awaits the browser process exiting before it resolves.
      this.browserProcess.exitCode = 0
    }

    async getState () {
      return mockHooks.getState ? mockHooks.getState(this) : this.state
    }
  }

  class FakeLocalAuth {
    constructor (options) {
      this.options = options
      // The real LocalAuth creates the profile directory, and the delete path expects it.
      require('fs').mkdirSync(require('path').join(options.dataPath, `session-${options.clientId}`), { recursive: true })
    }

    logout () {}
  }

  return { Client: FakeClient, LocalAuth: FakeLocalAuth }
})

// Lets queued microtasks and the short timeouts above run to completion.
const settle = (ms = 250) => new Promise((resolve) => setTimeout(resolve, ms))

let sessionsModule

beforeEach(() => {
  jest.resetModules()
  mockClients.length = 0
  for (const key of Object.keys(mockHooks)) { delete mockHooks[key] }
  sessionsModule = require('../src/sessions')
})

afterEach(() => {
  sessionsModule.stopHealthChecks()
})

describe('restart guard', () => {
  // A crashing page emits BOTH 'error' and 'close'. Without a guard each one starts its own
  // setupSession, and because the sessions Map is only written after initialize() resolves,
  // the second call sails past the "session already exists" check and launches a second
  // chromium on the same profile directory.
  it('restarts a crashed session once even though the page emits error and close', async () => {
    await sessionsModule.setupSession('crash')
    expect(mockClients).toHaveLength(1)
    const crashed = mockClients[0]

    crashed.pupPage.emit('error', new Error('page crashed'))
    crashed.pupPage.emit('close')
    await settle()

    expect(mockClients).toHaveLength(2)
    expect(sessionsModule.sessions.get('crash')).toBe(mockClients[1])
  })
})

describe('browser teardown', () => {
  // A failed initialize used to return without touching the browser, so the chromium process
  // outlived the client that owned it. Every restore leaked one.
  it('kills the browser process when destroy hangs after a failed initialize', async () => {
    mockHooks.initialize = async () => { throw new Error('Runtime.callFunctionOn timed out') }
    mockHooks.destroy = () => new Promise(() => {})

    const result = await sessionsModule.setupSession('stuck')

    expect(result.success).toBe(false)
    expect(mockClients[0].destroyCalls).toBe(1)
    expect(mockClients[0].browserProcess.signalCode).toBe('SIGKILL')
  })
})

describe('session watchdog', () => {
  it('restarts a session that stops reporting CONNECTED', async () => {
    await sessionsModule.setupSession('healthy')
    const original = mockClients[0]

    await sessionsModule.runHealthChecks()
    original.state = 'UNPAIRED'
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()
    expect(mockClients).toHaveLength(1)

    await sessionsModule.runHealthChecks()
    await settle()
    expect(mockClients).toHaveLength(2)
  })

  it('counts a hung getState as a failure', async () => {
    await sessionsModule.setupSession('wedged')

    await sessionsModule.runHealthChecks()
    mockHooks.getState = () => new Promise(() => {})
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()
    await settle()

    expect(mockClients).toHaveLength(2)
  })

  it('recovers without restarting when a session reports CONNECTED again', async () => {
    await sessionsModule.setupSession('flappy')
    const client = mockClients[0]

    await sessionsModule.runHealthChecks()
    client.state = 'OPENING'
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()
    client.state = 'CONNECTED'
    await sessionsModule.runHealthChecks()
    client.state = 'OPENING'
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()
    await settle()

    expect(mockClients).toHaveLength(1)
  })

  // The watchdog is a new path into restartSession, so it can now collide with a teardown an
  // operator asked for. A session already carrying failures is exactly the one someone deletes.
  it('does not restart a session while it is being torn down', async () => {
    await sessionsModule.setupSession('doomed')
    const client = mockClients[0]

    await sessionsModule.runHealthChecks()
    client.state = 'UNPAIRED'
    await sessionsModule.runHealthChecks()
    await sessionsModule.runHealthChecks()

    // Teardown stalls, so the session is still in the Map when the next probe lands.
    mockHooks.destroy = () => new Promise(() => {})
    sessionsModule.deleteSession('doomed', { success: false, message: 'session_not_connected' }).catch(() => {})
    await settle(50)

    await sessionsModule.runHealthChecks()
    await settle()

    expect(mockClients).toHaveLength(1)
  })

  // A session waiting to be paired is never CONNECTED either, but restarting it only throws
  // away the QR code the operator is about to scan. Those get reported, not recycled.
  it('never restarts a session that has not been paired yet', async () => {
    mockHooks.getState = () => null
    await sessionsModule.setupSession('unpaired')

    for (let i = 0; i < 5; i++) { await sessionsModule.runHealthChecks() }
    await settle()

    expect(mockClients).toHaveLength(1)
  })
})

describe('shutdown', () => {
  // puppeteer's own SIGTERM handler does not close the browser, it SIGKILLs the whole chromium
  // process group - so IndexedDB never flushes and the next boot finds an unreadable profile.
  // Taking the signal away from puppeteer is what makes a graceful shutdown possible at all.
  it('does not let puppeteer handle termination signals', async () => {
    await sessionsModule.setupSession('signals')
    const { puppeteer } = mockClients[0].options

    expect(puppeteer.handleSIGTERM).toBe(false)
    expect(puppeteer.handleSIGINT).toBe(false)
    expect(puppeteer.handleSIGHUP).toBe(false)
  })

  it('closes every session and empties the session map', async () => {
    await sessionsModule.setupSession('one')
    await sessionsModule.setupSession('two')

    await sessionsModule.shutdownSessions()

    expect(mockClients[0].destroyCalls).toBe(1)
    expect(mockClients[1].destroyCalls).toBe(1)
    expect(sessionsModule.sessions.size).toBe(0)
  })

  // Closing the browser closes its page, and the page-close handler is the restore path. Left
  // alone it would launch a fresh browser on the way out of the process.
  it('does not rebuild a session whose page closes during shutdown', async () => {
    await sessionsModule.setupSession('leaving')
    mockHooks.destroy = (client) => { client.pupPage.emit('close') }

    await sessionsModule.shutdownSessions()
    await settle()

    expect(mockClients).toHaveLength(1)
  })

  // stopHealthChecks only stops future ticks; a pass already awaiting a probe can still come
  // back and ask for a restart after the browsers are gone.
  it('ignores a restart requested for a session that is shutting down', async () => {
    await sessionsModule.setupSession('gone')
    const client = mockClients[0]

    await sessionsModule.shutdownSessions()
    await sessionsModule.restartSession('gone', client, 'late health check pass')
    await settle()

    expect(mockClients).toHaveLength(1)
  })

  // The missing half of the SIGKILL tests: every one of them checked that the fallback fires,
  // none checked that it stays out of the way. That gap hid a `killed` check that is false
  // after a clean shutdown, so a browser that closed properly got shot anyway.
  it('leaves a browser that shut down cleanly alone', async () => {
    await sessionsModule.setupSession('tidy')

    await sessionsModule.shutdownSessions()

    expect(mockClients[0].browserProcess.signalCode).toBeNull()
  })

  it('kills a browser that will not shut down in time', async () => {
    await sessionsModule.setupSession('stubborn')
    mockHooks.destroy = () => new Promise(() => {})

    await sessionsModule.shutdownSessions()

    expect(mockClients[0].browserProcess.signalCode).toBe('SIGKILL')
  })
})

describe('manual reload', () => {
  // reloadSession used to hand-roll its own teardown - close the pages, race pupBrowser.close,
  // kill(9) on failure - which is hardDestroy with different constants and one more way to get
  // it wrong. It goes through the shared path now.
  it('kills a browser that will not close', async () => {
    await sessionsModule.setupSession('reloaded')
    const original = mockClients[0]
    mockHooks.destroy = () => new Promise(() => {})

    await sessionsModule.reloadSession('reloaded')

    expect(original.browserProcess.signalCode).toBe('SIGKILL')
    expect(mockClients).toHaveLength(2)
  })
})

describe('session validation', () => {
  // The existing retry loop looks like a timeout but is not one: the race resolves after a
  // second either way, and the getState that follows had no deadline at all. A wedged page
  // held /session/status open for the whole protocol timeout.
  it('gives up instead of hanging when the page stops answering', async () => {
    await sessionsModule.setupSession('frozen')
    mockHooks.getState = () => new Promise(() => {})

    const result = await sessionsModule.validateSession('frozen')

    expect(result.success).toBe(false)
    expect(result.state).toBe('unresponsive')
  })
})

describe('session deletion', () => {
  // deleteSession only tore the browser down for the exact message 'session_not_connected'.
  // Any other unhealthy verdict fell through both branches and left the process running.
  it('tears the browser down when the page is already gone', async () => {
    await sessionsModule.setupSession('drop')
    const client = mockClients[0]
    client.pupPage.isClosed = () => true

    const validation = await sessionsModule.validateSession('drop')
    await sessionsModule.deleteSession('drop', validation)

    expect(client.destroyCalls).toBe(1)
    expect(sessionsModule.sessions.has('drop')).toBe(false)
  })
})
