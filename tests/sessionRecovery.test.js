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
    constructor () {
      super()
      this.browserProcess = {
        killed: false,
        signal: null,
        kill (signal) {
          this.killed = true
          this.signal = signal
        }
      }
      this.pupPage = new MockEventEmitter()
      this.pupPage.isClosed = () => false
      this.pupPage.evaluate = async () => 1
      this.pupBrowser = { process: () => this.browserProcess }
      this.destroyCalls = 0
      this.state = 'CONNECTED'
      mockClients.push(this)
    }

    async initialize () {
      return mockHooks.initialize ? mockHooks.initialize(this) : undefined
    }

    async destroy () {
      this.destroyCalls++
      return mockHooks.destroy ? mockHooks.destroy(this) : undefined
    }

    async getState () {
      return mockHooks.getState ? mockHooks.getState(this) : this.state
    }
  }

  class FakeLocalAuth {
    constructor (options) { this.options = options }
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
    expect(mockClients[0].browserProcess.signal).toBe('SIGKILL')
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
