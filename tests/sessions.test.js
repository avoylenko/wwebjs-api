let mockReceivedOptions

jest.mock('whatsapp-web.js', () => ({
  Client: jest.fn().mockImplementation((options) => {
    const { EventEmitter } = require('events')
    mockReceivedOptions = options
    const client = new EventEmitter()
    client.initialize = jest.fn(async () => client.emit('code', 'ABCD1234'))
    return client
  }),
  LocalAuth: jest.fn().mockImplementation(() => ({ logout: jest.fn() }))
}))
jest.mock('../src/websocket', () => ({
  initWebSocketServer: jest.fn(),
  terminateWebSocketServer: jest.fn(),
  triggerWebSocket: jest.fn()
}))
jest.mock('../src/utils', () => ({
  triggerWebhook: jest.fn(),
  waitForNestedObject: jest.fn(() => Promise.reject(new Error('not needed'))),
  isEventEnabled: jest.fn(),
  sendMessageSeenStatus: jest.fn(),
  sleep: jest.fn(),
  patchWWebLibrary: jest.fn()
}))

const { setupSession, sessions } = require('../src/sessions')

afterEach(() => sessions.clear())

test('configures phone pairing before initializing the client', async () => {
  const result = await setupSession('phone-test', {
    phoneNumber: '12025550108',
    showNotification: false,
    intervalMs: 180000
  })

  expect(mockReceivedOptions.pairWithPhoneNumber).toEqual({
    phoneNumber: '12025550108',
    showNotification: false,
    intervalMs: 180000
  })
  expect(result.pairingCode).toBe('ABCD1234')
})
