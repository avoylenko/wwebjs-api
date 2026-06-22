const request = require('supertest')
const fs = require('fs')

// Mock your application's environment variables
process.env.API_KEY = 'test_api_key'
process.env.SESSIONS_PATH = './sessions_test'
process.env.ENABLE_LOCAL_CALLBACK_EXAMPLE = 'TRUE'
process.env.BASE_WEBHOOK_URL = 'http://localhost:3000/localCallbackExample'

const app = require('../src/app')
jest.mock('qrcode-terminal')

jest.setTimeout(5 * 60 * 1000)

let server
beforeAll(() => {
  fs.rmSync(process.env.SESSIONS_PATH, { recursive: true, force: true })
  server = app.listen(3000)
})

beforeEach(() => {
  if (fs.existsSync('./sessions_test/message_log.txt')) {
    fs.writeFileSync('./sessions_test/message_log.txt', '')
  }
})

afterAll(() => {
  server.close()
  fs.rmSync(process.env.SESSIONS_PATH, { recursive: true, force: true })
})

// Define test cases
describe('API health checks', () => {
  it('should return valid health check', async () => {
    const response = await request(app).get('/ping')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ message: 'pong', success: true })
  })

  it('should return a valid callback status', async () => {
    const response = await request(app).post('/localCallbackExample')
      .set('x-api-key', 'test_api_key')
      .send({ sessionId: '1', dataType: 'testDataType', data: 'testData' })
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true })

    expect(fs.existsSync('./sessions_test/message_log.txt')).toBe(true)
    expect(fs.readFileSync('./sessions_test/message_log.txt', 'utf-8')).toEqual('{"sessionId":"1","dataType":"testDataType","data":"testData"}\r\n')
  })
})

describe('API session checks', () => {
  it('should return 403 Forbidden for invalid API key', async () => {
    const response = await request(app).get('/session/start/1')
    expect(response.status).toBe(403)
    expect(response.body).toEqual({ success: false, error: 'Invalid API key' })
  })

  it('should fail invalid sessionId', async () => {
    const response = await request(app).get('/session/start/ABCD1@').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(422)
    expect(response.body).toEqual({ success: false, error: 'Session should be alphanumerical or -' })
  })

  it('should setup and terminate a client session', async () => {
    const response = await request(app).get('/session/start/1').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Session initiated successfully' })
    expect(fs.existsSync('./sessions_test/session-1')).toBe(true)

    const response2 = await request(app).get('/session/terminate/1').set('x-api-key', 'test_api_key')
    expect(response2.status).toBe(200)
    expect(response2.body).toEqual({ success: true, message: 'Logged out successfully' })

    expect(fs.existsSync('./sessions_test/session-1')).toBe(false)
  })

  it('should setup and flush multiple client sessions', async () => {
    const response = await request(app).get('/session/start/2').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Session initiated successfully' })
    expect(fs.existsSync('./sessions_test/session-2')).toBe(true)

    const response2 = await request(app).get('/session/start/3').set('x-api-key', 'test_api_key')
    expect(response2.status).toBe(200)
    expect(response2.body).toEqual({ success: true, message: 'Session initiated successfully' })
    expect(fs.existsSync('./sessions_test/session-3')).toBe(true)

    const response3 = await request(app).get('/session/terminateInactive').set('x-api-key', 'test_api_key')
    expect(response3.status).toBe(200)
    expect(response3.body).toEqual({ success: true, message: 'Flush completed successfully' })

    expect(fs.existsSync('./sessions_test/session-2')).toBe(false)
    expect(fs.existsSync('./sessions_test/session-3')).toBe(false)
  })
})

describe('API action checks', () => {
  it('should setup, create at least a QR, and terminate a client session', async () => {
    const response = await request(app).get('/session/start/4').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Session initiated successfully' })
    expect(fs.existsSync('./sessions_test/session-4')).toBe(true)

    // Wait for message_log.txt to not be empty
    const result = await waitForFileNotToBeEmpty('./sessions_test/message_log.txt', 120_000, 1000)
      .then(() => { return true })
      .catch(() => { return false })
    expect(result).toBe(true)

    // Verify the message content
    const expectedMessage = {
      dataType: 'qr',
      data: expect.objectContaining({ qr: expect.any(String) }),
      sessionId: '4'
    }
    expect(JSON.parse(fs.readFileSync('./sessions_test/message_log.txt', 'utf-8'))).toEqual(expectedMessage)

    const response2 = await request(app).get('/session/terminate/4').set('x-api-key', 'test_api_key')
    expect(response2.status).toBe(200)
    expect(response2.body).toEqual({ success: true, message: 'Logged out successfully' })
    expect(fs.existsSync('./sessions_test/session-4')).toBe(false)
  })
})

describe('Session endpoints - no active session', () => {
  beforeAll(() => {
    if (!fs.existsSync(process.env.SESSIONS_PATH)) {
      fs.mkdirSync(process.env.SESSIONS_PATH, { recursive: true })
    }
  })

  it('GET /session/getSessions returns empty array', async () => {
    const response = await request(app).get('/session/getSessions').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, result: [] })
  })

  it('GET /session/status/:id returns session_not_found', async () => {
    const response = await request(app).get('/session/status/nonexistent').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, state: null, message: 'session_not_found' })
  })

  it('GET /session/stop/:id succeeds silently for non-existent session', async () => {
    const response = await request(app).get('/session/stop/nonexistent').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Session stopped successfully' })
  })

  it('GET /session/qr/:id returns session_not_found', async () => {
    const response = await request(app).get('/session/qr/nonexistent').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, message: 'session_not_found' })
  })

  it('GET /session/qr/:id/image returns session_not_found', async () => {
    const response = await request(app).get('/session/qr/nonexistent/image').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, message: 'session_not_found' })
  })

  it('GET /session/restart/:id returns session_not_found', async () => {
    const response = await request(app).get('/session/restart/nonexistent').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, state: null, message: 'session_not_found' })
  })

  it('GET /session/terminateAll succeeds with no active sessions', async () => {
    const response = await request(app).get('/session/terminateAll').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Flush completed successfully' })
  })

  it('POST /session/requestPairingCode/:id returns session_not_found', async () => {
    const response = await request(app).post('/session/requestPairingCode/nonexistent')
      .set('x-api-key', 'test_api_key')
      .send({ phoneNumber: '12025550108' })
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, message: 'session_not_found' })
  })

  it('GET /session/getPageScreenshot/:id returns session_not_found', async () => {
    const response = await request(app).get('/session/getPageScreenshot/nonexistent').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: false, message: 'session_not_found' })
  })
})

describe('Session validation - 404 for non-existent session', () => {
  it.each([
    ['GET', '/client/getContacts/nonexistent'],
    ['POST', '/client/sendMessage/nonexistent'],
    ['POST', '/chat/getClassInfo/nonexistent'],
    ['POST', '/chat/fetchMessages/nonexistent'],
    ['POST', '/groupChat/getClassInfo/nonexistent'],
    ['POST', '/groupChat/leave/nonexistent'],
    ['POST', '/message/getClassInfo/nonexistent'],
    ['POST', '/message/react/nonexistent'],
    ['POST', '/contact/getClassInfo/nonexistent'],
    ['POST', '/contact/getAbout/nonexistent'],
    ['POST', '/channel/getClassInfo/nonexistent'],
    ['POST', '/channel/sendMessage/nonexistent']
  ])('%s %s returns 404 session_not_found', async (method, url) => {
    const response = await request(app)[method.toLowerCase()](url).set('x-api-key', 'test_api_key')
    expect(response.status).toBe(404)
    expect(response.body).toEqual({ success: false, error: 'session_not_found' })
  })
})

describe('Authentication - 403 without a valid API key', () => {
  it.each([
    ['GET', '/client/getContacts/1'],
    ['POST', '/chat/getClassInfo/1'],
    ['POST', '/groupChat/getClassInfo/1'],
    ['POST', '/message/getClassInfo/1'],
    ['POST', '/contact/getClassInfo/1'],
    ['POST', '/channel/getClassInfo/1']
  ])('%s %s returns 403 when the API key header is missing', async (method, url) => {
    const response = await request(app)[method.toLowerCase()](url)
    expect(response.status).toBe(403)
    expect(response.body).toEqual({ success: false, error: 'Invalid API key' })
  })

  it('returns 403 when the API key is wrong', async () => {
    const response = await request(app).get('/client/getContacts/1').set('x-api-key', 'wrong_api_key')
    expect(response.status).toBe(403)
    expect(response.body).toEqual({ success: false, error: 'Invalid API key' })
  })
})

// Function to wait for a specific item to be equal a specific value
const waitForFileNotToBeEmpty = (filePath, maxWaitTime = 10000, interval = 100) => {
  const start = Date.now()
  return new Promise((resolve, reject) => {
    const checkObject = async () => {
      try {
        const filecontent = await fs.promises.readFile(filePath, 'utf-8')
        if (filecontent !== '') {
        // Nested object exists, resolve the promise
          resolve()
        } else if (Date.now() - start > maxWaitTime) {
        // Maximum wait time exceeded, reject the promise
          console.log('Timed out waiting for nested object')
          reject(new Error('Timeout waiting for nested object'))
        } else {
        // Nested object not yet created, continue waiting
          setTimeout(checkObject, interval)
        }
      } catch (ignore) {
        // continue waiting
        setTimeout(checkObject, interval)
      }
    }
    checkObject()
  })
}
