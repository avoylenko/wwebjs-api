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

describe('API Authentication Tests', () => {
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

describe('Session webhook Tests', () => {
  it('should reject an invalid webhookUrl on start', async () => {
    const response = await request(app).post('/session/start/5').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: 'file:///etc/passwd' })
    expect(response.status).toBe(400)
    expect(fs.existsSync('./sessions_test/session-5')).toBe(false)
  })

  it('should return 404 for webhook endpoints of an unknown session', async () => {
    const response = await request(app).get('/session/getWebhook/unknown').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(404)
    const response2 = await request(app).put('/session/setWebhook/unknown').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: 'https://example.com/hook' })
    expect(response2.status).toBe(404)
  })

  it('should start with, update, persist and clear a session webhook', async () => {
    const configPath = './sessions_test/session-6/webhook_config.json'
    const response = await request(app).post('/session/start/6').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: 'http://127.0.0.1:9/a' })
    expect(response.status).toBe(200)
    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8'))).toEqual({ webhookUrl: 'http://127.0.0.1:9/a' })

    const response2 = await request(app).get('/session/getWebhook/6').set('x-api-key', 'test_api_key')
    expect(response2.body).toEqual({ success: true, webhookUrl: 'http://127.0.0.1:9/a', source: 'runtime' })

    const response3 = await request(app).put('/session/setWebhook/6').set('x-api-key', 'test_api_key').send({})
    expect(response3.status).toBe(400)

    const response4 = await request(app).put('/session/setWebhook/6').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: 'not a url' })
    expect(response4.status).toBe(400)

    const response5 = await request(app).put('/session/setWebhook/6').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: 'http://127.0.0.1:9/b' })
    expect(response5.status).toBe(200)
    expect(JSON.parse(fs.readFileSync(configPath, 'utf-8'))).toEqual({ webhookUrl: 'http://127.0.0.1:9/b' })

    const response6 = await request(app).put('/session/setWebhook/6').set('x-api-key', 'test_api_key')
      .send({ webhookUrl: null })
    expect(response6.status).toBe(200)
    expect(fs.existsSync(configPath)).toBe(false)
    const response7 = await request(app).get('/session/getWebhook/6').set('x-api-key', 'test_api_key')
    expect(response7.body).toEqual({ success: true, webhookUrl: process.env.BASE_WEBHOOK_URL, source: 'env_global' })

    // restart without a webhookUrl must pick up the URL persisted on disk
    await request(app).put('/session/setWebhook/6').set('x-api-key', 'test_api_key').send({ webhookUrl: 'http://127.0.0.1:9/c' })
    await request(app).get('/session/stop/6').set('x-api-key', 'test_api_key')
    await request(app).get('/session/start/6').set('x-api-key', 'test_api_key')
    const response10 = await request(app).get('/session/getWebhook/6').set('x-api-key', 'test_api_key')
    expect(response10.body).toEqual({ success: true, webhookUrl: 'http://127.0.0.1:9/c', source: 'runtime' })

    // restart with an explicit null must not pick up the URL persisted on disk
    await request(app).get('/session/stop/6').set('x-api-key', 'test_api_key')
    const response9 = await request(app).post('/session/start/6').set('x-api-key', 'test_api_key').send({ webhookUrl: null })
    expect(response9.status).toBe(200)
    expect(fs.existsSync(configPath)).toBe(false)

    const response8 = await request(app).get('/session/terminate/6').set('x-api-key', 'test_api_key')
    expect(response8.status).toBe(200)
  })
})

describe('API Action Tests', () => {
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
