const request = require('supertest')
const fs = require('fs')

// Mock your application's environment variables
process.env.API_KEY = 'test_api_key'
process.env.SESSIONS_PATH = './sessions_test'

const app = require('../src/app')

jest.setTimeout(5 * 60 * 1000)

let server
beforeAll(() => {
  fs.rmSync(process.env.SESSIONS_PATH, { recursive: true, force: true })
  server = app.listen(3000)
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

describe('API Action Tests', () => {
  it('should setup and terminate a client session', async () => {
    const response = await request(app).get('/session/start/4').set('x-api-key', 'test_api_key')
    expect(response.status).toBe(200)
    expect(response.body).toEqual({ success: true, message: 'Session initiated successfully' })
    expect(fs.existsSync('./sessions_test/session-4')).toBe(true)

    const response2 = await request(app).get('/session/terminate/4').set('x-api-key', 'test_api_key')
    expect(response2.status).toBe(200)
    expect(response2.body).toEqual({ success: true, message: 'Logged out successfully' })
    expect(fs.existsSync('./sessions_test/session-4')).toBe(false)
  })
})
