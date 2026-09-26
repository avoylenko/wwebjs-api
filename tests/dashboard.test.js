const request = require('supertest')

// Mock your application's environment variables
process.env.API_KEY = 'test_api_key'
process.env.SESSIONS_PATH = './sessions_test'
process.env.ENABLE_WEB_UI = 'TRUE'

const app = require('../src/app')
jest.mock('qrcode-terminal')

describe('Web UI dashboard', () => {
  it('should serve the dashboard page', async () => {
    const response = await request(app).get('/dashboard/')
    expect(response.status).toBe(200)
    expect(response.headers['content-type']).toMatch(/html/)
    expect(response.text).toContain('<title>WWebJS API Dashboard</title>')
  })

  it('should redirect /dashboard to /dashboard/', async () => {
    const response = await request(app).get('/dashboard')
    expect(response.status).toBe(301)
    expect(response.headers.location).toBe('/dashboard/')
  })

  it('should serve the dashboard assets', async () => {
    const response = await request(app).get('/dashboard/app.js')
    expect(response.status).toBe(200)
    expect(response.headers['content-type']).toMatch(/javascript/)
  })

  it('should not serve the dashboard when disabled', async () => {
    process.env.ENABLE_WEB_UI = 'FALSE'
    let disabledApp
    jest.isolateModules(() => {
      disabledApp = require('../src/app')
    })
    const response = await request(disabledApp).get('/dashboard/')
    expect(response.status).toBe(404)
    process.env.ENABLE_WEB_UI = 'TRUE'
  })
})
