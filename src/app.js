require('./routes')
const express = require('express')
const cors = require('cors')
const { routes } = require('./routes')
const { maxAttachmentSize, basePath, trustProxy } = require('./config')

const app = express()

// Initialize Express app
app.disable('x-powered-by')

// Configure trust proxy for reverse proxy compatibility
if (trustProxy) {
  app.set('trust proxy', true)
}

app.use(express.json({ limit: maxAttachmentSize + 1000000 }))
app.use(express.urlencoded({ limit: maxAttachmentSize + 1000000, extended: true }))

// Debug logging middleware - prints request URL and body
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`)
  if (req.body && Object.keys(req.body).length > 0) {
    console.log('Request Body:', JSON.stringify(req.body, null, 2))
  }
  next()
})

// Mount routes with configurable base path
app.use(basePath, routes)

module.exports = app
