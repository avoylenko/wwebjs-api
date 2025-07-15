require('./routes') // Keep this line if it's needed for side effects in routes.js
const express = require('express')
const { routes } = require('./routes')
const { maxAttachmentSize } = require('./config')
const cors = require('cors');

const app = express()

// Initialize Express app
app.disable('x-powered-by')
app.use(cors({
    origin: '*' // Allow requests from any origin
  }));
app.use(express.json({ limit: maxAttachmentSize + 1000000 }))
app.use(express.urlencoded({ limit: maxAttachmentSize + 1000000, extended: true }))
app.use('/', routes) // Then apply your routes

module.exports = app