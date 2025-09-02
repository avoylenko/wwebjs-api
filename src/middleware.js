const { globalApiKey, rateLimitMax, rateLimitWindowMs } = require('./config')
const { sendErrorResponse } = require('./utils')
const { validateSession } = require('./sessions')
const rateLimiting = require('express-rate-limit')

const apikey = async (req, res, next) => {
  /*
    #swagger.security = [{
          "apiKeyAuth": []
    }]
  */
  /* #swagger.responses[403] = {
        description: "Forbidden.",
        content: {
          "application/json": {
            schema: { "$ref": "#/definitions/ForbiddenResponse" }
          }
        }
      }
  */
  if (globalApiKey) {
    const apiKey = req.headers['x-api-key']
    if (!apiKey || apiKey !== globalApiKey) {
      return sendErrorResponse(res, 403, 'Invalid API key')
    }
  }
  next()
}

const sessionNameValidation = async (req, res, next) => {
  /*
    #swagger.parameters['sessionId'] = {
      in: 'path',
      description: 'Unique identifier for the session (alphanumeric and - allowed)',
      required: true,
      type: 'string',
      example: 'f8377d8d-a589-4242-9ba6-9486a04ef80c'
    }
  */
  if ((!/^[\w-]+$/.test(req.params.sessionId))) {
    /* #swagger.responses[422] = {
        description: "Unprocessable Entity.",
        content: {
          "application/json": {
            schema: { "$ref": "#/definitions/ErrorResponse" }
          }
        }
      }
    */
    return sendErrorResponse(res, 422, 'Session should be alphanumerical or -')
  }
  next()
}

const sessionValidation = async (req, res, next) => {
  const validation = await validateSession(req.params.sessionId)
  if (validation.success !== true) {
    /* #swagger.responses[404] = {
        description: "Not Found.",
        content: {
          "application/json": {
            schema: { "$ref": "#/definitions/NotFoundResponse" }
          }
        }
      }
    */
    return sendErrorResponse(res, 404, validation.message)
  }
  next()
}

const rateLimiter = rateLimiting({
  limit: rateLimitMax,
  windowMs: rateLimitWindowMs,
  message: "You can't make any more requests at the moment. Try again later",
  // Use real client IP when behind reverse proxy
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress
  }
})

const sessionSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Session']
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

const clientSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Client']
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

const contactSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Contact']
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          contactId: {
            type: 'string',
            description: 'Unique WhatsApp ID for the contact',
            example: '6281288888888@c.us'
          }
        }
      }
    }
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

const messageSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Message']
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'The chat id which contains the message',
            example: '6281288888888@c.us'
          },
          messageId: {
            type: 'string',
            description: 'Unique WhatsApp ID for the message',
            example: 'ABCDEF999999999'
          }
        }
      }
    }
  */
  next()
}

const chatSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Chat']
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp ID for the given chat (either group or personal)',
            example: '6281288888888@c.us'
          }
        }
      }
    }
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

const groupChatSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Group Chat']
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          }
        }
      }
    }
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

const channelSwagger = async (req, res, next) => {
  /*
    #swagger.tags = ['Channel Chat']
    #swagger.responses[500] = {
      description: "Server failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
  */
  next()
}

module.exports = {
  sessionValidation,
  apikey,
  sessionNameValidation,
  sessionSwagger,
  clientSwagger,
  contactSwagger,
  messageSwagger,
  chatSwagger,
  groupChatSwagger,
  channelSwagger,
  rateLimiter
}
