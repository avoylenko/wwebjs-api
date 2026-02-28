const swaggerAutogen = require('swagger-autogen')({ openapi: '3.0.0', autoBody: false })

const outputFile = './swagger.json'
const endpointsFiles = ['./src/routes.js']

const doc = {
  info: {
    title: 'WWebJS API',
    description: 'API wrapper for WhatsAppWebJS'
  },
  servers: [
    {
      url: '/',
      description: 'default server'
    },
    {
      url: 'http://localhost:3000',
      description: 'localhost server'
    }
  ],
  securityDefinitions: {
    apiKeyAuth: {
      type: 'apiKey',
      in: 'header',
      name: 'x-api-key'
    }
  },
  produces: ['application/json'],
  tags: [
    {
      name: 'Session',
      description: 'Handling multiple sessions logic, creation and deletion'
    },
    {
      name: 'Client',
      description: 'All functions related to the client'
    },
    {
      name: 'Message'
    }
  ],
  definitions: {
    StartSessionResponse: {
      success: true,
      message: 'Session initiated successfully'
    },
    StopSessionResponse: {
      success: true,
      message: 'Session stopped successfully'
    },
    StatusSessionResponse: {
      success: true,
      state: 'CONNECTED',
      message: 'session_connected'
    },
    RestartSessionResponse: {
      success: true,
      message: 'Restarted successfully'
    },
    TerminateSessionResponse: {
      success: true,
      message: 'Logged out successfully'
    },
    TerminateSessionsResponse: {
      success: true,
      message: 'Flush completed successfully'
    },
    ErrorResponse: {
      success: false,
      error: 'Some server error'
    },
    NotFoundResponse: {
      success: false,
      error: 'Not found error'
    },
    ForbiddenResponse: {
      success: false,
      error: 'Invalid API key'
    },
    GetSessionsResponse: {
      success: true,
      result: ['session1', 'session2']
    },
    ChatId: {
      server: 'c.us | g.us',
      user: '1234567890',
      _serialized: '1234567890@c.us',
    },
    Chat: {
      id: { $ref: '#/definitions/ChatId' },
      name: 'John Doe',
      isGroup: false, 
      unreadCount: 0,
      timestamp: 1770140061,
      archived: false,
      pinned: false,
      isMuted: false,
      muteExpiration: 0,
      // Add other chat properties as needed after create definitions
    },
    GetChatsResponse: {
      success: true,
      chats: [ { $ref: '#/definitions/Chat' } ],
      error: 'error message if any',
    }
  }
}

swaggerAutogen(outputFile, endpointsFiles, doc)
