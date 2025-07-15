const qr = require('qr-image')
const { setupSession, deleteSession, reloadSession, validateSession, flushSessions, destroySession, sessions } = require('../sessions')
const { sendErrorResponse, waitForNestedObject } = require('../utils')
const { logger } = require('../logger')

/**
 * Starts a session for the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to start.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error starting the session.
 */
const startSession = async (req, res) => {
  // #swagger.summary = 'Start new session'
  // #swagger.description = 'Starts a session for the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const setupSessionReturn = await setupSession(sessionId)
    if (!setupSessionReturn.success) {
      /* #swagger.responses[422] = {
        description: "Unprocessable Entity.",
        content: {
          "application/json": {
            schema: { "$ref": "#/definitions/ErrorResponse" }
          }
        }
      }
      */
      sendErrorResponse(res, 422, setupSessionReturn.message)
      return
    }
    /* #swagger.responses[200] = {
      description: "Status of the initiated session.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/StartSessionResponse" }
        }
      }
    }
    */
    // wait until the client is created
    await waitForNestedObject(setupSessionReturn.client, 'pupPage')
    res.json({ success: true, message: setupSessionReturn.message })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to start session')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Stops a session for the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to stop.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error stopping the session.
 */
const stopSession = async (req, res) => {
  // #swagger.summary = 'Stop session'
  // #swagger.description = 'Stops a session for the given session ID.'
  const sessionId = req.params.sessionId
  try {
    await destroySession(sessionId)
    /* #swagger.responses[200] = {
      description: "Status of the stopped session.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/StopSessionResponse" }
        }
      }
    }
    */
    res.json({ success: true, message: 'Session stopped successfully' })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to stop session')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Status of the session with the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to start.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error getting status of the session.
 */
const statusSession = async (req, res) => {
  // #swagger.summary = 'Get session status'
  // #swagger.description = 'Status of the session with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const sessionData = await validateSession(sessionId)
    /* #swagger.responses[200] = {
      description: "Status of the session.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/StatusSessionResponse" }
        }
      }
    }
    */
    res.json(sessionData)
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to get session status')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * QR code of the session with the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to start.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error getting status of the session.
 */
const sessionQrCode = async (req, res) => {
  // #swagger.summary = 'Get session QR code'
  // #swagger.description = 'QR code of the session with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const session = sessions.get(sessionId)
    if (!session) {
      return res.json({ success: false, message: 'session_not_found' })
    }
    if (session.qr) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate')
      res.setHeader('Expires', 0)
      return res.json({ success: true, qr: session.qr })
    }
    return res.json({ success: false, message: 'qr code not ready or already scanned' })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to get session qr code')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * QR code as image of the session with the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to start.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error getting status of the session.
 */
const sessionQrCodeImage = async (req, res) => {
  // #swagger.summary = 'Get session QR code as image'
  // #swagger.description = 'QR code as image of the session with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const session = sessions.get(sessionId)
    if (!session) {
      return res.json({ success: false, message: 'session_not_found' })
    }
    if (session.qr) {
      const qrImage = qr.image(session.qr)
      /* #swagger.responses[200] = {
          description: "QR image.",
          content: {
            "image/png": {}
          }
        }
      */
      res.writeHead(200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        Expires: 0,
        'Content-Type': 'image/png'
      })
      return qrImage.pipe(res)
    }
    return res.json({ success: false, message: 'qr code not ready or already scanned' })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to get session qr code image')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Restarts the session with the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to terminate.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error terminating the session.
 */
const restartSession = async (req, res) => {
  // #swagger.summary = 'Restart session'
  // #swagger.description = 'Restarts the session with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const validation = await validateSession(sessionId)
    if (validation.message === 'session_not_found') {
      return res.json(validation)
    }
    await reloadSession(sessionId)
    /* #swagger.responses[200] = {
      description: "Sessions restarted.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/RestartSessionResponse" }
        }
      }
    }
    */
    res.json({ success: true, message: 'Restarted successfully' })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to restart session')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Terminates the session with the given session ID.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID to terminate.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error terminating the session.
 */
const terminateSession = async (req, res) => {
  // #swagger.summary = 'Terminate session'
  // #swagger.description = 'Terminates the session with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const validation = await validateSession(sessionId)
    if (validation.message === 'session_not_found') {
      return res.json(validation)
    }
    await deleteSession(sessionId, validation)
    /* #swagger.responses[200] = {
      description: "Sessions terminated.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/TerminateSessionResponse" }
        }
      }
    }
    */
    res.json({ success: true, message: 'Logged out successfully' })
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to terminate session')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Terminates all inactive sessions.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error terminating the sessions.
 */
const terminateInactiveSessions = async (req, res) => {
  // #swagger.summary = 'Terminate inactive sessions'
  // #swagger.description = 'Terminates all inactive sessions.'
  try {
    await flushSessions(true)
    /* #swagger.responses[200] = {
      description: "Sessions terminated.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/TerminateSessionsResponse" }
        }
      }
    }
    */
    res.json({ success: true, message: 'Flush completed successfully' })
  } catch (error) {
    logger.error(error, 'Failed to terminate inactive sessions')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Terminates all sessions.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<void>}
 * @throws {Error} If there was an error terminating the sessions.
 */
const terminateAllSessions = async (req, res) => {
  // #swagger.summary = 'Terminate all sessions'
  // #swagger.description = 'Terminates all sessions.'
  try {
    await flushSessions(false)
    /* #swagger.responses[200] = {
      description: "Sessions terminated.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/TerminateSessionsResponse" }
        }
      }
    }
    */
    res.json({ success: true, message: 'Flush completed successfully' })
  } catch (error) {
    logger.error(error, 'Failed to terminate all sessions')
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Request authentication via pairing code instead of QR code.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.phoneNumber - The phone number in international, symbol-free format (e.g. 12025550108 for US, 551155501234 for Brazil).
 * @param {boolean} req.body.showNotification - Show notification to pair on phone number.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const requestPairingCode = async (req, res) => {
  /*
    #swagger.summary = 'Request authentication via pairing code'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          phoneNumber: {
            type: 'string',
            description: 'Phone number in international, symbol-free format',
            example: '12025550108'
          },
          showNotification: {
            type: 'boolean',
            description: 'Show notification to pair on phone number',
            example: true
          },
        }
      },
    }
  */
  try {
    const { phoneNumber, showNotification = true } = req.body
    const client = sessions.get(req.params.sessionId)
    if (!client) {
      return res.json({ success: false, message: 'session_not_found' })
    }
    const result = await client.requestPairingCode(phoneNumber, showNotification)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get all sessions.
 *
 * @function
 * @async
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @returns {<Object>}
 */
const getSessions = async (req, res) => {
  // #swagger.summary = 'Get all sessions'
  // #swagger.description = 'Get all sessions.'
  /* #swagger.responses[200] = {
      description: "Retrieved all sessions.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/GetSessionsResponse" }
        }
      }
    }
  */
  return res.json({ success: true, result: Array.from(sessions.keys()) })
}

/**
 * Get pupPage screenshot image
 *
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} If there is an issue setting the profile picture, an error will be thrown.
 */
const getPageScreenshot = async (req, res) => {
  // #swagger.summary = 'Get page screenshot'
  // #swagger.description = 'Screenshot of the client with the given session ID.'
  const sessionId = req.params.sessionId
  try {
    const session = sessions.get(sessionId)
    if (!session) {
      return res.json({ success: false, message: 'session_not_found' })
    }

    if (!session.pupPage) {
      return res.json({ success: false, message: 'page_not_ready' })
    }

    const pngBase64String = await session.pupPage.screenshot({
      fullPage: true,
      encoding: 'base64',
      type: 'png'
    })

    /* #swagger.responses[200] = {
        description: "Screenshot image.",
        content: {
          "image/png": {}
        }
      }
    */
    res.writeHead(200, {
      'Content-Type': 'image/png'
    })
    res.write(Buffer.from(pngBase64String, 'base64'))
    res.end()
  } catch (error) {
    logger.error({ sessionId, err: error }, 'Failed to get page screenshot')
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  startSession,
  stopSession,
  statusSession,
  sessionQrCode,
  sessionQrCodeImage,
  requestPairingCode,
  restartSession,
  terminateSession,
  terminateInactiveSessions,
  terminateAllSessions,
  getSessions,
  getPageScreenshot
}