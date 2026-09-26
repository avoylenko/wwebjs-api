const fsp = require('fs').promises
const qrcode = require('qrcode-terminal')
const { sessionFolderPath } = require('../config')
const { logger } = require('../logger')

/**
 * Responds to request with 'pong'
 *
 * @function ping
 * @async
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Promise that resolves once response is sent
 * @throws {Object} - Throws error if response fails
 */
const ping = async (req, res) => {
  /*
    #swagger.tags = ['Various']
    #swagger.summary = 'Health check'
    #swagger.description = 'Responds to request with "pong" message'
    #swagger.responses[200] = {
      description: "Response message",
      content: {
        "application/json": {
          example: {
            success: true,
            message: "pong"
          }
        }
      }
    }
  */
  res.json({ success: true, message: 'pong' })
}

/**
 * Example local callback that generates a QR code and writes a log file
 *
 * @function localCallbackExample
 * @async
 * @param {Object} req - Express request object containing a body object with dataType and data
 * @param {string} req.body.dataType - Type of data (in this case, 'qr')
 * @param {Object} req.body.data - Data to generate a QR code from
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Promise that resolves once response is sent
 * @throws {Object} - Throws error if response fails
 */
const localCallbackExample = async (req, res) => {
  /*
    #swagger.tags = ['Various']
    #swagger.summary = 'Local callback'
    #swagger.description = 'Used to generate a QR code and writes a log file. ONLY FOR DEVELOPMENT/TEST PURPOSES.'
    #swagger.responses[200] = {
      description: "Response message",
      content: {
        "application/json": {
          example: {
            success: true
          }
        }
      }
    }
  */
  try {
    const { dataType, data } = req.body
    if (dataType === 'qr') { qrcode.generate(data.qr, { small: true }) }
    await fsp.mkdir(sessionFolderPath, { recursive: true })
    await fsp.writeFile(`${sessionFolderPath}/message_log.txt`, `${JSON.stringify(req.body)}\r\n`, { flag: 'a+' })
    res.json({ success: true })
  } catch (error) {
    /* #swagger.responses[500] = {
      description: "Server Failure.",
      content: {
        "application/json": {
          schema: { "$ref": "#/definitions/ErrorResponse" }
        }
      }
    }
    */
    logger.error({ err: error }, 'Failed to handle local callback')
    res.status(500).json({ success: false, error: error.message })
  }
}

module.exports = { ping, localCallbackExample }
