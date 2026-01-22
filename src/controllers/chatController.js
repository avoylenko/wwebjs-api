const { sessions } = require('../sessions')
const { sendErrorResponse } = require('../utils')

/**
 * @function
 * @async
 * @name getClassInfo
 * @description Gets information about a chat using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the chat to get information for
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and chat information
 * @throws {Error} - Throws an error if chat is not found or if there is a server error
 */
const getClassInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get the chat'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    res.json({ success: true, chat })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Clears all messages in a chat.
 *
 * @function
 * @async
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The ID of the session.
 * @param {string} req.body.chatId - The ID of the chat to clear messages from.
 * @throws {Error} If the chat is not found or there is an internal server error.
 * @returns {Object} The success status and the cleared messages.
 */
const clearMessages = async (req, res) => {
  /*
    #swagger.summary = 'Clear all messages from the chat'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.clearMessages()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Stops typing or recording in chat immediately.
 *
 * @function
 * @async
 * @param {Object} req - Request object.
 * @param {Object} res - Response object.
 * @param {string} req.body.chatId - ID of the chat to clear the state for.
 * @param {string} req.params.sessionId - ID of the session the chat belongs to.
 * @returns {Promise<void>} - A Promise that resolves with a JSON object containing a success flag and the result of clearing the state.
 * @throws {Error} - If there was an error while clearing the state.
 */
const clearState = async (req, res) => {
  /*
    #swagger.summary = 'Stop typing or recording in chat immediately'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.clearState()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Delete a chat.
 *
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.chatId - The ID of the chat to be deleted.
 * @returns {Object} A JSON response indicating whether the chat was deleted successfully.
 * @throws {Object} If there is an error while deleting the chat, an error response is sent with a status code of 500.
 * @throws {Object} If the chat is not found, an error response is sent with a status code of 404.
 */
const deleteChat = async (req, res) => {
  /*
    #swagger.summary = 'Delete the chat'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.delete()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Fetches messages from a specified chat.
 *
 * @function
 * @async
 *
 * @param {Object} req - The request object containing sessionId, chatId, and searchOptions.
 * @param {string} req.params.sessionId - The ID of the session associated with the chat.
 * @param {Object} req.body - The body of the request containing chatId and searchOptions.
 * @param {string} req.body.chatId - The ID of the chat from which to fetch messages.
 * @param {Object} req.body.searchOptions - The search options to use when fetching messages.
 *
 * @param {Object} res - The response object to send the fetched messages.
 * @returns {Promise<Object>} A JSON object containing the success status and fetched messages.
 *
 * @throws {Error} If the chat is not found or there is an error fetching messages.
 */
const fetchMessages = async (req, res) => {
  try {
    /*
    #swagger.summary = 'Load chat messages'
    #swagger.description = 'Messages sorted from earliest to latest'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp identifier for the given Chat (either group or personal)',
            example: '6281288888888@c.us'
          },
          searchOptions: {
            type: 'object',
            description: 'Search options for fetching messages',
            example: { limit: 10, fromMe: true }
          }
        }
      }
    }
    */
    const { chatId, searchOptions = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const messages = Object.keys(searchOptions).length ? await chat.fetchMessages(searchOptions) : await chat.fetchMessages()
    res.json({ success: true, messages })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Gets the contact for a chat
 * @async
 * @function
 * @param {Object} req - The HTTP request object
 * @param {Object} res - The HTTP response object
 * @param {string} req.params.sessionId - The ID of the current session
 * @param {string} req.body.chatId - The ID of the chat to get the contact for
 * @returns {Promise<void>} - Promise that resolves with the chat's contact information
 * @throws {Error} - Throws an error if chat is not found or if there is an error getting the contact information
 */
const getContact = async (req, res) => {
  /*
    #swagger.summary = 'Get the contact'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const contact = await chat.getContact()
    res.json({ success: true, contact })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send a recording state to a WhatsApp chat.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the recording state to.
 * @returns {object} - An object containing a success message and the result of the sendStateRecording method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const sendStateRecording = async (req, res) => {
  /*
    #swagger.summary = 'Simulate recording audio'
    #swagger.description = 'Simulate recording audio in chat. This will last for 25 seconds'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.sendStateRecording()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send a typing state to a WhatsApp chat.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const sendStateTyping = async (req, res) => {
  /*
    #swagger.summary = 'Simulate typing in chat'
    #swagger.description = 'Simulate typing in chat. This will last for 25 seconds.'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.sendStateTyping()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send a seen state to a WhatsApp chat.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const sendSeen = async (req, res) => {
  /*
    #swagger.summary = 'Set the message as seen'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.markSeen()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Mark this chat as unread.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const markUnread = async (req, res) => {
  /*
    #swagger.summary = 'Mark this chat as unread'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.markUnread()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sync history.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const syncHistory = async (req, res) => {
  /*
    #swagger.summary = 'Sync chat history'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const result = await chat.syncHistory()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Return array of all labels.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const getLabels = async (req, res) => {
  /*
    #swagger.summary = 'Return all labels'
    #swagger.description = 'Return array of all labels assigned to this chat'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    const labels = await chat.getLabels()
    res.json({ success: true, labels })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Add or remove labels.
 * @async
 * @function
 * @param {object} req - The request object.
 * @param {object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {object} req.body - The request body.
 * @param {string} req.body.chatId - The ID of the chat to send the typing state to.
 * @returns {object} - An object containing a success message and the result of the sendStateTyping method.
 * @throws {object} - An error object containing a status code and error message if an error occurs.
 */
const changeLabels = async (req, res) => {
  /*
    #swagger.summary = 'Add or remove labels'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp identifier for the given Chat (either group or personal)',
            example: '6281288888888@c.us'
          },
          labelIds: {
            type: 'array',
            description: 'Array of (number or string)',
            example: [0, 1]
          }
        }
      }
    }
  */
  try {
    const { chatId, labelIds } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    await chat.changeLabels(labelIds)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Executes a method on the chat associated with the given sessionId.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const runMethod = async (req, res) => {
  /*
    #swagger.summary = 'Execute a method on the chat'
    #swagger.description = 'Execute a method on the chat and return the result'
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
          method: {
            type: 'string',
            description: 'The name of the method to execute',
            example: 'getLabels'
          },
          options: {
            anyOf: [
              { type: 'object' },
              { type: 'string' }
            ],
            description: 'The options to pass to the method',
          }
        }
      },
    }
  */
  try {
    const { chatId, method, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Chat not Found')
      return
    }
    if (typeof chat[method] !== 'function') {
      throw new Error('Method is not implemented')
    }
    const result = options ? await chat[method](options) : await chat[method]()
    res.json({ success: true, data: result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getClassInfo,
  clearMessages,
  clearState,
  deleteChat,
  fetchMessages,
  getContact,
  sendStateRecording,
  sendStateTyping,
  sendSeen,
  markUnread,
  syncHistory,
  getLabels,
  changeLabels,
  runMethod
}
