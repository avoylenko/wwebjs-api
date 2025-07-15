const { MessageMedia, Location, Poll } = require('whatsapp-web.js')
const { Readable } = require('stream')
const { sessions } = require('../sessions')
const { sendErrorResponse, decodeBase64 } = require('../utils')

/**
 * Get message by its ID from a given chat using the provided client.
 * @async
 * @function
 * @param {object} client - The chat client.
 * @param {string} messageId - The ID of the message to get.
 * @param {string} chatId - The ID of the chat to search in.
 * @returns {Promise<object>} - A Promise that resolves with the message object that matches the provided ID, or undefined if no such message exists.
 * @throws {Error} - Throws an error if the provided client, message ID or chat ID is invalid.
 */
const _getMessageById = async (client, messageId, chatId) => {
  const chat = await client.getChatById(chatId)
  const messages = await chat.fetchMessages({ limit: 100 })
  return messages.find((message) => { return message.id.id === messageId })
}

/**
 * Gets information about a message's class.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise<void>} - A Promise that resolves with no value when the function completes.
 */
const getClassInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get message'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    res.json({ success: true, message })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Deletes a message.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @param {boolean} req.body.everyone - Whether to delete the message for everyone or just the sender.
 * @returns {Promise<void>} - A Promise that resolves with no value when the function completes.
 */
const deleteMessage = async (req, res) => {
  /*
    #swagger.summary = 'Delete a message from the chat'
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
            description: 'Unique WhatsApp identifier for the message',
            example: 'ABCDEF999999999'
          },
          everyone: {
            type: 'boolean',
            description: 'If true and the message is sent by the current user or the user is an admin, will delete it for everyone in the chat.',
            example: true
          },
          clearMedia: {
            type: 'boolean',
            description: 'If true, any associated media will also be deleted from a device',
            example: true
          }
        }
      }
    }
  */
  try {
    const { messageId, chatId, everyone, clearMedia = true } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.delete(everyone, clearMedia)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Downloads media from a message.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @param {boolean} req.body.everyone - Whether to download the media for everyone or just the sender.
 * @returns {Promise<void>} - A Promise that resolves with no value when the function completes.
 */
const downloadMedia = async (req, res) => {
  /*
    #swagger.summary = 'Download attached message media'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    if (!message.hasMedia) { throw new Error('Message media not found') }
    const messageMedia = await message.downloadMedia()
    res.json({ success: true, messageMedia })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Downloads media from a message and sends it as binary data.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise<void>} - A Promise that resolves with no value when the function completes.
 */
const downloadMediaAsData = async (req, res) => {
  /*
    #swagger.summary = 'Download attached message media as binary data'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    if (!message.hasMedia) { throw new Error('Message media not found') }
    const { data, mimetype, filename, filesize } = await message.downloadMedia()
    /* #swagger.responses[200] = {
        description: 'Binary data.'
      }
    */
    res.writeHead(200, {
      ...(mimetype && { 'Content-Type': mimetype }),
      ...(filesize && { 'Content-Length': filesize }),
      ...(filename && { 'Content-Disposition': `attachment; filename=${encodeURIComponent(filename)}` })
    })
    const readableStream = new Readable({
      read () {
        for (const chunk of decodeBase64(data)) {
          this.push(chunk)
        }
        this.push(null)
      }
    })
    readableStream.on('end', () => {
      res.end()
    })
    readableStream.pipe(res)
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Forwards a message to a destination chat.
 * @async
 * @function forward
 * @param {Object} req - The request object received by the server.
 * @param {Object} req.body - The body of the request object.
 * @param {string} req.body.messageId - The ID of the message to forward.
 * @param {string} req.body.chatId - The ID of the chat that contains the message to forward.
 * @param {string} req.body.destinationChatId - The ID of the chat to forward the message to.
 * @param {string} req.params.sessionId - The ID of the session to use the Telegram API with.
 * @param {Object} res - The response object to be sent back to the client.
 * @returns {Object} - The response object with a JSON body containing the result of the forward operation.
 * @throws Will throw an error if the message is not found or if there is an error during the forward operation.
 */
const forward = async (req, res) => {
  /*
    #swagger.summary = 'Delete a message from the chat'
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
            description: 'Unique WhatsApp identifier for the message',
            example: 'ABCDEF999999999'
          },
          destinationChatId: {
            type: 'string',
            description: 'The chat id to forward the message to',
            example: '6281288888889@c.us'
          }
        }
      }
    }
  */
  try {
    const { messageId, chatId, destinationChatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.forward(destinationChatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Gets information about a message.
 * @async
 * @function getInfo
 * @param {Object} req - The request object received by the server.
 * @param {Object} req.body - The body of the request object.
 * @param {string} req.body.messageId - The ID of the message to get information about.
 * @param {string} req.body.chatId - The ID of the chat that contains the message to get information about.
 * @param {string} req.params.sessionId - The ID of the session to use the Telegram API with.
 * @param {Object} res - The response object to be sent back to the client.
 * @returns {Object} - The response object with a JSON body containing the information about the message.
 * @throws Will throw an error if the message is not found or if there is an error during the get info operation.
 */
const getInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get information about message delivery status'
    #swagger.description = 'May return null if the message does not exist or is not sent by you.'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const info = await message.getInfo()
    res.json({ success: true, info })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves a list of contacts mentioned in a specific message
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object
 * @param {Object} req.body - The request body
 * @param {string} req.body.messageId - The ID of the message to retrieve mentions from
 * @param {string} req.body.chatId - The ID of the chat where the message was sent
 * @param {string} req.params.sessionId - The ID of the session for the client making the request
 * @param {Object} res - The HTTP response object
 * @returns {Promise<void>} - The JSON response with the list of contacts
 * @throws {Error} - If there's an error retrieving the message or mentions
 */
const getMentions = async (req, res) => {
  /*
    #swagger.summary = 'Get the contacts mentioned'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const contacts = await message.getMentions()
    res.json({ success: true, contacts })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the order information contained in a specific message
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object
 * @param {Object} req.body - The request body
 * @param {string} req.body.messageId - The ID of the message to retrieve the order from
 * @param {string} req.body.chatId - The ID of the chat where the message was sent
 * @param {string} req.params.sessionId - The ID of the session for the client making the request
 * @param {Object} res - The HTTP response object
 * @returns {Promise<void>} - The JSON response with the order information
 * @throws {Error} - If there's an error retrieving the message or order information
 */
const getOrder = async (req, res) => {
  /*
    #swagger.summary = 'Get the order details'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const order = await message.getOrder()
    res.json({ success: true, order })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the payment information from a specific message identified by its ID.
 *
 * @async
 * @function getPayment
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID associated with the client making the request.
 * @param {Object} req.body - The message ID and chat ID associated with the message to retrieve payment information from.
 * @param {string} req.body.messageId - The ID of the message to retrieve payment information from.
 * @param {string} req.body.chatId - The ID of the chat the message is associated with.
 * @returns {Object} An object containing a success status and the payment information for the specified message.
 * @throws {Object} If the specified message is not found or if an error occurs during the retrieval process.
 */
const getPayment = async (req, res) => {
  /*
    #swagger.summary = 'Get the payment details'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const payment = await message.getPayment()
    res.json({ success: true, payment })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the quoted message information from a specific message identified by its ID.
 *
 * @async
 * @function getQuotedMessage
 * @param {Object} req - The HTTP request object.
 * @param {Object} res - The HTTP response object.
 * @param {string} req.params.sessionId - The session ID associated with the client making the request.
 * @param {Object} req.body - The message ID and chat ID associated with the message to retrieve quoted message information from.
 * @param {string} req.body.messageId - The ID of the message to retrieve quoted message information from.
 * @param {string} req.body.chatId - The ID of the chat the message is associated with.
 * @returns {Object} An object containing a success status and the quoted message information for the specified message.
 * @throws {Object} If the specified message is not found or if an error occurs during the retrieval process.
 */
const getQuotedMessage = async (req, res) => {
  /*
    #swagger.summary = 'Get the quoted message'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const quotedMessage = await message.getQuotedMessage()
    res.json({ success: true, quotedMessage })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * React to a specific message in a chat
 *
 * @async
 * @function react
 * @param {Object} req - The HTTP request object containing the request parameters and body.
 * @param {Object} res - The HTTP response object to send the result.
 * @param {string} req.params.sessionId - The ID of the session to use.
 * @param {Object} req.body - The body of the request.
 * @param {string} req.body.messageId - The ID of the message to react to.
 * @param {string} req.body.chatId - The ID of the chat the message is in.
 * @param {string} req.body.reaction - The reaction to add to the message.
 * @returns {Object} The HTTP response containing the result of the operation.
 * @throws {Error} If there was an error during the operation.
 */
const react = async (req, res) => {
  /*
    #swagger.summary = 'React with an emoji'
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
            description: 'Unique WhatsApp identifier for the message',
            example: 'ABCDEF999999999'
          },
          reaction: {
            type: 'string',
            description: 'Emoji to react with. Send an empty string to remove the reaction.',
            example: '👍'
          }
        }
      }
    }
  */
  try {
    const { messageId, chatId, reaction = '' } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.react(reaction)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Reply to a specific message in a chat
 *
 * @async
 * @function reply
 * @param {Object} req - The HTTP request object containing the request parameters and body.
 * @param {Object} res - The HTTP response object to send the result.
 * @param {string} req.params.sessionId - The ID of the session to use.
 * @param {string} req.body.messageId - The ID of the message to reply to.
 * @param {string} req.body.chatId - The ID of the chat the message is in.
 * @param {string} req.body.content - The content of the message to send.
 * @param {string} req.body.destinationChatId - The ID of the chat to send the reply to.
 * @param {Object} req.body.options - Additional options for sending the message.
 * @returns {Object} The HTTP response containing the result of the operation.
 * @throws {Error} If there was an error during the operation.
 */
const reply = async (req, res) => {
  /*
    #swagger.summary = 'Send a message as a reply'
    #swagger.requestBody = {
      required: true,
      '@content': {
        "application/json": {
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
                description: 'Unique WhatsApp identifier for the message',
                example: 'ABCDEF999999999'
              },
              contentType: {
                type: 'string',
                description: 'The type of message content, must be one of the following: string, MessageMedia, MessageMediaFromURL, Location, Contact or Poll',
              },
              content: {
                type: 'object',
                description: 'The content of the message, can be a string or an object',
              },
              options: {
                type: 'object',
                description: 'The message send options',
              }
            }
          },
          examples: {
            string: { value: { messageId: '3A80E857F9B44AF60C2C', chatId: '6281288888888@c.us', contentType: 'string', content: 'Reply text!' } }
          }
        }
      }
    }
  */
  try {
    const { messageId, chatId, content, contentType, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    let contentMessage
    switch (contentType) {
      case 'string':
        if (options?.media) {
          const media = options.media
          media.filename = null
          media.filesize = null
          options.media = new MessageMedia(media.mimetype, media.data, media.filename, media.filesize)
        }
        contentMessage = content
        break
      case 'MessageMediaFromURL': {
        contentMessage = await MessageMedia.fromUrl(content, { unsafeMime: true })
        break
      }
      case 'MessageMedia': {
        contentMessage = new MessageMedia(content.mimetype, content.data, content.filename, content.filesize)
        break
      }
      case 'Location': {
        contentMessage = new Location(content.latitude, content.longitude, content.description)
        break
      }
      case 'Contact': {
        const contactId = content.contactId.endsWith('@c.us') ? content.contactId : `${content.contactId}@c.us`
        contentMessage = await client.getContactById(contactId)
        break
      }
      case 'Poll': {
        contentMessage = new Poll(content.pollName, content.pollOptions, content.options)
        // fix for poll events not being triggered (open the chat that you sent the poll)
        await client.interface.openChatWindow(chatId)
        break
      }
      default:
        return sendErrorResponse(res, 400, 'contentType invalid, must be string, MessageMedia, MessageMediaFromURL, Location, Contact or Poll')
    }
    const repliedMessage = await message.reply(contentMessage, chatId, options)
    res.json({ success: true, repliedMessage })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function star
 * @async
 * @description Stars a message by message ID and chat ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.star() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const star = async (req, res) => {
  /*
    #swagger.summary = 'Star the message'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.star()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function unstar
 * @async
 * @description Unstars a message by message ID and chat ID.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.unstar() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const unstar = async (req, res) => {
  /*
    #swagger.summary = 'Unstar the message'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.unstar()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function getReactions
 * @async
 * @description Gets the reactions associated with the given message.
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.getReactions() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const getReactions = async (req, res) => {
  /*
    #swagger.summary = 'Get the reactions associated'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.getReactions()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function getReactions
 * @async
 * @description Gets groups mentioned in this message
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.getReactions() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const getGroupMentions = async (req, res) => {
  /*
    #swagger.summary = 'Get groups mentioned in this message'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const result = await message.getGroupMentions()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function edit
 * @async
 * @description Edits the current message
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.edit() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const edit = async (req, res) => {
  /*
    #swagger.summary = 'Edit the message'
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
            description: 'Unique WhatsApp identifier for the message',
            example: 'ABCDEF999999999'
          },
          content: {
            type: 'string',
            description: 'The content of the message',
          },
          options: {
            type: 'object',
            description: 'Options used when editing the message',
          }
        }
      }
    }
  */
  try {
    const { messageId, chatId, content, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const editedMessage = await message.edit(content, options)
    res.json({ success: true, message: editedMessage })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function getContact
 * @async
 * @description Gets groups mentioned in this message
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.messageId - The message ID.
 * @param {string} req.body.chatId - The chat ID.
 * @returns {Promise} A Promise that resolves with the result of the message.getReactions() call.
 * @throws {Error} If message is not found, it throws an error with the message "Message not found".
 */
const getContact = async (req, res) => {
  /*
    #swagger.summary = 'Get the contact'
  */
  try {
    const { messageId, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const message = await _getMessageById(client, messageId, chatId)
    if (!message) { throw new Error('Message not found') }
    const contact = await message.getContact()
    res.json({ success: true, contact })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getClassInfo,
  deleteMessage,
  downloadMedia,
  downloadMediaAsData,
  forward,
  getInfo,
  getMentions,
  getOrder,
  getPayment,
  getQuotedMessage,
  react,
  reply,
  star,
  unstar,
  getReactions,
  getGroupMentions,
  edit,
  getContact
}
