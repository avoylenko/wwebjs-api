const { MessageMedia } = require('whatsapp-web.js')
const { sessions } = require('../sessions')
const { sendErrorResponse } = require('../utils')

/**
 * @function
 * @async
 * @name getClassInfo
 * @description Gets information about a channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to get information for
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const getClassInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get the channel'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    res.json({ success: true, channel: chat })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send a message to a chat using the WhatsApp API
 *
 * @async
 * @function sendMessage
 * @param {Object} req - The request object containing the request parameters
 * @param {Object} req.body - The request body containing the chatId, content, contentType and options
 * @param {string} req.body.chatId - The chat id where the message will be sent
 * @param {string|Object} req.body.content - The message content to be sent, can be a string or an object containing the MessageMedia data
 * @param {string} req.body.contentType - The type of the message content, must be one of the following: 'string', 'MessageMedia', 'MessageMediaFromURL'
 * @param {Object} req.body.options - Additional options to be passed to the WhatsApp API
 * @param {string} req.params.sessionId - The id of the WhatsApp session to be used
 * @param {Object} res - The response object
 * @returns {Object} - The response object containing a success flag and the sent message data
 * @throws {Error} - If there is an error while sending the message
 */
const sendMessage = async (req, res) => {
  /*
    #swagger.summary = 'Sends a message to this channel'
    #swagger.requestBody = {
      required: true,
      '@content': {
        "application/json": {
          schema: {
            type: 'object',
            properties: {
              chatId: {
                type: 'string',
                description: 'The channel id',
                example: 'XXXXXXXXXX@newsletter'
              },
              contentType: {
                type: 'string',
                description: 'The type of message content, must be one of the following: string, MessageMedia, MessageMediaFromURL',
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
            string: { value: { chatId: 'XXXXXXXXXX@newsletter', contentType: 'string', content: 'Hello World!' } },
            MessageMedia: { value: { chatId: 'XXXXXXXXXX@newsletter', contentType: 'MessageMedia', content: { mimetype: 'image/jpeg', data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=' } } },
            MessageMediaFromURL: { value: { chatId: 'XXXXXXXXXX@newsletter', contentType: 'MessageMediaFromURL', content: 'https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=Example' } },
          }
        }
      }
    }
  */

  try {
    const { chatId, content, contentType, options, mediaFromURLOptions = {} } = req.body
    const sendOptions = { waitUntilMsgSent: true, ...options }
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    let messageOut
    switch (contentType) {
      case 'string':
        messageOut = await chat.sendMessage(content, sendOptions)
        break
      case 'MessageMediaFromURL': {
        const messageMediaFromURL = await MessageMedia.fromUrl(content, { unsafeMime: true, ...mediaFromURLOptions })
        messageOut = await chat.sendMessage(messageMediaFromURL, sendOptions)
        break
      }
      case 'MessageMedia': {
        const messageMedia = new MessageMedia(content.mimetype, content.data, content.filename, content.filesize)
        messageOut = await chat.sendMessage(messageMedia, sendOptions)
        break
      }
      default:
        return sendErrorResponse(res, 400, 'invalid contentType')
    }
    res.json({ success: true, message: messageOut })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Fetches messages from a specified channel.
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
    #swagger.summary = 'Load channel messages'
    #swagger.description = 'Messages sorted from earliest to latest'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp identifier for the given Chat (either group or personal)',
            example: 'XXXXXXXXXX@newsletter'
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
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const messages = Object.keys(searchOptions).length ? await chat.fetchMessages(searchOptions) : await chat.fetchMessages()
    res.json({ success: true, messages })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name sendSeen
 * @description Sends a seen status to the channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to send seen status
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const sendSeen = async (req, res) => {
  /*
    #swagger.summary = 'Send seen status to the channel'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.sendSeen()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name mute
 * @description Mutes a channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const mute = async (req, res) => {
  /*
    #swagger.summary = 'Mute the channel'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.mute()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name unmute
 * @description Unmute a channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const unmute = async (req, res) => {
  /*
    #swagger.summary = 'Unmute the channel'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.unmute()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name setSubject
 * @description Sets the subject of a channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const setSubject = async (req, res) => {
  /*
    #swagger.summary = 'Set the subject of the channel'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          newSubject: {
            type: 'string',
            description: 'The new subject for the channel',
            example: 'New Channel Subject'
          },
        }
      }
    }
  */
  try {
    const { chatId, newSubject = '' } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.setSubject(newSubject)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name acceptChannelAdminInvite
 * @description Accepts a channel admin invitation and promotes the current user to a channel admin
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const acceptChannelAdminInvite = async (req, res) => {
  /*
    #swagger.summary = 'Accept channel admin invite'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.acceptChannelAdminInvite()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name sendChannelAdminInvite
 * @description Sends a channel admin invite using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const sendChannelAdminInvite = async (req, res) => {
  /*
    #swagger.summary = 'Sends a channel admin invitation to a user'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          userId: {
            type: 'string',
            description: 'The ID of the user to demote',
            example: 'XXXXXXXXXX@c.us'
          },
          options: {
            type: 'object',
            description: 'Options for sending a channel admin invitation to a user',
            example: { comment: 'Hello' }
          },
        }
      }
    }
  */
  try {
    const { chatId, userId, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = options ? await chat.sendChannelAdminInvite(userId, options) : await chat.sendChannelAdminInvite(userId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name demoteChannelAdmin
 * @description Demotes a channel admin using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const demoteChannelAdmin = async (req, res) => {
  /*
    #swagger.summary = 'Demotes a channel admin to a regular subscriber'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          userId: {
            type: 'string',
            description: 'The ID of the user to demote',
            example: 'XXXXXXXXXX@c.us'
          },
        }
      }
    }
  */
  try {
    const { chatId, userId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.demoteChannelAdmin(userId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name transferChannelOwnership
 * @description Transfers channel ownership to another user using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const transferChannelOwnership = async (req, res) => {
  /*
    #swagger.summary = 'Transfers a channel ownership to another user',
    #swagger.description = 'Note: the user you are transferring the channel ownership to must be a channel admin',
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          newOwnerId: {
            type: 'string',
            description: 'The ID of the user to transfer ownership to',
            example: 'XXXXXXXXXX@c.us'
          },
          options: {
            type: 'object',
            description: 'Options for transferring a channel ownership to another user',
            example: { shouldDismissSelfAsAdmin: false }
          },
        }
      }
    }
  */
  try {
    const { chatId, newOwnerId, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = options ? await chat.transferChannelOwnership(newOwnerId, options) : await chat.transferChannelOwnership(newOwnerId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name revokeChannelAdminInvite
 * @description Revokes a channel admin invite using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const revokeChannelAdminInvite = async (req, res) => {
  /*
    #swagger.summary = 'Revokes a channel admin invitation sent to a user by a channel owner'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          userId: {
            type: 'string',
            description: 'The ID of the user to demote',
            example: 'XXXXXXXXXX@c.us'
          },
        }
      }
    }
  */
  try {
    const { chatId, userId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.revokeChannelAdminInvite(userId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name getSubscribers
 * @description Retrieves the list of subscribers for a channel using the chatId and sessionId
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel to mute
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const getSubscribers = async (req, res) => {
  /*
    #swagger.summary = 'Gets the subscribers of the channel (only those who are in your contact list)'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
          limit: {
            type: 'number',
            description: 'The maximum number of subscribers to return',
            example: 100
          },
        }
      }
    }
  */
  try {
    const { chatId, limit = null } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.getSubscribers(limit)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name deleteChannel
 * @description Deletes the channel you created
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const deleteChannel = async (req, res) => {
  /*
    #swagger.summary = 'Delete a channel you created'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given channel group',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      }
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.deleteChannel()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name setReactionSetting
 * @description Updates the channel description
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const setReactionSetting = async (req, res) => {
  /*
    #swagger.summary = 'Updates available reactions to use in the channel'
    #swagger.description = 'Valid values for passing to the method are: 0 for NONE reactions to be available 1 for BASIC reactions to be available: 👍, ❤️, 😂, 😮, 😢, 🙏 2 for ALL reactions to be available'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
            chatId: {
              type: 'string',
              description: 'Unique WhatsApp id for the given channel group',
              example: 'XXXXXXXXXX@newsletter'
            },
            reactionCode: {
              type: 'number',
              description: 'New reaction setting for the channel',
              example: 1
            }
        }
      }
    }
  */
  try {
    const { chatId, reactionCode = 0 } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.setReactionSetting(reactionCode)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name setDescription
 * @description Updates the channel description
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const setDescription = async (req, res) => {
  /*
    #swagger.summary = 'Update a channel description'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
            chatId: {
              type: 'string',
              description: 'Unique WhatsApp id for the given channel group',
              example: 'XXXXXXXXXX@newsletter'
            },
            newDescription: {
              type: 'string',
              description: 'New description for the channel',
              example: 'This is the updated channel description'
            }
        }
      }
    }
  */
  try {
    const { chatId, newDescription = '' } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    const result = await chat.setDescription(newDescription)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * @function
 * @async
 * @name setProfilePicture
 * @description Updates the channel profile picture
 * @param {Object} req - Request object
 * @param {Object} res - Response object
 * @param {string} req.body.chatId - The ID of the channel
 * @param {string} req.params.sessionId - The ID of the session to use
 * @returns {Object} - Returns a JSON object with the success status and channel information
 * @throws {Error} - Throws an error if channel is not found or if there is a server error
 */
const setProfilePicture = async (req, res) => {
  /*
    #swagger.summary = 'Update a channel profile picture'
    #swagger.requestBody = {
      required: true,
      '@content': {
        "application/json": {
          schema: {
            type: 'object',
            properties: {
              chatId: {
                type: 'string',
                description: 'Unique WhatsApp id for the given channel group',
                example: 'XXXXXXXXXX@newsletter'
              },
              newProfilePictureUrl: {
                type: 'string',
                description: 'New profile picture URL for the channel',
              },
              newProfilePictureMedia: {
                type: 'object',
                description: 'New profile picture media for the channel',
              }
            }
          },
          examples: {
            string: { value: { chatId: 'XXXXXXXXXX@newsletter', newProfilePictureUrl: 'string' } }
          },
        }
      }
    }
  */
  try {
    const { chatId, newProfilePictureUrl, newProfilePictureMedia } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      sendErrorResponse(res, 404, 'Channel not Found')
      return
    }
    if (!chat.isChannel) {
      sendErrorResponse(res, 400, 'The chat is not a channel')
      return
    }
    let messageMedia =
      newProfilePictureUrl &&
      (await MessageMedia.fromUrl(newProfilePictureUrl, { unsafeMime: true }))
    if (newProfilePictureMedia?.data) {
      messageMedia = new MessageMedia(
        newProfilePictureMedia.mimetype,
        newProfilePictureMedia.data,
        null,
        null
      )
    }
    const result = await chat.setProfilePicture(messageMedia)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getClassInfo,
  sendMessage,
  fetchMessages,
  sendSeen,
  mute,
  unmute,
  acceptChannelAdminInvite,
  sendChannelAdminInvite,
  revokeChannelAdminInvite,
  transferChannelOwnership,
  demoteChannelAdmin,
  getSubscribers,
  setProfilePicture,
  setDescription,
  setSubject,
  setReactionSetting,
  deleteChannel
}
