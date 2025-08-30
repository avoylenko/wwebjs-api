const { MessageMedia, Location, Poll } = require('whatsapp-web.js')
const { sessions } = require('../sessions')
const { sendErrorResponse } = require('../utils')

/**
 * Send a message to a chat using the WhatsApp API
 *
 * @async
 * @function sendMessage
 * @param {Object} req - The request object containing the request parameters
 * @param {Object} req.body - The request body containing the chatId, content, contentType and options
 * @param {string} req.body.chatId - The chat id where the message will be sent
 * @param {string|Object} req.body.content - The message content to be sent, can be a string or an object containing the MessageMedia data
 * @param {string} req.body.contentType - The type of the message content, must be one of the following: 'string', 'MessageMedia', 'MessageMediaFromURL', 'Location', 'Buttons', or 'List'
 * @param {Object} req.body.options - Additional options to be passed to the WhatsApp API
 * @param {string} req.params.sessionId - The id of the WhatsApp session to be used
 * @param {Object} res - The response object
 * @returns {Object} - The response object containing a success flag and the sent message data
 * @throws {Error} - If there is an error while sending the message
 */
const sendMessage = async (req, res) => {
  /*
    #swagger.summary = 'Send a message to a specific chatId'
    #swagger.requestBody = {
      required: true,
      '@content': {
        "application/json": {
          schema: {
            type: 'object',
            properties: {
              chatId: {
                type: 'string',
                description: 'The chat id which contains the message (Group or Individual)',
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
            string: { value: { chatId: '6281288888888@c.us', contentType: 'string', content: 'Hello World!' } },
            MessageMedia: { value: { chatId: '6281288888888@c.us', contentType: 'MessageMedia', content: { mimetype: 'image/jpeg', data: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=', filename: 'image.jpg' } } },
            MessageMediaFromURL: { value: { chatId: '6281288888888@c.us', contentType: 'MessageMediaFromURL', content: 'https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=Example' } },
            Location: { value: { chatId: '6281288888888@c.us', contentType: 'Location', content: { latitude: -6.2, longitude: 106.8, description: 'Jakarta' } } },
            Contact: {
              value: { chatId: '6281288888888@c.us', contentType: 'Contact', content: { contactId: '6281288888889@c.us' } }
            },
            Poll: {
              value: { chatId: '6281288888888@c.us', contentType: 'Poll', content: { pollName: 'Cats or Dogs?', pollOptions: ['Cats', 'Dogs'], options: { allowMultipleAnswers: true } } }
            },
          }
        }
      }
    }
  */

  try {
    const { chatId, content, contentType, options = {}, mediaFromURLOptions = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const sendOptions = { waitUntilMsgSent: true, ...options }

    let messageOut
    switch (contentType) {
      case 'string':
        if (sendOptions?.media) {
          const { mimetype, data, filename = null, filesize = null } = sendOptions.media
          if (!mimetype || !data) {
            return sendErrorResponse(res, 400, 'invalid media options')
          }
          sendOptions.media = new MessageMedia(mimetype, data, filename, filesize)
        }
        messageOut = await client.sendMessage(chatId, content, sendOptions)
        break
      case 'MessageMediaFromURL': {
        const messageMediaFromURL = await MessageMedia.fromUrl(content, { unsafeMime: true, ...mediaFromURLOptions })
        messageOut = await client.sendMessage(chatId, messageMediaFromURL, sendOptions)
        break
      }
      case 'MessageMedia': {
        const messageMedia = new MessageMedia(content.mimetype, content.data, content.filename, content.filesize)
        messageOut = await client.sendMessage(chatId, messageMedia, sendOptions)
        break
      }
      case 'Location': {
        const location = new Location(content.latitude, content.longitude, content.description)
        messageOut = await client.sendMessage(chatId, location, sendOptions)
        break
      }
      case 'Contact': {
        const contactId = content.contactId.endsWith('@c.us') ? content.contactId : `${content.contactId}@c.us`
        const contact = await client.getContactById(contactId)
        messageOut = await client.sendMessage(chatId, contact, sendOptions)
        break
      }
      case 'Poll': {
        const poll = new Poll(content.pollName, content.pollOptions, content.options)
        messageOut = await client.sendMessage(chatId, poll, sendOptions)
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
 * Get session information for a given sessionId
 *
 * @function getClientInfo
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {string} req.params.sessionId - The sessionId for which the session info is requested
 * @returns {Object} - Response object with session info
 * @throws Will throw an error if session info cannot be retrieved
 */
const getClassInfo = (req, res) => {
  /*
    #swagger.summary = 'Get current connection information'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const sessionInfo = client.info
    res.json({ success: true, sessionInfo })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Check if a user is registered on WhatsApp
 *
 * @async
 * @function isRegisteredUser
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {string} req.params.sessionId - The sessionId in which the user is registered
 * @param {string} req.body.id - The id of the user to check
 * @returns {Object} - Response object with a boolean indicating whether the user is registered
 * @throws Will throw an error if user registration cannot be checked
 */
const isRegisteredUser = async (req, res) => {
  /*
    #swagger.summary = 'Check if a given ID is registered in WhatsApp'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          number: {
            type: 'string',
            description: 'The number or ID (\"@c.us\" will be automatically appended if not specified)',
            example: '6281288888888'
          },
        }
      },
    }
  */
  try {
    const { number } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.isRegisteredUser(number)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the registered WhatsApp ID for a number
 *
 * @async
 * @function getNumberId
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {string} req.params.sessionId - The sessionId in which the user is registered
 * @param {string} req.body.id - The id of the user to check
 * @returns {Object} - Response object with a boolean indicating whether the user is registered
 * @throws Will throw an error if user registration cannot be checked
 */
const getNumberId = async (req, res) => {
  /*
    #swagger.summary = 'Get the registered WhatsApp ID for a number'
    #swagger.description = 'Return null if the number is not registered on WhatsApp'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          number: {
            type: 'string',
            description: 'The number or ID (\"@c.us\" will be automatically appended if not specified)',
            example: '6281288888888'
          },
        }
      },
    }
  */
  try {
    const { number } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getNumberId(number)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Create a group with the given name and participants
 *
 * @async
 * @function createGroup
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {string} req.params.sessionId - The sessionId in which to create the group
 * @param {string} req.body.name - The name of the group to create
 * @param {Array} req.body.participants - Array of user ids to add to the group
 * @returns {Object} - Response object with information about the created group
 * @throws Will throw an error if group cannot be created
 */
const createGroup = async (req, res) => {
  /*
    #swagger.summary = 'Create a new group'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          title: {
            type: 'string',
            description: 'Group title',
            example: 'Group name'
          },
          participants: {
            type: 'array',
            description: 'A single contact ID as a string or an array of contact IDs to add to the group',
            example: []
          },
          options: {
            type: 'object',
            description: 'An object that handles options for group creation',
            example: {}
          },
        }
      },
    }
  */
  try {
    const { title, participants, options = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    let response
    if (Object.keys(options).length) {
      response = await client.createGroup(title, participants, options)
    } else {
      response = await client.createGroup(title, participants)
    }
    res.json({ success: true, response })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set the status of the user in a given session
 *
 * @async
 * @function setStatus
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {string} req.params.sessionId - The sessionId in which to set the status
 * @param {string} req.body.status - The status to set
 * @returns {Object} - Response object indicating success
 * @throws Will throw an error if status cannot be set
 */
const setStatus = async (req, res) => {
  /*
    #swagger.summary = "Set the current user's status message"
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          status: {
            type: 'string',
            description: 'New status message',
            example: 'I\'m running WWebJS Api'
          },
        }
      },
    }
  */
  try {
    const { status } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setStatus(status)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the contacts of the current session.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID associated with the client.
 * @param {Object} res - The response object.
 * @returns {Promise<void>} - A Promise that resolves with the retrieved contacts or rejects with an error.
 */
const getContacts = async (req, res) => {
  /*
    #swagger.summary = 'Get all current contacts'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const contacts = await client.getContacts()
    res.json({ success: true, contacts })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieve all chats for the given session ID.
 *
 * @function
 * @async
 *
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {Object} res - The response object.
 *
 * @returns {Promise<void>} A Promise that resolves when the operation is complete.
 *
 * @throws {Error} If the operation fails, an error is thrown.
 */
const getChats = async (req, res) => {
  /*
    #swagger.summary = 'Get all current chats'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const chats = await client.getChats()
    res.json({ success: true, chats })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Returns the profile picture URL for a given contact ID.
 *
 * @async
 * @function
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {string} req.params.sessionId - The ID of the current session.
 * @param {string} req.body.contactId - The ID of the contact to get the profile picture for.
 * @returns {Promise<void>} - A Promise that resolves with the profile picture URL.
 * @throws {Error} - If there is an error retrieving the profile picture URL.
 */
const getProfilePictureUrl = async (req, res) => {
  /*
    #swagger.summary = "Return the contact ID's profile picture URL"
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          contactId: {
            type: 'string',
            description: 'The contact ID\'s of profile',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getProfilePicUrl(contactId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Accepts an invite.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object.
 * @param {Object} req.body - The request body.
 * @param {Object} req.params - The request parameters.
 * @param {string} req.params.sessionId - The ID of the session.
 * @param {Object} res - The HTTP response object.
 * @returns {Object} The response object.
 * @throws {Error} If there is an error while accepting the invite.
 */
const acceptInvite = async (req, res) => {
  /*
    #swagger.summary = 'Accept an invitation to join a group'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          inviteCode: {
            type: 'string',
            description: 'Invitation code',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { inviteCode } = req.body
    const client = sessions.get(req.params.sessionId)
    const acceptInvite = await client.acceptInvite(inviteCode)
    res.json({ success: true, acceptInvite })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the version of WhatsApp Web currently being run.
 *
 * @async
 * @function getWWebVersion
 * @param {Object} req - The HTTP request object.
 * @param {Object} req.params - The request parameters.
 * @param {string} req.params.sessionId - The ID of the session.
 * @param {Object} res - The HTTP response object.
 * @returns {Object} The response object.
 * @throws {Error} If there is an error while accepting the invite.
 */
const getWWebVersion = async (req, res) => {
  /*
    #swagger.summary = 'Return the version of WhatsApp Web currently being run'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const result = await client.getWWebVersion()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Archives a chat.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object.
 * @param {Object} req.body - The request body.
 * @param {Object} req.params - The request parameters.
 * @param {string} req.params.sessionId - The ID of the session.
 * @param {Object} res - The HTTP response object.
 * @returns {Object} The response object.
 * @throws {Error} If there is an error while archiving the chat.
 */
const archiveChat = async (req, res) => {
  /*
    #swagger.summary = 'Archive the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.archiveChat(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the list of blocked contacts for the user's client.
 *
 * @async
 * @function getBlockedContacts
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID to use for the client.
 * @param {Object} res - The response object.
 * @returns {Promise<Object>} - A promise that resolves to an object with a success property and an array of blocked contacts.
 * @throws {Error} - Throws an error if the operation fails.
 */
const getBlockedContacts = async (req, res) => {
  /*
    #swagger.summary = 'Get all blocked contacts by host account'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const blockedContacts = await client.getBlockedContacts()
    res.json({ success: true, blockedContacts })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the chat with the given ID.
 *
 * @async
 * @function getChatById
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID to use for the client.
 * @param {string} req.body.chatId - The ID of the chat to get.
 * @param {Object} res - The response object.
 * @returns {Promise<Object>} - A promise that resolves to an object with a success property and the chat object.
 * @throws {Error} - Throws an error if the operation fails.
 */
const getChatById = async (req, res) => {
  /*
    #swagger.summary = 'Get the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat) {
      throw new Error('Chat not found')
    }
    res.json({ success: true, chat })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the labels for the chat with the given ID.
 *
 * @async
 * @function getChatLabels
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID to use for the client.
 * @param {string} req.body.chatId - The ID of the chat to get labels for.
 * @param {Object} res - The response object.
 * @returns {Promise<Object>} - A promise that resolves to an object with a success property and an array of labels for the chat.
 * @throws {Error} - Throws an error if the operation fails.
 */
const getChatLabels = async (req, res) => {
  /*
    #swagger.summary = 'Get all labels assigned to the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chatLabels = await client.getChatLabels(chatId)
    res.json({ success: true, chatLabels })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the chats with the given label ID.
 *
 * @async
 * @function getChatsByLabelId
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID to use for the client.
 * @param {string} req.body.labelId - The ID of the label to get chats for.
 * @param {Object} res - The response object.
 * @returns {Promise<Object>} - A promise that resolves to an object with a success property and an array of chats with the given label.
 * @throws {Error} - Throws an error if the operation fails.
 */
const getChatsByLabelId = async (req, res) => {
  /*
    #swagger.summary = 'Get all chats for a specific label'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          labelId: {
            type: 'string',
            description: 'ID of the label',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { labelId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chats = await client.getChatsByLabelId(labelId)
    res.json({ success: true, chats })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the common groups between the client's session and the specified contact.
 * @async
 * @function getCommonGroups
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID of the client.
 * @param {string} req.body.contactId - The ID of the contact to retrieve the common groups with.
 * @param {Object} res - The response object.
 * @returns {Object} - An object containing a success flag and the retrieved groups.
 * @throws {Error} - If an error occurs while retrieving the common groups.
 */
const getCommonGroups = async (req, res) => {
  /*
    #swagger.summary = "Get the contact's common groups"
    #swagger.description = "Get the contact's common groups with you. Returns empty array if you don't have any common group."
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          contactId: {
            type: 'string',
            description: 'The whatsapp user\'s ID (_serialized format)',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const groups = await client.getCommonGroups(contactId)
    res.json({ success: true, groups })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the contact with the specified ID.
 * @async
 * @function getContactById
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID of the client.
 * @param {string} req.body.contactId - The ID of the contact to retrieve.
 * @param {Object} res - The response object.
 * @returns {Object} - An object containing a success flag and the retrieved contact.
 * @throws {Error} - If an error occurs while retrieving the contact.
 */
const getContactById = async (req, res) => {
  /*
    #swagger.summary = 'Get the contact'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          contactId: {
            type: 'string',
            description: 'The whatsapp user\'s ID',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    res.json({ success: true, contact })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the invite information for the specified invite code.
 * @async
 * @function getInviteInfo
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The session ID of the client.
 * @param {string} req.body.inviteCode - The invite code to retrieve information for.
 * @param {Object} res - The response object.
 * @returns {Object} - An object containing a success flag and the retrieved invite information.
 * @throws {Error} - If an error occurs while retrieving the invite information.
 */
const getInviteInfo = async (req, res) => {
  /*
    #swagger.summary = 'Return invite information'
    #swagger.description = 'Return an object with information about the invite code's group'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          inviteCode: {
            type: 'string',
            description: 'Invitation code',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { inviteCode } = req.body
    const client = sessions.get(req.params.sessionId)
    const inviteInfo = await client.getInviteInfo(inviteCode)
    res.json({ success: true, inviteInfo })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the label with the given ID for a particular session.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The ID of the session to retrieve the label for.
 * @param {Object} req.body - The request body object.
 * @param {string} req.body.labelId - The ID of the label to retrieve.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 * @throws {Error} If there is an error retrieving the label.
 */
const getLabelById = async (req, res) => {
  /*
    #swagger.summary = 'Get the label'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          labelId: {
            type: 'string',
            description: 'ID of the label',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { labelId } = req.body
    const client = sessions.get(req.params.sessionId)
    const label = await client.getLabelById(labelId)
    res.json({ success: true, label })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves all labels for a particular session.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The ID of the session to retrieve the labels for.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 * @throws {Error} If there is an error retrieving the labels.
 */
const getLabels = async (req, res) => {
  /*
    #swagger.summary = 'Get all current labels'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const labels = await client.getLabels()
    res.json({ success: true, labels })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Adds or removes labels to/from chats.
 * @async
 * @function
 * @param {Object} req - the request object
 * @param {Object} res - the response object
 * @return {Promise} a Promise that resolves to the JSON response with success status and labels
 * @throws {Error} if an error occurs
 */
const addOrRemoveLabels = async (req, res) => {
  /*
  #swagger.summary = 'Change labels in chats'
  #swagger.requestBody = {
    required: true,
    schema: {
      type: 'object',
      properties: {
        labelIds: {
          type: 'array',
          description: 'Array of label IDs',
          example: []
        },
        chatIds: {
          type: 'array',
          description: 'Array of chat IDs',
          example: []
        },
      }
    },
  }
  */
  try {
    const { labelIds, chatIds } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.addOrRemoveLabels(labelIds, chatIds)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieves the state for a particular session.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {string} req.params.sessionId - The ID of the session to retrieve the state for.
 * @param {Object} res - The response object.
 * @returns {Promise<void>}
 * @throws {Error} If there is an error retrieving the state.
 */
const getState = async (req, res) => {
  /*
    #swagger.summary = 'Get the current connection state for the client'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const state = await client.getState()
    res.json({ success: true, state })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Marks a chat as unread.
 *
 * @async
 * @function markChatUnread
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.chatId - The ID of the chat to mark as unread.
 * @returns {Promise<void>} - A Promise that resolves when the chat is marked as unread.
 * @throws {Error} - If an error occurs while marking the chat as unread.
 */
const markChatUnread = async (req, res) => {
  /*
    #swagger.summary = 'Mark the chat as unread'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.markChatUnread(chatId)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Mutes a chat.
 *
 * @async
 * @function muteChat
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.chatId - The ID of the chat to mute.
 * @param {Date} [req.body.unmuteDate] - The date and time when the chat should be unmuted. If not provided, the chat will be muted indefinitely.
 * @returns {Promise<void>} - A Promise that resolves when the chat is muted.
 * @throws {Error} - If an error occurs while muting the chat.
 */
const muteChat = async (req, res) => {
  /*
    #swagger.summary = 'Mute the chat'
    #swagger.description = 'Mute this chat forever, unless a date is specified'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: ''
          },
          unmuteDate: {
            type: 'string',
            description: 'Timestamp when the chat will be muted, leave as is to mute forever',
            example: '1733489397'
          },
        }
      },
    }
  */
  try {
    const { chatId, unmuteDate } = req.body
    const client = sessions.get(req.params.sessionId)
    if (unmuteDate) {
      await client.muteChat(chatId, new Date(unmuteDate * 1000))
    } else {
      await client.muteChat(chatId, null)
    }
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Pins a chat.
 *
 * @async
 * @function pinChat
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.chatId - The ID of the chat to pin.
 * @returns {Promise<void>} - A Promise that resolves when the chat is pinned.
 * @throws {Error} - If an error occurs while pinning the chat.
 */
const pinChat = async (req, res) => {
  /*
    #swagger.summary = 'Pin the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.pinChat(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}
/**
 * Search messages with the given query and options.
 * @async
 * @function searchMessages
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {Object} req.body - The request body.
 * @param {string} req.body.query - The search query.
 * @param {Object} [req.body.options] - The search options (optional).
 * @returns {Promise<void>} - A Promise that resolves with the search results.
 * @throws {Error} - If there's an error during the search.
 */
const searchMessages = async (req, res) => {
  /*
    #swagger.summary = 'Search for messages'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Search string',
            example: ''
          },
          options: {
            type: 'object',
            description: 'Search options',
            example: { limit: 10, page: 1 }
          },
        }
      },
    }
  */
  try {
    const { query, options } = req.body
    const client = sessions.get(req.params.sessionId)
    let messages
    if (options) {
      messages = await client.searchMessages(query, options)
    } else {
      messages = await client.searchMessages(query)
    }
    res.json({ success: true, messages })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send presence available to the XMPP server.
 * @async
 * @function sendPresenceAvailable
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @returns {Promise<void>} - A Promise that resolves with the presence status.
 * @throws {Error} - If there's an error during the presence sending.
 */
const sendPresenceAvailable = async (req, res) => {
  /*
    #swagger.summary = 'Mark the client as online'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    await client.sendPresenceAvailable()
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send presence unavailable to the XMPP server.
 * @async
 * @function sendPresenceUnavailable
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @returns {Promise<void>} - A Promise that resolves with the presence status.
 * @throws {Error} - If there's an error during the presence sending.
 */
const sendPresenceUnavailable = async (req, res) => {
  /*
    #swagger.summary = 'Mark the client as unavailable'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    await client.sendPresenceUnavailable()
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Send a 'seen' message status for a given chat ID.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.body.chatId - The ID of the chat to set the seen status for.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue sending the seen status message, an error will be thrown.
 */
const sendSeen = async (req, res) => {
  /*
    #swagger.summary = 'Mark the chat as seen'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.sendSeen(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set the display name for the user's WhatsApp account.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.body.displayName - The new display name to set for the user's WhatsApp account.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the display name, an error will be thrown.
 */
const setDisplayName = async (req, res) => {
  /*
    #swagger.summary = 'Set the current user's display name'
    #swagger.description = 'This is the name shown to WhatsApp users that have not added you as a contact beside your number in groups and in your profile.'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          displayName: {
            type: 'string',
            description: 'New display name',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { displayName } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.setDisplayName(displayName)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Unarchive a chat for the user's WhatsApp account.
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.body.chatId - The ID of the chat to unarchive.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue unarchiving the chat, an error will be thrown.
 */
const unarchiveChat = async (req, res) => {
  /*
    #swagger.summary = 'Changes archive state of the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.unarchiveChat(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Unmutes the chat identified by chatId using the client associated with the given sessionId.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const unmuteChat = async (req, res) => {
  /*
    #swagger.summary = 'Unmute the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.unmuteChat(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Unpins the chat identified by chatId using the client associated with the given sessionId.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unpin.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const unpinChat = async (req, res) => {
  /*
    #swagger.summary = 'Unpin the chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.unpinChat(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Update the profile Picture of the session user
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.media - The new profile picture to set for the user's WhatsApp account.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the profile picture, an error will be thrown.
 */

const setProfilePicture = async (req, res) => {
  /*
    #swagger.summary = 'Set the current user\'s profile picture'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: "object",
        properties: {
          pictureMimetype: {
            type: "string",
            description: "The mimetype of the picture to set as the profile picture for the user WhatsApp account.",
            example: "image/png"
          },
          pictureData: {
            type: "string",
            description: "The base64 data of the picture to set as the profile picture for the user WhatsApp account.",
            example: "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklEQVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII="
          }
        }
      }
    }
  */

  try {
    const { pictureMimetype, pictureData } = req.body
    const client = sessions.get(req.params.sessionId)
    const media = new MessageMedia(pictureMimetype, pictureData)
    const result = await client.setProfilePicture(media)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Delete the profile Picture of the session user
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue deleting the profile picture, an error will be thrown.
 */

const deleteProfilePicture = async (req, res) => {
  /*
    #swagger.summary = "Delete the current user's profile picture"
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const result = await client.deleteProfilePicture()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set auto load download audio value
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue deleting the profile picture, an error will be thrown.
 */

const setAutoDownloadAudio = async (req, res) => {
  /*
    #swagger.summary = 'Set auto load download audio flag'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          flag: {
            type: 'boolean',
            description: 'Flag true/false',
            example: true
          },
        }
      },
    }
  */
  try {
    const { flag } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setAutoDownloadAudio(flag)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set auto load download documents value
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue deleting the profile picture, an error will be thrown.
 */

const setAutoDownloadDocuments = async (req, res) => {
  /*
    #swagger.summary = 'Set auto load download documents flag'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          flag: {
            type: 'boolean',
            description: 'Flag true/false',
            example: true
          },
        }
      },
    }
  */
  try {
    const { flag } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setAutoDownloadDocuments(flag)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set auto load download photos value
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue deleting the profile picture, an error will be thrown.
 */

const setAutoDownloadPhotos = async (req, res) => {
  /*
    #swagger.summary = 'Set auto load download photos flag'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          flag: {
            type: 'boolean',
            description: 'Flag true/false',
            example: true
          },
        }
      },
    }
  */
  try {
    const { flag } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setAutoDownloadPhotos(flag)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set auto load download videos value
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue deleting the profile picture, an error will be thrown.
 */

const setAutoDownloadVideos = async (req, res) => {
  /*
    #swagger.summary = 'Set auto load download videos flag'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          flag: {
            type: 'boolean',
            description: 'Flag true/false',
            example: true
          },
        }
      },
    }
  */
  try {
    const { flag } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setAutoDownloadVideos(flag)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sync chat history conversation.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const syncHistory = async (req, res) => {
  /*
    #swagger.summary = 'Sync chat history'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.syncHistory(chatId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get user device count by ID.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getContactDeviceCount = async (req, res) => {
  /*
    #swagger.summary = 'Get user device count'
    #swagger.description = 'Each WaWeb Connection counts as one device, and the phone (if exists) counts as one device. So for a non-enterprise user with one WaWeb connection it should return "2"'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          userId: {
            type: 'string',
            description: 'ID of the user',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { userId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getContactDeviceCount(userId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the country code of a WhatsApp ID.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getCountryCode = async (req, res) => {
  /*
    #swagger.summary = 'Get the country code'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          number: {
            type: 'string',
            description: 'Number or ID',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { number } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getCountryCode(number)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get the formatted number of a WhatsApp ID.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getFormattedNumber = async (req, res) => {
  /*
    #swagger.summary = 'Get the formatted number'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          number: {
            type: 'string',
            description: 'Number or ID',
            example: ''
          },
        }
      },
    }
  */
  try {
    const { number } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getFormattedNumber(number)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Open the chat window.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const openChatWindow = async (req, res) => {
  /*
    #swagger.summary = 'Open the chat window'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'ID of the chat',
            example: '6281288888888@c.us'
          },
        }
      },
    }
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.interface.openChatWindow(chatId)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Open or scroll the chat window to the position of the message.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const openChatWindowAt = async (req, res) => {
  /*
    #swagger.summary = 'Open the chat window to the position of the message'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          messageId: {
            type: 'string',
            description: 'ID of the message to scroll to (serialized)',
            example: 'false_31235678901@c.us_3A40CB10BC3680B1EE'
          },
        }
      },
    }
  */
  try {
    const { messageId } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.interface.openChatWindowAt(messageId)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Force reset of connection state for the client.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const resetState = async (req, res) => {
  /*
    #swagger.summary = 'Force reset of connection state for the client'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    await client.resetState()
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Change the background synchronization setting.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const setBackgroundSync = async (req, res) => {
  /*
    #swagger.summary = 'Change the background synchronization setting'
    #swagger.description = 'NOTE: This action will take effect after you restart the client'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          flag: {
            type: 'boolean',
            description: 'flag true/false',
            example: true
          },
        }
      },
    }
  */
  try {
    const { flag = true } = req.body
    const client = sessions.get(req.params.sessionId)
    await client.setBackgroundSync(flag)
    res.json({ success: true })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Retrieve the contact lid and phone number for a specific chat.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.chatId - The unique identifier of the chat to unmute.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getContactLidAndPhone = async (req, res) => {
  /*
    #swagger.summary = 'Get contact lid and phone'
    #swagger.description = 'Retrieve the contact lid and phone number for a specific chat'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          userIds: {
            type: 'array',
            items: {
              type: 'string',
              description: 'The unique identifier of the user',
            },
            example: ['6281288888888@c.us']
          },
        }
      },
    }
  */
  try {
    const { userIds = [] } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getContactLidAndPhone(userIds)
    res.json({ success: true, data: result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Gets all cached Channel instances.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getChannels = async (req, res) => {
  /*
    #swagger.summary = 'Get channels from the client'
    #swagger.description = 'Retrieve a list of channels from the client'
  */
  try {
    const client = sessions.get(req.params.sessionId)
    const result = await client.getChannels()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Creates a new channel.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const createChannel = async (req, res) => {
  /*
    #swagger.summary = 'Create a new channel',
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          title: {
            type: 'string',
            description: 'The title of the channel',
            example: 'My New Channel'
          },
          options: {
            type: 'object',
            properties: {
              description: {
                type: 'string',
                description: 'The description of the channel',
                example: 'This is my new channel'
              },
            }
          }
        }
      },
    }
  */
  try {
    const { title, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = options ? await client.createChannel(title, options) : await client.createChannel(title)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Subscribes to a new channel.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const subscribeToChannel = async (req, res) => {
  /*
    #swagger.summary = 'Subscribe to a channel',
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          channelId: {
            type: 'string',
            description: 'The ID of the channel',
            example: 'XXXXXXXXXX@newsletter'
          },
        }
      },
    }
  */
  try {
    const { channelId } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.subscribeToChannel(channelId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Unsubscribe from a channel.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const unsubscribeFromChannel = async (req, res) => {
  /*
    #swagger.summary = 'Unsubscribe from channel',
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          channelId: {
            type: 'string',
            description: 'The ID of the channel',
            example: 'XXXXXXXXXX@newsletter'
          },
          options: {
            type: 'object',
            properties: {
              deleteLocalModels: {
                type: 'boolean',
                example: true
              },
            }
          }
        }
      },
    }
  */
  try {
    const { channelId, options } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = options ? await client.unsubscribeFromChannel(channelId, options) : await client.unsubscribeFromChannel(channelId)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Search channels.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const searchChannels = async (req, res) => {
  /*
    #swagger.summary = 'Search channels',
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          searchOptions: {
            properties: {
              searchText: {
                type: 'string',
                description: 'The text to search for in channel names',
                example: ''
              },
              countryCodes: {
                type: 'array',
                description: 'An array of country codes in ISO 3166-1 alpha-2 standard to search',
                example: ['US', 'CA']
              },
              skipSubscribedNewsletters: {
                type: 'boolean',
                description: 'If true, channels that user is subscribed to won\'t appear in found channels',
                example: true
              },
              view: {
                type: 'number',
                description: 'The category of channels to get',
                example: 0
              },
              limit: {
                type: 'number',
                description: 'The maximum number of channels to return',
                example: 10
              }
            }
          }
        }
      },
    }
  */
  try {
    const { searchOptions = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const foundChannels = await client.searchChannels(searchOptions)
    res.json({ success: true, result: foundChannels })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Gets a Channel instance by invite code.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.body.inviteCode - The unique identifier of the channel to retrieve.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const getChannelByInviteCode = async (req, res) => {
  /*
    #swagger.summary = 'Get channel by invite code'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          inviteCode: {
            type: 'string',
            description: 'The code that comes after the \"https://whatsapp.com/channel/\"',
          },
        }
      },
    }
  */
  try {
    const { inviteCode } = req.body
    const client = sessions.get(req.params.sessionId)
    const result = await client.getChannelByInviteCode(inviteCode)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Executes a method on the client associated with the given sessionId.
 *
 * @async
 * @function
 * @param {Object} req - The HTTP request object containing the chatId and sessionId.
 * @param {string} req.params.sessionId - The unique identifier of the session associated with the client to use.
 * @param {Object} res - The HTTP response object.
 * @returns {Promise<Object>} - A Promise that resolves with a JSON object containing a success flag and the result of the operation.
 * @throws {Error} - If an error occurs during the operation, it is thrown and handled by the catch block.
 */
const runMethod = async (req, res) => {
  /*
    #swagger.summary = 'Execute a method on the client'
    #swagger.description = 'Execute a method on the client and return the result'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
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
    const { method, options } = req.body
    const client = sessions.get(req.params.sessionId)
    if (typeof client[method] !== 'function') {
      throw new Error('Method is not implemented')
    }
    const result = options ? await client[method](options) : await client[method]()
    res.json({ success: true, data: result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getClassInfo,
  acceptInvite,
  archiveChat,
  createGroup,
  getBlockedContacts,
  getChatById,
  getChatLabels,
  getChats,
  getChatsByLabelId,
  getCommonGroups,
  getContactById,
  getContacts,
  getInviteInfo,
  getLabelById,
  getLabels,
  addOrRemoveLabels,
  isRegisteredUser,
  getNumberId,
  getProfilePictureUrl,
  getState,
  markChatUnread,
  muteChat,
  pinChat,
  searchMessages,
  sendMessage,
  sendPresenceAvailable,
  sendPresenceUnavailable,
  sendSeen,
  setDisplayName,
  setProfilePicture,
  setStatus,
  unarchiveChat,
  unmuteChat,
  unpinChat,
  getWWebVersion,
  deleteProfilePicture,
  setAutoDownloadAudio,
  setAutoDownloadDocuments,
  setAutoDownloadPhotos,
  setAutoDownloadVideos,
  syncHistory,
  getContactDeviceCount,
  getCountryCode,
  getFormattedNumber,
  openChatWindow,
  openChatWindowAt,
  resetState,
  setBackgroundSync,
  getContactLidAndPhone,
  getChannels,
  getChannelByInviteCode,
  createChannel,
  subscribeToChannel,
  unsubscribeFromChannel,
  searchChannels,
  runMethod
}
