const { MessageMedia } = require('whatsapp-web.js')
const { sessions } = require('../sessions')
const { sendErrorResponse } = require('../utils')

/**
 * Retrieves information about a chat based on the provided chatId
 *
 * @async
 * @function getClassInfo
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {string} req.body.chatId - The chatId of the chat to retrieve information about
 * @param {string} req.params.sessionId - The sessionId of the client making the request
 * @throws {Error} The chat is not a group.
 * @returns {Promise<void>} - A JSON response with success true and chat object containing chat information
 */
const getClassInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get the group'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    res.json({ success: true, chat })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Adds participants to a group chat.
 * @async
 * @function
 * @param {Object} req - The request object containing the chatId and participantIds in the body.
 * @param {string} req.body.chatId - The ID of the group chat.
 * @param {Array<string>} req.body.participantIds - An array of participant IDs to be added to the group.
 * @param {Object} res - The response object.
 * @returns {Object} Returns a JSON object containing a success flag and the updated participants list.
 * @throws {Error} Throws an error if the chat is not a group chat.
*/
const addParticipants = async (req, res) => {
  /*
    #swagger.summary = 'Add the participants'
    #swagger.description = 'Add a list of participants by ID to the group'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          participantIds: {
            type: 'array',
            description: 'Unique WhatsApp identifiers for the participants',
            example: ['6281288888887@c.us']
          },
          options: {
            type: 'object',
            description: 'Options for adding participants',
            example: { sleep: [250, 500], comment: '' }
          }
        }
      }
    }
  */
  try {
    const { chatId, contactIds, participantIds, options = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    // support old property name
    const addParticipants = participantIds || contactIds
    const participantIdsArray = Array.isArray(addParticipants) ? addParticipants : [addParticipants]
    const result = Object.keys(options).length ? await chat.addParticipants(participantIdsArray, options) : await chat.addParticipants(participantIdsArray)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Removes participants from a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and updated participants list
 * @throws {Error} If chat is not a group
 */
const removeParticipants = async (req, res) => {
  /*
    #swagger.summary = 'Remove the participants'
    #swagger.description = 'Remove a list of participants by ID to the group'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          participantIds: {
            type: 'array',
            description: 'Unique WhatsApp identifiers for the participants',
            example: ['6281288888887@c.us']
          }
        }
      }
    }
  */
  try {
    const { chatId, contactIds, participantIds } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    // support old property name
    const addParticipants = participantIds || contactIds
    const participantIdsArray = Array.isArray(addParticipants) ? addParticipants : [addParticipants]
    const result = await chat.removeParticipants(participantIdsArray)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Promotes participants in a group chat to admin
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and updated participants list
 * @throws {Error} If chat is not a group
 */
const promoteParticipants = async (req, res) => {
  /*
    #swagger.summary = 'Promote the participants'
    #swagger.description = 'Promote participants by ID to admins'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          participantIds: {
            type: 'array',
            description: 'Unique WhatsApp identifiers for the participants',
            example: ['6281288888887@c.us']
          }
        }
      }
    }
  */
  try {
    const { chatId, contactIds, participantIds } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    // support old property name
    const addParticipants = participantIds || contactIds
    const participantIdsArray = Array.isArray(addParticipants) ? addParticipants : [addParticipants]
    const result = await chat.promoteParticipants(participantIdsArray)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Demotes admin participants in a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and updated participants list
 * @throws {Error} If chat is not a group
 */
const demoteParticipants = async (req, res) => {
  /*
    #swagger.summary = 'Demote the participants'
    #swagger.description = 'Demote participants by ID to regular users'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          participantIds: {
            type: 'array',
            description: 'Unique WhatsApp identifiers for the participants',
            example: ['6281288888887@c.us']
          }
        }
      }
    }
  */
  try {
    const { chatId, contactIds, participantIds } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    // support old property name
    const addParticipants = participantIds || contactIds
    const participantIdsArray = Array.isArray(addParticipants) ? addParticipants : [addParticipants]
    const result = await chat.demoteParticipants(participantIdsArray)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Gets the invite code for a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and invite code
 * @throws {Error} If chat is not a group
 */
const getInviteCode = async (req, res) => {
  /*
    #swagger.summary = 'Get the invite code'
    #swagger.description = 'Get the invite code for a specific group'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const inviteCode = await chat.getInviteCode()
    res.json({ success: true, inviteCode })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sets the subject of a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and updated chat object
 * @throws {Error} If chat is not a group
 */
const setSubject = async (req, res) => {
  /*
    #swagger.summary = 'Update the group subject'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          subject: {
            type: 'string',
            description: 'Group subject',
            example: ''
          }
        }
      }
    }
  */
  try {
    const { chatId, subject } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.setSubject(subject)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sets the description of a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and updated chat object
 * @throws {Error} If chat is not a group
 */
const setDescription = async (req, res) => {
  /*
    #swagger.summary = 'Update the group description'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          description: {
            type: 'string',
            description: 'Group description',
            example: ''
          }
        }
      }
    }
  */
  try {
    const { chatId, description } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.setDescription(description)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Leaves a group chat
 *
 * @async
 * @function
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<Object>} Returns a JSON object with success flag and outcome of leaving the chat
 * @throws {Error} If chat is not a group
 */
const leave = async (req, res) => {
  /*
    #swagger.summary = 'Leave the group'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.leave()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Revokes the invite link for a group chat based on the provided chatId
 *
 * @async
 * @function revokeInvite
 * @param {object} req - The request object
 * @param {object} res - The response object
 * @param {string} req.body.chatId - The chatId of the group chat to revoke the invite for
 * @param {string} req.params.sessionId - The sessionId of the client making the request
 * @throws {Error} The chat is not a group.
 * @returns {Promise<void>} - A JSON response with success true and the new invite code for the group chat
 */
const revokeInvite = async (req, res) => {
  /*
    #swagger.summary = 'Invalidate the invite code'
    #swagger.description = 'Invalidate the current group invite code and generates a new one'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.revokeInvite()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sets admins-only status of a group chat's info or messages.
 *
 * @async
 * @function setInfoAdminsOnly
 * @param {Object} req - Request object.
 * @param {Object} res - Response object.
 * @param {string} req.params.sessionId - ID of the user's session.
 * @param {Object} req.body - Request body.
 * @param {string} req.body.chatId - ID of the group chat.
 * @param {boolean} req.body.adminsOnly - Desired admins-only status.
 * @returns {Promise<void>} Promise representing the success or failure of the operation.
 * @throws {Error} If the chat is not a group.
 */
const setInfoAdminsOnly = async (req, res) => {
  /*
    #swagger.summary = 'Update the info group settings'
    #swagger.summary = 'Update the group settings to only allow admins to edit group info (title, description, photo).'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          adminsOnly: {
            type: 'boolean',
            description: 'Enable or disable this option',
            example: true
          }
        }
      }
    }
  */
  try {
    const { chatId, adminsOnly = true } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.setInfoAdminsOnly(adminsOnly)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Sets admins-only status of a group chat's messages.
 *
 * @async
 * @function setMessagesAdminsOnly
 * @param {Object} req - Request object.
 * @param {Object} res - Response object.
 * @param {string} req.params.sessionId - ID of the user's session.
 * @param {Object} req.body - Request body.
 * @param {string} req.body.chatId - ID of the group chat.
 * @param {boolean} req.body.adminsOnly - Desired admins-only status.
 * @returns {Promise<void>} Promise representing the success or failure of the operation.
 * @throws {Error} If the chat is not a group.
 */
const setMessagesAdminsOnly = async (req, res) => {
  /*
    #swagger.summary = 'Update the message group settings'
    #swagger.summary = 'Update the group settings to only allow admins to send messages.'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          adminsOnly: {
            type: 'boolean',
            description: 'Enable or disable this option',
            example: true
          }
        }
      }
    }
  */
  try {
    const { chatId, adminsOnly = true } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.setMessagesAdminsOnly(adminsOnly)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Set the group Picture
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.pictureMimetype - The mimetype of the image.
 * @param {Object} req.body.pictureData - The new group picture in base64 format.
 * @param {Object} req.body.chatId - ID of the group chat.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the group picture, an error will be thrown.
 */
const setPicture = async (req, res) => {
  /*
    #swagger.summary = 'Set the group picture'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          pictureMimeType: {
            type: 'string',
            description: 'MIME type of the attachment'
          },
          pictureData: {
            type: 'string',
            description: 'Base64-encoded data of the file'
          }
        }
      }
    }
  */
  try {
    const { pictureMimeType, pictureData, chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const media = new MessageMedia(pictureMimeType, pictureData)
    const result = await chat.setPicture(media)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Delete the group Picture
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.chatId - ID of the group chat.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the group picture, an error will be thrown.
 */
const deletePicture = async (req, res) => {
  /*
    #swagger.summary = 'Delete the group picture'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.deletePicture()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Get an array of membership requests
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.chatId - ID of the group chat.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the group picture, an error will be thrown.
 */
const getGroupMembershipRequests = async (req, res) => {
  /*
    #swagger.summary = 'Get the membership requests'
  */
  try {
    const { chatId } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.getGroupMembershipRequests()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Approve membership requests if any
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.chatId - ID of the group chat.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the group picture, an error will be thrown.
 */
const approveGroupMembershipRequests = async (req, res) => {
  /*
    #swagger.summary = 'Approve membership request'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          options: {
            type: 'object',
            description: 'Options for performing a membership request action',
            example: { requesterIds: [], sleep: [250, 500] }
          }
        }
      }
    }
  */
  try {
    const { chatId, options = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.approveGroupMembershipRequests(options)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

/**
 * Reject membership requests if any
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {Object} req.body.chatId - ID of the group chat.
 * @param {string} req.params.sessionId - The ID of the session for the user.
 * @returns {Object} Returns a JSON object with a success status and the result of the function.
 * @throws {Error} If there is an issue setting the group picture, an error will be thrown.
 */
const rejectGroupMembershipRequests = async (req, res) => {
  /*
    #swagger.summary = 'Reject membership request'
    #swagger.requestBody = {
      required: true,
      schema: {
        type: 'object',
        properties: {
          chatId: {
            type: 'string',
            description: 'Unique WhatsApp id for the given chat group',
            example: 'XXXXXXXXXX@g.us'
          },
          options: {
            type: 'object',
            description: 'Options for performing a membership request action',
            example: { requesterIds: [], sleep: [250, 500] }
          }
        }
      }
    }
  */
  try {
    const { chatId, options = {} } = req.body
    const client = sessions.get(req.params.sessionId)
    const chat = await client.getChatById(chatId)
    if (!chat.isGroup) { throw new Error('The chat is not a group') }
    const result = await chat.rejectGroupMembershipRequests(options)
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error.message)
  }
}

module.exports = {
  getClassInfo,
  addParticipants,
  demoteParticipants,
  getInviteCode,
  leave,
  promoteParticipants,
  removeParticipants,
  revokeInvite,
  setDescription,
  setInfoAdminsOnly,
  setMessagesAdminsOnly,
  setSubject,
  setPicture,
  deletePicture,
  getGroupMembershipRequests,
  approveGroupMembershipRequests,
  rejectGroupMembershipRequests
}
