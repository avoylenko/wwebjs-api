const { sessions } = require('../sessions')
const { sendErrorResponse } = require('../utils')

/**
 * Retrieves information about a WhatsApp contact by ID.
 *
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The ID of the current session.
 * @param {string} req.body.contactId - The ID of the contact to retrieve information for.
 * @throws {Error} If there is an error retrieving the contact information.
 * @returns {Object} The contact information object.
 */
const getClassInfo = async (req, res) => {
  /*
    #swagger.summary = 'Get the contact'
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    res.json({ success: true, contact })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Blocks a WhatsApp contact by ID.
 *
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The ID of the current session.
 * @param {string} req.body.contactId - The ID of the contact to block.
 * @throws {Error} If there is an error blocking the contact.
 * @returns {Object} The result of the blocking operation.
 */
const block = async (req, res) => {
  /*
    #swagger.summary = 'Block contact'
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.block()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Retrieves the 'About' information of a WhatsApp contact by ID.
 *
 * @async
 * @function
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The ID of the current session.
 * @param {string} req.body.contactId - The ID of the contact to retrieve 'About' information for.
 * @throws {Error} If there is an error retrieving the contact information.
 * @returns {Object} The 'About' information of the contact.
 */
const getAbout = async (req, res) => {
  /*
    #swagger.summary = "Get the contact's current info"
    #swagger.description = "Get the Contact's current 'about' info. Returns null if you don't have permission to read their status."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getAbout()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Retrieves the chat information of a contact with a given contactId.
 *
 * @async
 * @function getChat
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose chat information is being retrieved.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error retrieving the chat information.
 * @returns {Promise<void>} A promise that resolves with the chat information of the contact.
 */
const getChat = async (req, res) => {
  /*
    #swagger.summary = 'Get the chat'
    #swagger.description = 'Get the chat that corresponds to the contact. Will return null when getting chat for currently logged in user.'
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getChat()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Retrieves the formatted number of a contact with a given contactId.
 *
 * @async
 * @function getFormattedNumber
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose chat information is being retrieved.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error retrieving the chat information.
 * @returns {Promise<void>} A promise that resolves with the formatted number of the contact.
 */
const getFormattedNumber = async (req, res) => {
  /*
    #swagger.summary = 'Get the formatted phone number'
    #swagger.description = "Returns the contact's formatted phone number, (12345678901@c.us) => (+1 (234) 5678-901)."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getFormattedNumber()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Retrieves the country code of a contact with a given contactId.
 *
 * @async
 * @function getCountryCode
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose chat information is being retrieved.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error retrieving the chat information.
 * @returns {Promise<void>} A promise that resolves with the country code of the contact.
 */
const getCountryCode = async (req, res) => {
  /*
    #swagger.summary = 'Get the country code'
    #swagger.description = "Returns the contact's country code, (1541859685@c.us) => (1)."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getCountryCode()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Retrieves the profile picture url of a contact with a given contactId.
 *
 * @async
 * @function getProfilePicUrl
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose chat information is being retrieved.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error retrieving the chat information.
 * @returns {Promise<void>} A promise that resolves with the profile picture url of the contact.
 */
const getProfilePicUrl = async (req, res) => {
  /*
    #swagger.summary = 'Get the profile picture URL'
    #swagger.description = "Get the contact's profile picture URL, if privacy settings allow it."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getProfilePicUrl() || null
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Unblocks the contact with a given contactId.
 *
 * @async
 * @function unblock
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose contact is being unblocked.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error unblocking the contact.
 * @returns {Promise<void>} A promise that resolves with the result of unblocking the contact.
 */
const unblock = async (req, res) => {
  /*
    #swagger.summary = 'Unblock the contact'
    #swagger.description = "Unblock the contact from WhatsApp."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.unblock()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

/**
 * Gets the contact's common groups with you.
 *
 * @async
 * @function unblock
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @param {string} req.params.sessionId - The session ID.
 * @param {string} req.body.contactId - The ID of the client whose contact is being unblocked.
 * @throws {Error} If the contact with the given contactId is not found or if there is an error unblocking the contact.
 * @returns {Promise<void>} A promise that resolves with the result of unblocking the contact.
 */
const getCommonGroups = async (req, res) => {
  /*
    #swagger.summary = "Get the contact's common groups"
    #swagger.description = "Get the contact's common groups with you. Returns empty array if you don't have any common group."
  */
  try {
    const { contactId } = req.body
    const client = sessions.get(req.params.sessionId)
    const contact = await client.getContactById(contactId)
    if (!contact) {
      throw new Error('Contact not found')
    }
    const result = await contact.getCommonGroups()
    res.json({ success: true, result })
  } catch (error) {
    sendErrorResponse(res, 500, error)
  }
}

module.exports = {
  getClassInfo,
  block,
  getAbout,
  getChat,
  unblock,
  getFormattedNumber,
  getCountryCode,
  getProfilePicUrl,
  getCommonGroups
}
