jest.mock('../src/sessions', () => ({ sessions: new Map() }))

const { sessions } = require('../src/sessions')
const { sendMessage } = require('../src/controllers/clientController')
const { sendMessage: sendChannelMessage } = require('../src/controllers/channelController')

const createResponse = () => {
  const res = {
    statusCode: 200,
    body: null,
    status (code) {
      this.statusCode = code
      return this
    },
    json (body) {
      this.body = body
      return this
    }
  }
  return res
}

const createRequest = (client) => {
  sessions.set('test', client)
  return {
    params: { sessionId: 'test' },
    body: { chatId: '123@c.us', contentType: 'string', content: 'Hello World!' }
  }
}

const sentMessage = { id: { id: 'ABCD', _serialized: 'true_123@c.us_ABCD' }, body: 'Hello World!' }

afterEach(() => sessions.clear())

// Clients keep the returned id to correlate the message later on, so a 200 that carries no
// message leaves them dereferencing undefined. Anything the library refuses to send has to
// come back as an error instead.
describe('POST /client/sendMessage', () => {
  it('returns the sent message', async () => {
    const req = createRequest({ sendMessage: async () => sentMessage })
    const res = createResponse()

    await sendMessage(req, res)

    expect(res.statusCode).toBe(200)
    expect(res.body).toEqual({ success: true, message: sentMessage })
  })

  it('says the message is missing instead of pretending it is there', async () => {
    const req = createRequest({ sendMessage: async () => undefined })
    const res = createResponse()

    await sendMessage(req, res)

    // not a 500: the library looks the message up only after handing it to the chat, so a retry
    // would send the contact a second copy of something they already have
    expect(res.statusCode).toBe(200)
    expect(res.body.message).toBeNull()
    expect(res.body.warning).toMatch(/did not return the sent message/)
  })
})

describe('POST /channel/sendMessage', () => {
  const createChannelRequest = (chat) => {
    sessions.set('test', { getChatById: async () => chat })
    return {
      params: { sessionId: 'test' },
      body: { chatId: '123@newsletter', contentType: 'string', content: 'Hello World!' }
    }
  }

  it('returns the sent message', async () => {
    const req = createChannelRequest({ isChannel: true, sendMessage: async () => sentMessage })
    const res = createResponse()

    await sendChannelMessage(req, res)

    expect(res.statusCode).toBe(200)
    expect(res.body).toEqual({ success: true, message: sentMessage })
  })

  it('says the message is missing instead of pretending it is there', async () => {
    const req = createChannelRequest({ isChannel: true, sendMessage: async () => null })
    const res = createResponse()

    await sendChannelMessage(req, res)

    expect(res.statusCode).toBe(200)
    expect(res.body.message).toBeNull()
    expect(res.body.warning).toMatch(/did not return the sent message/)
  })
})
