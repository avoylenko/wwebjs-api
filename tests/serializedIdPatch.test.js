const { patchSerializedIds } = require('../src/utils')

// Builds a stand-in for the WhatsApp Web page context. `widField` and `msgKeyField` name the
// property each class exposes its serialized id under: `_serialized` on healthy builds, and a
// minified alias such as `$1` on the builds that renamed it. The two classes are independent -
// a build can rename one and leave the other alone.
const createFakeWindow = ({ widField = '_serialized', msgKeyField = '_serialized' } = {}) => {
  class Wid {
    constructor (jid) {
      const [user, server] = jid.split('@')
      this.user = user
      this.server = server
      this[widField] = jid
    }
  }

  class MsgKey {
    constructor ({ from, to, id, selfDir }) {
      this.fromMe = selfDir === 'out'
      this.remote = to
      this.id = id
      this.self = selfDir
      this[msgKeyField] = `${this.fromMe}_${to[widField]}_${id}_${selfDir}`
    }
  }

  const modules = {
    WAWebWidFactory: { createWid: (jid) => new Wid(jid) },
    WAWebMsgKey: MsgKey
  }

  return {
    Wid,
    MsgKey,
    require: (name) => {
      if (!modules[name]) { throw new Error(`module ${name} is not available`) }
      return modules[name]
    },
    WWebJS: {
      getMessageModel: (message) => ({ ...message }),
      getChatModel: async (chat) => ({ ...chat }),
      getContactModel: (contact) => ({ ...contact })
    }
  }
}

const createFakeClient = (fakeWindow) => ({
  pupPage: {
    evaluate: async (pageFunction, ...args) => {
      global.window = fakeWindow
      try {
        return await pageFunction(...args)
      } finally {
        delete global.window
      }
    }
  }
})

const newMsgKey = (fakeWindow) => new fakeWindow.MsgKey({
  from: fakeWindow.require('WAWebWidFactory').createWid('1@c.us'),
  to: fakeWindow.require('WAWebWidFactory').createWid('123@c.us'),
  id: 'ABCD',
  selfDir: 'out'
})

describe('patchSerializedIds', () => {
  it('restores _serialized on both classes when the build renamed both', async () => {
    const fakeWindow = createFakeWindow({ widField: '$1', msgKeyField: '$1' })

    const result = await patchSerializedIds(createFakeClient(fakeWindow))

    expect(result.applied).toBe(true)
    expect(result.wid).toEqual({ patched: true, alias: '$1' })
    expect(result.msgKey).toEqual({ patched: true, alias: '$1' })
    expect(fakeWindow.require('WAWebWidFactory').createWid('123@c.us')._serialized).toBe('123@c.us')
    expect(newMsgKey(fakeWindow)._serialized).toBe('true_123@c.us_ABCD_out')
  })

  // The case that reached production: the wid probe found a healthy `_serialized` and the
  // original patch bailed out before it ever looked at MsgKey, which is the class sendMessage
  // needs to find the message it has just sent.
  it('patches MsgKey even when Wid still exposes _serialized', async () => {
    const fakeWindow = createFakeWindow({ widField: '_serialized', msgKeyField: '$1' })

    const result = await patchSerializedIds(createFakeClient(fakeWindow))

    expect(result.applied).toBe(true)
    expect(result.wid).toEqual({ patched: false, reason: 'exposes _serialized' })
    expect(result.msgKey).toEqual({ patched: true, alias: '$1' })
    expect(newMsgKey(fakeWindow)._serialized).toBe('true_123@c.us_ABCD_out')
  })

  // `$1` is minifier output, so the index is not something to rely on across builds.
  it('finds the alias whatever it is named', async () => {
    const fakeWindow = createFakeWindow({ widField: '$7', msgKeyField: '$4' })

    const result = await patchSerializedIds(createFakeClient(fakeWindow))

    expect(result.wid).toEqual({ patched: true, alias: '$7' })
    expect(result.msgKey).toEqual({ patched: true, alias: '$4' })
    expect(newMsgKey(fakeWindow)._serialized).toBe('true_123@c.us_ABCD_out')
  })

  it('leaves a healthy build untouched', async () => {
    const fakeWindow = createFakeWindow()
    const getMessageModel = fakeWindow.WWebJS.getMessageModel

    const result = await patchSerializedIds(createFakeClient(fakeWindow))

    expect(result.applied).toBe(false)
    expect(result.wid).toEqual({ patched: false, reason: 'exposes _serialized' })
    expect(result.msgKey).toEqual({ patched: false, reason: 'exposes _serialized' })
    expect(fakeWindow.WWebJS.getMessageModel).toBe(getMessageModel)
    expect(Object.getOwnPropertyDescriptor(fakeWindow.Wid.prototype, '_serialized')).toBeUndefined()
    expect(Object.getOwnPropertyDescriptor(fakeWindow.MsgKey.prototype, '_serialized')).toBeUndefined()
  })

  describe('once an alias was found', () => {
    let fakeWindow

    beforeEach(async () => {
      fakeWindow = createFakeWindow({ widField: '$1', msgKeyField: '$1' })
      await patchSerializedIds(createFakeClient(fakeWindow))
    })

    it('keeps _serialized writable', () => {
      const wid = fakeWindow.require('WAWebWidFactory').createWid('123@c.us')
      wid._serialized = '456@c.us'
      expect(wid._serialized).toBe('456@c.us')
    })

    it('restores _serialized on the plain ids returned by the model getters', async () => {
      const model = fakeWindow.WWebJS.getMessageModel({
        id: { fromMe: true, remote: '123@c.us', id: 'ABCD', $1: 'true_123@c.us_ABCD_out' },
        body: 'hello'
      })
      expect(model.id._serialized).toBe('true_123@c.us_ABCD_out')

      const chat = await fakeWindow.WWebJS.getChatModel({ id: { user: '123', server: 'c.us', $1: '123@c.us' } })
      expect(chat.id._serialized).toBe('123@c.us')
    })

    it('applies again after the page reloaded and dropped the patch', async () => {
      // `ready` fires again on every reload, and the page comes back without the prototype
      // getter. In production the patch went stale about a day into each session and
      // `Msg.get(key._serialized)` started missing for every message the library had just sent.
      const reloaded = createFakeWindow({ widField: '$1', msgKeyField: '$1' })
      const result = await patchSerializedIds(createFakeClient(reloaded))

      expect(result.applied).toBe(true)
      const wid = reloaded.require('WAWebWidFactory').createWid('123@c.us')
      const key = new (reloaded.require('WAWebMsgKey'))({ from: wid, to: wid, id: 'ABCD', selfDir: 'out' })
      // this is the read whatsapp-web.js does on the message it has just sent
      expect(key._serialized).toBe('true_123@c.us_ABCD_out')
    })

    it('does not apply twice', async () => {
      const wrapped = fakeWindow.WWebJS.getMessageModel
      const result = await patchSerializedIds(createFakeClient(fakeWindow))
      expect(result.applied).toBe(false)
      expect(result.reason).toBe('already applied')
      expect(fakeWindow.WWebJS.getMessageModel).toBe(wrapped)
    })
  })
})
