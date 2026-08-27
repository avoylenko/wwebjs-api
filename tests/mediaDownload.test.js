const { Message } = require('whatsapp-web.js/src/structures')
const { patchMediaDownload } = require('../src/utils')

// The failure this patch exists for: WhatsApp Web 2.3000.x keeps the Msg collection under a key
// the serialized id no longer matches, so `Msg.get()` misses and whatsapp-web.js falls through to
// `Msg.getMessagesById()`, whose IndexedDB lookup throws a minified DataError. `indexedKeys` names
// the keys this fake page will actually resolve - everything else behaves like the broken build.
const createFakeWindow = ({ indexedKeys = [], models = [], mediaStage = 'RESOLVED', stageAfterDownload = 'RESOLVED', resolveDelayMs = 0, cached = null } = {}) => {
  const calls = { get: [], getMessagesById: 0, downloadManager: 0, asked: 0 }

  const blob = { arrayBuffer: async () => new ArrayBuffer(8) }

  const message = {
    id: { fromMe: false, remote: '120363402133099473@g.us', id: 'ACAF63', participant: '167474247016533@lid' },
    mediaData: { mediaStage },
    // the page hangs the fetched media off `mediaObject`, not off the message - only it holds the
    // key material a media retry refreshed
    mediaObject: { filehash: 'plain', mediaBlob: null },
    type: 'image',
    mimetype: 'image/jpeg',
    filename: undefined,
    size: 96945,
    // The real call returns before the page has finished fetching, so neither the stage nor the
    // blob is there yet - that gap is what this patch exists to survive.
    downloadMedia: async () => {
      calls.asked++
      const settle = () => {
        message.mediaData.mediaStage = stageAfterDownload
        if (stageAfterDownload === 'RESOLVED') { message.mediaObject.mediaBlob = { forceToBlob: () => blob } }
      }
      if (resolveDelayMs === 0) { settle(); return }
      setTimeout(settle, resolveDelayMs)
    }
  }

  const modules = {
    WAWebCollections: {
      Msg: {
        get: (key) => {
          calls.get.push(key)
          if (indexedKeys.includes(key)) { return message }
          // what the real build does for a key it cannot use
          const error = new Error("Failed to execute 'get' on 'IDBObjectStore': No key or key range specified.")
          error.name = 'DataError'
          throw error
        },
        getMessagesById: async () => {
          calls.getMessagesById++
          throw new Error('the IndexedDB fallback must never be reached')
        }
      }
    },
    WAWebMediaInMemoryBlobCache: {
      InMemoryMediaBlobCache: { get: (filehash) => (filehash === 'plain' ? cached : null) }
    },
    WAWebDownloadManager: {
      get downloadManager () {
        calls.downloadManager++
        throw new Error('re-decrypting the media must never be reached')
      }
    }
  }

  return {
    calls,
    blob,
    message,
    require: (name) => {
      if (!modules[name]) { throw new Error(`module ${name} is not available`) }
      return modules[name]
    },
    WWebJS: {
      arrayBufferToBase64Async: async () => 'BASE64DATA',
      // the collection `_getMessageById` already reads to hand the message to the caller
      getChat: async () => ({
        msgs: { getModelsArray: () => models.map((m) => (m === 'match' ? message : { id: { id: 'other' } })) }
      })
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

const download = (fakeWindow, overrides = {}, resolveTimeoutMs = 10000) => {
  const client = createFakeClient(fakeWindow)
  patchMediaDownload(resolveTimeoutMs)
  return Message.prototype.downloadMedia.call({
    hasMedia: true,
    client,
    id: { ...fakeWindow.message.id, _serialized: 'false_120363402133099473@g.us_ACAF63_167474247016533@lid' },
    ...overrides
  })
}

const indexed = ['false_120363402133099473@g.us_ACAF63_167474247016533@lid']

describe('patchMediaDownload', () => {
  it('downloads through the serialized id when the collection still indexes it', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed })

    const media = await download(fakeWindow)

    expect(media).toMatchObject({ mimetype: 'image/jpeg', data: 'BASE64DATA', filesize: 96945 })
    expect(fakeWindow.calls.getMessagesById).toBe(0)
  })

  it('falls back to the three part key the older builds used', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: ['false_120363402133099473@g.us_ACAF63'] })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.calls.get).toEqual([
      'false_120363402133099473@g.us_ACAF63_167474247016533@lid',
      'false_120363402133099473@g.us_ACAF63'
    ])
  })

  it('scans the chat collection when no key resolves, instead of hitting IndexedDB', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: [], models: ['other', 'match'] })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    // reaching this is what produced the opaque `t: t` in production
    expect(fakeWindow.calls.getMessagesById).toBe(0)
  })

  it('reports why the media is missing rather than a minified class name', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: [], models: ['other'] })

    await expect(download(fakeWindow)).rejects.toThrow('message is not in the page collection')
  })

  it('takes the blob the page decrypted instead of decrypting a second time', async () => {
    // production: re-decrypting off the message's own stale key material answered
    // `InvalidMediaFileType: Unexpected mimetype application/octet-stream for media type image`
    const fakeWindow = createFakeWindow({ indexedKeys: indexed })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.calls.downloadManager).toBe(0)
  })

  it('prefers WhatsApp own media cache when it holds the file', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, cached: { arrayBuffer: async () => new ArrayBuffer(8) } })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    // the cache already had it, so the page was never asked to fetch
    expect(fakeWindow.calls.asked).toBe(0)
  })

  it('ignores a cache entry that is not readable as a blob', async () => {
    // the same cache keys upload FormData under the filehash
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, cached: { append: () => {} } })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.calls.asked).toBe(1)
  })

  it('fetches again when the stage says RESOLVED but the cache was evicted', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'RESOLVED' })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.calls.asked).toBe(1)
  })

  it('surfaces the real error when the blob cannot be read', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed })
    fakeWindow.blob.arrayBuffer = async () => { throw new Error('detached ArrayBuffer') }

    await expect(download(fakeWindow)).rejects.toThrow('reading the decrypted media failed')
  })

  it('waits for the page to finish fetching before it reads the blob', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'INIT', resolveDelayMs: 300 })

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.message.mediaData.mediaStage).toBe('RESOLVED')
  })

  it('keeps asking the page to fetch, because one dropped request never recovers', async () => {
    // production: several media arriving at once left every one of them stuck at INIT for the
    // whole wait, so the single up-front request had gone nowhere
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'INIT', stageAfterDownload: 'INIT' })
    fakeWindow.message.downloadMedia = async () => {
      fakeWindow.calls.asked++
      if (fakeWindow.calls.asked >= 3) {
        fakeWindow.message.mediaData.mediaStage = 'RESOLVED'
        fakeWindow.message.mediaObject.mediaBlob = { forceToBlob: () => fakeWindow.blob }
      }
    }

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    expect(fakeWindow.calls.asked).toBe(3)
  })

  it('gives up on the stage it got stuck at rather than answering without media', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'INIT', stageAfterDownload: 'INIT' })

    await expect(download(fakeWindow, {}, 300)).rejects.toThrow('media did not resolve in time')
  })

  it('stops waiting once the page reports it cannot fetch the media', async () => {
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'INIT', stageAfterDownload: 'ERROR_FILE_GONE' })

    await expect(download(fakeWindow)).rejects.toThrow('the page could not fetch the media')
    expect(fakeWindow.calls.asked).toBe(1)
  })

  it('waits out a re-upload instead of failing on it', async () => {
    // the media expired and the sender is uploading it again - the page is already on it
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'REUPLOADING' })
    setTimeout(() => { fakeWindow.message.mediaObject.mediaBlob = { forceToBlob: () => fakeWindow.blob } }, 300)

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
    // asking again while the page is re-uploading would only pile on
    expect(fakeWindow.calls.asked).toBe(0)
  })

  it('survives the page dropping mediaData while it works', async () => {
    // production 2026-08-25: `Cannot read properties of undefined (reading 'mediaStage')`
    const fakeWindow = createFakeWindow({ indexedKeys: indexed, mediaStage: 'INIT' })
    fakeWindow.message.downloadMedia = async () => {
      fakeWindow.calls.asked++
      delete fakeWindow.message.mediaData
      if (fakeWindow.calls.asked >= 2) {
        fakeWindow.message.mediaData = { mediaStage: 'RESOLVED' }
        fakeWindow.message.mediaObject.mediaBlob = { forceToBlob: () => fakeWindow.blob }
      }
    }

    await expect(download(fakeWindow)).resolves.toMatchObject({ data: 'BASE64DATA' })
  })

  it('leaves a message without media alone', async () => {
    const fakeWindow = createFakeWindow()

    await expect(download(fakeWindow, { hasMedia: false })).resolves.toBeUndefined()
    expect(fakeWindow.calls.get).toEqual([])
  })
})
