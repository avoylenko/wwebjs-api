(function () {
  const API_BASE = window.location.pathname.slice(0, window.location.pathname.lastIndexOf('/dashboard'))
  const STORAGE_KEY = 'wwebjsApiKey'
  // must match sessionNameValidation in src/middleware.js
  const SESSION_ID_PATTERN = /^[\w-]+$/
  const POLL_INTERVAL_MS = 5000
  const QR_POLL_INTERVAL_MS = 3000

  const $ = (id) => document.getElementById(id)

  let pollTimer = null
  let qrTimer = null
  let qrSessionId = null
  let qrObjectUrl = null
  let authFailed = false

  async function apiFetch (path, options = {}) {
    const headers = Object.assign({}, options.headers)
    const apiKey = window.localStorage.getItem(STORAGE_KEY)
    if (apiKey) {
      headers['x-api-key'] = apiKey
    }
    const response = await window.fetch(API_BASE + path, Object.assign({}, options, { headers, cache: 'no-store' }))
    if (response.status === 403) {
      authFailed = true
      $('apiKeyBanner').classList.remove('hidden')
      throw new Error('Invalid or missing API key')
    }
    return response
  }

  async function apiJson (path, options) {
    const response = await apiFetch(path, options)
    return response.json()
  }

  function showToast (message, isError) {
    const toast = document.createElement('div')
    toast.className = 'toast' + (isError ? ' toast-error' : '')
    toast.textContent = message
    $('toasts').appendChild(toast)
    setTimeout(() => toast.remove(), 4000)
  }

  /*
   * Sessions list
   */

  async function refreshSessions () {
    const body = await apiJson('/session/getSessions')
    if (!body.success) {
      throw new Error(body.error || 'Failed to fetch sessions')
    }
    const ids = body.result.sort()
    const statuses = await Promise.all(
      ids.map((id) => apiJson('/session/status/' + encodeURIComponent(id)).catch(() => null))
    )
    renderSessions(ids, statuses)
  }

  function renderSessions (ids, statuses) {
    const tbody = $('sessionsBody')
    tbody.textContent = ''
    $('emptyState').classList.toggle('hidden', ids.length > 0)
    ids.forEach((id, index) => {
      const status = statuses[index]
      const connected = Boolean(status && status.success && status.state === 'CONNECTED')
      const row = document.createElement('tr')

      const idCell = document.createElement('td')
      idCell.className = 'session-id'
      idCell.textContent = id
      row.appendChild(idCell)

      const statusCell = document.createElement('td')
      const badge = document.createElement('span')
      badge.className = 'badge ' + (connected ? 'badge-connected' : 'badge-pending')
      badge.textContent = (status && status.state) || 'STARTING'
      statusCell.appendChild(badge)
      row.appendChild(statusCell)

      const actionsCell = document.createElement('td')
      actionsCell.className = 'actions-cell'
      const actions = document.createElement('div')
      actions.className = 'actions'
      if (connected) {
        actions.appendChild(actionButton('Details', () => openDetailsModal(id)))
      } else {
        actions.appendChild(actionButton('Show QR', () => openQrModal(id)))
      }
      actions.appendChild(actionButton('Restart', () => sessionAction(id, 'restart')))
      actions.appendChild(actionButton('Stop', () => sessionAction(id, 'stop')))
      actions.appendChild(actionButton('Terminate', () => sessionAction(id, 'terminate', 'Terminate session "' + id + '"? This logs out the linked device.'), 'danger'))
      actionsCell.appendChild(actions)
      row.appendChild(actionsCell)

      tbody.appendChild(row)
    })
  }

  function actionButton (label, onClick, extraClass) {
    const button = document.createElement('button')
    button.type = 'button'
    button.className = 'secondary' + (extraClass ? ' ' + extraClass : '')
    button.textContent = label
    button.addEventListener('click', onClick)
    return button
  }

  async function sessionAction (id, action, confirmMessage) {
    if (confirmMessage && !window.confirm(confirmMessage)) {
      return
    }
    try {
      const body = await apiJson('/session/' + action + '/' + encodeURIComponent(id))
      if (body.success) {
        showToast(id + ': ' + (body.message || action + ' completed'))
      } else {
        showToast(id + ': ' + (body.error || body.message || action + ' failed'), true)
      }
    } catch (error) {
      showToast(error.message, true)
    }
    refreshNow()
  }

  async function globalAction (path, confirmMessage) {
    if (confirmMessage && !window.confirm(confirmMessage)) {
      return
    }
    try {
      const body = await apiJson(path)
      showToast(body.message || body.error || 'Done', !body.success)
    } catch (error) {
      showToast(error.message, true)
    }
    refreshNow()
  }

  /*
   * Polling
   */

  function refreshNow () {
    clearTimeout(pollTimer)
    pollLoop()
  }

  async function pollLoop () {
    if (!document.hidden && !authFailed) {
      try {
        await refreshSessions()
      } catch {
        // errors surface through the API key banner or action toasts
      }
    }
    pollTimer = setTimeout(pollLoop, POLL_INTERVAL_MS)
  }

  /*
   * Add session
   */

  function openStartModal () {
    $('newSessionId').value = ''
    $('addSessionError').classList.add('hidden')
    $('startModal').classList.remove('hidden')
    $('newSessionId').focus()
  }

  function closeStartModal () {
    $('startModal').classList.add('hidden')
  }

  async function startNewSession (event) {
    event.preventDefault()
    const input = $('newSessionId')
    const errorEl = $('addSessionError')
    const id = input.value.trim()
    if (!SESSION_ID_PATTERN.test(id)) {
      errorEl.textContent = 'Session id should be alphanumerical or -'
      errorEl.classList.remove('hidden')
      return
    }
    errorEl.classList.add('hidden')
    const button = $('startSubmitBtn')
    button.disabled = true
    button.textContent = 'Starting…'
    try {
      const body = await apiJson('/session/start/' + encodeURIComponent(id))
      if (body.success) {
        showToast(id + ': ' + body.message)
        closeStartModal()
        openQrModal(id)
      } else {
        showToast(id + ': ' + (body.error || body.message), true)
      }
    } catch (error) {
      showToast(error.message, true)
    }
    button.disabled = false
    button.textContent = 'Start'
    refreshNow()
  }

  /*
   * QR modal
   */

  function openQrModal (id) {
    clearTimeout(qrTimer)
    qrSessionId = id
    $('qrSessionName').textContent = id
    $('qrImage').classList.add('hidden')
    $('qrConnected').classList.add('hidden')
    $('qrWaiting').textContent = 'Waiting for QR code…'
    $('qrWaiting').classList.remove('hidden')
    $('pairingCode').classList.add('hidden')
    $('pairingPhone').value = ''
    $('qrModal').classList.remove('hidden')
    qrTick()
  }

  async function qrTick () {
    try {
      const status = await apiJson('/session/status/' + encodeURIComponent(qrSessionId))
      if (status.message === 'session_not_found') {
        $('qrImage').classList.add('hidden')
        $('qrWaiting').classList.remove('hidden')
        $('qrWaiting').textContent = 'Session no longer exists'
        refreshNow()
        return
      }
      if (status.success && status.state === 'CONNECTED') {
        $('qrWaiting').classList.add('hidden')
        $('qrImage').classList.add('hidden')
        $('qrConnected').classList.remove('hidden')
        refreshNow()
        return
      }
      const response = await apiFetch('/session/qr/' + encodeURIComponent(qrSessionId) + '/image')
      const contentType = response.headers.get('content-type') || ''
      // the endpoint responds 200 with a JSON body when the QR is not ready
      if (contentType.startsWith('image/png')) {
        const blob = await response.blob()
        if (qrObjectUrl) {
          URL.revokeObjectURL(qrObjectUrl)
        }
        qrObjectUrl = URL.createObjectURL(blob)
        const image = $('qrImage')
        image.src = qrObjectUrl
        image.classList.remove('hidden')
        $('qrWaiting').classList.add('hidden')
      }
    } catch {
      // keep polling; auth errors surface through the API key banner
    }
    qrTimer = setTimeout(qrTick, QR_POLL_INTERVAL_MS)
  }

  function closeQrModal () {
    clearTimeout(qrTimer)
    if (qrObjectUrl) {
      URL.revokeObjectURL(qrObjectUrl)
      qrObjectUrl = null
    }
    $('qrModal').classList.add('hidden')
    refreshNow()
  }

  async function requestPairingCode () {
    const phoneNumber = $('pairingPhone').value.replace(/\D/g, '')
    if (!phoneNumber) {
      showToast('Enter the phone number in international format, digits only', true)
      return
    }
    const button = $('pairingBtn')
    button.disabled = true
    try {
      const body = await apiJson('/session/requestPairingCode/' + encodeURIComponent(qrSessionId), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phoneNumber, showNotification: true })
      })
      if (body.success) {
        const codeEl = $('pairingCode')
        codeEl.textContent = body.result
        codeEl.classList.remove('hidden')
      } else {
        showToast(body.error || body.message || 'Failed to request pairing code', true)
      }
    } catch (error) {
      showToast(error.message, true)
    }
    button.disabled = false
  }

  /*
   * Details modal
   */

  async function openDetailsModal (id) {
    $('detailsSessionName').textContent = id
    const list = $('detailsList')
    list.textContent = ''
    $('detailsModal').classList.remove('hidden')
    try {
      const status = await apiJson('/session/status/' + encodeURIComponent(id))
      addDetail(list, 'State', status.state || status.message)
      if (status.success && status.state === 'CONNECTED') {
        const body = await apiJson('/client/getClassInfo/' + encodeURIComponent(id))
        const info = body.sessionInfo || {}
        addDetail(list, 'Phone number', info.wid && info.wid.user)
        addDetail(list, 'Push name', info.pushname)
        addDetail(list, 'Platform', info.platform)
      }
    } catch (error) {
      showToast(error.message, true)
    }
  }

  function addDetail (list, label, value) {
    const dt = document.createElement('dt')
    dt.textContent = label
    const dd = document.createElement('dd')
    dd.textContent = value || '—'
    list.appendChild(dt)
    list.appendChild(dd)
  }

  /*
   * API key
   */

  function saveApiKey () {
    const value = $('apiKeyInput').value.trim()
    if (value) {
      window.localStorage.setItem(STORAGE_KEY, value)
    } else {
      window.localStorage.removeItem(STORAGE_KEY)
    }
    authFailed = false
    $('apiKeyBanner').classList.add('hidden')
    showToast('API key saved')
    refreshNow()
  }

  // the swagger endpoint is optional (ENABLE_SWAGGER_ENDPOINT); only show the link when it responds
  async function checkApiDocs () {
    try {
      const response = await window.fetch(API_BASE + '/api-docs', { method: 'HEAD', cache: 'no-store' })
      if (response.ok) {
        $('apiDocsLink').classList.remove('hidden')
      }
    } catch {
      // endpoint unavailable; keep the link hidden
    }
  }

  function init () {
    $('apiKeyInput').value = window.localStorage.getItem(STORAGE_KEY) || ''
    checkApiDocs()
    $('apiKeySaveBtn').addEventListener('click', saveApiKey)
    $('addSessionBtn').addEventListener('click', openStartModal)
    $('addSessionForm').addEventListener('submit', startNewSession)
    $('startCloseBtn').addEventListener('click', closeStartModal)
    $('refreshBtn').addEventListener('click', () => refreshNow())
    $('terminateInactiveBtn').addEventListener('click', () => globalAction('/session/terminateInactive', 'Terminate all inactive sessions?'))
    $('terminateAllBtn').addEventListener('click', () => globalAction('/session/terminateAll', 'Terminate ALL sessions? This logs out every linked device.'))
    $('qrCloseBtn').addEventListener('click', closeQrModal)
    $('pairingBtn').addEventListener('click', requestPairingCode)
    $('detailsCloseBtn').addEventListener('click', () => $('detailsModal').classList.add('hidden'))
    $('startModal').addEventListener('click', (event) => {
      if (event.target === $('startModal')) {
        closeStartModal()
      }
    })
    $('qrModal').addEventListener('click', (event) => {
      if (event.target === $('qrModal')) {
        closeQrModal()
      }
    })
    $('detailsModal').addEventListener('click', (event) => {
      if (event.target === $('detailsModal')) {
        $('detailsModal').classList.add('hidden')
      }
    })
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        refreshNow()
      }
    })
    pollLoop()
  }

  init()
})()
