// Cliente da API local. O token vem injetado no index.html pelo servidor (por sessao).
import { useCallback, useEffect, useRef, useState } from 'react'

const TOKEN = document.querySelector('meta[name="vion-token"]')?.content || ''

export async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: { 'X-VION-Token': TOKEN, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  let data
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  if (!res.ok) throw new Error(data?.error || `Erro ${res.status}`)
  return data
}

export const reportUrl = (id, download = false) => `/api/reports/${id}/file?t=${encodeURIComponent(TOKEN)}${download ? '&download=1' : ''}`

// ── eventos ao vivo (um EventSource para o app inteiro) ──
const listeners = new Set()
let source = null
let connected = false
const statusListeners = new Set()

function ensureSource() {
  if (source) return
  source = new EventSource(`/api/events?t=${encodeURIComponent(TOKEN)}`)
  source.addEventListener('vion', ev => {
    let e
    try {
      e = JSON.parse(ev.data)
    } catch {
      return
    }
    for (const fn of listeners) fn(e)
  })
  source.onopen = () => {
    connected = true
    statusListeners.forEach(fn => fn(true))
  }
  source.onerror = () => {
    connected = false
    statusListeners.forEach(fn => fn(false))
  }
}

export function useLiveEvents(handler) {
  const ref = useRef(handler)
  ref.current = handler
  useEffect(() => {
    ensureSource()
    const fn = e => ref.current(e)
    listeners.add(fn)
    return () => listeners.delete(fn)
  }, [])
}

export function useConnection() {
  const [ok, setOk] = useState(connected)
  useEffect(() => {
    ensureSource()
    statusListeners.add(setOk)
    return () => statusListeners.delete(setOk)
  }, [])
  return ok
}

/** GET com recarga automatica quando chegam eventos relevantes (debounce). */
export function useApi(path, { live = null, deps = [] } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: true })
  const timer = useRef(null)
  const load = useCallback(async () => {
    if (!path) return
    try {
      const data = await api(path)
      setState({ data, error: null, loading: false })
    } catch (error) {
      setState(s => ({ ...s, error, loading: false }))
    }
  }, [path])
  useEffect(() => {
    setState(s => ({ ...s, loading: true }))
    load()
  }, [load, ...deps])
  useLiveEvents(e => {
    if (!live) return
    if (typeof live === 'function' ? !live(e) : false) return
    clearTimeout(timer.current)
    timer.current = setTimeout(load, 600)
  })
  return { ...state, reload: load }
}
