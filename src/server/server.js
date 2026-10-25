// ── Servidor da UI local (node:http, sem dependencias) ──
// Sem login por design, entao a protecao e de rede/origem:
//  - escuta so em 127.0.0.1
//  - Host precisa ser localhost/127.0.0.1:<porta>  (anti DNS rebinding)
//  - toda rota /api exige o token da sessao (header X-VION-Token ou ?t= no SSE)
//  - mutacoes exigem Origin da propria UI + JSON
//  - CSP estrita, sem frames, nosniff

import http from 'node:http'
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { PKG_ROOT, ensureHome } from '../core/paths.js'
import { createApi, REPLY } from './api.js'
import { eventsSince, lastEventId } from '../core/store.js'
import { reapOrphans } from '../core/runner.js'

const UI_DIR = path.join(PKG_ROOT, 'dist', 'ui')
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.json': 'application/json; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
}
const MAX_BODY = 64 * 1024

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Cache-Control': 'no-store',
}
const APP_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
// relatorio HTML gerado pelo VION: estilos inline, nenhum script
const REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; sandbox"

export class HttpError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}

export function allowedHosts(port) {
  return new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`])
}

/** Validacoes de origem/rede. Exportada para testes. */
export function checkRequest({ method, headers, url }, { port, token }) {
  const host = String(headers.host || '').toLowerCase()
  if (!allowedHosts(port).has(host)) return { status: 403, error: 'Host nao permitido' }
  const isApi = url.startsWith('/api/')
  if (!isApi) return null
  const u = new URL(url, `http://${host}`)
  const given = headers['x-vion-token'] || u.searchParams.get('t') || ''
  const a = Buffer.from(String(given))
  const b = Buffer.from(token)
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return { status: 401, error: 'Token da sessao ausente ou invalido (recarregue a pagina)' }
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = String(headers.origin || '')
    if (!allowedHosts(port).has(origin.replace(/^http:\/\//, ''))) return { status: 403, error: 'Origin nao permitido' }
    if (method !== 'DELETE' && !String(headers['content-type'] || '').startsWith('application/json')) return { status: 415, error: 'Use application/json' }
  }
  return null
}

function send(res, status, body, headers = {}) {
  const isBuf = Buffer.isBuffer(body)
  const payload = isBuf || typeof body === 'string' ? body : JSON.stringify(body)
  res.writeHead(status, {
    ...BASE_HEADERS,
    'Content-Security-Policy': APP_CSP,
    ...(isBuf || typeof body === 'string' ? {} : { 'Content-Type': 'application/json; charset=utf-8' }),
    ...headers,
  })
  res.end(payload)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', c => {
      size += c.length
      if (size > MAX_BODY) {
        reject(new HttpError(413, 'Corpo muito grande'))
        req.destroy()
      } else chunks.push(c)
    })
    req.on('end', () => {
      if (!chunks.length) return resolve({})
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')))
      } catch {
        reject(new HttpError(400, 'JSON invalido'))
      }
    })
    req.on('error', reject)
  })
}

function serveStatic(res, urlPath, token) {
  const rel = decodeURIComponent(urlPath.split('?')[0]).replace(/^\/+/, '') || 'index.html'
  let file = path.resolve(UI_DIR, rel)
  if (!file.startsWith(UI_DIR + path.sep) && file !== UI_DIR) return send(res, 404, 'nao encontrado')
  if (!fs.existsSync(file) || fs.statSync(file).isDirectory()) file = path.join(UI_DIR, 'index.html')
  if (!fs.existsSync(file)) return send(res, 500, 'UI nao compilada. No codigo-fonte rode: npm run build:ui', { 'Content-Type': 'text/plain; charset=utf-8' })
  const ext = path.extname(file)
  let body = fs.readFileSync(file)
  if (ext === '.html') body = Buffer.from(body.toString('utf8').replace('%VION_TOKEN%', token))
  const cache = ext === '.html' ? 'no-store' : 'public, max-age=31536000, immutable'
  send(res, 200, body, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': cache })
}

function serveSse(req, res, url) {
  const auditId = url.searchParams.get('audit') || null
  let last = Number(url.searchParams.get('after')) || lastEventId()
  res.writeHead(200, { ...BASE_HEADERS, 'Content-Type': 'text/event-stream; charset=utf-8', Connection: 'keep-alive' })
  res.write(`retry: 2000\n\n`)
  // varios processos (worker, MCP) escrevem no SQLite: o servidor faz polling leve e repassa
  const tick = () => {
    try {
      for (const e of eventsSince(last, auditId, 200)) {
        last = e.id
        res.write(`id: ${e.id}\nevent: vion\ndata: ${JSON.stringify(e)}\n\n`)
      }
    } catch {
      // banco ocupado: tenta no proximo tick
    }
  }
  const timer = setInterval(tick, 1000)
  const ping = setInterval(() => res.write(': ping\n\n'), 15000)
  req.on('close', () => {
    clearInterval(timer)
    clearInterval(ping)
  })
}

export function createUiServer({ port }) {
  const token = crypto.randomBytes(24).toString('base64url')
  const api = createApi()
  ensureHome()
  reapOrphans()

  const server = http.createServer(async (req, res) => {
    if (process.env.VION_HTTP_LOG) console.error(new Date().toISOString(), req.method, req.url.slice(0, 80), req.headers.host)
    try {
      const denied = checkRequest(req, { port, token })
      if (denied) return send(res, denied.status, { error: denied.error })
      const url = new URL(req.url, `http://${req.headers.host}`)
      if (!url.pathname.startsWith('/api/')) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Metodo nao permitido' })
        return serveStatic(res, url.pathname, token)
      }
      if (url.pathname === '/api/events' && req.method === 'GET') return serveSse(req, res, url)
      const body = ['POST', 'PUT', 'PATCH'].includes(req.method) ? await readBody(req) : {}
      const out = await api.handle(req.method, url, body)
      if (out?.[REPLY] && out.file) {
        const csp = out.contentType?.startsWith('text/html') ? REPORT_CSP : APP_CSP
        return send(res, 200, fs.readFileSync(out.file), {
          'Content-Type': out.contentType,
          'Content-Security-Policy': csp,
          ...(out.download ? { 'Content-Disposition': `attachment; filename="${out.download}"` } : {}),
        })
      }
      if (out?.[REPLY]) return send(res, out.status, out.body)
      return send(res, 200, out ?? {})
    } catch (err) {
      const status = err.status || (/nao encontrad/i.test(err.message) ? 404 : 400)
      if (status >= 500 || !err.status) process.env.VION_DEBUG && console.error(err)
      send(res, status, { error: err.message })
    }
  })
  return { server, token }
}

export function startUiServer({ port, host = '127.0.0.1' }) {
  const { server, token } = createUiServer({ port })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, host, () => resolve({ server, token, url: `http://localhost:${port}/` }))
  })
}
