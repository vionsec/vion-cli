// ── Escopo autorizado de uma auditoria ──
// O escopo e validado pelo motor (hook PreToolUse + MCP), nunca so pelo prompt.

import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { isInside } from './paths.js'

export const SCOPE_VERSION = 1

export class ScopeError extends Error {}

function normHost(h) {
  return String(h || '').trim().toLowerCase().replace(/\.$/, '')
}

function isFsRoot(p) {
  const r = path.resolve(p)
  return path.parse(r).root === r
}

/**
 * Normaliza e valida um escopo vindo do CLI/UI.
 * input: { target, paths?, hosts?, cidrs?, active?, authorization? }
 */
export function normalizeScope(input) {
  if (!input || typeof input !== 'object') throw new ScopeError('Escopo ausente.')
  const target = String(input.target || '').trim()
  if (!target) throw new ScopeError('Escopo sem alvo (target).')

  const scope = {
    version: SCOPE_VERSION,
    target,
    targetType: /^https?:\/\//i.test(target) ? 'url' : 'path',
    paths: [],
    hosts: [],
    cidrs: [],
    active: input.active === true,
    authorization: {
      statement: String(input.authorization?.statement || '').trim(),
      by: String(input.authorization?.by || '').trim(),
      date: input.authorization?.date || new Date().toISOString(),
    },
  }

  const rawPaths = [...(input.paths || [])]
  if (scope.targetType === 'path') rawPaths.unshift(target)
  for (const p of rawPaths) {
    const abs = path.resolve(String(p))
    if (isFsRoot(abs)) throw new ScopeError(`Escopo nao pode ser a raiz do disco: ${abs}`)
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new ScopeError(`Diretorio nao existe: ${abs}`)
    if (!scope.paths.some(x => x.toLowerCase() === abs.toLowerCase())) scope.paths.push(abs)
  }

  const rawHosts = [...(input.hosts || [])]
  if (scope.targetType === 'url') {
    try {
      rawHosts.unshift(new URL(target).hostname)
    } catch {
      throw new ScopeError(`URL invalida: ${target}`)
    }
  }
  for (const h of rawHosts) {
    const host = normHost(h)
    if (!host) continue
    if (host === '*' || host === '*.' || /^\*\.[^.]+$/.test(host)) throw new ScopeError(`Curinga amplo demais: ${h}`)
    if (!/^(\*\.)?[a-z0-9.-]+$/.test(host) && !net.isIP(host)) throw new ScopeError(`Host invalido: ${h}`)
    if (!scope.hosts.includes(host)) scope.hosts.push(host)
  }

  for (const c of input.cidrs || []) {
    const parsed = parseCidr(c)
    if (!parsed) throw new ScopeError(`CIDR invalido (somente IPv4): ${c}`)
    if (parsed.bits < 16) throw new ScopeError(`CIDR amplo demais (minimo /16): ${c}`)
    scope.cidrs.push(`${parsed.base}/${parsed.bits}`)
  }

  if (scope.active || scope.hosts.length || scope.cidrs.length) {
    if (scope.authorization.statement.length < 10) {
      throw new ScopeError('Teste em alvo de rede exige declaracao de autorizacao (authorization.statement, min. 10 caracteres).')
    }
  }
  if (!scope.paths.length && !scope.hosts.length && !scope.cidrs.length) throw new ScopeError('Escopo vazio.')
  return scope
}

function ipToInt(ip) {
  return ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0
}

export function parseCidr(c) {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(c).trim())
  if (!m || net.isIPv4(m[1]) === false) return null
  const bits = Number(m[2])
  if (bits > 32) return null
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  const base = ipToInt(m[1]) & mask
  return { base: [24, 16, 8, 0].map(s => (base >>> s) & 255).join('.'), bits, mask, baseInt: base >>> 0 }
}

/** Hosts de loopback sao sempre permitidos (ambiente local do proprio usuario). */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1'])

export function hostAllowed(scope, rawHost) {
  const host = normHost(rawHost).replace(/^\[|\]$/g, '')
  if (!host) return false
  if (LOOPBACK.has(host)) return true
  for (const h of scope.hosts || []) {
    if (h === host) return true
    if (h.startsWith('*.') && host.endsWith(h.slice(1))) return true
  }
  if (net.isIPv4(host)) {
    const n = ipToInt(host)
    for (const c of scope.cidrs || []) {
      const p = parseCidr(c)
      if (p && ((n & p.mask) >>> 0) === p.baseInt) return true
    }
  }
  return false
}

export function pathAllowed(scope, p, extraAllowed = []) {
  if (!p) return false
  const abs = path.resolve(p)
  return [...(scope.paths || []), ...extraAllowed].some(base => isInside(base, abs))
}
