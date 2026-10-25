// ── Redacao de segredos antes de persistir em DB, evidencias, logs e relatorios ──
// Reaproveita a mascara por chave de sanitize-log e os padroes de valor do secret-detector.

import { redact as redactKeys } from '../analyzers/sanitize-log.js'

const VALUE_PATTERNS = [
  /AKIA[0-9A-Z]{16}/g,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g,
  /\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bxox[bporas]-[A-Za-z0-9-]{10,}/g,
  /\bsk-ant-[A-Za-z0-9_-]{20,}/g,
  /\bsk-[A-Za-z0-9]{32,}/g,
  /\bAIza[0-9A-Za-z_-]{35}/g,
  /(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp):\/\/[^:\s/]+:[^@\s]+@/gi,
]

// chave=valor / "chave": "valor" / Header: valor
const KV_PATTERN =
  /((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|bearer|cookie|set-cookie|session(?:id)?|jwt|access[_-]?key|private[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?)([^"'\s,;&}]{4,})/gi

function mask(v) {
  if (v.length <= 8) return '[REDACTED]'
  return `${v.slice(0, 4)}…[REDACTED]`
}

export function redactText(text) {
  if (typeof text !== 'string' || !text) return text
  let out = text
  for (const re of VALUE_PATTERNS) out = out.replace(re, m => mask(m))
  out = out.replace(KV_PATTERN, (_, k, v) => (v.includes('[REDACTED]') ? `${k}${v}` : `${k}${mask(v)}`))
  return out
}

/** Redige recursivamente: chaves sensiveis viram [REDACTED], strings passam por redactText. */
export function redactDeep(value, depth = 0) {
  if (depth > 8 || value == null) return value
  if (typeof value === 'string') return redactText(value)
  if (Array.isArray(value)) return value.map(v => redactDeep(v, depth + 1))
  if (typeof value === 'object') {
    const byKey = redactKeys(value)
    const out = {}
    for (const [k, v] of Object.entries(byKey)) out[k] = redactDeep(v, depth + 1)
    return out
  }
  return value
}
