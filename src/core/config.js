// ── Configuracao local (VION_HOME/config.json) ──

import fs from 'node:fs'
import { ensureHome } from './paths.js'

export const ROLES = ['orquestrador', 'recon', 'vuln', 'investigador', 'threat-intel', 'correlacao', 'relatorio']
export const MODELS = ['opus', 'sonnet', 'haiku', 'inherit']

export const DEFAULT_CONFIG = {
  models: {
    orquestrador: 'opus',
    recon: 'haiku',
    vuln: 'sonnet',
    investigador: 'sonnet',
    'threat-intel': 'haiku',
    correlacao: 'haiku',
    relatorio: 'haiku',
  },
  limits: {
    maxCostUsd: 5,
    maxConcurrentAudits: 1,
    timeoutMinutes: 45,
  },
  retention: { days: 0 },
  ui: { port: 3333 },
}

// Chaves que o usuario pode alterar via `vion config set`. Valida tipo e valores aceitos.
export const SETTABLE = {
  ...Object.fromEntries(ROLES.map(r => [`models.${r}`, { type: 'enum', values: MODELS }])),
  'limits.maxCostUsd': { type: 'number', min: 0 },
  'limits.maxConcurrentAudits': { type: 'int', min: 1, max: 8 },
  'limits.timeoutMinutes': { type: 'int', min: 1 },
  'retention.days': { type: 'int', min: 0 },
  'ui.port': { type: 'int', min: 1024, max: 65535 },
}

function merge(base, over) {
  const out = structuredClone(base)
  for (const [k, v] of Object.entries(over || {})) {
    if (v && typeof v === 'object' && !Array.isArray(v) && typeof out[k] === 'object') out[k] = merge(out[k], v)
    else out[k] = v
  }
  return out
}

export function loadConfig() {
  const p = ensureHome()
  try {
    return merge(DEFAULT_CONFIG, JSON.parse(fs.readFileSync(p.config, 'utf8')))
  } catch {
    return structuredClone(DEFAULT_CONFIG)
  }
}

export function saveConfig(cfg) {
  const p = ensureHome()
  fs.writeFileSync(p.config, JSON.stringify(cfg, null, 2), { mode: 0o600 })
}

export function getKey(cfg, key) {
  return key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), cfg)
}

export function coerceValue(key, raw) {
  const spec = SETTABLE[key]
  if (!spec) throw new Error(`Chave desconhecida: ${key}. Chaves validas: ${Object.keys(SETTABLE).join(', ')}`)
  if (spec.type === 'enum') {
    if (!spec.values.includes(raw)) throw new Error(`Valor invalido para ${key}: ${raw}. Aceitos: ${spec.values.join(', ')}`)
    return raw
  }
  const n = Number(raw)
  if (!Number.isFinite(n) || (spec.type === 'int' && !Number.isInteger(n))) throw new Error(`${key} precisa ser numero${spec.type === 'int' ? ' inteiro' : ''}`)
  if (spec.min != null && n < spec.min) throw new Error(`${key} minimo: ${spec.min}`)
  if (spec.max != null && n > spec.max) throw new Error(`${key} maximo: ${spec.max}`)
  return n
}

export function setKey(key, raw) {
  const cfg = loadConfig()
  const value = coerceValue(key, raw)
  const parts = key.split('.')
  let o = cfg
  for (const k of parts.slice(0, -1)) o = o[k] ??= {}
  o[parts.at(-1)] = value
  saveConfig(cfg)
  return cfg
}
