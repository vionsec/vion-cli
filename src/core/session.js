// ── Marcadores de auditoria ativa ──
// Permitem que o hook PreToolUse saiba qual escopo aplicar:
//  - headless (vion audit / UI): VION_AUDIT_ID no ambiente -> modo estrito
//  - sessao interativa (/vion:* abriu a auditoria via MCP): marcador por diretorio -> modo rede

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { ensureHome } from './paths.js'
import { getAudit } from './store.js'

const TTL_MS = 6 * 60 * 60 * 1000

function activeDir() {
  const dir = path.join(ensureHome().audits, 'active')
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function keyFor(cwd) {
  const norm = path.resolve(cwd)
  return crypto.createHash('sha1').update(process.platform === 'win32' ? norm.toLowerCase() : norm).digest('hex').slice(0, 20)
}

export function markActive(auditId, cwd) {
  fs.writeFileSync(path.join(activeDir(), `${keyFor(cwd)}.json`), JSON.stringify({ auditId, cwd: path.resolve(cwd), at: Date.now() }))
}

export function clearActive(auditId) {
  for (const f of fs.readdirSync(activeDir())) {
    try {
      const m = JSON.parse(fs.readFileSync(path.join(activeDir(), f), 'utf8'))
      if (m.auditId === auditId) fs.rmSync(path.join(activeDir(), f), { force: true })
    } catch {
      // marcador corrompido: ignora
    }
  }
}

/** Retorna { audit, mode } ou null. */
export function resolveActiveAudit({ env = process.env, cwd = process.cwd() } = {}) {
  if (env.VION_AUDIT_ID) {
    const audit = getAudit(env.VION_AUDIT_ID)
    if (audit) return { audit, mode: 'strict' }
  }
  const file = path.join(activeDir(), `${keyFor(cwd)}.json`)
  if (!fs.existsSync(file)) return null
  try {
    const m = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (Date.now() - m.at > TTL_MS) return null
    const audit = getAudit(m.auditId)
    if (!audit || !['running', 'pending'].includes(audit.status)) return null
    return { audit, mode: 'session' }
  } catch {
    return null
  }
}
