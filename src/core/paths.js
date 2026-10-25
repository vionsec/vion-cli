// ── VION_HOME: diretorio local de dados, seguindo o padrao de cada SO ──

import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'
import { fileURLToPath } from 'node:url'

export const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')

export function vionHome() {
  if (process.env.VION_HOME) return path.resolve(process.env.VION_HOME)
  const home = os.homedir()
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'vion')
  }
  if (process.platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'vion')
  }
  return path.join(process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'vion')
}

export function paths() {
  const root = vionHome()
  return {
    root,
    config: path.join(root, 'config.json'),
    db: path.join(root, 'vion.sqlite'),
    evidence: path.join(root, 'evidence'),
    reports: path.join(root, 'reports'),
    logs: path.join(root, 'logs'),
    cache: path.join(root, 'cache'),
    audits: path.join(root, 'audits'),
  }
}

export function ensureHome() {
  const p = paths()
  for (const dir of [p.root, p.evidence, p.reports, p.logs, p.cache, p.audits]) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
  }
  return p
}

export function claudeHome() {
  return process.env.CLAUDE_CONFIG_DIR
    ? path.resolve(process.env.CLAUDE_CONFIG_DIR)
    : path.join(os.homedir(), '.claude')
}

/** Garante que `target` esta dentro de `base` (apos resolver `..` e symlinks quando existem). */
export function isInside(base, target) {
  const real = p => {
    try {
      return fs.realpathSync.native(p)
    } catch {
      return path.resolve(p)
    }
  }
  const b = real(base)
  const t = real(target)
  const rel = path.relative(b, t)
  const norm = s => (process.platform === 'win32' ? s.toLowerCase() : s)
  if (norm(b) === norm(t)) return true
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel)
}
