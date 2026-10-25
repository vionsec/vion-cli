// ── Migracao do @vionsec/cli <= 0.6 (versao SaaS) ──
// A versao antiga guardava credenciais da API em ~/.vion e deixava um daemon
// (fix-watcher) consultando o servidor. Ao atualizar, paramos o daemon e
// renomeamos a pasta (nada e apagado).

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { vionHome } from './paths.js'

export function legacyDir() {
  return process.env.VION_LEGACY_DIR || path.join(os.homedir(), '.vion')
}

function alive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return err.code === 'EPERM'
  }
}

function commandLine(pid) {
  const r = process.platform === 'win32'
    ? spawnSync('powershell.exe', ['-NoProfile', '-Command', `(Get-CimInstance Win32_Process -Filter "ProcessId=${pid}").CommandLine`], { encoding: 'utf8', windowsHide: true })
    : spawnSync('ps', ['-o', 'args=', '-p', String(pid)], { encoding: 'utf8' })
  return r.status === 0 ? r.stdout.trim() : ''
}

export function detectLegacy() {
  const dir = legacyDir()
  if (!fs.existsSync(dir) || path.resolve(dir) === path.resolve(vionHome())) return null
  let pid = null
  try {
    pid = Number.parseInt(fs.readFileSync(path.join(dir, 'fix-watcher.pid'), 'utf8').trim(), 10) || null
  } catch {}
  return {
    dir,
    credentials: fs.existsSync(path.join(dir, 'credentials.json')),
    watcherPid: pid,
    watcherRunning: !!pid && alive(pid) && /fix-watcher/.test(commandLine(pid)),
  }
}

export function migrateLegacy({ dryRun = false } = {}) {
  const legacy = detectLegacy()
  if (!legacy) return { legacy: null, actions: [] }
  const actions = []
  if (legacy.watcherRunning) {
    actions.push(`legado: parando o fix-watcher do CLI antigo (PID ${legacy.watcherPid})`)
    if (!dryRun) {
      try {
        process.kill(legacy.watcherPid)
      } catch (err) {
        actions.push(`legado: nao consegui parar o PID ${legacy.watcherPid} (${err.code}); encerre manualmente`)
      }
    }
  }
  const d = new Date()
  const p = n => String(n).padStart(2, '0')
  const dest = `${legacy.dir}.legacy-${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`
  actions.push(`legado: ${legacy.dir} -> ${dest}${legacy.credentials ? ' (contem a API key da versao SaaS; apague quando quiser)' : ''}`)
  if (!dryRun) {
    try {
      fs.renameSync(legacy.dir, dest)
    } catch (err) {
      actions.push(`legado: nao consegui mover (${err.code}); a pasta antiga nao e usada por esta versao`)
    }
  }
  return { legacy, actions }
}
