import { spawn } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, unlinkSync, openSync } from 'node:fs'
import {
  WATCHER_PID_PATH,
  WATCHER_LOG_PATH,
  WATCHER_SCRIPT_PATH,
} from '../lib/storage.js'
import { color, info, success, warn, error, header, blank } from '../lib/ui.js'

function isAlive(pid) {
  if (!pid || Number.isNaN(pid)) return false
  try {
    // signal 0 = existence check, no actual signal sent
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

function readPid() {
  if (!existsSync(WATCHER_PID_PATH)) return null
  const raw = readFileSync(WATCHER_PID_PATH, 'utf8').trim()
  const pid = parseInt(raw, 10)
  return Number.isFinite(pid) ? pid : null
}

/**
 * Start the fix-watcher daemon. Returns one of:
 *   { ok: true, pid }       — newly started
 *   { ok: true, pid, already: true } — already running
 *   { ok: false, reason }   — script missing or spawn error
 *
 * Used by `vion watch start` AND by `vion install` (auto-start).
 */
export function startWatcher() {
  if (!existsSync(WATCHER_SCRIPT_PATH)) {
    return { ok: false, reason: 'script_missing' }
  }

  const existing = readPid()
  if (isAlive(existing)) {
    return { ok: true, pid: existing, already: true }
  }

  try {
    const out = openSync(WATCHER_LOG_PATH, 'a')
    const err = openSync(WATCHER_LOG_PATH, 'a')
    const child = spawn(process.execPath, [WATCHER_SCRIPT_PATH], {
      detached: true,
      stdio: ['ignore', out, err],
    })
    child.unref()
    writeFileSync(WATCHER_PID_PATH, String(child.pid))
    return { ok: true, pid: child.pid }
  } catch (e) {
    return { ok: false, reason: 'spawn_failed', error: e.message }
  }
}

/**
 * Stop the running watcher. Returns:
 *   { ok: true, pid, was: 'running' | 'stale' | 'absent' }
 *   { ok: false, error }
 */
export function stopWatcher() {
  const pid = readPid()
  if (!pid) return { ok: true, was: 'absent' }
  if (!isAlive(pid)) {
    try {
      unlinkSync(WATCHER_PID_PATH)
    } catch {
      // ignore
    }
    return { ok: true, pid, was: 'stale' }
  }
  try {
    process.kill(pid, 'SIGTERM')
    try {
      unlinkSync(WATCHER_PID_PATH)
    } catch {
      // ignore
    }
    return { ok: true, pid, was: 'running' }
  } catch (e) {
    return { ok: false, error: e.message }
  }
}

export function watcherStatus() {
  const pid = readPid()
  return { pid, alive: isAlive(pid) }
}

export async function watchCommand(action) {
  header(`VION CLI — Fix Watcher (${action})`)

  if (action === 'start') {
    const r = startWatcher()
    if (!r.ok) {
      if (r.reason === 'script_missing') {
        error('Fix watcher não instalado. Rode `vion install --cli=claude` primeiro.')
      } else {
        error(`Falha ao iniciar: ${r.error || r.reason}`)
      }
      blank()
      process.exit(1)
    }
    if (r.already) {
      warn(`Já rodando (PID ${r.pid}). Use \`vion watch stop\` antes.`)
    } else {
      success(`Fix watcher iniciado (PID ${r.pid}).`)
      info(color.dim(`Log: ${WATCHER_LOG_PATH}`))
    }
    blank()
    return
  }

  if (action === 'stop') {
    const r = stopWatcher()
    if (!r.ok) {
      error(`Falha ao parar PID ${r.pid}: ${r.error}`)
      blank()
      return
    }
    if (r.was === 'absent') {
      info('Watcher não está rodando.')
    } else if (r.was === 'stale') {
      info(`PID ${r.pid} já estava morto. Limpando.`)
    } else {
      success(`Watcher parado (PID ${r.pid}).`)
    }
    blank()
    return
  }

  if (action === 'status') {
    const s = watcherStatus()
    if (s.alive) {
      success(`Rodando (PID ${s.pid}).`)
      info(color.dim(`Log: ${WATCHER_LOG_PATH}`))
    } else {
      warn('Não está rodando.')
    }
    blank()
    return
  }

  error(`Ação inválida: ${action}. Use: start | stop | status`)
  blank()
  process.exit(1)
}
