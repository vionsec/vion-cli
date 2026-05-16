import { homedir, platform } from 'node:os'
import { join, dirname } from 'node:path'
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  unlinkSync,
  chmodSync,
} from 'node:fs'

const VION_DIR = join(homedir(), '.vion')
export const CREDENTIALS_PATH = join(VION_DIR, 'credentials.json')
export const WATCHER_PID_PATH = join(VION_DIR, 'fix-watcher.pid')
export const WATCHER_LOG_PATH = join(VION_DIR, 'fix-watcher.log')
export const WATCHER_SCRIPT_PATH = join(VION_DIR, 'fix-watcher.mjs')
export const CURLRC_PATH = join(VION_DIR, 'curlrc')

function ensureDir(path) {
  const dir = dirname(path)
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true })
  }
}

/**
 * Resolve "~/foo" or "~\foo" to an absolute path under the user's home dir.
 * Pass-through for already absolute paths.
 */
export function expandHome(p) {
  if (typeof p !== 'string') return p
  if (p.startsWith('~/') || p.startsWith('~\\')) {
    return join(homedir(), p.slice(2))
  }
  if (p === '~') return homedir()
  return p
}

/**
 * Persist credentials to ~/.vion/credentials.json with restrictive perms.
 * On Windows, NTFS ACLs default to user-only when written under the home
 * directory — chmod is best-effort and silently ignored when unsupported.
 */
export function saveCredentials(creds) {
  ensureDir(CREDENTIALS_PATH)
  const json = JSON.stringify(creds, null, 2)
  writeFileSync(CREDENTIALS_PATH, json, { encoding: 'utf8' })
  if (platform() !== 'win32') {
    try {
      chmodSync(CREDENTIALS_PATH, 0o600)
    } catch {
      // best effort
    }
  }
}

export function loadCredentials() {
  if (!existsSync(CREDENTIALS_PATH)) return null
  try {
    return JSON.parse(readFileSync(CREDENTIALS_PATH, 'utf8'))
  } catch {
    return null
  }
}

export function clearCredentials() {
  let removed = false
  if (existsSync(CREDENTIALS_PATH)) {
    unlinkSync(CREDENTIALS_PATH)
    removed = true
  }
  if (existsSync(CURLRC_PATH)) {
    unlinkSync(CURLRC_PATH)
  }
  return removed
}

/**
 * Write a curl config file that carries the Bearer token. Used by the
 * agent's slash-command markdown so the API key never appears inline in any
 * `curl ...` command — Claude Code (and similar CLIs) display tool arguments
 * verbatim in the UI, which would otherwise leak the token to anyone watching
 * the user's screen.
 *
 * `cli` (opcional): qual agente IA o curlrc serve. Quando informado, ja escreve
 * `X-Vion-Agent: <cli>` pra que o backend renderize o markdown no dialeto desse
 * CLI sem precisar de query string em cada request. Default 'claude'.
 *
 * The CLI pairs each saved credentials.json with a curlrc; deleting one
 * deletes the other.
 */
export function saveCurlrc(apiKey, cli = 'claude') {
  ensureDir(CURLRC_PATH)
  // X-Vion-Agent: nome do CLI (claude|blackbox|codex|cursor|terminal).
  // Backend usa pra renderizar prompts no dialeto certo.
  // Nota: phase-fetching usa `vion call` (HMAC dinâmico). Este curlrc é
  // mantido apenas para chamadas de coleta (POST /api/analyze, etc.) onde
  // o agente precisa de curl direto sem expor o token na UI.
  const body = `# VION Security CLI — headers for slash-command curl calls.
# Generated automatically. Do not edit by hand.
# Permissions: 0600 (Unix). Treat as a secret.
header = "Authorization: Bearer ${apiKey}"
header = "X-Vion-Agent: ${cli}"
`
  writeFileSync(CURLRC_PATH, body, { encoding: 'utf8' })
  if (platform() !== 'win32') {
    try {
      chmodSync(CURLRC_PATH, 0o600)
    } catch {
      // best effort
    }
  }
}

export function writeFileFromBase64(targetPath, base64) {
  const abs = expandHome(targetPath)
  ensureDir(abs)
  writeFileSync(abs, Buffer.from(base64, 'base64'))
  return abs
}
