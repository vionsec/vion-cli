// ── Hook PreToolUse do Claude Code: aplica o escopo da auditoria ativa ──
// Modo "strict" (headless, VION_AUDIT_ID): leitura so dentro do escopo, sem escrita, rede so p/ hosts do escopo.
// Modo "session" (skill interativa abriu auditoria): rede so p/ hosts do escopo; leitura/escrita livres.
// Sem auditoria ativa: nao interfere.

import fs from 'node:fs'
import path from 'node:path'
import net from 'node:net'
import { resolveActiveAudit } from '../core/session.js'
import { hostAllowed, pathAllowed } from '../core/scope.js'
import { ensureHome, PKG_ROOT } from '../core/paths.js'
import { addEvent } from '../core/store.js'

const NET_COMMANDS = new Set([
  'curl', 'wget', 'http', 'https', 'nc', 'ncat', 'netcat', 'telnet', 'ssh', 'scp', 'sftp', 'ftp', 'ping', 'traceroute', 'tracert',
  'dig', 'nslookup', 'host', 'whois', 'nmap', 'masscan', 'rustscan', 'nikto', 'sqlmap', 'ffuf', 'gobuster', 'dirb', 'dirsearch',
  'feroxbuster', 'wfuzz', 'hydra', 'nuclei', 'whatweb', 'wafw00f', 'testssl', 'testssl.sh', 'sslscan', 'sslyze', 'openssl',
  'subfinder', 'amass', 'httpx', 'katana', 'dnsx', 'naabu', 'Invoke-WebRequest', 'Invoke-RestMethod', 'iwr', 'irm', 'Test-NetConnection',
])
// Ferramentas de teste ativo: exigem scope.active === true.
const ACTIVE_COMMANDS = new Set([
  'nmap', 'masscan', 'rustscan', 'nikto', 'sqlmap', 'ffuf', 'gobuster', 'dirb', 'dirsearch', 'feroxbuster', 'wfuzz', 'hydra',
  'nuclei', 'naabu', 'katana', 'wafw00f', 'testssl', 'testssl.sh', 'sslscan', 'sslyze',
])
const READ_TOOLS = { Read: 'file_path', Grep: 'path', Glob: 'path', NotebookRead: 'notebook_path', LS: 'path' }
const WRITE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])
const MCP_TARGET_KEYS = ['target', 'targets', 'url', 'urls', 'host', 'hosts', 'domain', 'domains', 'ip', 'ips', 'hostname']

const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i

export function extractHost(token) {
  let t = String(token || '').trim().replace(/^['"]|['"]$/g, '')
  if (!t || t.startsWith('-')) return null
  const url = /^[a-z][a-z0-9+.-]*:\/\/([^/?#\s]+)/i.exec(t)
  if (url) t = url[1]
  t = t.replace(/^[^@]*@/, '') // user@host
  if (t.startsWith('[')) {
    const m = /^\[([^\]]+)\]/.exec(t)
    return m && net.isIP(m[1]) ? m[1] : null
  }
  t = t.replace(/:\d+$/, '').replace(/\/.*$/, '')
  if (net.isIP(t)) return t
  if (HOSTNAME.test(t) && !/\.(js|ts|jsx|tsx|json|md|txt|py|sh|ps1|yml|yaml|html|css|log|lock|env|sql|xml|csv|gz|zip|tar|exe)$/i.test(t)) return t.toLowerCase()
  return null
}

/** Hosts alvo de um comando de shell (URLs em qualquer lugar + argumentos de comandos de rede). */
export function hostsInCommand(command) {
  const hosts = new Set()
  for (const m of String(command).matchAll(/\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`|;&)<>]+/gi)) {
    const h = extractHost(m[0])
    if (h) hosts.add(h)
  }
  const commands = []
  for (const seg of String(command).split(/&&|\|\||[;|\n]|\$\(|`/)) {
    const tokens = seg.trim().split(/\s+/).filter(Boolean)
    while (tokens.length && /^(sudo|env|time|nohup|timeout|\w+=\S*)$/.test(tokens[0])) tokens.shift()
    if (!tokens.length) continue
    const cmd = path.basename(tokens[0]).replace(/\.exe$/i, '')
    commands.push(cmd)
    if (!NET_COMMANDS.has(cmd)) continue
    for (let i = 1; i < tokens.length; i++) {
      const tok = tokens[i]
      if (/^-connect$/.test(tok) && tokens[i + 1]) {
        const h = extractHost(tokens[++i])
        if (h) hosts.add(h)
        continue
      }
      const eq = /^--?[a-z-]+=(.+)$/i.exec(tok)
      const h = extractHost(eq ? eq[1] : tok)
      if (h) hosts.add(h)
    }
  }
  return { hosts: [...hosts], commands }
}

function collectMcpTargets(input, out = []) {
  if (!input || typeof input !== 'object') return out
  for (const [k, v] of Object.entries(input)) {
    if (v == null) continue
    if (MCP_TARGET_KEYS.includes(k.toLowerCase())) {
      for (const item of Array.isArray(v) ? v : [v]) {
        for (const part of String(item).split(/[\s,]+/)) {
          const h = extractHost(part)
          if (h) out.push(h)
        }
      }
    } else if (typeof v === 'object') collectMcpTargets(v, out)
  }
  return out
}

/** Decide sobre uma chamada de ferramenta. Retorna { decision: 'allow'|'deny', reason? }. */
export function decide({ tool_name: tool, tool_input: input = {}, cwd }, { audit, mode }) {
  const scope = audit.scope
  const deny = reason => ({ decision: 'deny', reason: `VION: bloqueado — ${reason} (auditoria ${audit.id}). Nao tente contornar; registre como limitacao.` })
  const checkHosts = (hosts, label) => {
    const outside = hosts.filter(h => !hostAllowed(scope, h))
    return outside.length ? deny(`${label} fora do escopo: ${outside.join(', ')}`) : null
  }

  if (tool.startsWith('mcp__vion__')) return { decision: 'allow' }

  if (READ_TOOLS[tool]) {
    if (mode !== 'strict') return { decision: 'allow' }
    const p = input[READ_TOOLS[tool]] || cwd
    const abs = path.resolve(cwd || process.cwd(), String(p))
    if (!pathAllowed(scope, abs, [path.join(PKG_ROOT, 'assets')])) return deny(`leitura fora do escopo: ${abs}`)
    return { decision: 'allow' }
  }

  if (WRITE_TOOLS.has(tool)) {
    if (mode === 'strict') return deny('auditoria e somente leitura; use /vion:corrigir ou /vion:fixes depois')
    return { decision: 'allow' }
  }

  if (tool === 'Bash' || tool === 'PowerShell') {
    const { hosts, commands } = hostsInCommand(input.command || '')
    const active = commands.filter(c => ACTIVE_COMMANDS.has(c))
    if (active.length && !scope.active) return deny(`teste ativo (${active.join(', ')}) sem autorizacao de teste ativo no escopo`)
    return checkHosts(hosts, 'host') || { decision: 'allow' }
  }

  if (tool === 'WebFetch') return checkHosts([extractHost(input.url)].filter(Boolean), 'URL') || { decision: 'allow' }
  if (tool === 'WebSearch') return mode === 'strict' ? deny('busca na web desativada durante auditoria headless') : { decision: 'allow' }

  if (tool.startsWith('mcp__')) return checkHosts(collectMcpTargets(input), 'alvo de ferramenta MCP') || { decision: 'allow' }

  return { decision: 'allow' }
}

function log(entry) {
  try {
    fs.appendFileSync(path.join(ensureHome().logs, 'hook.log'), JSON.stringify({ at: new Date().toISOString(), ...entry }) + '\n')
  } catch {
    // log best-effort
  }
}

function anyActive() {
  if (process.env.VION_AUDIT_ID) return true
  try {
    return fs.readdirSync(path.join(ensureHome().audits, 'active')).length > 0
  } catch {
    return false
  }
}

export async function runHook() {
  if (!anyActive()) return // caminho rapido: nenhuma auditoria ativa, nem abre o banco
  let raw = ''
  for await (const chunk of process.stdin) raw += chunk
  let input
  try {
    input = JSON.parse(raw || '{}')
  } catch {
    return // entrada invalida: nao interfere
  }
  let active
  try {
    active = resolveActiveAudit({ env: process.env, cwd: input.cwd || process.cwd() })
  } catch (err) {
    log({ error: err.message })
    return
  }
  if (!active) return
  const result = decide(input, active)
  if (result.decision === 'deny') {
    log({ audit: active.audit.id, mode: active.mode, tool: input.tool_name, decision: 'deny', reason: result.reason })
    try {
      addEvent(active.audit.id, 'hook.denied', { tool: input.tool_name, reason: result.reason })
    } catch {
      // evento best-effort
    }
    process.stdout.write(
      JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'deny', permissionDecisionReason: result.reason } }),
    )
  }
}
