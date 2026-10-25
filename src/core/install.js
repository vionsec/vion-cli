// ── Instalacao no Claude Code: skills, subagentes, MCP e hook ──

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { PKG_ROOT, claudeHome } from './paths.js'
import { loadConfig } from './config.js'
import { VERSION } from './version.js'

export const HOOK_MATCHER = 'Bash|PowerShell|Read|Grep|Glob|LS|Write|Edit|MultiEdit|NotebookEdit|WebFetch|WebSearch|mcp__.*'
const SKILLS_SRC = path.join(PKG_ROOT, 'assets', 'skills')
const AGENTS_SRC = path.join(PKG_ROOT, 'assets', 'agents')
const BIN = path.join(PKG_ROOT, 'bin', 'vion.js')

const fwd = p => p.replace(/\\/g, '/')

export function targets({ project = false, cwd = process.cwd() } = {}) {
  const base = project ? path.join(cwd, '.claude') : claudeHome()
  return {
    base,
    project,
    commands: path.join(base, 'commands', 'vion'),
    agents: path.join(base, 'agents'),
    settings: path.join(base, 'settings.json'),
    manifest: path.join(base, 'vion', 'manifest.json'),
  }
}

/** Comando que o Claude Code usa para chamar o VION (absoluto: nao depende do PATH). */
export function vionInvocation(sub) {
  return { command: process.execPath, args: [BIN, sub], shell: `"${fwd(process.execPath)}" "${fwd(BIN)}" ${sub}` }
}

export function readManifest(t) {
  try {
    return JSON.parse(fs.readFileSync(t.manifest, 'utf8'))
  } catch {
    return null
  }
}

export function renderAgent(file, cfg = loadConfig()) {
  const role = path.basename(file, '.md').replace(/^vion-/, '')
  const model = cfg.models[role] || 'inherit'
  return fs.readFileSync(file, 'utf8').replace('{{MODEL}}', model)
}

function stamp() {
  return new Date().toISOString().replace(/[-:]/g, '').replace(/\..*/, '').replace('T', '-')
}

// ── settings.json (hook) ──

function isVionHook(h) {
  return typeof h?.command === 'string' && /vion(\.js)?"?\s+hook\s*$/.test(h.command)
}

export function readSettings(file) {
  if (!fs.existsSync(file)) return {}
  const raw = fs.readFileSync(file, 'utf8')
  try {
    return raw.trim() ? JSON.parse(raw) : {}
  } catch {
    throw new Error(`settings.json invalido: ${file}. Corrija o JSON; o VION nao sobrescreve arquivo invalido.`)
  }
}

export function withVionHook(settings, command) {
  const s = structuredClone(settings)
  s.hooks ??= {}
  const list = (s.hooks.PreToolUse ??= [])
  for (const entry of list) if (Array.isArray(entry.hooks)) entry.hooks = entry.hooks.filter(h => !isVionHook(h))
  s.hooks.PreToolUse = list.filter(e => !Array.isArray(e.hooks) || e.hooks.length)
  s.hooks.PreToolUse.push({ matcher: HOOK_MATCHER, hooks: [{ type: 'command', command, timeout: 15 }] })
  return s
}

export function withoutVionHook(settings) {
  const s = structuredClone(settings)
  if (!s.hooks?.PreToolUse) return s
  for (const entry of s.hooks.PreToolUse) if (Array.isArray(entry.hooks)) entry.hooks = entry.hooks.filter(h => !isVionHook(h))
  s.hooks.PreToolUse = s.hooks.PreToolUse.filter(e => !Array.isArray(e.hooks) || e.hooks.length)
  if (!s.hooks.PreToolUse.length) delete s.hooks.PreToolUse
  if (!Object.keys(s.hooks).length) delete s.hooks
  return s
}

export function hasVionHook(settings) {
  return (settings.hooks?.PreToolUse || []).some(e => (e.hooks || []).some(isVionHook))
}

// ── claude CLI ──

function quoteWin(a) {
  return /[\s"&()<>^|]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a
}

export function runClaude(args, opts = {}) {
  const win = process.platform === 'win32'
  const res = win
    ? spawnSync(['claude', ...args].map(quoteWin).join(' '), { shell: true, encoding: 'utf8', timeout: 60000, ...opts })
    : spawnSync('claude', args, { encoding: 'utf8', timeout: 60000, ...opts })
  return { ok: res.status === 0, status: res.status, stdout: res.stdout || '', stderr: res.stderr || '', error: res.error }
}

export function claudeAvailable() {
  const r = runClaude(['--version'])
  return r.ok ? r.stdout.trim() : null
}

// ── install / uninstall ──

export function install({ project = false, mcp = true, hook = true, dryRun = false, cwd = process.cwd() } = {}) {
  const t = targets({ project, cwd })
  const cfg = loadConfig()
  const actions = []
  const previous = readManifest(t)

  // skills
  const skillFiles = fs.readdirSync(SKILLS_SRC).filter(f => f.endsWith('.md'))
  if (fs.existsSync(t.commands) && !previous) {
    const bak = path.join(path.dirname(t.commands), `vion.bak-${stamp()}`)
    actions.push(`backup: ${t.commands} -> ${bak}`)
    if (!dryRun) fs.renameSync(t.commands, bak)
  }
  if (!dryRun) {
    fs.mkdirSync(t.commands, { recursive: true })
    for (const old of previous?.skills || []) if (!skillFiles.includes(old)) fs.rmSync(path.join(t.commands, old), { force: true })
    for (const f of skillFiles) fs.copyFileSync(path.join(SKILLS_SRC, f), path.join(t.commands, f))
  }
  actions.push(`skills: ${skillFiles.length} arquivos em ${t.commands}`)

  // agents
  const agentFiles = fs.readdirSync(AGENTS_SRC).filter(f => f.endsWith('.md'))
  if (!dryRun) {
    fs.mkdirSync(t.agents, { recursive: true })
    for (const f of agentFiles) fs.writeFileSync(path.join(t.agents, f), renderAgent(path.join(AGENTS_SRC, f), cfg))
  }
  actions.push(`agentes: ${agentFiles.map(f => `${f.replace('.md', '')}(${cfg.models[f.replace(/^vion-|\.md$/g, '')] || 'inherit'})`).join(', ')}`)

  // hook
  let hookOk = null
  if (hook) {
    const settings = readSettings(t.settings)
    const next = withVionHook(settings, vionInvocation('hook').shell)
    if (!dryRun) {
      fs.mkdirSync(path.dirname(t.settings), { recursive: true })
      if (fs.existsSync(t.settings) && !previous) fs.copyFileSync(t.settings, `${t.settings}.bak-${stamp()}`)
      fs.writeFileSync(t.settings, JSON.stringify(next, null, 2) + '\n')
    }
    hookOk = true
    actions.push(`hook PreToolUse: ${t.settings}`)
  }

  // mcp
  let mcpOk = null
  let mcpManual = null
  if (mcp) {
    const inv = vionInvocation('mcp')
    const scope = project ? 'project' : 'user'
    mcpManual = `claude mcp add vion -s ${scope} -- "${inv.command}" "${inv.args[0]}" mcp`
    if (dryRun) {
      actions.push(`mcp: ${mcpManual}`)
    } else if (!claudeAvailable()) {
      mcpOk = false
      actions.push(`mcp: \`claude\` nao encontrado. Registre depois com: ${mcpManual}`)
    } else {
      runClaude(['mcp', 'remove', 'vion', '-s', scope], { cwd })
      const r = runClaude(['mcp', 'add', 'vion', '-s', scope, '--', inv.command, ...inv.args], { cwd })
      mcpOk = r.ok
      actions.push(r.ok ? `mcp: servidor "vion" registrado (escopo ${scope})` : `mcp: falhou (${(r.stderr || r.stdout).trim().slice(0, 200)}). Rode: ${mcpManual}`)
    }
  }

  if (!dryRun) {
    fs.mkdirSync(path.dirname(t.manifest), { recursive: true })
    fs.writeFileSync(
      t.manifest,
      JSON.stringify({ version: VERSION, installedAt: new Date().toISOString(), skills: skillFiles, agents: agentFiles, models: cfg.models, hook: !!hookOk, mcp: !!mcpOk, project, bin: BIN }, null, 2),
    )
  }
  return { targets: t, actions, mcpOk, hookOk, mcpManual }
}

export function uninstall({ project = false, cwd = process.cwd() } = {}) {
  const t = targets({ project, cwd })
  const m = readManifest(t)
  const actions = []
  if (fs.existsSync(t.commands)) {
    fs.rmSync(t.commands, { recursive: true, force: true })
    actions.push(`removido: ${t.commands}`)
  }
  for (const f of m?.agents || fs.readdirSync(AGENTS_SRC)) {
    const p = path.join(t.agents, f)
    if (fs.existsSync(p)) {
      fs.rmSync(p)
      actions.push(`removido: ${p}`)
    }
  }
  if (fs.existsSync(t.settings)) {
    const s = readSettings(t.settings)
    if (hasVionHook(s)) {
      fs.writeFileSync(t.settings, JSON.stringify(withoutVionHook(s), null, 2) + '\n')
      actions.push(`hook removido de ${t.settings}`)
    }
  }
  if (claudeAvailable()) {
    const r = runClaude(['mcp', 'remove', 'vion', '-s', project ? 'project' : 'user'], { cwd })
    actions.push(r.ok ? 'mcp "vion" removido' : 'mcp "vion" nao estava registrado')
  }
  fs.rmSync(path.dirname(t.manifest), { recursive: true, force: true })
  return actions
}
