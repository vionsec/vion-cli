// ── Runner headless: executa o orquestrador via `claude -p` e alimenta o store ──
// MCP, hook de escopo e subagentes sao injetados por execucao (--mcp-config, --settings,
// --agents), entao a auditoria headless nao depende do que estiver em ~/.claude.

import fs from 'node:fs'
import path from 'node:path'
import { spawn, spawnSync, execFileSync } from 'node:child_process'
import { PKG_ROOT, ensureHome } from './paths.js'
import { loadConfig } from './config.js'
import { getAudit, updateAudit, addEvent, listAudits, listTasks, updateTask, deleteAudit } from './store.js'
import { runAnalyzersForAudit, runDependencyAuditForAudit, finalizeAudit } from './engine.js'
import { renderOrchestrator, skillPrompt, agentsJson } from './prompts.js'
import { getSkill } from '../cli/skills-meta.js'
import { DEFAULT_AUDIT_PLAN, listChecklists } from './checklists.js'
import { HOOK_MATCHER, vionInvocation } from './install.js'

const BIN = path.join(PKG_ROOT, 'bin', 'vion.js')

// ── localizar o claude ──

let claudeCache
export function resolveClaude() {
  if (claudeCache !== undefined) return claudeCache
  claudeCache = null
  if (process.env.VION_CLAUDE_BIN) return (claudeCache = { file: process.env.VION_CLAUDE_BIN, shell: /\.(cmd|bat)$/i.test(process.env.VION_CLAUDE_BIN) })
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('where.exe', ['claude'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).split(/\r?\n/).filter(Boolean)
      const exe = out.find(p => /\.exe$/i.test(p))
      const cmd = out.find(p => /\.(cmd|bat)$/i.test(p))
      if (exe) claudeCache = { file: exe, shell: false }
      else if (cmd) claudeCache = { file: cmd, shell: true }
    } else {
      const p = execFileSync('sh', ['-c', 'command -v claude'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
      if (p) claudeCache = { file: p, shell: false }
    }
  } catch {
    // nao encontrado
  }
  return claudeCache
}

let featureCache
function claudeFeatures(bin) {
  if (featureCache) return featureCache
  const res = spawnSync(bin.shell ? `"${bin.file}" --help` : bin.file, bin.shell ? [] : ['--help'], { encoding: 'utf8', shell: bin.shell, timeout: 30000 })
  const help = res.stdout || ''
  featureCache = { restricted: help.includes('--restricted'), budget: help.includes('--max-budget-usd'), agents: help.includes('--agents') }
  return featureCache
}

// ── plano de prompt ──

/** Decide o prompt a partir das skills pedidas. */
export function buildPrompt(audit, skills, focus = '') {
  const args = [`audit_id=${audit.id}`, focus].filter(Boolean).join(' ')
  const checklistNames = new Set(listChecklists().map(c => c.name))
  const list = skills.length ? skills : ['auditoria']
  if (list.length === 1 && list[0] === 'auditoria') return { kind: 'orchestrated', prompt: renderOrchestrator({ skill: 'auditoria', plan: DEFAULT_AUDIT_PLAN }).replaceAll('$ARGUMENTS', args) }
  if (list.length === 1 && getSkill(list[0]) && !getSkill(list[0]).orchestrated && !checklistNames.has(list[0])) {
    return { kind: 'single', prompt: `${skillPrompt(list[0], args)}\n\nO audit_id desta execucao e ${audit.id}: use-o em todas as chamadas mcp__vion__* (nao abra outra auditoria).` }
  }
  const plan = list.flatMap(s => (s === 'auditoria' ? DEFAULT_AUDIT_PLAN : [s]))
  for (const p of plan) if (!checklistNames.has(p)) throw new Error(`"${p}" nao pode ser orquestrada. Checklists validas: ${[...checklistNames].join(', ')}`)
  return { kind: 'orchestrated', prompt: renderOrchestrator({ skill: 'orquestrar', plan: [...new Set(plan)] }).replaceAll('$ARGUMENTS', `${args} plano=${[...new Set(plan)].join(',')}`) }
}

function toolsFor(scope) {
  const tools = ['Read', 'Grep', 'Glob', 'Agent', 'Bash']
  const allowed = [
    'Read', 'Grep', 'Glob', 'Agent', 'Task', 'mcp__vion',
    'Bash(npm audit:*)', 'Bash(pnpm audit:*)', 'Bash(yarn audit:*)', 'Bash(yarn npm audit:*)', 'Bash(pip-audit:*)', 'Bash(npm ls:*)',
    'Bash(npm outdated:*)', 'Bash(git log:*)', 'Bash(git ls-files:*)', 'Bash(git status:*)', 'Bash(ls:*)', 'Bash(which:*)', 'Bash(command -v:*)',
  ]
  if (scope.hosts.length || scope.cidrs.length) {
    tools.push('WebFetch')
    allowed.push('WebFetch', 'Bash(curl:*)', 'Bash(dig:*)', 'Bash(nslookup:*)', 'Bash(host:*)', 'Bash(whois:*)', 'Bash(openssl s_client:*)', 'Bash(openssl x509:*)', 'Bash(whatweb:*)')
    if (scope.active) allowed.push('Bash(nmap:*)', 'Bash(nikto:*)', 'Bash(testssl.sh:*)', 'Bash(sslscan:*)', 'Bash(ffuf:*)', 'Bash(gobuster:*)', 'Bash(nuclei:*)')
  }
  return { tools, allowed }
}

// ── controle de processos ──

function alive(pid) {
  if (!pid) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return err.code === 'EPERM'
  }
}

export function killTree(pid) {
  if (!pid) return
  try {
    if (process.platform === 'win32') spawnSync('taskkill', ['/pid', String(pid), '/T', '/F'], { stdio: 'ignore' })
    else process.kill(-pid, 'SIGTERM')
  } catch {
    try {
      process.kill(pid, 'SIGTERM')
    } catch {
      // ja terminou
    }
  }
}

export function runningAudits() {
  return listAudits({ status: 'running', limit: 100 }).filter(a => a.origin !== 'session' && alive(a.pid))
}

/** Marca como falhas auditorias "running" cujo processo morreu (ex.: maquina reiniciou). */
export function reapOrphans() {
  for (const a of listAudits({ status: 'running', limit: 200 })) {
    if (a.origin === 'session') continue
    if (!alive(a.pid)) {
      for (const t of listTasks(a.id)) if (t.status === 'running') updateTask(t.id, { status: 'failed', error: 'processo encerrado' })
      try {
        finalizeAudit(a.id, { status: 'failed', error: 'Processo da auditoria encerrou inesperadamente.' })
      } catch {
        updateAudit(a.id, { status: 'failed', error: 'Processo da auditoria encerrou inesperadamente.' })
      }
    }
  }
  // auditorias pendentes que nunca iniciaram
  for (const a of listAudits({ status: 'pending', limit: 200 })) {
    if (a.origin !== 'session' && Date.now() - Date.parse(a.created_at) > 10 * 60 * 1000) updateAudit(a.id, { status: 'failed', error: 'Nao iniciou.' })
  }
  applyRetention()
}

/** Politica de retencao (retention.days > 0): apaga auditorias encerradas mais antigas. */
export function applyRetention(cfg = loadConfig()) {
  const days = Number(cfg.retention?.days) || 0
  if (days <= 0) return 0
  const limit = Date.now() - days * 86400000
  const old = listAudits({ limit: 100000 }).filter(a => ['completed', 'failed', 'stopped'].includes(a.status) && Date.parse(a.finished_at || a.updated_at) < limit)
  for (const a of old) deleteAudit(a.id)
  return old.length
}

/** Dispara o worker desacoplado (sobrevive ao fechamento da UI/terminal). */
export function launchWorker(auditId, { skills = [], focus = '', analyzersOnly = false, maxCost = null } = {}) {
  const cfg = loadConfig()
  reapOrphans()
  if (runningAudits().length >= cfg.limits.maxConcurrentAudits) {
    throw new Error(`Limite de auditorias simultaneas (${cfg.limits.maxConcurrentAudits}) atingido. Pare uma com \`vion audit stop <id>\` ou ajuste limits.maxConcurrentAudits.`)
  }
  const home = ensureHome()
  const workDir = path.join(home.audits, auditId)
  fs.mkdirSync(workDir, { recursive: true })
  fs.writeFileSync(path.join(workDir, 'job.json'), JSON.stringify({ skills, focus, analyzersOnly, maxCost }))
  const log = fs.openSync(path.join(workDir, 'worker.log'), 'a')
  const child = spawn(process.execPath, [BIN, 'worker', auditId], {
    detached: true,
    stdio: ['ignore', log, log],
    windowsHide: true,
    env: { ...process.env, VION_HOME: home.root },
  })
  child.unref()
  updateAudit(auditId, { pid: child.pid })
  return child.pid
}

export function stopAudit(auditId) {
  const a = getAudit(auditId)
  if (!a) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  if (!['running', 'pending'].includes(a.status)) return a
  updateAudit(auditId, { status: 'stopped' })
  addEvent(auditId, 'audit.stop_requested', {})
  if (a.origin !== 'session') killTree(a.pid)
  for (const t of listTasks(auditId)) if (t.status === 'running') updateTask(t.id, { status: 'failed', error: 'interrompida pelo usuario' })
  try {
    finalizeAudit(auditId, { status: 'stopped' })
  } catch {
    // relatorio best-effort
  }
  return getAudit(auditId)
}

// ── worker (roda dentro do processo desacoplado) ──

function shortInput(name, input = {}) {
  if (name === 'Task' || name === 'Agent') return { subagent: input.subagent_type, description: input.description }
  if (name === 'Read') return { file: input.file_path }
  if (name === 'Grep') return { pattern: String(input.pattern || '').slice(0, 80), path: input.path }
  if (name === 'Glob') return { pattern: input.pattern }
  if (name === 'Bash') return { command: String(input.command || '').slice(0, 160) }
  if (name === 'WebFetch') return { url: input.url }
  if (name.startsWith('mcp__vion__')) {
    const keep = ['audit_id', 'task_id', 'name', 'id', 'severity', 'status', 'title', 'checklist']
    return Object.fromEntries(Object.entries(input).filter(([k]) => keep.includes(k)).map(([k, v]) => [k, String(v).slice(0, 120)]))
  }
  return {}
}

export async function runWorker(auditId) {
  const audit = getAudit(auditId)
  if (!audit) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  const home = ensureHome()
  const workDir = path.join(home.audits, auditId)
  const job = JSON.parse(fs.readFileSync(path.join(workDir, 'job.json'), 'utf8'))
  const cfg = loadConfig()
  updateAudit(auditId, { status: 'running', pid: process.pid })

  // 1) analisadores deterministicos: resultado imediato na UI e 0 tokens
  if (audit.scope.paths.length) {
    addEvent(auditId, 'phase', { name: 'analisadores', status: 'running' })
    const res = await runAnalyzersForAudit(auditId)
    addEvent(auditId, 'phase', { name: 'analisadores', status: 'done', added: res.added })
    addEvent(auditId, 'phase', { name: 'dependencias', status: 'running' })
    try {
      const deps = runDependencyAuditForAudit(auditId)
      addEvent(auditId, 'phase', { name: 'dependencias', status: 'done', added: deps.added })
    } catch (err) {
      addEvent(auditId, 'warning', { message: `audit de dependencias falhou: ${err.message}` })
    }
  }
  if (job.analyzersOnly) {
    finalizeAudit(auditId, { summary: 'Somente analisadores deterministicos (sem agentes de IA). Achados permanecem como suspeitos ate validacao.' })
    return
  }

  // 2) claude headless
  const bin = resolveClaude()
  if (!bin) {
    finalizeAudit(auditId, { status: 'failed', error: 'Claude Code (`claude`) nao encontrado no PATH. Instale ou defina VION_CLAUDE_BIN.' })
    return
  }
  const features = claudeFeatures(bin)
  const { prompt, kind } = buildPrompt(audit, job.skills || [], job.focus || '')
  const { tools, allowed } = toolsFor(audit.scope)
  const mcpInv = vionInvocation('mcp')
  const env = { ...process.env, VION_AUDIT_ID: auditId, VION_HOME: home.root }
  fs.writeFileSync(path.join(workDir, 'prompt.md'), prompt)
  fs.writeFileSync(
    path.join(workDir, 'mcp.json'),
    JSON.stringify({ mcpServers: { vion: { type: 'stdio', command: mcpInv.command, args: mcpInv.args, env: { VION_AUDIT_ID: auditId, VION_HOME: home.root } } } }, null, 2),
  )
  fs.writeFileSync(
    path.join(workDir, 'settings.json'),
    JSON.stringify({ hooks: { PreToolUse: [{ matcher: HOOK_MATCHER, hooks: [{ type: 'command', command: vionInvocation('hook').shell, timeout: 15 }] }] } }, null, 2),
  )
  fs.writeFileSync(path.join(workDir, 'agents.json'), JSON.stringify(agentsJson(cfg.models), null, 2))

  const maxCost = Number(job.maxCost ?? cfg.limits.maxCostUsd)
  const args = [
    '-p',
    '--output-format', 'stream-json',
    '--verbose',
    '--model', cfg.models.orquestrador === 'inherit' ? 'opus' : cfg.models.orquestrador,
    '--permission-mode', 'dontAsk',
    '--strict-mcp-config',
    '--mcp-config', path.join(workDir, 'mcp.json'),
    '--settings', path.join(workDir, 'settings.json'),
    '--tools', tools.join(','),
    '--allowedTools', ...allowed,
  ]
  if (features.agents) args.push('--agents', path.join(workDir, 'agents.json'))
  if (features.budget && maxCost > 0) args.push('--max-budget-usd', String(maxCost))
  if (features.restricted) args.push('--restricted')
  const cwd = audit.scope.paths[0] || workDir
  for (const extra of audit.scope.paths.slice(1)) args.push('--add-dir', extra)

  addEvent(auditId, 'phase', { name: kind === 'orchestrated' ? 'orquestrador' : 'agente', status: 'running', model: cfg.models.orquestrador })
  const quote = a => (/[\s"&()<>^|]/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a)
  const child = bin.shell
    ? spawn([quote(bin.file), ...args.map(quote)].join(' '), { cwd, env, shell: true, windowsHide: true })
    : spawn(bin.file, args, { cwd, env, windowsHide: true })
  child.stdin.end(prompt)

  const usage = {}
  let result = null
  let mcpOk = null
  let stderrTail = ''
  let buffer = ''
  let lastFlush = 0
  const flushUsage = (force = false) => {
    if (!force && Date.now() - lastFlush < 3000) return
    lastFlush = Date.now()
    const tot = Object.values(usage).reduce((a, u) => ({ input: a.input + u.inputTokens, output: a.output + u.outputTokens, cache: a.cache + u.cacheReadInputTokens }), { input: 0, output: 0, cache: 0 })
    updateAudit(auditId, { input_tokens: tot.input, output_tokens: tot.output, cache_read_tokens: tot.cache, usage_json: JSON.stringify(usage) })
  }

  const onLine = line => {
    let m
    try {
      m = JSON.parse(line)
    } catch {
      return
    }
    if (m.type === 'system' && m.subtype === 'init') {
      if (mcpOk !== null) return // o init se repete a cada turno; registra so o primeiro
      const vion = (m.mcp_servers || []).find(s => s.name === 'vion')
      mcpOk = vion?.status === 'connected'
      addEvent(auditId, 'claude.init', { model: m.model, session_id: m.session_id, mcp: vion?.status || 'ausente', tools: m.tools?.length })
      if (!mcpOk) {
        addEvent(auditId, 'error', { message: `MCP vion nao conectou (${vion?.status || 'ausente'})` })
        killTree(child.pid)
      }
      return
    }
    if (m.type === 'assistant' && m.message) {
      const model = m.message.model || 'desconhecido'
      const u = m.message.usage
      if (u) {
        const acc = (usage[model] ??= { inputTokens: 0, outputTokens: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0, costUSD: null })
        acc.inputTokens += u.input_tokens || 0
        acc.outputTokens += u.output_tokens || 0
        acc.cacheReadInputTokens += u.cache_read_input_tokens || 0
        acc.cacheCreationInputTokens += u.cache_creation_input_tokens || 0
        flushUsage()
      }
      const sub = !!m.parent_tool_use_id
      for (const block of m.message.content || []) {
        if (block.type === 'tool_use') {
          addEvent(auditId, 'agent.tool', { model, sub, tool: block.name, input: shortInput(block.name, block.input) })
        } else if (block.type === 'text' && block.text?.trim() && !sub) {
          addEvent(auditId, 'orchestrator.text', { model, text: block.text.slice(0, 1200) })
        }
      }
      return
    }
    if (m.type === 'result') result = m
  }

  child.stdout.on('data', d => {
    buffer += d
    let i
    while ((i = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, i).trim()
      buffer = buffer.slice(i + 1)
      if (line) onLine(line)
    }
  })
  child.stderr.on('data', d => {
    stderrTail = (stderrTail + d).slice(-4000)
  })

  const timeout = setTimeout(() => {
    addEvent(auditId, 'error', { message: `Tempo limite de ${cfg.limits.timeoutMinutes} min atingido` })
    killTree(child.pid)
  }, cfg.limits.timeoutMinutes * 60 * 1000)

  const code = await new Promise(resolve => {
    child.on('error', err => {
      stderrTail += `\n${err.message}`
      resolve(-1)
    })
    child.on('close', resolve)
  })
  clearTimeout(timeout)
  if (buffer.trim()) onLine(buffer.trim())

  // 3) fechamento
  if (result?.modelUsage) {
    for (const [model, mu] of Object.entries(result.modelUsage)) usage[model] = { ...mu }
  }
  const tot = Object.values(usage).reduce((a, u) => ({ input: a.input + (u.inputTokens || 0), output: a.output + (u.outputTokens || 0), cache: a.cache + (u.cacheReadInputTokens || 0) }), { input: 0, output: 0, cache: 0 })
  updateAudit(auditId, {
    input_tokens: tot.input,
    output_tokens: tot.output,
    cache_read_tokens: tot.cache,
    cost_usd: result?.total_cost_usd ?? null,
    usage_json: JSON.stringify(usage),
  })
  for (const t of listTasks(auditId)) if (t.status === 'running') updateTask(t.id, { status: 'failed', error: 'tarefa nao concluida ao fim da execucao' })

  const current = getAudit(auditId)
  if (current.status === 'stopped') return
  const budgetHit = result?.subtype === 'error_max_budget_usd' || /budget/i.test(result?.subtype || '')
  if (mcpOk === false) {
    finalizeAudit(auditId, { status: 'failed', error: 'O servidor MCP vion nao conectou no Claude Code. Rode `vion doctor`.' })
  } else if (budgetHit) {
    finalizeAudit(auditId, { status: 'completed', summary: current.summary || `Encerrada ao atingir o teto de custo (US$ ${maxCost}). Resultados parciais.` })
    addEvent(auditId, 'warning', { message: 'teto de custo atingido; resultados parciais' })
  } else if (code !== 0 || result?.is_error) {
    const msg = result?.result || result?.subtype || stderrTail.trim().split('\n').slice(-3).join(' ') || `claude saiu com codigo ${code}`
    finalizeAudit(auditId, { status: 'failed', error: String(msg).slice(0, 1000) })
  } else {
    finalizeAudit(auditId, { summary: current.summary || (result?.result ? String(result.result).slice(0, 4000) : null) })
  }
}
