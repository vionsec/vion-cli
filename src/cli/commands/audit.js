import fs from 'node:fs'
import path from 'node:path'
import { startAudit, uiUrl } from '../../core/engine.js'
import { launchWorker, stopAudit, reapOrphans } from '../../core/runner.js'
import { getAudit, listAudits, listTasks, eventsSince, listFindings } from '../../core/store.js'
import { auditSummary } from '../../core/report.js'
import { c, table, printJson, SEV_COLOR, SEV_PT } from '../term.js'

const sleep = ms => new Promise(r => setTimeout(r, ms))
const TERMINAL = ['completed', 'failed', 'stopped']

function fmtCost(a) {
  return a.cost_usd != null ? `US$ ${a.cost_usd.toFixed(4)}` : a.input_tokens ? `${a.input_tokens + a.output_tokens} tokens` : '—'
}

function printEvent(e) {
  const d = e.data
  const t = new Date(e.created_at).toLocaleTimeString()
  const line = s => console.log(`${c.dim(t)} ${s}`)
  switch (e.type) {
    case 'phase':
      return line(`${c.cyan('fase')} ${d.name}: ${d.status}${d.added != null ? ` (${d.added} achados)` : ''}${d.model ? ` [${d.model}]` : ''}`)
    case 'claude.init':
      return line(`${c.cyan('claude')} sessao ${d.session_id?.slice(0, 8)} · modelo ${d.model} · MCP vion: ${d.mcp === 'connected' ? c.green(d.mcp) : c.red(d.mcp)}`)
    case 'task.created':
      return line(`${c.blue('plano')} ${d.agent}${d.model ? ` (${d.model})` : ''}: ${d.title}`)
    case 'task.updated':
      return d.status && d.status !== 'running' ? line(`${d.status === 'done' ? c.green('ok') : c.yellow(d.status)} tarefa ${d.agent}`) : line(`${c.blue('>>')} ${d.agent} iniciou`)
    case 'agent.tool':
      if (d.tool === 'Task' || d.tool === 'Agent') return line(`${c.magenta('delegou')} ${d.input.subagent}: ${d.input.description || ''}`)
      return undefined
    case 'finding.added':
      return ['critical', 'high'].includes(d.severity) ? line(`${SEV_COLOR[d.severity](SEV_PT[d.severity])} ${d.title} ${c.dim(`(${d.agent})`)}`) : undefined
    case 'finding.updated':
      return d.status ? line(`${d.status === 'confirmed' ? c.green('confirmado') : d.status === 'false_positive' ? c.dim('falso positivo') : d.status} ${c.dim(d.id)}`) : undefined
    case 'hook.denied':
      return line(`${c.red('bloqueado')} ${d.tool}: ${d.reason}`)
    case 'error':
    case 'warning':
      return line(`${c.red(e.type)} ${d.message}`)
    case 'audit.status':
      return line(`${c.bold('status')} ${d.status}${d.error ? `: ${d.error}` : ''}`)
    default:
      return undefined
  }
}

async function follow(id) {
  let last = 0
  let stopping = false
  const onSig = () => {
    if (stopping) process.exit(130)
    stopping = true
    console.log(c.yellow('\nInterrompendo a auditoria... (Ctrl+C de novo para sair sem esperar)'))
    stopAudit(id)
  }
  process.on('SIGINT', onSig)
  for (;;) {
    for (const e of eventsSince(last, id, 500)) {
      last = e.id
      printEvent(e)
    }
    const a = getAudit(id)
    if (TERMINAL.includes(a.status)) break
    await sleep(800)
  }
  process.off('SIGINT', onSig)
  return getAudit(id)
}

function printResult(a) {
  const s = auditSummary(a.id)
  console.log('')
  console.log(c.bold(`Auditoria ${a.id} — ${a.status}`))
  if (a.error) console.log(c.red(`  erro: ${a.error}`))
  console.log(`  score ${s.score}/100 · ${Object.entries(s.counts).filter(([, n]) => n).map(([k, n]) => SEV_COLOR[k](`${n} ${SEV_PT[k]}`)).join(' · ') || 'nenhum achado'}`)
  console.log(`  ${s.by_status.confirmed} confirmados · ${s.by_status.suspected} suspeitos · ${s.by_status.false_positive} falsos positivos`)
  console.log(`  custo: ${fmtCost(a)}`)
  if (a.usage) for (const [m, u] of Object.entries(a.usage)) console.log(c.dim(`    ${m}: ${u.inputTokens} in / ${u.outputTokens} out${u.costUSD != null ? ` · US$ ${Number(u.costUSD).toFixed(4)}` : ''}`))
  console.log(`  pagina: ${c.cyan(uiUrl(a.id))}  ${c.dim('(vion ui)')}`)
  console.log(`  relatorio: ${c.cyan(`vion report ${a.id} --format html --open`)}`)
}

export async function run({ positionals, values }) {
  const [first, second] = positionals
  if (!first && !values.scope) throw new Error('Informe o alvo: vion audit <diretorio|url>  (veja `vion help audit`)')

  if (first === 'history') {
    reapOrphans()
    const rows = listAudits({ limit: Number(values.limit) || 20 })
    if (values.json) return printJson(rows.map(({ scope_json, models_json, plan_json, usage_json, ...r }) => r))
    if (!rows.length) return console.log('Nenhuma auditoria ainda. Comece com `vion audit .`')
    return console.log(
      table(
        rows.map(a => {
          const fs_ = listFindings(a.id)
          return [a.id, a.created_at.slice(0, 16).replace('T', ' '), a.status, a.skills || '—', a.score ?? '—', fs_.length, fmtCost(a), a.target.length > 40 ? `…${a.target.slice(-39)}` : a.target]
        }),
        ['ID', 'Criada', 'Status', 'Skills', 'Score', 'Achados', 'Custo', 'Alvo'],
      ),
    )
  }
  if (first === 'status') {
    if (!second) throw new Error('Uso: vion audit status <id>')
    reapOrphans()
    const a = getAudit(second)
    if (!a) throw new Error(`Auditoria nao encontrada: ${second}`)
    if (values.json) return printJson({ ...auditSummary(a.id), tasks: listTasks(a.id) })
    printResult(a)
    const tasks = listTasks(a.id)
    if (tasks.length) console.log('\n' + table(tasks.map(t => [t.agent, t.model || '—', t.status, t.title]), ['Agente', 'Modelo', 'Status', 'Tarefa']))
    return
  }
  if (first === 'stop') {
    if (!second) throw new Error('Uso: vion audit stop <id>')
    const a = stopAudit(second)
    return console.log(`Auditoria ${a.id}: ${a.status}`)
  }

  // nova auditoria
  let scopeInput
  if (values.scope) {
    scopeInput = JSON.parse(fs.readFileSync(values.scope, 'utf8'))
    if (first) scopeInput.target = first
  } else {
    const target = /^https?:\/\//i.test(first) ? first : path.resolve(first)
    scopeInput = { target, hosts: values.host || [], active: !!values.active, authorization: { statement: values.authorization || '', by: process.env.USERNAME || process.env.USER || '' } }
  }
  const skills = values.skills ? values.skills.split(',').map(s => s.trim().replace(/^\/?vion:/, '')).filter(Boolean) : []
  const audit = startAudit({ scopeInput, origin: 'cli', skills: skills.length ? skills : ['auditoria'] })
  launchWorker(audit.id, { skills, analyzersOnly: !!values['analyzers-only'], maxCost: values['max-cost'] ? Number(values['max-cost']) : null })

  console.log(`${c.bold('VION')} auditoria ${c.cyan(audit.id)} iniciada · alvo ${audit.target}`)
  console.log(c.dim(`Acompanhe na UI: ${uiUrl(audit.id)} (vion ui)`))
  if (values.detach) return console.log(`Rodando em segundo plano. Status: vion audit status ${audit.id}`)
  const done = await follow(audit.id)
  printResult(done)
  if (done.status === 'failed') process.exitCode = 1
}
