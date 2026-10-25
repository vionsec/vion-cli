// ── Motor: operacoes de alto nivel compartilhadas por MCP, CLI, runner e UI ──

import fs from 'node:fs'
import path from 'node:path'
import { normalizeScope } from './scope.js'
import { loadConfig } from './config.js'
import {
  createAudit, getAudit, updateAudit, addFinding, addEvent, eventsSince, listFindings, computeScore, addProject,
  addEvidence, updateFinding,
} from './store.js'
import { runAnalyzers } from '../analyzers/run.js'
import { auditDependencies } from '../analyzers/deps.js'
import { generateReports, auditSummary } from './report.js'
import { markActive, clearActive } from './session.js'

const ROLE_BY_AGENT = {
  'vion-recon': 'recon',
  'vion-vuln': 'vuln',
  'vion-investigador': 'investigador',
  'vion-threat-intel': 'threat-intel',
  'vion-correlacao': 'correlacao',
  'vion-relatorio': 'relatorio',
}

export function modelForAgent(agent, cfg = loadConfig()) {
  const role = ROLE_BY_AGENT[agent]
  return role ? cfg.models[role] : cfg.models.orquestrador
}

export function uiUrl(auditId, cfg = loadConfig()) {
  return `http://localhost:${cfg.ui.port}/#/audits/${auditId}`
}

/** Cria uma auditoria a partir de um escopo bruto (CLI/UI/sessao). */
export function startAudit({ scopeInput, origin, skills = [] }) {
  const scope = normalizeScope(scopeInput)
  const cfg = loadConfig()
  if (scope.targetType === 'path') addProject(scope.paths[0])
  const audit = createAudit({ scope, origin, skills, models: cfg.models })
  return audit
}

/**
 * Abre (ou reaproveita) a auditoria de uma sessao interativa do Claude Code.
 * Se VION_AUDIT_ID esta no ambiente (headless), reaproveita essa e so acrescenta a skill.
 */
export function openSessionAudit({ skill, target, hosts, cidrs, active, authorization }, env = process.env) {
  if (env.VION_AUDIT_ID) {
    const existing = getAudit(env.VION_AUDIT_ID)
    if (existing) return { audit: existing, reused: true }
  }
  const audit = startAudit({
    scopeInput: { target, hosts, cidrs, active, authorization },
    origin: 'session',
    skills: [skill],
  })
  updateAudit(audit.id, { status: 'running' })
  const cwd = audit.scope.targetType === 'path' ? audit.scope.paths[0] : process.cwd()
  markActive(audit.id, cwd)
  return { audit: getAudit(audit.id), reused: false }
}

/** Roda os analisadores deterministicos sobre os paths do escopo (uma vez por auditoria). */
export async function runAnalyzersForAudit(auditId, { only = null } = {}) {
  const audit = getAudit(auditId)
  if (!audit) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  const previous = eventsSince(0, auditId, 5000).find(e => e.type === 'analyzers.done')
  if (previous) return { ...previous.data, cached: true }
  const stats = {}
  let added = 0
  let filesScanned = 0
  let truncated = false
  const multi = audit.scope.paths.length > 1
  for (const root of audit.scope.paths) {
    const res = await runAnalyzers(root, { only })
    filesScanned += res.filesScanned
    truncated ||= res.truncated
    for (const [k, v] of Object.entries(res.stats)) {
      stats[k] = { status: v.status, count: (stats[k]?.count || 0) + (v.count || 0), ...(v.error ? { error: v.error } : {}) }
    }
    for (const f of res.findings) {
      if (multi && f.file_path) f.file_path = `${path.basename(root)}/${f.file_path}`
      addFinding(auditId, f, { agent: `analisador:${f.analyzer}`, source: 'analyzer' })
      added++
    }
  }
  const data = { stats, added, filesScanned, truncated }
  addEvent(auditId, 'analyzers.done', data)
  return data
}

/**
 * Audit de dependencias pelo motor (npm/pnpm audit com argumentos fixos). Advisories oficiais
 * entram como confirmados com a saida da ferramenta como evidencia.
 */
export function runDependencyAuditForAudit(auditId) {
  const audit = getAudit(auditId)
  if (!audit) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  const previous = eventsSince(0, auditId, 5000).find(e => e.type === 'deps.done')
  if (previous) return { ...previous.data, cached: true }
  const notes = []
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  let added = 0
  for (const root of audit.scope.paths) {
    const res = auditDependencies(root)
    notes.push(...res.notes)
    const raw = res.raws.map(r => `$ ${r.tool}\n${r.output}`).join('\n\n')
    for (const f of res.findings) {
      const { validation_method, ...rest } = f
      const row = addFinding(auditId, rest, { agent: 'analisador:deps', source: 'analyzer' })
      if (row.duplicate_of) continue
      const ev = addEvidence(auditId, {
        finding_id: row.id,
        kind: raw && f.rule !== 'deps:no-lockfile' ? 'tool_output' : 'note',
        title: f.rule === 'deps:no-lockfile' ? 'Arquivos de manifesto no projeto' : `Saida resumida do audit (${f.asset})`,
        content: f.rule === 'deps:no-lockfile' ? fs.readdirSync(root).join('\n') : raw,
        source: f.rule === 'deps:no-lockfile' ? root : 'npm audit --json',
        agent: 'analisador:deps',
      })
      if (ev) updateFinding(row.id, { status: 'confirmed', validation_method })
      counts[row.severity]++
      added++
    }
  }
  const data = { added, counts, notes }
  addEvent(auditId, 'deps.done', data)
  return data
}

/** Fecha a auditoria: score, relatorios, status. Idempotente. */
export function finalizeAudit(auditId, { summary = null, status = 'completed', error = null } = {}) {
  const audit = getAudit(auditId)
  if (!audit) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  const findings = listFindings(auditId)
  const patch = { score: computeScore(findings), finished_at: new Date().toISOString() }
  if (summary) patch.summary = summary
  if (!['completed', 'failed', 'stopped'].includes(audit.status) || status !== 'completed') patch.status = status
  if (error) patch.error = error
  updateAudit(auditId, patch)
  const files = generateReports(auditId, summary || audit.summary)
  clearActive(auditId)
  return { ...auditSummary(auditId), reports: files, url: uiUrl(auditId) }
}
