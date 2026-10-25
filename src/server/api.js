// ── Rotas /api da UI local ──

import fs from 'node:fs'
import path from 'node:path'
import { ensureHome } from '../core/paths.js'
import { loadConfig, setKey, SETTABLE, ROLES, MODELS } from '../core/config.js'
import {
  listAudits, getAudit, listFindings, getFinding, updateFinding, listEvidence, readEvidence, listTasks, listAssets,
  listReports, eventsSince, listProjects, addProject, getProject, removeProject, deleteAudit, severityCounts, computeScore,
  STATUSES, REMEDIATIONS,
} from '../core/store.js'
import { openDb } from '../core/db.js'
import { startAudit } from '../core/engine.js'
import { launchWorker, stopAudit, runningAudits, resolveClaude, reapOrphans } from '../core/runner.js'
import { generateReports, auditSummary } from '../core/report.js'
import { listAgents } from '../core/agents.js'
import { listChecklists } from '../core/checklists.js'
import { readManifest, targets } from '../core/install.js'
import { SKILLS, GROUPS } from '../cli/skills-meta.js'
import { VERSION } from '../core/version.js'

class ApiError extends Error {
  constructor(status, message) {
    super(message)
    this.status = status
  }
}
export const REPLY = Symbol('vion.reply')
const reply = (status, body) => ({ [REPLY]: true, status, body })
const fileReply = f => ({ [REPLY]: true, ...f })
const notFound = what => new ApiError(404, `${what} nao encontrado(a)`)

function auditRow(a) {
  const fs_ = listFindings(a.id)
  const { scope_json, models_json, plan_json, usage_json, ...rest } = a
  return {
    ...rest,
    counts: severityCounts(fs_),
    findings_total: fs_.length,
    confirmed: fs_.filter(f => f.status === 'confirmed').length,
    live_score: computeScore(fs_),
  }
}

function tail(file, lines = 200) {
  if (!fs.existsSync(file)) return ''
  const data = fs.readFileSync(file, 'utf8')
  return data.split('\n').slice(-lines).join('\n')
}

const routes = []
const route = (method, pattern, handler) => {
  const keys = []
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([^/]+)')) + '$')
  routes.push({ method, re, keys, handler })
}

// ── estado geral ──
route('GET', '/api/status', () => {
  reapOrphans()
  const db = openDb()
  const audits = db.prepare('SELECT status, COUNT(*) n FROM audits GROUP BY status').all()
  const open = db.prepare("SELECT severity, COUNT(*) n FROM findings WHERE duplicate_of IS NULL AND status != 'false_positive' AND remediation = 'open' GROUP BY severity").all()
  const manifest = readManifest(targets())
  const errors = listAudits({ status: 'failed', limit: 5 }).map(a => ({ id: a.id, target: a.target, error: a.error, at: a.updated_at }))
  return {
    version: VERSION,
    home: ensureHome().root,
    claude: !!resolveClaude(),
    installed: manifest ? { version: manifest.version, mcp: manifest.mcp, hook: manifest.hook, at: manifest.installedAt } : null,
    audits: Object.fromEntries(audits.map(r => [r.status, r.n])),
    open_findings: Object.fromEntries(open.map(r => [r.severity, r.n])),
    running: runningAudits().map(a => a.id),
    recent_errors: errors,
  }
})

// ── auditorias ──
route('GET', '/api/audits', (_, url) => listAudits({ limit: Math.min(Number(url.searchParams.get('limit')) || 100, 500) }).map(auditRow))

route('GET', '/api/audits/:id', ({ id }) => {
  const a = getAudit(id)
  if (!a) throw notFound('Auditoria')
  return { ...auditRow(a), scope: a.scope, models: a.models, plan: a.plan, usage: a.usage, summary_data: auditSummary(id), tasks: listTasks(id), assets: listAssets(id), reports: listReports(id) }
})

route('POST', '/api/audits', (_, __, body) => {
  const skills = Array.isArray(body.skills) ? body.skills.map(String).filter(s => /^[a-z0-9-]{2,40}$/.test(s)).slice(0, 20) : []
  let scopeInput
  if (body.projectId) {
    const p = getProject(String(body.projectId))
    if (!p) throw new ApiError(400, 'Projeto nao cadastrado. Adicione o diretorio em "Projetos".')
    scopeInput = { target: p.path, hosts: body.hosts || [], active: !!body.active, authorization: { statement: body.authorization || '', by: 'ui' } }
  } else if (body.url) {
    if (!/^https?:\/\//i.test(String(body.url))) throw new ApiError(400, 'URL precisa comecar com http:// ou https://')
    scopeInput = { target: String(body.url), hosts: body.hosts || [], active: !!body.active, authorization: { statement: body.authorization || '', by: 'ui' } }
  } else throw new ApiError(400, 'Escolha um projeto ou informe uma URL.')
  if (!body.confirmAuthorized) throw new ApiError(400, 'Confirme que voce e dono do alvo ou tem autorizacao para testa-lo.')
  const audit = startAudit({ scopeInput, origin: 'ui', skills: skills.length ? skills : ['auditoria'] })
  const maxCost = body.maxCost != null && body.maxCost !== '' ? Number(body.maxCost) : null
  if (maxCost != null && (!Number.isFinite(maxCost) || maxCost < 0)) throw new ApiError(400, 'Teto de custo invalido')
  launchWorker(audit.id, { skills, analyzersOnly: !!body.analyzersOnly, maxCost })
  return reply(201, { id: audit.id })
})

route('POST', '/api/audits/:id/stop', ({ id }) => {
  if (!getAudit(id)) throw notFound('Auditoria')
  return auditRow(stopAudit(id))
})

route('DELETE', '/api/audits/:id', ({ id }) => {
  const a = getAudit(id)
  if (!a) throw notFound('Auditoria')
  if (['running', 'pending'].includes(a.status)) throw new ApiError(409, 'Pare a auditoria antes de apagar.')
  deleteAudit(id)
  return { ok: true }
})

route('GET', '/api/audits/:id/findings', ({ id }, url) => {
  if (!getAudit(id)) throw notFound('Auditoria')
  return listFindings(id, { includeDuplicates: url.searchParams.get('duplicates') === '1' })
})

route('GET', '/api/audits/:id/evidence', ({ id }) => listEvidence(id))
route('GET', '/api/audits/:id/events', ({ id }, url) => eventsSince(Number(url.searchParams.get('after')) || 0, id, 2000))
route('GET', '/api/audits/:id/logs', ({ id }) => {
  const home = ensureHome()
  return { worker: tail(path.join(home.audits, id, 'worker.log')), hook: tail(path.join(home.logs, 'hook.log'), 400).split('\n').filter(l => l.includes(id)).join('\n') }
})

route('POST', '/api/audits/:id/report', ({ id }) => {
  if (!getAudit(id)) throw notFound('Auditoria')
  generateReports(id)
  return listReports(id)
})

// ── findings / evidencias (visao global) ──
route('GET', '/api/findings', (_, url) => {
  const db = openDb()
  const sev = url.searchParams.get('severity')
  const status = url.searchParams.get('status')
  let sql = `SELECT f.*, a.target AS audit_target FROM findings f JOIN audits a ON a.id = f.audit_id WHERE f.duplicate_of IS NULL`
  const args = []
  if (sev) (sql += ' AND f.severity = ?'), args.push(sev)
  if (status) (sql += ' AND f.status = ?'), args.push(status)
  sql += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.created_at DESC LIMIT 1000"
  return db.prepare(sql).all(...args)
})

route('GET', '/api/findings/:id', ({ id }) => {
  const f = getFinding(id)
  if (!f) throw notFound('Finding')
  return { ...f, evidence: listEvidence(f.audit_id).filter(e => e.finding_id === id) }
})

// triagem manual pela UI: falso positivo / reabrir / status da correcao
route('POST', '/api/findings/:id', ({ id }, __, body) => {
  const patch = {}
  if (body.status !== undefined) {
    if (!STATUSES.includes(body.status)) throw new ApiError(400, 'status invalido')
    patch.status = body.status
  }
  if (body.remediation !== undefined) {
    if (!REMEDIATIONS.includes(body.remediation)) throw new ApiError(400, 'remediation invalido')
    patch.remediation = body.remediation
  }
  if (body.note) patch.limitations = String(body.note).slice(0, 2000)
  return updateFinding(id, patch, { agent: 'usuario (UI)' })
})

route('GET', '/api/evidence', () =>
  openDb().prepare('SELECT e.*, a.target AS audit_target FROM evidence e JOIN audits a ON a.id = e.audit_id ORDER BY e.collected_at DESC LIMIT 500').all(),
)
route('GET', '/api/evidence/:id', ({ id }) => {
  const e = readEvidence(id)
  if (!e) throw notFound('Evidencia')
  return e
})

// ── relatorios ──
route('GET', '/api/reports', () =>
  openDb().prepare('SELECT r.*, a.target AS audit_target FROM reports r JOIN audits a ON a.id = r.audit_id ORDER BY r.created_at DESC LIMIT 500').all(),
)
route('GET', '/api/reports/:id/file', ({ id }, url) => {
  const r = openDb().prepare('SELECT * FROM reports WHERE id = ?').get(id)
  if (!r) throw notFound('Relatorio')
  const home = ensureHome()
  const file = path.resolve(home.reports, r.rel_path)
  if (!file.startsWith(path.resolve(home.reports) + path.sep) || !fs.existsSync(file)) throw notFound('Arquivo do relatorio')
  const types = { html: 'text/html; charset=utf-8', md: 'text/markdown; charset=utf-8', json: 'application/json; charset=utf-8' }
  return fileReply({ file, contentType: types[r.format], download: url.searchParams.get('download') === '1' ? path.basename(file) : null })
})

// ── catalogo ──
route('GET', '/api/skills', () => ({ groups: GROUPS, skills: SKILLS, checklists: listChecklists() }))
route('GET', '/api/agents', () => {
  const db = openDb()
  const stats = db.prepare("SELECT agent, status, COUNT(*) n FROM tasks GROUP BY agent, status").all()
  const recent = db.prepare('SELECT t.*, a.target AS audit_target FROM tasks t JOIN audits a ON a.id = t.audit_id ORDER BY t.updated_at DESC LIMIT 200').all()
  return { agents: listAgents(), stats, recent }
})

// ── projetos (allowlist) ──
route('GET', '/api/projects', () => listProjects())
route('POST', '/api/projects', (_, __, body) => {
  const p = path.resolve(String(body.path || ''))
  if (!body.path || !fs.existsSync(p) || !fs.statSync(p).isDirectory()) throw new ApiError(400, `Diretorio nao existe: ${p}`)
  if (path.parse(p).root === p) throw new ApiError(400, 'Nao e permitido cadastrar a raiz do disco.')
  return addProject(p)
})
route('DELETE', '/api/projects/:id', ({ id }) => {
  removeProject(id)
  return { ok: true }
})

// ── configuracao ──
route('GET', '/api/config', () => ({ config: loadConfig(), settable: SETTABLE, roles: ROLES, models: MODELS }))
route('POST', '/api/config', (_, __, body) => {
  const entries = Object.entries(body || {})
  if (!entries.length) throw new ApiError(400, 'Nada para alterar')
  let cfg
  for (const [k, v] of entries) cfg = setKey(k, String(v))
  return { config: cfg, note: 'Mudancas de modelo valem na proxima auditoria. Para as skills interativas, rode `vion init`.' }
})

export function createApi() {
  return {
    async handle(method, url, body) {
      for (const r of routes) {
        if (r.method !== method) continue
        const m = r.re.exec(url.pathname)
        if (!m) continue
        const params = Object.fromEntries(r.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]))
        return r.handler(params, url, body)
      }
      throw new ApiError(404, 'Rota nao encontrada')
    },
  }
}
