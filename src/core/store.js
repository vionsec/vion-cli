// ── Store: toda leitura/escrita de auditorias, tarefas, findings e evidencias ──

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { openDb } from './db.js'
import { ensureHome } from './paths.js'
import { redactText } from './redact.js'

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES = ['suspected', 'confirmed', 'false_positive']
export const CONFIDENCES = ['low', 'medium', 'high']
const SEV_PT = { critico: 'critical', crítico: 'critical', alto: 'high', medio: 'medium', médio: 'medium', baixo: 'low', info: 'info' }
const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export function newId(prefix) {
  return `${prefix}_${Date.now().toString(36)}${crypto.randomBytes(5).toString('hex')}`
}

const now = () => new Date().toISOString()

export function normSeverity(s) {
  const v = String(s || '').toLowerCase().trim()
  if (SEVERITIES.includes(v)) return v
  return SEV_PT[v] || 'medium'
}

function normConfidence(c) {
  const v = String(c || '').toLowerCase()
  return CONFIDENCES.includes(v) ? v : 'medium'
}

function normPath(p) {
  return p ? String(p).replace(/\\/g, '/').replace(/^\.\//, '') : null
}

function clip(s, n = 8000) {
  if (s == null) return null
  const t = redactText(String(s))
  return t.length > n ? `${t.slice(0, n)}…` : t
}

export function fingerprint(f) {
  const base = [
    normPath(f.file_path) || String(f.asset || '').toLowerCase(),
    f.line ? Math.floor(Number(f.line) / 3) : '',
    String(f.cwe || f.category || '').toLowerCase(),
    f.cwe ? '' : String(f.rule || f.title || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim(),
  ].join('|')
  return crypto.createHash('sha1').update(base).digest('hex').slice(0, 16)
}

// ── eventos ──

export function addEvent(auditId, type, data = {}) {
  const db = openDb()
  db.prepare('INSERT INTO events (audit_id, type, data_json, created_at) VALUES (?, ?, ?, ?)').run(
    auditId ?? null,
    type,
    JSON.stringify(data),
    now(),
  )
}

export function eventsSince(lastId = 0, auditId = null, limit = 200) {
  const db = openDb()
  const rows = auditId
    ? db.prepare('SELECT * FROM events WHERE id > ? AND audit_id = ? ORDER BY id LIMIT ?').all(lastId, auditId, limit)
    : db.prepare('SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?').all(lastId, limit)
  return rows.map(r => ({ ...r, data: JSON.parse(r.data_json || '{}'), data_json: undefined }))
}

export function lastEventId() {
  return openDb().prepare('SELECT COALESCE(MAX(id), 0) AS id FROM events').get().id
}

// ── projetos (allowlist de diretorios que a UI pode auditar) ──

export function addProject(dir) {
  const db = openDb()
  const abs = path.resolve(dir)
  const existing = db.prepare('SELECT * FROM projects WHERE path = ?').get(abs)
  if (existing) return existing
  const row = { id: newId('p'), path: abs, name: path.basename(abs), created_at: now() }
  db.prepare('INSERT INTO projects (id, path, name, created_at) VALUES (?, ?, ?, ?)').run(row.id, row.path, row.name, row.created_at)
  return row
}

export function listProjects() {
  return openDb().prepare('SELECT * FROM projects ORDER BY name').all()
}

export function getProject(id) {
  return openDb().prepare('SELECT * FROM projects WHERE id = ?').get(id)
}

export function removeProject(id) {
  openDb().prepare('DELETE FROM projects WHERE id = ?').run(id)
}

// ── auditorias ──

function hydrateAudit(r) {
  if (!r) return null
  return {
    ...r,
    scope: JSON.parse(r.scope_json),
    models: r.models_json ? JSON.parse(r.models_json) : null,
    plan: r.plan_json ? JSON.parse(r.plan_json) : null,
    usage: r.usage_json ? JSON.parse(r.usage_json) : null,
  }
}

export function createAudit({ scope, origin = 'cli', skills = [], models = null }) {
  const db = openDb()
  const id = newId('a')
  const t = now()
  db.prepare(
    `INSERT INTO audits (id, target, target_type, scope_json, status, origin, skills, models_json, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`,
  ).run(id, scope.target, scope.targetType, JSON.stringify(scope), origin, skills.join(','), models ? JSON.stringify(models) : null, t, t)
  fs.mkdirSync(path.join(ensureHome().evidence, id), { recursive: true })
  addEvent(id, 'audit.created', { target: scope.target, origin })
  return getAudit(id)
}

export function getAudit(id) {
  return hydrateAudit(openDb().prepare('SELECT * FROM audits WHERE id = ?').get(id))
}

export function listAudits({ limit = 50, status } = {}) {
  const db = openDb()
  const rows = status
    ? db.prepare('SELECT * FROM audits WHERE status = ? ORDER BY created_at DESC LIMIT ?').all(status, limit)
    : db.prepare('SELECT * FROM audits ORDER BY created_at DESC LIMIT ?').all(limit)
  return rows.map(hydrateAudit)
}

const AUDIT_FIELDS = ['status', 'plan_json', 'summary', 'score', 'pid', 'input_tokens', 'output_tokens', 'cache_read_tokens', 'cost_usd', 'usage_json', 'error', 'finished_at', 'models_json']

export function updateAudit(id, patch) {
  const db = openDb()
  const entries = Object.entries(patch).filter(([k]) => AUDIT_FIELDS.includes(k))
  if (!entries.length) return getAudit(id)
  const sets = entries.map(([k]) => `${k} = ?`).join(', ')
  db.prepare(`UPDATE audits SET ${sets}, updated_at = ? WHERE id = ?`).run(...entries.map(([, v]) => v), now(), id)
  if (patch.status) addEvent(id, 'audit.status', { status: patch.status, error: patch.error || null })
  return getAudit(id)
}

export function deleteAudit(id) {
  const db = openDb()
  db.prepare('DELETE FROM events WHERE audit_id = ?').run(id)
  db.prepare('DELETE FROM audits WHERE id = ?').run(id)
  const home = ensureHome()
  fs.rmSync(path.join(home.evidence, id), { recursive: true, force: true })
  fs.rmSync(path.join(home.reports, id), { recursive: true, force: true })
  fs.rmSync(path.join(home.audits, id), { recursive: true, force: true })
}

// ── tarefas ──

export function addTask(auditId, { agent, model = null, title, checklist = null, status = 'planned' }) {
  const db = openDb()
  const id = newId('t')
  const t = now()
  db.prepare(
    'INSERT INTO tasks (id, audit_id, agent, model, title, checklist, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(id, auditId, agent, model, clip(title, 300), checklist, status, t, t)
  addEvent(auditId, 'task.created', { id, agent, model, title, status })
  return getTask(id)
}

export function getTask(id) {
  return openDb().prepare('SELECT * FROM tasks WHERE id = ?').get(id)
}

export function listTasks(auditId) {
  return openDb().prepare('SELECT * FROM tasks WHERE audit_id = ? ORDER BY created_at').all(auditId)
}

export function updateTask(id, { status, summary, error, model }) {
  const db = openDb()
  const task = getTask(id)
  if (!task) throw new Error(`Tarefa nao encontrada: ${id}`)
  const attempts = status === 'running' ? task.attempts + 1 : task.attempts
  db.prepare(
    `UPDATE tasks SET status = COALESCE(?, status), summary = COALESCE(?, summary), error = COALESCE(?, error),
     model = COALESCE(?, model), attempts = ?, updated_at = ? WHERE id = ?`,
  ).run(status ?? null, summary != null ? clip(summary, 4000) : null, error != null ? clip(error, 2000) : null, model ?? null, attempts, now(), id)
  addEvent(task.audit_id, 'task.updated', { id, agent: task.agent, status, attempts })
  return getTask(id)
}

// ── ativos ──

export function addAsset(auditId, { kind, name, details = null, agent = null }) {
  const db = openDb()
  const id = newId('as')
  db.prepare('INSERT OR IGNORE INTO assets (id, audit_id, kind, name, details, agent, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
    id,
    auditId,
    kind,
    clip(name, 500),
    clip(details, 2000),
    agent,
    now(),
  )
  return db.prepare('SELECT * FROM assets WHERE audit_id = ? AND kind = ? AND name = ?').get(auditId, kind, clip(name, 500))
}

export function listAssets(auditId) {
  return openDb().prepare('SELECT * FROM assets WHERE audit_id = ? ORDER BY kind, name').all(auditId)
}

// ── findings ──

export function addFinding(auditId, f, { agent, source = 'agent' }) {
  const db = openDb()
  const row = {
    id: newId('f'),
    audit_id: auditId,
    title: clip(f.title, 300),
    description: clip(f.description || f.title, 6000),
    asset: clip(f.asset, 500),
    file_path: normPath(f.file_path),
    line: Number.isInteger(f.line) && f.line > 0 ? f.line : null,
    severity: normSeverity(f.severity),
    severity_reason: clip(f.severity_reason, 1000),
    category: clip(f.category, 120),
    cwe: f.cwe ? String(f.cwe).toUpperCase().replace(/^(\d)/, 'CWE-$1') : null,
    rule: clip(f.rule, 120),
    impact: clip(f.impact, 2000),
    recommendation: clip(f.recommendation || f.fix, 4000),
    validation_method: clip(f.validation_method, 2000),
    limitations: clip(f.limitations, 2000),
    code_snippet: clip(f.code_snippet, 1000),
    // Todo achado nasce suspeito: so vira confirmado via updateFinding com evidencia.
    status: 'suspected',
    confidence: normConfidence(f.confidence),
    agent: agent || 'desconhecido',
    source,
  }
  row.fingerprint = fingerprint(row)
  const dup = db.prepare('SELECT id FROM findings WHERE audit_id = ? AND fingerprint = ? AND duplicate_of IS NULL').get(auditId, row.fingerprint)
  row.duplicate_of = dup ? dup.id : null
  const t = now()
  const cols = Object.keys(row)
  db.prepare(`INSERT INTO findings (${cols.join(', ')}, created_at, updated_at) VALUES (${cols.map(() => '?').join(', ')}, ?, ?)`).run(
    ...cols.map(c => row[c]),
    t,
    t,
  )
  addEvent(auditId, 'finding.added', { id: row.id, severity: row.severity, title: row.title, agent: row.agent, duplicate_of: row.duplicate_of })
  return getFinding(row.id)
}

export function getFinding(id) {
  const f = openDb().prepare('SELECT * FROM findings WHERE id = ?').get(id)
  if (!f) return null
  f.evidence_ids = openDb().prepare('SELECT id FROM evidence WHERE finding_id = ?').all(id).map(r => r.id)
  return f
}

export function listFindings(auditId, { includeDuplicates = false, status } = {}) {
  const db = openDb()
  let sql = 'SELECT * FROM findings WHERE audit_id = ?'
  const args = [auditId]
  if (!includeDuplicates) sql += ' AND duplicate_of IS NULL'
  if (status) {
    sql += ' AND status = ?'
    args.push(status)
  }
  const rows = db.prepare(sql).all(...args)
  const ev = db.prepare('SELECT id, finding_id FROM evidence WHERE audit_id = ? AND finding_id IS NOT NULL').all(auditId)
  for (const r of rows) r.evidence_ids = ev.filter(e => e.finding_id === r.id).map(e => e.id)
  return rows.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.created_at.localeCompare(b.created_at))
}

const FINDING_PATCHABLE = ['severity', 'severity_reason', 'impact', 'recommendation', 'validation_method', 'limitations', 'confidence', 'status', 'remediation', 'duplicate_of']
export const REMEDIATIONS = ['open', 'applied', 'rejected', 'wont_fix']

export function updateFinding(id, patch, { agent } = {}) {
  const db = openDb()
  const f = getFinding(id)
  if (!f) throw new Error(`Finding nao encontrado: ${id}`)
  if (patch.status && !STATUSES.includes(patch.status)) throw new Error(`Status invalido: ${patch.status}`)
  if (patch.remediation && !REMEDIATIONS.includes(patch.remediation)) throw new Error(`Remediation invalido: ${patch.remediation}`)
  if (patch.status === 'confirmed') {
    if (!f.evidence_ids.length) throw new Error('Nao e possivel confirmar sem evidencia anexada (use evidence_add com finding_id).')
    if (!(patch.validation_method || f.validation_method)) throw new Error('Confirmacao exige validation_method descrevendo como foi validado.')
  }
  const entries = Object.entries(patch).filter(([k, v]) => FINDING_PATCHABLE.includes(k) && v !== undefined)
  if (!entries.length) return f
  const values = entries.map(([k, v]) =>
    k === 'severity' ? normSeverity(v) : k === 'confidence' ? normConfidence(v) : ['status', 'remediation', 'duplicate_of'].includes(k) ? v : clip(v, 4000),
  )
  db.prepare(`UPDATE findings SET ${entries.map(([k]) => `${k} = ?`).join(', ')}, updated_at = ? WHERE id = ?`).run(...values, now(), id)
  addEvent(f.audit_id, 'finding.updated', { id, agent: agent || null, ...Object.fromEntries(entries.filter(([k]) => ['status', 'severity', 'confidence', 'remediation'].includes(k))) })
  return getFinding(id)
}

// ── evidencias (conteudo em arquivo, referencia + hash no DB) ──

export function addEvidence(auditId, { finding_id = null, kind, title, content, source = null, context = null, agent = null }) {
  const db = openDb()
  if (finding_id) {
    const f = db.prepare('SELECT audit_id FROM findings WHERE id = ?').get(finding_id)
    if (!f || f.audit_id !== auditId) throw new Error(`finding_id ${finding_id} nao pertence a auditoria ${auditId}`)
  }
  const id = newId('e')
  const body = redactText(String(content ?? ''))
  const dir = path.join(ensureHome().evidence, auditId)
  fs.mkdirSync(dir, { recursive: true })
  const rel = path.join(auditId, `${id}.txt`)
  fs.writeFileSync(path.join(ensureHome().evidence, rel), body, { mode: 0o600 })
  const sha = crypto.createHash('sha256').update(body).digest('hex')
  db.prepare(
    'INSERT INTO evidence (id, audit_id, finding_id, kind, title, rel_path, sha256, bytes, source, context, agent, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(id, auditId, finding_id, kind, clip(title, 300), rel.replace(/\\/g, '/'), sha, Buffer.byteLength(body), clip(source, 500), clip(context, 2000), agent, now())
  addEvent(auditId, 'evidence.added', { id, finding_id, kind, title })
  return getEvidence(id)
}

export function getEvidence(id) {
  return openDb().prepare('SELECT * FROM evidence WHERE id = ?').get(id)
}

export function listEvidence(auditId) {
  return openDb().prepare('SELECT * FROM evidence WHERE audit_id = ? ORDER BY collected_at').all(auditId)
}

/** Le o conteudo e confere a integridade (sha256). */
export function readEvidence(id) {
  const e = getEvidence(id)
  if (!e) return null
  const file = path.join(ensureHome().evidence, e.rel_path)
  const content = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : ''
  const intact = crypto.createHash('sha256').update(content).digest('hex') === e.sha256
  return { ...e, content, intact }
}

// ── correlacao deterministica ──

/**
 * Agrupa duplicatas exatas (fingerprint), aponta quase-duplicatas (mesmo arquivo, linhas
 * proximas, mesma categoria/CWE) e conflitos de status. So o que sobrar vai para o agente.
 */
export function correlate(auditId) {
  const all = listFindings(auditId, { includeDuplicates: true })
  const byFp = new Map()
  let markedDuplicates = 0
  for (const f of all) {
    if (!byFp.has(f.fingerprint)) byFp.set(f.fingerprint, [])
    byFp.get(f.fingerprint).push(f)
  }
  const conflicts = []
  for (const group of byFp.values()) {
    if (group.length < 2) continue
    const statuses = new Set(group.map(g => g.status))
    if (statuses.has('confirmed') && statuses.has('false_positive')) conflicts.push({ type: 'status', ids: group.map(g => g.id) })
    const primary = [...group].sort(
      (a, b) =>
        (b.status === 'confirmed') - (a.status === 'confirmed') ||
        b.evidence_ids.length - a.evidence_ids.length ||
        SEV_RANK[a.severity] - SEV_RANK[b.severity],
    )[0]
    for (const g of group) {
      if (g.id !== primary.id && g.duplicate_of !== primary.id) {
        updateFinding(g.id, { duplicate_of: primary.id })
        markedDuplicates++
      }
    }
    if (primary.duplicate_of) updateFinding(primary.id, { duplicate_of: null })
  }
  const primaries = listFindings(auditId)
  const near = []
  for (let i = 0; i < primaries.length; i++) {
    for (let j = i + 1; j < primaries.length; j++) {
      const a = primaries[i]
      const b = primaries[j]
      if (!a.file_path || a.file_path !== b.file_path) continue
      if (a.line && b.line && Math.abs(a.line - b.line) > 5) continue
      const sameClass = (a.cwe && a.cwe === b.cwe) || (a.category && a.category === b.category)
      if (sameClass) near.push({ ids: [a.id, b.id], file: a.file_path, reason: 'mesmo arquivo, linhas proximas, mesma classe' })
    }
  }
  const summary = { total: primaries.length, markedDuplicates, nearDuplicates: near, conflicts }
  addEvent(auditId, 'audit.correlated', { total: summary.total, markedDuplicates, near: near.length, conflicts: conflicts.length })
  return summary
}

// ── relatorios ──

export function addReport(auditId, { format, relPath, sha256, executive_summary = null }) {
  const id = newId('r')
  openDb()
    .prepare('INSERT INTO reports (id, audit_id, format, rel_path, sha256, executive_summary, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, auditId, format, relPath, sha256, executive_summary ? clip(executive_summary, 8000) : null, now())
  addEvent(auditId, 'report.generated', { id, format })
  return id
}

export function listReports(auditId) {
  return openDb().prepare('SELECT * FROM reports WHERE audit_id = ? ORDER BY created_at DESC').all(auditId)
}

export function severityCounts(findings) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) if (f.status !== 'false_positive') c[f.severity]++
  return c
}

/** Score 0-100 (mesmos pesos do motor original em detect/index.js), so findings nao descartados. */
export function computeScore(findings) {
  const W = { critical: 20, high: 10, medium: 4, low: 1, info: 0 }
  const c = severityCounts(findings)
  return Math.max(0, Math.min(100, 100 - Object.entries(c).reduce((s, [k, n]) => s + n * W[k], 0)))
}
