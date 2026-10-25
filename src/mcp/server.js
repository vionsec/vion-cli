// ── MCP stdio "vion": ponte entre os agentes do Claude Code e o store local ──
// Toda entrada e validada (zod) e todo texto passa por redacao no store.

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import path from 'node:path'
import {
  getAudit, listAudits, updateAudit, addTask, getTask, updateTask, addAsset, addFinding, getFinding,
  listFindings, updateFinding, addEvidence, correlate, SEVERITIES, STATUSES, REMEDIATIONS,
} from '../core/store.js'
import { listChecklists, getChecklist } from '../core/checklists.js'
import { openSessionAudit, runAnalyzersForAudit, runDependencyAuditForAudit, finalizeAudit, modelForAgent, uiUrl } from '../core/engine.js'
import { auditSummary } from '../core/report.js'
import { pathAllowed } from '../core/scope.js'
import { VERSION } from '../core/version.js'

const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]))

const ok = data => ({ content: [{ type: 'text', text: typeof data === 'string' ? data : JSON.stringify(data, null, 1) }] })
const fail = msg => ({ isError: true, content: [{ type: 'text', text: `VION: ${msg}` }] })

function guard(fn) {
  return async args => {
    try {
      return await fn(args)
    } catch (err) {
      return fail(err.message)
    }
  }
}

function needAudit(id) {
  const a = getAudit(id)
  if (!a) throw new Error(`auditoria ${id} nao existe`)
  if (['completed', 'failed', 'stopped'].includes(a.status)) throw new Error(`auditoria ${id} ja esta ${a.status}; abra outra com audit_open`)
  return a
}

function brief(f) {
  return { id: f.id, severity: f.severity, status: f.status, title: f.title, loc: f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ''}` : f.asset, confidence: f.confidence, agent: f.agent, remediation: f.remediation, evidence: f.evidence_ids.length }
}

const id = z.string().regex(/^[a-z]{1,2}_[a-z0-9]+$/, 'id VION invalido')
const agentName = z.string().max(60).optional().describe('nome do agente que esta chamando (ex: vion-vuln)')

export function createServer() {
  const server = new McpServer({ name: 'vion', version: VERSION })
  const tool = (name, description, inputSchema, handler) => server.registerTool(name, { description, inputSchema }, guard(handler))

  tool(
    'audit_open',
    'Abre uma auditoria no store local do VION (ou reaproveita a da sessao headless). Use no inicio de qualquer skill /vion:*. Alvo de rede exige authorization.statement do usuario.',
    {
      skill: z.string().max(40),
      target: z.string().max(500).describe('diretorio absoluto do projeto ou URL'),
      hosts: z.array(z.string().max(253)).max(50).optional(),
      cidrs: z.array(z.string().max(18)).max(10).optional(),
      active: z.boolean().optional().describe('true para testes ativos (scan/exploracao)'),
      authorization: z.object({ statement: z.string().max(2000), by: z.string().max(200).optional() }).optional(),
    },
    async args => {
      const { audit, reused } = openSessionAudit(args)
      return ok({ audit_id: audit.id, reused, scope: audit.scope, url: uiUrl(audit.id) })
    },
  )

  tool('scope_get', 'Retorna o escopo autorizado da auditoria. Trabalhe somente dentro dele.', { audit_id: id }, async ({ audit_id }) => {
    const a = getAudit(audit_id)
    if (!a) throw new Error('auditoria nao existe')
    return ok({ audit_id, status: a.status, ...a.scope })
  })

  tool('checklist_list', 'Lista as checklists que podem ser delegadas a subagentes.', {}, async () => ok(listChecklists()))

  tool('checklist_get', 'Conteudo de uma checklist (texto enxuto, sem relatorio).', { name: z.string().max(40) }, async ({ name }) => {
    const c = getChecklist(name)
    if (!c) throw new Error(`checklist desconhecida: ${name}. Use checklist_list.`)
    return ok(c)
  })

  tool(
    'plan_set',
    'Registra o plano de execucao (tarefas por agente). Retorna task_id de cada tarefa.',
    {
      audit_id: id,
      tasks: z.array(z.object({ agent: z.string().max(60), checklist: z.string().max(40).optional(), title: z.string().max(200) })).min(1).max(40),
    },
    async ({ audit_id, tasks }) => {
      needAudit(audit_id)
      const created = tasks.map(t => addTask(audit_id, { ...t, model: modelForAgent(t.agent) }))
      updateAudit(audit_id, { plan_json: JSON.stringify(tasks), status: 'running' })
      return ok(created.map(t => ({ task_id: t.id, agent: t.agent, checklist: t.checklist, model: t.model })))
    },
  )

  tool('task_start', 'Marca uma tarefa como em execucao.', { task_id: id }, async ({ task_id }) => {
    const t = getTask(task_id)
    if (!t) throw new Error('tarefa nao existe')
    needAudit(t.audit_id)
    updateTask(task_id, { status: 'running' })
    return ok({ task_id, audit_id: t.audit_id, status: 'running' })
  })

  tool(
    'task_finish',
    'Conclui uma tarefa com resumo curto (ate ~200 palavras).',
    { task_id: id, status: z.enum(['done', 'failed', 'skipped']), summary: z.string().max(4000).optional(), error: z.string().max(2000).optional() },
    async ({ task_id, ...rest }) => {
      const t = updateTask(task_id, rest)
      return ok({ task_id, status: t.status })
    },
  )

  tool(
    'asset_add',
    'Registra um ativo da superficie de ataque.',
    { audit_id: id, kind: z.enum(['endpoint', 'file', 'host', 'service', 'dependency', 'component']), name: z.string().max(500), details: z.string().max(2000).optional(), agent: agentName },
    async ({ audit_id, ...a }) => {
      needAudit(audit_id)
      const row = addAsset(audit_id, a)
      return ok({ asset_id: row.id })
    },
  )

  tool(
    'run_analyzers',
    'Roda os analisadores deterministicos do VION (0 tokens) sobre o escopo e grava os findings. Retorna so contagens.',
    { audit_id: id },
    async ({ audit_id }) => {
      needAudit(audit_id)
      return ok(await runAnalyzersForAudit(audit_id))
    },
  )

  tool(
    'run_dependency_audit',
    'Audit de dependencias executado pelo motor (npm/pnpm audit). Advisories oficiais entram como confirmados, com evidencia. Retorna contagens e observacoes (ex.: sem lockfile).',
    { audit_id: id },
    async ({ audit_id }) => {
      needAudit(audit_id)
      return ok(runDependencyAuditForAudit(audit_id))
    },
  )

  const findingInput = {
    title: z.string().min(3).max(300),
    description: z.string().min(3).max(6000),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info', 'critico', 'alto', 'medio', 'baixo']),
    severity_reason: z.string().max(1000).optional(),
    category: z.string().max(120).optional(),
    cwe: z.string().max(20).optional(),
    rule: z.string().max(120).optional(),
    asset: z.string().max(500).optional(),
    file_path: z.string().max(500).optional(),
    line: z.number().int().positive().optional(),
    code_snippet: z.string().max(1000).optional(),
    impact: z.string().max(2000).optional(),
    recommendation: z.string().max(4000).optional(),
    validation_method: z.string().max(2000).optional(),
    limitations: z.string().max(2000).optional(),
    confidence: z.enum(['low', 'medium', 'high']).optional(),
  }

  tool(
    'finding_add',
    'Registra um achado. Sempre nasce "suspected"; so vira "confirmed" com evidencia (evidence_add + finding_update).',
    { audit_id: id, ...findingInput, agent: agentName },
    async ({ audit_id, agent, ...f }) => {
      const a = needAudit(audit_id)
      if (f.file_path && path.isAbsolute(f.file_path) && a.scope.paths.length) {
        if (!pathAllowed(a.scope, f.file_path)) throw new Error(`file_path fora do escopo: ${f.file_path}`)
        f.file_path = path.relative(a.scope.paths[0], f.file_path)
      }
      const row = addFinding(audit_id, f, { agent: agent || 'agente' })
      return ok({ finding_id: row.id, status: row.status, duplicate_of: row.duplicate_of })
    },
  )

  tool('finding_get', 'Detalhe completo de um finding.', { id }, async ({ id: fid }) => {
    const f = getFinding(fid)
    if (!f) throw new Error('finding nao existe')
    return ok(f)
  })

  tool(
    'finding_update',
    'Atualiza um finding: validacao (status), severidade, correcao, remediation, duplicate_of. "confirmed" exige evidencia anexada e validation_method.',
    {
      id,
      status: z.enum(STATUSES).optional(),
      remediation: z.enum(REMEDIATIONS).optional(),
      severity: findingInput.severity.optional(),
      severity_reason: findingInput.severity_reason,
      impact: findingInput.impact,
      recommendation: findingInput.recommendation,
      validation_method: findingInput.validation_method,
      limitations: findingInput.limitations,
      confidence: findingInput.confidence,
      duplicate_of: id.nullable().optional(),
      agent: agentName,
    },
    async ({ id: fid, agent, ...patch }) => {
      const f = getFinding(fid)
      if (!f) throw new Error('finding nao existe')
      // remediation pode ser atualizado depois da auditoria fechada (fluxo /vion:fixes)
      const onlyRemediation = Object.keys(patch).every(k => k === 'remediation' || k === 'limitations')
      if (!onlyRemediation) needAudit(f.audit_id)
      if (patch.duplicate_of && getFinding(patch.duplicate_of)?.audit_id !== f.audit_id) throw new Error('duplicate_of precisa ser da mesma auditoria')
      const row = updateFinding(fid, patch, { agent })
      return ok(brief(row))
    },
  )

  tool(
    'findings_list',
    'Lista findings com filtros. Use fields="brief" para economizar tokens.',
    {
      audit_id: id,
      status: z.enum(STATUSES).optional(),
      exclude_status: z.enum(STATUSES).optional(),
      remediation: z.enum(REMEDIATIONS).optional(),
      min_severity: z.enum(SEVERITIES).optional(),
      file_path: z.string().max(500).optional(),
      has_recommendation: z.boolean().optional(),
      fields: z.enum(['brief', 'full']).optional(),
      limit: z.number().int().min(1).max(500).optional(),
    },
    async q => {
      let rows = listFindings(q.audit_id, { status: q.status })
      if (q.exclude_status) rows = rows.filter(f => f.status !== q.exclude_status)
      if (q.remediation) rows = rows.filter(f => f.remediation === q.remediation)
      if (q.min_severity) rows = rows.filter(f => SEV_RANK[f.severity] <= SEV_RANK[q.min_severity])
      if (q.file_path) rows = rows.filter(f => f.file_path && f.file_path.replace(/\\/g, '/').includes(q.file_path.replace(/\\/g, '/')))
      if (q.has_recommendation) rows = rows.filter(f => f.recommendation)
      const total = rows.length
      rows = rows.slice(0, q.limit || 100)
      return ok({ total, findings: q.fields === 'full' ? rows : rows.map(brief) })
    },
  )

  tool(
    'evidence_add',
    'Anexa evidencia (trecho de codigo, request/response, saida de ferramenta). Segredos sao mascarados automaticamente.',
    {
      audit_id: id,
      finding_id: id.optional(),
      kind: z.enum(['http', 'log', 'tool_output', 'code', 'file', 'note']),
      title: z.string().max(300),
      content: z.string().max(200_000),
      source: z.string().max(500).optional().describe('origem: arquivo:linhas, comando, URL'),
      context: z.string().max(2000).optional(),
      agent: agentName,
    },
    async ({ audit_id, ...e }) => {
      needAudit(audit_id)
      const row = addEvidence(audit_id, e)
      return ok({ evidence_id: row.id, sha256: row.sha256 })
    },
  )

  tool('correlate', 'Deduplicacao deterministica + lista de quase-duplicatas e conflitos para revisao.', { audit_id: id }, async ({ audit_id }) => {
    needAudit(audit_id)
    return ok(correlate(audit_id))
  })

  tool('audit_summary', 'Resumo da auditoria: contagens, score, tarefas, limitacoes.', { audit_id: id }, async ({ audit_id }) => ok(auditSummary(audit_id)))

  tool(
    'report_finalize',
    'Conclui a auditoria, calcula o score e gera os relatorios locais (HTML/MD/JSON). Retorna o link da pagina local.',
    { audit_id: id, summary: z.string().max(8000).optional() },
    async ({ audit_id, summary }) => {
      const a = getAudit(audit_id)
      if (!a) throw new Error('auditoria nao existe')
      // em execucao headless o runner fecha a auditoria ao final do processo; aqui so grava o resumo
      if (process.env.VION_AUDIT_ID === audit_id) {
        updateAudit(audit_id, { summary })
        return ok({ ...auditSummary(audit_id), url: uiUrl(audit_id), note: 'relatorio final sera gerado ao encerrar a execucao' })
      }
      const res = finalizeAudit(audit_id, { summary })
      return ok({ score: res.score, counts: res.counts, by_status: res.by_status, url: res.url, reports: res.reports })
    },
  )

  tool(
    'audits_list',
    'Historico de auditorias (filtrar por diretorio alvo). Inclui contagem de findings abertos.',
    { target: z.string().max(500).optional(), limit: z.number().int().min(1).max(200).optional() },
    async ({ target, limit }) => {
      let rows = listAudits({ limit: 500 })
      if (target) {
        const norm = s => path.resolve(s).toLowerCase()
        rows = rows.filter(a => a.scope.paths.some(p => norm(p) === norm(target)) || a.target === target)
      }
      rows = rows.slice(0, limit || 20)
      return ok(
        rows.map(a => {
          const fs = listFindings(a.id)
          return {
            audit_id: a.id, skills: a.skills, status: a.status, created_at: a.created_at, score: a.score,
            findings: fs.length, open_findings: fs.filter(f => f.remediation === 'open' && f.status !== 'false_positive').length,
            critical_open: fs.filter(f => f.severity === 'critical' && f.remediation === 'open' && f.status !== 'false_positive').length,
          }
        }),
      )
    },
  )

  return server
}

export async function startMcp() {
  const server = createServer()
  await server.connect(new StdioServerTransport())
}
