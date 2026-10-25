// ── Relatorios gerados a partir do store (HTML autocontido, Markdown e JSON) ──

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { ensureHome } from './paths.js'
import {
  getAudit, listFindings, listTasks, listAssets, listEvidence, eventsSince,
  severityCounts, computeScore, addReport,
} from './store.js'

export const SEV_LABEL = { critical: 'Critico', high: 'Alto', medium: 'Medio', low: 'Baixo', info: 'Info' }
export const STATUS_LABEL = { suspected: 'Suspeito (nao validado)', confirmed: 'Confirmado', false_positive: 'Falso positivo' }

export function auditSummary(auditId) {
  const audit = getAudit(auditId)
  if (!audit) throw new Error(`Auditoria nao encontrada: ${auditId}`)
  const findings = listFindings(auditId)
  const tasks = listTasks(auditId)
  const byStatus = { suspected: 0, confirmed: 0, false_positive: 0 }
  for (const f of findings) byStatus[f.status]++
  const analyzerEvent = eventsSince(0, auditId, 5000).filter(e => e.type === 'analyzers.done').at(-1)
  const limitations = []
  for (const t of tasks) if (t.status === 'failed') limitations.push(`Tarefa "${t.title}" (${t.agent}) falhou: ${t.error || 'sem detalhe'}`)
  for (const t of tasks) if (t.status === 'planned') limitations.push(`Tarefa "${t.title}" nao foi executada.`)
  if (analyzerEvent?.data?.truncated) limitations.push('Projeto grande: os analisadores deterministicos leram so os primeiros 6000 arquivos.')
  if (byStatus.suspected) limitations.push(`${byStatus.suspected} achado(s) continuam como suspeita nao validada.`)
  if (audit.scope.targetType === 'path' && !audit.scope.active) limitations.push('Analise estatica do codigo: nao houve teste ativo contra o sistema em execucao.')
  return {
    audit_id: auditId,
    target: audit.target,
    status: audit.status,
    skills: audit.skills,
    score: computeScore(findings),
    counts: severityCounts(findings),
    by_status: byStatus,
    tasks: tasks.map(t => ({ agent: t.agent, model: t.model, title: t.title, status: t.status })),
    analyzers: analyzerEvent?.data?.stats || null,
    tokens: audit.input_tokens != null ? { input: audit.input_tokens, output: audit.output_tokens, cache_read: audit.cache_read_tokens, cost_usd: audit.cost_usd } : null,
    limitations,
  }
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c])
}

function loc(f) {
  return f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ''}` : f.asset || '—'
}

export function buildReportData(auditId, executiveSummary) {
  const audit = getAudit(auditId)
  const findings = listFindings(auditId)
  return {
    generated_at: new Date().toISOString(),
    generator: 'VION (@vionsec/cli) — relatorio local',
    executive_summary: executiveSummary || audit.summary || null,
    summary: auditSummary(auditId),
    scope: audit.scope,
    findings,
    tasks: listTasks(auditId),
    assets: listAssets(auditId),
    evidence: listEvidence(auditId).map(e => ({ id: e.id, finding_id: e.finding_id, kind: e.kind, title: e.title, sha256: e.sha256, source: e.source, collected_at: e.collected_at })),
  }
}

export function renderMarkdown(d) {
  const s = d.summary
  const lines = [
    `# Relatorio VION — ${d.scope.target}`,
    '',
    `- Auditoria: \`${s.audit_id}\``,
    `- Gerado em: ${d.generated_at}`,
    `- Skills: ${s.skills || '—'}`,
    `- Score: **${s.score}/100** (reflete apenas o escopo verificado)`,
    `- Achados: ${Object.entries(s.counts).map(([k, v]) => `${SEV_LABEL[k]} ${v}`).join(' · ')}`,
    `- Validacao: ${s.by_status.confirmed} confirmados · ${s.by_status.suspected} suspeitos · ${s.by_status.false_positive} falsos positivos`,
    '',
  ]
  if (d.executive_summary) lines.push('## Resumo executivo', '', d.executive_summary, '')
  for (const [status, title] of [['confirmed', 'Vulnerabilidades confirmadas'], ['suspected', 'Suspeitas nao validadas'], ['false_positive', 'Descartados (falsos positivos)']]) {
    const group = d.findings.filter(f => f.status === status)
    if (!group.length) continue
    lines.push(`## ${title} (${group.length})`, '')
    for (const f of group) {
      lines.push(`### [${SEV_LABEL[f.severity]}] ${f.title}`, '')
      lines.push(`- ID: \`${f.id}\` · Local: \`${loc(f)}\` · Confianca: ${f.confidence} · Agente: ${f.agent}${f.cwe ? ` · ${f.cwe}` : ''}`)
      if (status !== 'false_positive') {
        lines.push('', f.description)
        if (f.impact) lines.push('', `**Impacto:** ${f.impact}`)
        if (f.validation_method) lines.push('', `**Validacao:** ${f.validation_method}`)
        if (f.recommendation) lines.push('', `**Correcao:** ${f.recommendation}`)
        if (f.evidence_ids.length) lines.push('', `**Evidencias:** ${f.evidence_ids.map(e => `\`${e}\``).join(', ')}`)
      }
      if (f.limitations) lines.push('', `**Limitacoes:** ${f.limitations}`)
      lines.push('')
    }
  }
  if (s.limitations.length) lines.push('## Limitacoes da auditoria', '', ...s.limitations.map(l => `- ${l}`), '')
  lines.push('## Agentes e tarefas', '', '| Agente | Modelo | Tarefa | Status |', '|---|---|---|---|')
  for (const t of d.tasks) lines.push(`| ${t.agent} | ${t.model || '—'} | ${t.title.replace(/\|/g, '/')} | ${t.status} |`)
  return lines.join('\n') + '\n'
}

export function renderHtml(d) {
  const s = d.summary
  const card = f => `
    <article class="f sev-${f.severity}">
      <header><span class="badge ${f.severity}">${esc(SEV_LABEL[f.severity])}</span><h3>${esc(f.title)}</h3></header>
      <p class="meta"><code>${esc(loc(f))}</code> · ${esc(STATUS_LABEL[f.status])} · confianca ${esc(f.confidence)} · ${esc(f.agent)}${f.cwe ? ` · ${esc(f.cwe)}` : ''} · <code>${esc(f.id)}</code></p>
      ${f.status === 'false_positive' ? '' : `<p>${esc(f.description)}</p>`}
      ${f.impact ? `<p><b>Impacto:</b> ${esc(f.impact)}</p>` : ''}
      ${f.validation_method ? `<p><b>Validacao:</b> ${esc(f.validation_method)}</p>` : ''}
      ${f.recommendation && f.status !== 'false_positive' ? `<p><b>Correcao:</b> ${esc(f.recommendation)}</p>` : ''}
      ${f.evidence_ids.length ? `<p><b>Evidencias:</b> ${f.evidence_ids.map(e => `<code>${esc(e)}</code>`).join(' ')}</p>` : ''}
      ${f.limitations ? `<p class="lim"><b>Limitacoes:</b> ${esc(f.limitations)}</p>` : ''}
    </article>`
  const section = (status, title) => {
    const g = d.findings.filter(f => f.status === status)
    return g.length ? `<h2>${title} (${g.length})</h2>${g.map(card).join('')}` : ''
  }
  return `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relatorio VION — ${esc(d.scope.target)}</title>
<style>
:root{--bg:#fff;--fg:#14161a;--mut:#5b6270;--line:#e3e6eb;--card:#f7f8fa;--crit:#b42318;--high:#c4320a;--med:#b54708;--low:#175cd3;--info:#475467}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--fg:#e6e8eb;--mut:#9aa3af;--line:#262a31;--card:#15181d;--crit:#f97066;--high:#fd853a;--med:#fdb022;--low:#53b1fd;--info:#98a2b3}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
h3{font-size:15px;margin:0}.sub{color:var(--mut);margin:0 0 20px}code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin:16px 0}.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.kpi b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.kpi span{color:var(--mut);font-size:12px}
.f{background:var(--card);border:1px solid var(--line);border-left:3px solid var(--info);border-radius:8px;padding:12px 14px;margin:10px 0}
.f header{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.f p{margin:8px 0 0}.meta{color:var(--mut);font-size:13px}.lim{color:var(--mut)}
.sev-critical{border-left-color:var(--crit)}.sev-high{border-left-color:var(--high)}.sev-medium{border-left-color:var(--med)}.sev-low{border-left-color:var(--low)}
.badge{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em;padding:2px 6px;border-radius:4px;border:1px solid currentColor}
.badge.critical{color:var(--crit)}.badge.high{color:var(--high)}.badge.medium{color:var(--med)}.badge.low{color:var(--low)}.badge.info{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:13px}td,th{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}
.exec{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;white-space:pre-wrap}
@media print{body{font-size:12px}.f{break-inside:avoid}}
</style></head><body><main>
<h1>Relatorio VION</h1>
<p class="sub"><code>${esc(d.scope.target)}</code> · auditoria <code>${esc(s.audit_id)}</code> · ${esc(d.generated_at)}</p>
<div class="kpis">
  <div class="kpi"><b>${s.score}</b><span>score (so o escopo verificado)</span></div>
  ${Object.entries(s.counts).map(([k, v]) => `<div class="kpi"><b>${v}</b><span>${SEV_LABEL[k]}</span></div>`).join('')}
  <div class="kpi"><b>${s.by_status.confirmed}</b><span>confirmados</span></div>
  <div class="kpi"><b>${s.by_status.suspected}</b><span>suspeitos</span></div>
</div>
${d.executive_summary ? `<h2>Resumo executivo</h2><div class="exec">${esc(d.executive_summary)}</div>` : ''}
${section('confirmed', 'Vulnerabilidades confirmadas')}
${section('suspected', 'Suspeitas nao validadas')}
${section('false_positive', 'Descartados (falsos positivos)')}
${s.limitations.length ? `<h2>Limitacoes</h2><ul>${s.limitations.map(l => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}
<h2>Agentes e tarefas</h2>
<table><thead><tr><th>Agente</th><th>Modelo</th><th>Tarefa</th><th>Status</th></tr></thead><tbody>
${d.tasks.map(t => `<tr><td>${esc(t.agent)}</td><td>${esc(t.model || '—')}</td><td>${esc(t.title)}</td><td>${esc(t.status)}</td></tr>`).join('')}
</tbody></table>
<h2>Escopo</h2>
<p><b>Caminhos:</b> ${d.scope.paths.map(p => `<code>${esc(p)}</code>`).join(', ') || '—'}<br>
<b>Hosts:</b> ${d.scope.hosts.map(h => `<code>${esc(h)}</code>`).join(', ') || '—'} · <b>Teste ativo:</b> ${d.scope.active ? 'sim' : 'nao'}<br>
${d.scope.authorization?.statement ? `<b>Autorizacao:</b> ${esc(d.scope.authorization.statement)} (${esc(d.scope.authorization.date)})` : ''}</p>
<p class="sub">Gerado localmente pelo VION (@vionsec/cli, open source). Achados "suspeitos" nao foram comprovados.</p>
</main></body></html>
`
}

/** Gera e registra os relatorios nos 3 formatos. Retorna { [format]: absPath }. */
export function generateReports(auditId, executiveSummary = null, formats = ['html', 'md', 'json']) {
  const home = ensureHome()
  const dir = path.join(home.reports, auditId)
  fs.mkdirSync(dir, { recursive: true })
  const data = buildReportData(auditId, executiveSummary)
  const out = {}
  const stamp = data.generated_at.replace(/[:.]/g, '-')
  for (const fmt of formats) {
    const body = fmt === 'html' ? renderHtml(data) : fmt === 'md' ? renderMarkdown(data) : JSON.stringify(data, null, 2)
    const rel = path.join(auditId, `relatorio-${stamp}.${fmt}`)
    fs.writeFileSync(path.join(home.reports, rel), body, { mode: 0o600 })
    addReport(auditId, { format: fmt, relPath: rel.replace(/\\/g, '/'), sha256: crypto.createHash('sha256').update(body).digest('hex'), executive_summary: executiveSummary })
    out[fmt] = path.join(home.reports, rel)
  }
  return out
}
