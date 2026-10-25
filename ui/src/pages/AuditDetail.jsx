import { useState } from 'react'
import { api, useApi, reportUrl } from '../api.js'
import { go } from '../router.js'
import {
  Section, Empty, ErrorBox, Loading, Kpi, Tabs, AuditStatus, Sev, FindingStatus, Pill, Code,
  fmtDate, fmtNum, fmtCost, loc, TASK_PT, REMED_PT, SEV, SEV_PT,
} from '../components/ui.jsx'

const EVENT_PT = {
  'audit.created': 'auditoria criada',
  'audit.status': 'status',
  phase: 'fase',
  'claude.init': 'claude',
  'task.created': 'plano',
  'task.updated': 'tarefa',
  'agent.tool': 'ferramenta',
  'orchestrator.text': 'orquestrador',
  'finding.added': 'achado',
  'finding.updated': 'validação',
  'evidence.added': 'evidência',
  'analyzers.done': 'analisadores',
  'audit.correlated': 'correlação',
  'report.generated': 'relatório',
  'hook.denied': 'BLOQUEADO',
  error: 'erro',
  warning: 'aviso',
  'audit.stop_requested': 'parada',
}

function describe(e) {
  const d = e.data || {}
  switch (e.type) {
    case 'audit.status':
      return `${d.status}${d.error ? ` — ${d.error}` : ''}`
    case 'phase':
      return `${d.name}: ${d.status}${d.added != null ? ` (${d.added} achados)` : ''}${d.model ? ` · ${d.model}` : ''}`
    case 'claude.init':
      return `sessão ${String(d.session_id || '').slice(0, 8)} · ${d.model} · MCP vion: ${d.mcp}`
    case 'task.created':
      return `${d.agent}${d.model ? ` (${d.model})` : ''}: ${d.title}`
    case 'task.updated':
      return `${d.agent}: ${TASK_PT[d.status] || d.status || 'iniciou'}${d.attempts > 1 ? ` (tentativa ${d.attempts})` : ''}`
    case 'agent.tool': {
      const who = d.sub ? 'subagente' : 'orquestrador'
      if (d.tool === 'Task' || d.tool === 'Agent') return `${who} delegou → ${d.input?.subagent}: ${d.input?.description || ''}`
      const arg = Object.values(d.input || {}).filter(Boolean).join(' ')
      return `${who} · ${d.tool.replace('mcp__vion__', 'vion.')}${arg ? ` ${arg}` : ''}`
    }
    case 'orchestrator.text':
      return d.text
    case 'finding.added':
      return `[${SEV_PT[d.severity] || d.severity}] ${d.title} — ${d.agent}${d.duplicate_of ? ' (duplicata)' : ''}`
    case 'finding.updated':
      return `${d.id}: ${[d.status, d.severity, d.remediation].filter(Boolean).join(' · ')}${d.agent ? ` — ${d.agent}` : ''}`
    case 'evidence.added':
      return `${d.kind}: ${d.title}${d.finding_id ? ` → ${d.finding_id}` : ''}`
    case 'audit.correlated':
      return `${d.total} únicos · ${d.markedDuplicates} duplicatas · ${d.near} quase-duplicatas · ${d.conflicts} conflitos`
    case 'hook.denied':
      return `${d.tool}: ${d.reason}`
    case 'error':
    case 'warning':
      return d.message
    case 'report.generated':
      return d.format
    case 'audit.created':
      return `${d.target} (${d.origin})`
    default:
      return JSON.stringify(d).slice(0, 200)
  }
}

export function AuditDetail({ id, tab }) {
  const isMine = e => e.audit_id === id
  const audit = useApi(`/api/audits/${id}`, { live: isMine })
  const findings = useApi(`/api/audits/${id}/findings`, { live: e => isMine(e) && (e.type.startsWith('finding.') || e.type === 'audit.correlated') })
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const setTab = t => go(`/audits/${id}?tab=${t}`)

  if (audit.error) return <ErrorBox error={audit.error} />
  if (!audit.data) return <Loading />
  const a = audit.data
  const s = a.summary_data
  const live = a.status === 'running' || a.status === 'pending'

  async function act(fn) {
    setBusy(true)
    setErr(null)
    try {
      await fn()
      await audit.reload()
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }

  const tabs = [
    { id: 'overview', label: 'Visão geral' },
    { id: 'agents', label: 'Agentes', count: a.tasks.length },
    { id: 'findings', label: 'Vulnerabilidades', count: findings.data?.length },
    { id: 'evidence', label: 'Evidências' },
    { id: 'assets', label: 'Ativos', count: a.assets.length },
    { id: 'timeline', label: 'Linha do tempo' },
    { id: 'reports', label: 'Relatórios', count: a.reports.length },
    { id: 'logs', label: 'Logs' },
  ]

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <a href="#/audits">Auditorias</a> / <span className="mono">{a.id}</span>
          </div>
          <h1 style={{ overflowWrap: 'anywhere' }}>{a.target}</h1>
          <p>
            <AuditStatus s={a.status} /> · {a.skills} · iniciada {fmtDate(a.created_at)} via {a.origin === 'session' ? 'Claude Code' : a.origin === 'ui' ? 'UI' : 'CLI'}
            {a.finished_at && ` · fim ${fmtDate(a.finished_at)}`}
          </p>
        </div>
        <div className="section-actions">
          {live && (
            <button className="btn btn-danger" disabled={busy} onClick={() => act(() => api(`/api/audits/${id}/stop`, { method: 'POST', body: {} }))}>
              Parar
            </button>
          )}
          {!live && (
            <button className="btn" disabled={busy} onClick={() => act(() => api(`/api/audits/${id}/report`, { method: 'POST', body: {} }))}>
              Gerar relatório
            </button>
          )}
          {!live && (
            <button
              className="btn btn-danger"
              disabled={busy}
              onClick={() => {
                if (window.confirm('Apagar esta auditoria, evidências e relatórios? Não dá para desfazer.')) act(async () => {
                  await api(`/api/audits/${id}`, { method: 'DELETE' })
                  go('/audits')
                })
              }}
            >
              Apagar
            </button>
          )}
        </div>
      </div>
      <ErrorBox error={err} />
      {a.error && <div className="error-box">{a.error}</div>}

      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === 'overview' && <Overview a={a} s={s} />}
      {tab === 'agents' && <AgentsTab a={a} />}
      {tab === 'findings' && <FindingsTable rows={findings.data} loading={findings.loading} />}
      {tab === 'evidence' && <EvidenceTab id={id} />}
      {tab === 'assets' && <AssetsTab assets={a.assets} />}
      {tab === 'timeline' && <Timeline id={id} />}
      {tab === 'reports' && <ReportsTab reports={a.reports} />}
      {tab === 'logs' && <LogsTab id={id} />}
    </>
  )
}

function Overview({ a, s }) {
  return (
    <>
      <div className="grid-kpi">
        <Kpi label="Score (escopo verificado)" value={s.score} tone={s.score >= 80 ? 'ok' : s.score < 50 ? 'crit' : undefined} />
        <Kpi label="Críticos" value={s.counts.critical} tone={s.counts.critical ? 'crit' : undefined} />
        <Kpi label="Altos" value={s.counts.high} tone={s.counts.high ? 'high' : undefined} />
        <Kpi label="Confirmados" value={s.by_status.confirmed} tone="ok" />
        <Kpi label="Suspeitos" value={s.by_status.suspected} hint="não validados" />
        <Kpi label="Falsos positivos" value={s.by_status.false_positive} />
        <Kpi label="Custo" value={fmtCost(a.cost_usd)} hint={a.input_tokens ? `${fmtNum(a.input_tokens + a.output_tokens)} tokens` : a.origin === 'session' ? 'indisponível em sessão interativa' : undefined} />
      </div>
      <div className="two-col">
        <div>
          {a.summary && (
            <Section title="Resumo executivo">
              <div className="prose">
                <p>{a.summary}</p>
              </div>
            </Section>
          )}
          <Section title="Limitações">
            {s.limitations.length ? (
              <ul style={{ margin: 0, padding: '12px 16px 12px 32px' }}>
                {s.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            ) : (
              <Empty title="Nenhuma limitação registrada" />
            )}
          </Section>
          {s.analyzers && (
            <Section title="Analisadores determinísticos (0 tokens)">
              <div className="table-wrap">
                <table>
                  <tbody>
                    {Object.entries(s.analyzers).map(([k, v]) => (
                      <tr key={k}>
                        <td>{k}</td>
                        <td>
                          <Pill kind={v.status === 'completed' ? 'done' : 'failed'}>{v.status === 'completed' ? 'ok' : 'falhou'}</Pill>
                        </td>
                        <td className="num">{v.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          )}
        </div>
        <div>
          <Section title="Escopo autorizado">
            <dl className="dl">
              <dt>Caminhos</dt>
              <dd>{a.scope.paths.length ? a.scope.paths.map(p => <Code key={p}>{p}</Code>) : '—'}</dd>
              <dt>Hosts</dt>
              <dd>{a.scope.hosts.length ? a.scope.hosts.join(', ') : '—'}</dd>
              <dt>Teste ativo</dt>
              <dd>{a.scope.active ? 'sim' : 'não'}</dd>
              {a.scope.authorization?.statement && (
                <>
                  <dt>Autorização</dt>
                  <dd>{a.scope.authorization.statement}</dd>
                </>
              )}
            </dl>
          </Section>
          <Section title="Consumo por modelo">
            {a.usage && Object.keys(a.usage).length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Modelo</th>
                      <th className="num">Entrada</th>
                      <th className="num">Saída</th>
                      <th className="num">Cache</th>
                      <th className="num">Custo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(a.usage).map(([m, u]) => (
                      <tr key={m}>
                        <td className="mono">{m}</td>
                        <td className="num">{fmtNum(u.inputTokens)}</td>
                        <td className="num">{fmtNum(u.outputTokens)}</td>
                        <td className="num">{fmtNum(u.cacheReadInputTokens)}</td>
                        <td className="num">{fmtCost(u.costUSD)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty title={a.origin === 'session' ? 'Indisponível' : 'Sem dados ainda'}>
                {a.origin === 'session' ? 'Auditorias abertas numa sessão interativa do Claude Code não expõem o consumo. Use a UI ou `vion audit` para medir.' : null}
              </Empty>
            )}
          </Section>
        </div>
      </div>
    </>
  )
}

function AgentsTab({ a }) {
  if (!a.tasks.length) return <Empty title="Nenhuma tarefa planejada ainda">O orquestrador registra o plano depois dos analisadores e do recon.</Empty>
  return (
    <Section title="Tarefas por agente">
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Agente</th>
              <th>Modelo</th>
              <th>Tarefa</th>
              <th>Status</th>
              <th className="num">Tentativas</th>
              <th>Resumo / erro</th>
            </tr>
          </thead>
          <tbody>
            {a.tasks.map(t => (
              <tr key={t.id}>
                <td className="mono">{t.agent}</td>
                <td>{t.model || '—'}</td>
                <td>
                  {t.title}
                  {t.checklist && <div className="sub-cell">checklist: {t.checklist}</div>}
                </td>
                <td>
                  <Pill kind={t.status}>{TASK_PT[t.status] || t.status}</Pill>
                </td>
                <td className="num">{t.attempts}</td>
                <td style={{ maxWidth: 420 }}>{t.error ? <span style={{ color: 'var(--err)' }}>{t.error}</span> : t.summary || <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

export function FindingsTable({ rows, loading, showAudit = false }) {
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  if (loading && !rows) return <Loading />
  const list = (rows || []).filter(f => (!sev || f.severity === sev) && (!status || f.status === status))
  return (
    <>
      <div className="toolbar">
        <select value={sev} onChange={e => setSev(e.target.value)} aria-label="Severidade">
          <option value="">Todas as severidades</option>
          {SEV.map(s => (
            <option key={s} value={s}>
              {SEV_PT[s]}
            </option>
          ))}
        </select>
        <select value={status} onChange={e => setStatus(e.target.value)} aria-label="Validação">
          <option value="">Toda validação</option>
          <option value="confirmed">Confirmados</option>
          <option value="suspected">Suspeitos</option>
          <option value="false_positive">Falsos positivos</option>
        </select>
        <span className="muted">{list.length} achado(s)</span>
      </div>
      <Section>
        {list.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severidade</th>
                  <th>Achado</th>
                  <th>Validação</th>
                  <th>Correção</th>
                  <th>Agente</th>
                  <th className="num">Evid.</th>
                </tr>
              </thead>
              <tbody>
                {list.map(f => (
                  <tr key={f.id} className="click" onClick={() => go(`/findings/${f.id}`)}>
                    <td>
                      <Sev s={f.severity} />
                    </td>
                    <td>
                      <div className="title-cell">{f.title}</div>
                      <div className="sub-cell">
                        {loc(f)}
                        {f.cwe ? ` · ${f.cwe}` : ''}
                        {showAudit && f.audit_target ? ` · ${f.audit_target}` : ''}
                      </div>
                    </td>
                    <td>
                      <FindingStatus s={f.status} />
                    </td>
                    <td>
                      <Pill kind={f.remediation}>{REMED_PT[f.remediation]}</Pill>
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {f.agent}
                    </td>
                    <td className="num">{f.evidence_ids?.length ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhum achado com esses filtros" />
        )}
      </Section>
    </>
  )
}

function EvidenceTab({ id }) {
  const { data, loading } = useApi(`/api/audits/${id}/evidence`, { live: e => e.audit_id === id && e.type === 'evidence.added' })
  if (loading && !data) return <Loading />
  if (!data?.length) return <Empty title="Nenhuma evidência anexada">Achados só viram “confirmados” quando um agente anexa a prova.</Empty>
  return <EvidenceTable rows={data} />
}

export function EvidenceTable({ rows, showAudit = false }) {
  return (
    <Section>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Evidência</th>
              <th>Origem</th>
              <th>Agente</th>
              <th>Coletada</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(e => (
              <tr key={e.id} className="click" onClick={() => go(`/evidence/${e.id}`)}>
                <td>
                  <Pill kind="planned">{e.kind}</Pill>
                </td>
                <td>
                  <div className="title-cell">{e.title}</div>
                  <div className="sub-cell">
                    {e.id}
                    {e.finding_id ? ` → ${e.finding_id}` : ''}
                    {showAudit && e.audit_target ? ` · ${e.audit_target}` : ''}
                  </div>
                </td>
                <td className="sub-cell">{e.source || '—'}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {e.agent || '—'}
                </td>
                <td className="muted">{fmtDate(e.collected_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

function AssetsTab({ assets }) {
  if (!assets.length) return <Empty title="Nenhum ativo registrado">O agente de recon registra endpoints, componentes, serviços e arquivos sensíveis.</Empty>
  return (
    <Section>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Ativo</th>
              <th>Detalhes</th>
              <th>Agente</th>
            </tr>
          </thead>
          <tbody>
            {assets.map(x => (
              <tr key={x.id}>
                <td>
                  <Pill kind="planned">{x.kind}</Pill>
                </td>
                <td className="mono" style={{ overflowWrap: 'anywhere' }}>
                  {x.name}
                </td>
                <td>{x.details || '—'}</td>
                <td className="mono" style={{ fontSize: 12 }}>
                  {x.agent || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Section>
  )
}

function Timeline({ id }) {
  const [filter, setFilter] = useState('key')
  const { data, loading } = useApi(`/api/audits/${id}/events`, { live: e => e.audit_id === id })
  if (loading && !data) return <Loading />
  const KEY = new Set(['audit.status', 'phase', 'claude.init', 'task.created', 'task.updated', 'finding.added', 'finding.updated', 'audit.correlated', 'hook.denied', 'error', 'warning', 'report.generated', 'orchestrator.text'])
  const rows = (data || []).filter(e => filter === 'all' || KEY.has(e.type) || (e.type === 'agent.tool' && ['Task', 'Agent'].includes(e.data?.tool)))
  return (
    <>
      <div className="toolbar">
        <div className="seg" role="group" aria-label="Filtro da linha do tempo">
          <button className={filter === 'key' ? 'on' : ''} onClick={() => setFilter('key')}>
            Principais
          </button>
          <button className={filter === 'all' ? 'on' : ''} onClick={() => setFilter('all')}>
            Tudo (inclui ferramentas)
          </button>
        </div>
        <span className="muted">{rows.length} evento(s)</span>
      </div>
      <Section>
        {rows.length ? (
          <ul className="timeline">
            {[...rows].reverse().map(e => (
              <li key={e.id} className={e.type === 'hook.denied' || e.type === 'error' ? 'denied' : ''}>
                <span className="t">{new Date(e.created_at).toLocaleTimeString('pt-BR')}</span>
                <span className="k">{EVENT_PT[e.type] || e.type}</span>
                <span className="d" style={{ overflowWrap: 'anywhere', whiteSpace: e.type === 'orchestrator.text' ? 'pre-wrap' : undefined }}>
                  {describe(e)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <Empty title="Sem eventos" />
        )}
      </Section>
    </>
  )
}

export function ReportsTab({ reports, showAudit = false }) {
  if (!reports?.length) return <Empty title="Nenhum relatório gerado">O relatório é gerado ao concluir a auditoria (ou em “Gerar relatório”).</Empty>
  return (
    <Section>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Formato</th>
              <th>Gerado</th>
              {showAudit && <th>Auditoria</th>}
              <th>Integridade (sha256)</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {reports.map(r => (
              <tr key={r.id}>
                <td>
                  <Pill kind="done">{r.format.toUpperCase()}</Pill>
                </td>
                <td className="muted">{fmtDate(r.created_at)}</td>
                {showAudit && (
                  <td>
                    <a href={`#/audits/${r.audit_id}`}>{r.audit_target}</a>
                  </td>
                )}
                <td className="sub-cell">{r.sha256.slice(0, 16)}…</td>
                <td className="num">
                  <span className="kv-row" style={{ justifyContent: 'flex-end' }}>
                    {r.format === 'html' && (
                      <a className="btn btn-sm" href={reportUrl(r.id)} target="_blank" rel="noreferrer">
                        Abrir
                      </a>
                    )}
                    <a className="btn btn-sm" href={reportUrl(r.id, true)}>
                      Baixar
                    </a>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="pad muted">Para PDF: abra o HTML e use Imprimir → Salvar como PDF.</div>
    </Section>
  )
}

function LogsTab({ id }) {
  const { data, loading, reload } = useApi(`/api/audits/${id}/logs`)
  if (loading && !data) return <Loading />
  return (
    <>
      <Section title="Worker (processo da auditoria)" actions={<button className="btn btn-sm" onClick={reload}>Atualizar</button>}>
        <div className="pad">{data?.worker ? <pre className="block">{data.worker}</pre> : <span className="muted">Sem log (auditorias de sessão interativa não têm worker).</span>}</div>
      </Section>
      <Section title="Bloqueios do hook de escopo">
        <div className="pad">{data?.hook ? <pre className="block">{data.hook}</pre> : <span className="muted">Nenhuma ação bloqueada.</span>}</div>
      </Section>
    </>
  )
}
