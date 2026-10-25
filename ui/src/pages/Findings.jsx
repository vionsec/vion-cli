import { useState } from 'react'
import { api, useApi } from '../api.js'
import { go } from '../router.js'
import { Section, ErrorBox, Loading, Sev, FindingStatus, Pill, Code, fmtDate, loc, REMED_PT } from '../components/ui.jsx'
import { FindingsTable } from './AuditDetail.jsx'

export function Findings() {
  const { data, loading, error } = useApi('/api/findings', { live: e => e.type.startsWith('finding.') })
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Vulnerabilidades</h1>
          <p>Achados de todas as auditorias (sem duplicatas). “Suspeito” significa não comprovado.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      <FindingsTable rows={data} loading={loading} showAudit />
    </>
  )
}

function Field({ label, children }) {
  if (!children) return null
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  )
}

export function FindingDetail({ id }) {
  const { data: f, error, reload } = useApi(`/api/findings/${id}`, { live: e => e.type === 'finding.updated' && e.data?.id === id })
  const [err, setErr] = useState(null)
  const [busy, setBusy] = useState(false)
  if (error) return <ErrorBox error={error} />
  if (!f) return <Loading />

  async function patch(body) {
    setBusy(true)
    setErr(null)
    try {
      await api(`/api/findings/${id}`, { method: 'POST', body })
      await reload()
    } catch (e) {
      setErr(e)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <a href={`#/audits/${f.audit_id}?tab=findings`}>Auditoria {f.audit_id}</a> / <span className="mono">{f.id}</span>
          </div>
          <h1>{f.title}</h1>
          <p className="kv-row">
            <Sev s={f.severity} /> <FindingStatus s={f.status} /> <Pill kind={f.remediation}>{REMED_PT[f.remediation]}</Pill>
            <span className="muted">
              confiança {f.confidence} · {f.agent} · {f.source === 'analyzer' ? 'analisador determinístico' : 'agente'}
            </span>
          </p>
        </div>
        <div className="section-actions">
          {f.status !== 'false_positive' ? (
            <button className="btn" disabled={busy} onClick={() => patch({ status: 'false_positive', note: 'Marcado como falso positivo pelo usuario na UI.' })}>
              Marcar falso positivo
            </button>
          ) : (
            <button className="btn" disabled={busy} onClick={() => patch({ status: 'suspected' })}>
              Reabrir como suspeito
            </button>
          )}
          {f.remediation !== 'applied' ? (
            <button className="btn" disabled={busy} onClick={() => patch({ remediation: 'applied' })}>
              Marcar corrigido
            </button>
          ) : (
            <button className="btn" disabled={busy} onClick={() => patch({ remediation: 'open' })}>
              Reabrir correção
            </button>
          )}
        </div>
      </div>
      <ErrorBox error={err} />
      {f.duplicate_of && (
        <div className="notice">
          Duplicata de <a href={`#/findings/${f.duplicate_of}`}>{f.duplicate_of}</a>.
        </div>
      )}
      {f.status === 'suspected' && <div className="notice warn">Não validado: nenhuma evidência comprova este achado ainda.</div>}
      <div className="two-col">
        <div>
          <Section title="Descrição">
            <div className="prose">
              <p>{f.description}</p>
            </div>
          </Section>
          {f.code_snippet && (
            <Section title="Trecho">
              <div className="pad">
                <pre className="block">{f.code_snippet}</pre>
              </div>
            </Section>
          )}
          <Section title="Evidências">
            {f.evidence.length ? (
              <div className="table-wrap">
                <table>
                  <tbody>
                    {f.evidence.map(e => (
                      <tr key={e.id} className="click" onClick={() => go(`/evidence/${e.id}`)}>
                        <td>
                          <Pill kind="planned">{e.kind}</Pill>
                        </td>
                        <td>
                          <div className="title-cell">{e.title}</div>
                          <div className="sub-cell">{e.source}</div>
                        </td>
                        <td className="muted">{fmtDate(e.collected_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="pad muted">Nenhuma evidência anexada.</div>
            )}
          </Section>
        </div>
        <Section title="Detalhes">
          <dl className="dl">
            <Field label="Local">
              <Code>{loc(f)}</Code>
            </Field>
            <Field label="CWE">{f.cwe}</Field>
            <Field label="Categoria">{f.category}</Field>
            <Field label="Regra">{f.rule}</Field>
            <Field label="Justificativa da severidade">{f.severity_reason}</Field>
            <Field label="Impacto">{f.impact}</Field>
            <Field label="Validação">{f.validation_method}</Field>
            <Field label="Correção recomendada">{f.recommendation}</Field>
            <Field label="Limitações">{f.limitations}</Field>
            <Field label="Registrado">{fmtDate(f.created_at)}</Field>
            <Field label="Atualizado">{fmtDate(f.updated_at)}</Field>
          </dl>
        </Section>
      </div>
    </>
  )
}
