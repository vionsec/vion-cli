import { useApi } from '../api.js'
import { Section, ErrorBox, Loading, Empty, Pill, Code, fmtDate } from '../components/ui.jsx'
import { EvidenceTable } from './AuditDetail.jsx'

export function EvidenceList() {
  const { data, loading, error } = useApi('/api/evidence', { live: e => e.type === 'evidence.added' })
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Evidências</h1>
          <p>Trechos de código, requisições/respostas e saídas de ferramentas. Segredos são mascarados ao salvar.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      {loading && !data ? <Loading /> : data?.length ? <EvidenceTable rows={data} showAudit /> : <Empty title="Nenhuma evidência ainda" />}
    </>
  )
}

export function EvidenceDetail({ id }) {
  const { data: e, error } = useApi(`/api/evidence/${id}`)
  if (error) return <ErrorBox error={error} />
  if (!e) return <Loading />
  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <a href={`#/audits/${e.audit_id}?tab=evidence`}>Auditoria {e.audit_id}</a> / <span className="mono">{e.id}</span>
          </div>
          <h1>{e.title}</h1>
          <p className="kv-row">
            <Pill kind="planned">{e.kind}</Pill>
            {e.intact ? <Pill kind="done">íntegra (sha256 confere)</Pill> : <Pill kind="failed">conteúdo alterado após a coleta</Pill>}
            <span className="muted">
              {e.agent || '—'} · {fmtDate(e.collected_at)}
            </span>
          </p>
        </div>
      </div>
      <Section title="Contexto">
        <dl className="dl">
          <dt>Origem</dt>
          <dd>{e.source ? <Code>{e.source}</Code> : '—'}</dd>
          <dt>Finding</dt>
          <dd>{e.finding_id ? <a href={`#/findings/${e.finding_id}`}>{e.finding_id}</a> : '—'}</dd>
          <dt>Contexto</dt>
          <dd>{e.context || '—'}</dd>
          <dt>sha256</dt>
          <dd className="mono">{e.sha256}</dd>
          <dt>Tamanho</dt>
          <dd>{e.bytes} bytes</dd>
        </dl>
      </Section>
      <Section title="Conteúdo">
        <div className="pad">
          <pre className="block">{e.content}</pre>
        </div>
      </Section>
    </>
  )
}
