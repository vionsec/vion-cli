import { useState } from 'react'
import { useApi } from '../api.js'
import { Section, Empty, ErrorBox, Loading, Code, AUDIT_PT } from '../components/ui.jsx'
import { AuditTable } from './Home.jsx'

export function Audits() {
  const [filter, setFilter] = useState('all')
  const { data, error, loading } = useApi('/api/audits?limit=500', { live: e => e.type.startsWith('audit.') || e.type === 'finding.added' })
  const rows = (data || []).filter(a => filter === 'all' || a.status === filter)
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Auditorias</h1>
          <p>Todas as execuções: pela UI, pelo terminal (vion audit) e pelas skills no Claude Code.</p>
        </div>
        <a className="btn btn-primary" href="#/audits/new">Nova auditoria</a>
      </div>
      <ErrorBox error={error} />
      <div className="toolbar">
        <div className="seg" role="group" aria-label="Filtrar por status">
          {['all', 'running', 'completed', 'failed', 'stopped'].map(s => (
            <button key={s} className={filter === s ? 'on' : ''} onClick={() => setFilter(s)}>
              {s === 'all' ? 'Todas' : AUDIT_PT[s]}
            </button>
          ))}
        </div>
      </div>
      <Section>
        {loading && !data ? (
          <Loading />
        ) : rows.length ? (
          <AuditTable rows={rows} />
        ) : (
          <Empty title="Nada por aqui">
            Inicie uma em <a href="#/audits/new">Nova auditoria</a> ou rode <Code>vion audit .</Code>
          </Empty>
        )}
      </Section>
    </>
  )
}
