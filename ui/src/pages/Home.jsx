import { useApi } from '../api.js'
import { go } from '../router.js'
import { Kpi, Section, Empty, ErrorBox, AuditStatus, SevBar, fmtDate, shortPath, Code } from '../components/ui.jsx'

export function Home() {
  const status = useApi('/api/status', { live: e => e.type.startsWith('audit.') || e.type.startsWith('finding.') })
  const audits = useApi('/api/audits?limit=8', { live: e => e.type.startsWith('audit.') || e.type === 'finding.added' })
  const s = status.data
  const open = s?.open_findings || {}
  const running = (audits.data || []).filter(a => a.status === 'running' || a.status === 'pending')

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Início</h1>
          <p>Estado do VION nesta máquina. Nada daqui sai do seu computador.</p>
        </div>
        <a className="btn btn-primary" href="#/audits/new">Nova auditoria</a>
      </div>
      <ErrorBox error={status.error || audits.error} />

      {s && !s.installed && (
        <div className="notice warn">
          As skills ainda não estão instaladas no Claude Code. Rode <Code>vion init</Code> no terminal e reinicie o Claude Code para usar
          <Code>/vion:auditoria</Code> nas sessões interativas.
        </div>
      )}
      {s && !s.claude && (
        <div className="notice warn">
          O <Code>claude</Code> (Claude Code) não foi encontrado no PATH. Sem ele, só é possível rodar os analisadores determinísticos.
        </div>
      )}

      <div className="grid-kpi">
        <Kpi label="Críticos em aberto" value={open.critical || 0} tone={open.critical ? 'crit' : 'ok'} />
        <Kpi label="Altos em aberto" value={open.high || 0} tone={open.high ? 'high' : undefined} />
        <Kpi label="Médios/baixos" value={(open.medium || 0) + (open.low || 0)} />
        <Kpi label="Em execução" value={s?.running?.length ?? '—'} />
        <Kpi label="Auditorias concluídas" value={s?.audits?.completed || 0} />
        <Kpi label="Com falha" value={s?.audits?.failed || 0} tone={s?.audits?.failed ? 'crit' : undefined} />
      </div>

      {running.length > 0 && (
        <Section title="Em andamento">
          <AuditTable rows={running} />
        </Section>
      )}

      <Section title="Auditorias recentes" actions={<a href="#/audits">ver todas</a>}>
        {audits.data?.length ? (
          <AuditTable rows={audits.data} />
        ) : (
          <Empty title="Nenhuma auditoria ainda">
            Clique em <b>Nova auditoria</b>, rode <Code>vion audit .</Code> no terminal ou <Code>/vion:auditoria</Code> no Claude Code.
          </Empty>
        )}
      </Section>

      {s?.recent_errors?.length > 0 && (
        <Section title="Erros recentes">
          <div className="table-wrap">
            <table>
              <tbody>
                {s.recent_errors.map(e => (
                  <tr key={e.id} className="click" onClick={() => go(`/audits/${e.id}`)}>
                    <td className="sub-cell">{e.id}</td>
                    <td>{e.error || 'sem detalhe'}</td>
                    <td className="muted">{fmtDate(e.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {s && (
        <p className="muted">
          Dados em <Code>{s.home}</Code>
        </p>
      )}
    </>
  )
}

export function AuditTable({ rows }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Alvo</th>
            <th>Skills</th>
            <th>Status</th>
            <th>Achados</th>
            <th className="num">Score</th>
            <th>Criada</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(a => (
            <tr key={a.id} className="click" onClick={() => go(`/audits/${a.id}`)}>
              <td>
                <div className="title-cell">{shortPath(a.target, 56)}</div>
                <div className="sub-cell">
                  {a.id} · {a.origin === 'session' ? 'Claude Code' : a.origin === 'ui' ? 'UI' : 'CLI'}
                </div>
              </td>
              <td>{a.skills || '—'}</td>
              <td>
                <AuditStatus s={a.status} />
              </td>
              <td>
                <SevBar counts={a.counts} />
              </td>
              <td className="num">{a.score ?? a.live_score}</td>
              <td className="muted">{fmtDate(a.created_at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
