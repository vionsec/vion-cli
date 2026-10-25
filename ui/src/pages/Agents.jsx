import { useApi } from '../api.js'
import { go } from '../router.js'
import { Section, ErrorBox, Loading, Pill, Code, Empty, fmtDate, TASK_PT, shortPath } from '../components/ui.jsx'

export function Agents() {
  const { data, loading, error } = useApi('/api/agents', { live: e => e.type.startsWith('task.') })
  if (error) return <ErrorBox error={error} />
  if (loading && !data) return <Loading />
  const count = (agent, status) => data.stats.filter(s => s.agent === agent && (!status || s.status === status)).reduce((a, s) => a + s.n, 0)
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Agentes</h1>
          <p>
            Orquestração hierárquica: o orquestrador planeja e revisa; os subagentes, em modelos mais baratos, fazem o trabalho delimitado. Troque os modelos em{' '}
            <a href="#/settings">Configurações</a>.
          </p>
        </div>
      </div>
      <Section title="Equipe">
        <div className="agent-grid">
          {data.agents.map(a => (
            <div key={a.name} className="agent-card">
              <div className="row">
                <strong className="mono">{a.name}</strong>
                <Pill kind={a.key === 'orquestrador' ? 'running' : 'planned'}>{a.model}</Pill>
              </div>
              <span className="muted">{a.role}</span>
              <div className="row">
                <span className="muted">
                  {a.key === 'orquestrador' ? 'sessão principal' : `${count(a.name, 'done')} concluídas · ${count(a.name, 'failed')} falhas`}
                </span>
                {a.installed ? <Pill kind="done">instalado</Pill> : <Pill kind="suspected">não instalado</Pill>}
              </div>
              {a.installed && a.installedModel && a.installedModel !== a.model && (
                <span className="muted">
                  Instalado com <Code>{a.installedModel}</Code>: rode <Code>vion init</Code> para atualizar.
                </span>
              )}
            </div>
          ))}
        </div>
      </Section>
      <Section title="Tarefas recentes">
        {data.recent.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agente</th>
                  <th>Modelo</th>
                  <th>Tarefa</th>
                  <th>Status</th>
                  <th className="num">Tentativas</th>
                  <th>Auditoria</th>
                  <th>Atualizada</th>
                </tr>
              </thead>
              <tbody>
                {data.recent.map(t => (
                  <tr key={t.id} className="click" onClick={() => go(`/audits/${t.audit_id}?tab=agents`)}>
                    <td className="mono">{t.agent}</td>
                    <td>{t.model || '—'}</td>
                    <td>
                      {t.title}
                      {t.error && <div className="sub-cell" style={{ color: 'var(--err)' }}>{t.error}</div>}
                    </td>
                    <td>
                      <Pill kind={t.status}>{TASK_PT[t.status] || t.status}</Pill>
                    </td>
                    <td className="num">{t.attempts}</td>
                    <td className="sub-cell">{shortPath(t.audit_target, 36)}</td>
                    <td className="muted">{fmtDate(t.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty title="Nenhuma tarefa ainda" />
        )}
      </Section>
    </>
  )
}
