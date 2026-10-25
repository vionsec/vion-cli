import { useApi } from '../api.js'
import { Section, ErrorBox, Loading, Pill, Code } from '../components/ui.jsx'

const PERM_PT = { read: 'lê código', write: 'edita arquivos', 'bash-local': 'ferramentas locais', 'network-passive': 'rede (passivo)', 'network-active': 'teste ativo' }

export function Skills() {
  const { data, loading, error } = useApi('/api/skills')
  if (error) return <ErrorBox error={error} />
  if (loading && !data) return <Loading />
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Skills</h1>
          <p>
            Comandos do VION dentro do Claude Code (<Code>/vion:&lt;nome&gt;</Code>). No terminal: <Code>vion help skills</Code>.
          </p>
        </div>
      </div>
      {data.groups.map(([g, title]) => {
        const items = data.skills.filter(s => s.group === g)
        if (!items.length) return null
        return (
          <Section key={g} title={title}>
            <div className="table-wrap">
              <table>
                <tbody>
                  {items.map(s => (
                    <tr key={s.name}>
                      <td style={{ width: 170 }}>
                        <Code>/vion:{s.name}</Code>
                        {s.orchestrated && (
                          <div style={{ marginTop: 6 }}>
                            <Pill kind="running">multiagente</Pill>
                          </div>
                        )}
                      </td>
                      <td>
                        <div className="title-cell">{s.summary}</div>
                        <div className="muted">{s.details}</div>
                        <div className="muted" style={{ marginTop: 4 }}>
                          <b>Quando usar:</b> {s.whenToUse}
                        </div>
                        {s.agents && (
                          <div className="muted">
                            <b>Agentes:</b> orquestrador ({s.model}) + {s.agents.join(', ')}
                          </div>
                        )}
                      </td>
                      <td style={{ width: 210 }}>
                        <div className="chips">
                          {s.permissions.map(p => (
                            <Pill key={p} kind={p === 'network-active' || p === 'write' ? 'suspected' : 'planned'}>
                              {PERM_PT[p] || p}
                            </Pill>
                          ))}
                        </div>
                        {s.scope === 'host' && <div className="muted" style={{ marginTop: 4 }}>exige URL + autorização</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Section>
        )
      })}
      <Section title="Checklists delegáveis aos subagentes">
        <div className="pad chips">
          {data.checklists.map(c => (
            <Pill key={c.name} kind="planned">
              {c.name} — {c.title}
            </Pill>
          ))}
        </div>
      </Section>
    </>
  )
}
