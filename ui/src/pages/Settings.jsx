import { useEffect, useState } from 'react'
import { api, useApi } from '../api.js'
import { Section, ErrorBox, Loading, Code } from '../components/ui.jsx'

const ROLE_PT = {
  orquestrador: 'Orquestrador (planeja, delega, revisa)',
  recon: 'Reconhecimento',
  vuln: 'Vulnerabilidades (checklists)',
  investigador: 'Investigação / validação',
  'threat-intel': 'Threat intelligence (dependências)',
  correlacao: 'Correlação',
  relatorio: 'Relatórios',
}

export function Settings() {
  const cfg = useApi('/api/config')
  const status = useApi('/api/status')
  const projects = useApi('/api/projects')
  const [form, setForm] = useState(null)
  const [msg, setMsg] = useState(null)
  const [err, setErr] = useState(null)

  useEffect(() => {
    if (cfg.data && !form) setForm(structuredClone(cfg.data.config))
  }, [cfg.data, form])

  if (cfg.error) return <ErrorBox error={cfg.error} />
  if (!form) return <Loading />
  const { roles, models } = cfg.data

  async function save(ev) {
    ev.preventDefault()
    setErr(null)
    setMsg(null)
    const body = {}
    for (const r of roles) if (form.models[r] !== cfg.data.config.models[r]) body[`models.${r}`] = form.models[r]
    for (const k of ['maxCostUsd', 'maxConcurrentAudits', 'timeoutMinutes']) if (String(form.limits[k]) !== String(cfg.data.config.limits[k])) body[`limits.${k}`] = form.limits[k]
    if (String(form.retention.days) !== String(cfg.data.config.retention.days)) body['retention.days'] = form.retention.days
    if (String(form.ui.port) !== String(cfg.data.config.ui.port)) body['ui.port'] = form.ui.port
    if (!Object.keys(body).length) return setMsg('Nada mudou.')
    try {
      const res = await api('/api/config', { method: 'POST', body })
      setForm(structuredClone(res.config))
      await cfg.reload()
      setMsg(res.note)
    } catch (e) {
      setErr(e)
    }
  }

  async function removeProject(id) {
    await api(`/api/projects/${id}`, { method: 'DELETE' })
    projects.reload()
  }

  const setModel = (r, v) => setForm(f => ({ ...f, models: { ...f.models, [r]: v } }))
  const setLimit = (k, v) => setForm(f => ({ ...f, limits: { ...f.limits, [k]: v } }))

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Configurações</h1>
          <p>
            Salvas em <Code>{status.data?.home}/config.json</Code>. Também via terminal: <Code>vion config set models.vuln haiku</Code>.
          </p>
        </div>
      </div>
      <ErrorBox error={err} />
      {msg && <div className="notice">{msg}</div>}
      <form onSubmit={save}>
        <Section title="Modelos por papel">
          <div className="pad">
            <p className="muted">
              Economia de tokens: o Opus fica no orquestrador, que lê só resumos. Tarefas delimitadas vão para Sonnet/Haiku. “inherit” usa o modelo da sessão.
            </p>
            {roles.map(r => (
              <div className="field" key={r} style={{ maxWidth: 520 }}>
                <label htmlFor={`m-${r}`}>{ROLE_PT[r] || r}</label>
                <select id={`m-${r}`} value={form.models[r]} onChange={e => setModel(r, e.target.value)}>
                  {models.map(m => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>
            ))}
            <p className="muted">
              As auditorias da UI/CLI usam a configuração na hora. Para as skills interativas (<Code>/vion:auditoria</Code>), rode <Code>vion init</Code> depois de mudar.
            </p>
          </div>
        </Section>
        <Section title="Limites de execução">
          <div className="pad" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '0 16px' }}>
            <div className="field">
              <label htmlFor="cost">Teto de custo por auditoria (US$)</label>
              <input id="cost" type="number" min="0" step="0.5" value={form.limits.maxCostUsd} onChange={e => setLimit('maxCostUsd', e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="conc">Auditorias simultâneas</label>
              <input id="conc" type="number" min="1" max="8" value={form.limits.maxConcurrentAudits} onChange={e => setLimit('maxConcurrentAudits', e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="to">Tempo limite (min)</label>
              <input id="to" type="number" min="1" value={form.limits.timeoutMinutes} onChange={e => setLimit('timeoutMinutes', e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="ret">Retenção (dias, 0 = manter)</label>
              <input id="ret" type="number" min="0" value={form.retention.days} onChange={e => setForm(f => ({ ...f, retention: { days: e.target.value } }))} />
            </div>
            <div className="field">
              <label htmlFor="port">Porta da UI</label>
              <input id="port" type="number" min="1024" max="65535" value={form.ui.port} onChange={e => setForm(f => ({ ...f, ui: { port: e.target.value } }))} />
              <span className="help">Vale no próximo `vion ui`.</span>
            </div>
          </div>
        </Section>
        <div style={{ marginBottom: 16 }}>
          <button className="btn btn-primary" type="submit">
            Salvar
          </button>
        </div>
      </form>

      <Section title="Projetos autorizados (allowlist da UI)">
        {projects.data?.length ? (
          <div className="table-wrap">
            <table>
              <tbody>
                {projects.data.map(p => (
                  <tr key={p.id}>
                    <td className="title-cell">{p.name}</td>
                    <td className="sub-cell">{p.path}</td>
                    <td className="num">
                      <button className="btn btn-sm btn-danger" onClick={() => removeProject(p.id)}>
                        Remover
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="pad muted">Nenhum projeto cadastrado. Adicione em Nova auditoria.</div>
        )}
      </Section>

      <Section title="Sistema">
        <dl className="dl">
          <dt>Versão</dt>
          <dd>@vionsec/cli {status.data?.version}</dd>
          <dt>Dados</dt>
          <dd>
            <Code>{status.data?.home}</Code>
          </dd>
          <dt>Claude Code</dt>
          <dd>{status.data?.claude ? 'encontrado' : 'não encontrado no PATH'}</dd>
          <dt>Instalação</dt>
          <dd>
            {status.data?.installed
              ? `v${status.data.installed.version} · MCP ${status.data.installed.mcp ? 'ok' : 'pendente'} · hook ${status.data.installed.hook ? 'ok' : 'pendente'}`
              : 'não instalado (rode vion init)'}
          </dd>
          <dt>Chaves de API</dt>
          <dd>Não são necessárias: o VION usa a autenticação do seu Claude Code. Nenhuma chave é guardada pelo VION.</dd>
        </dl>
      </Section>
    </>
  )
}
