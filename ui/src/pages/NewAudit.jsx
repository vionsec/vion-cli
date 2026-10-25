import { useState } from 'react'
import { api, useApi } from '../api.js'
import { go } from '../router.js'
import { Section, ErrorBox, Code } from '../components/ui.jsx'

const QUICK = [
  { id: 'full', label: 'Auditoria completa', skills: ['auditoria'], hint: 'Analisadores + orquestrador Opus + todas as checklists' },
  { id: 'custom', label: 'Escolher áreas', skills: null, hint: 'Monte o plano com as checklists que quiser' },
  { id: 'skill', label: 'Uma skill', skills: null, hint: 'Roda uma skill especializada (ex.: lgpd, recon, pentest)' },
]

export function NewAudit() {
  const projects = useApi('/api/projects')
  const catalog = useApi('/api/skills')
  const cfg = useApi('/api/config')
  const [targetType, setTargetType] = useState('project')
  const [projectId, setProjectId] = useState('')
  const [newPath, setNewPath] = useState('')
  const [url, setUrl] = useState('')
  const [hosts, setHosts] = useState('')
  const [mode, setMode] = useState('full')
  const [checks, setChecks] = useState([])
  const [skill, setSkill] = useState('lgpd')
  const [analyzersOnly, setAnalyzersOnly] = useState(false)
  const [active, setActive] = useState(false)
  const [authorization, setAuthorization] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [maxCost, setMaxCost] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const isUrl = targetType === 'url'
  const needsAuth = isUrl || active || hosts.trim()
  const singleSkills = (catalog.data?.skills || []).filter(s => !['vion', 'ajuda', 'status', 'ciclo', 'fixes', 'corrigir', 'dev-seguro', 'novo', 'auditoria', 'orquestrar'].includes(s.name))

  async function addProject() {
    setError(null)
    try {
      const p = await api('/api/projects', { method: 'POST', body: { path: newPath.trim() } })
      setNewPath('')
      await projects.reload()
      setProjectId(p.id)
    } catch (e) {
      setError(e)
    }
  }

  async function submit(ev) {
    ev.preventDefault()
    setError(null)
    const skills = mode === 'full' ? ['auditoria'] : mode === 'custom' ? checks : [skill]
    if (mode === 'custom' && !checks.length) return setError(new Error('Escolha ao menos uma área.'))
    setBusy(true)
    try {
      const res = await api('/api/audits', {
        method: 'POST',
        body: {
          projectId: isUrl ? undefined : projectId,
          url: isUrl ? url.trim() : undefined,
          hosts: hosts.split(/[\s,]+/).filter(Boolean),
          skills,
          analyzersOnly: !isUrl && analyzersOnly,
          active,
          authorization,
          confirmAuthorized: confirm,
          maxCost: maxCost === '' ? null : Number(maxCost),
        },
      })
      go(`/audits/${res.id}`)
    } catch (e) {
      setError(e)
      setBusy(false)
    }
  }

  const toggleCheck = name => setChecks(c => (c.includes(name) ? c.filter(x => x !== name) : [...c, name]))

  return (
    <>
      <div className="page-head">
        <div>
          <div className="crumbs">
            <a href="#/audits">Auditorias</a> /
          </div>
          <h1>Nova auditoria</h1>
          <p>O motor do VION aplica o escopo: leitura só dentro do diretório, sem escrita e rede só para os hosts declarados.</p>
        </div>
      </div>
      <ErrorBox error={error} />
      <form onSubmit={submit}>
        <Section title="1. Alvo">
          <div className="pad">
            <div className="toolbar">
              <div className="seg" role="group" aria-label="Tipo de alvo">
                <button type="button" className={!isUrl ? 'on' : ''} onClick={() => setTargetType('project')}>
                  Projeto local
                </button>
                <button type="button" className={isUrl ? 'on' : ''} onClick={() => setTargetType('url')}>
                  URL / domínio
                </button>
              </div>
            </div>
            {!isUrl ? (
              <>
                <div className="field">
                  <label htmlFor="proj">Projeto</label>
                  <select id="proj" value={projectId} onChange={e => setProjectId(e.target.value)} required>
                    <option value="">Selecione…</option>
                    {(projects.data || []).map(p => (
                      <option key={p.id} value={p.id}>
                        {p.name} — {p.path}
                      </option>
                    ))}
                  </select>
                  <span className="help">Só diretórios cadastrados aqui podem ser auditados pela UI.</span>
                </div>
                <div className="field">
                  <label htmlFor="np">Cadastrar diretório</label>
                  <div className="kv-row">
                    <input id="np" type="text" placeholder="C:\projetos\meu-app  ou  /home/eu/meu-app" value={newPath} onChange={e => setNewPath(e.target.value)} />
                    <button type="button" className="btn" onClick={addProject} disabled={!newPath.trim()}>
                      Adicionar
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div className="field">
                <label htmlFor="url">URL</label>
                <input id="url" type="text" placeholder="https://staging.meuapp.com" value={url} onChange={e => setUrl(e.target.value)} required />
              </div>
            )}
            <div className="field">
              <label htmlFor="hosts">Hosts adicionais autorizados (opcional)</label>
              <input id="hosts" type="text" placeholder="api.meuapp.com, *.staging.meuapp.com" value={hosts} onChange={e => setHosts(e.target.value)} />
              <span className="help">Qualquer acesso de rede fora desta lista é bloqueado pelo motor.</span>
            </div>
          </div>
        </Section>

        <Section title="2. O que auditar">
          <div className="pad">
            <div className="chips" style={{ marginBottom: 14 }}>
              {QUICK.map(q => (
                <label key={q.id} className={`chip ${mode === q.id ? 'on' : ''}`} title={q.hint}>
                  <input type="radio" name="mode" checked={mode === q.id} onChange={() => setMode(q.id)} /> {q.label}
                </label>
              ))}
            </div>
            {mode === 'custom' && (
              <div className="chips">
                {(catalog.data?.checklists || []).map(c => (
                  <label key={c.name} className={`chip ${checks.includes(c.name) ? 'on' : ''}`} title={c.title}>
                    <input type="checkbox" checked={checks.includes(c.name)} onChange={() => toggleCheck(c.name)} /> {c.name}
                  </label>
                ))}
              </div>
            )}
            {mode === 'skill' && (
              <div className="field">
                <select value={skill} onChange={e => setSkill(e.target.value)} aria-label="Skill">
                  {singleSkills.map(s => (
                    <option key={s.name} value={s.name}>
                      /vion:{s.name} — {s.menu || s.summary}
                    </option>
                  ))}
                </select>
                <span className="help">{singleSkills.find(s => s.name === skill)?.details}</span>
              </div>
            )}
            {!isUrl && (
              <label className="check" style={{ marginTop: 10 }}>
                <input type="checkbox" checked={analyzersOnly} onChange={e => setAnalyzersOnly(e.target.checked)} />
                <span>
                  Somente analisadores determinísticos <span className="muted">(0 tokens, sem IA; achados ficam como suspeitos)</span>
                </span>
              </label>
            )}
          </div>
        </Section>

        <Section title="3. Autorização e limites">
          <div className="pad">
            <label className="check field">
              <input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)} />
              <span>
                Permitir testes ativos <span className="muted">(scan de portas, fuzzing, exploração controlada; só para hosts do escopo)</span>
              </span>
            </label>
            {needsAuth && (
              <div className="field">
                <label htmlFor="auth">Declaração de autorização (obrigatória para rede)</label>
                <textarea
                  id="auth"
                  placeholder="Ex.: Sou responsável pelo domínio staging.meuapp.com; teste autorizado por Fulano em 25/10/2026, janela 14h-18h."
                  value={authorization}
                  onChange={e => setAuthorization(e.target.value)}
                />
              </div>
            )}
            <div className="field" style={{ maxWidth: 260 }}>
              <label htmlFor="cost">Teto de custo (US$)</label>
              <input id="cost" type="number" min="0" step="0.5" placeholder={String(cfg.data?.config?.limits?.maxCostUsd ?? 5)} value={maxCost} onChange={e => setMaxCost(e.target.value)} />
              <span className="help">A execução para ao atingir o teto (resultados parciais ficam salvos).</span>
            </div>
            <label className="check field">
              <input type="checkbox" checked={confirm} onChange={e => setConfirm(e.target.checked)} required />
              <span>Confirmo que sou dono deste alvo ou tenho autorização documentada para testá-lo.</span>
            </label>
            <div className="kv-row">
              <button className="btn btn-primary" type="submit" disabled={busy || !confirm || (!isUrl && !projectId) || (isUrl && !url)}>
                {busy ? 'Iniciando…' : 'Iniciar auditoria'}
              </button>
              <span className="muted">
                Orquestrador: <Code>{cfg.data?.config?.models?.orquestrador || 'opus'}</Code> · subagentes conforme <a href="#/settings">Configurações</a>
              </span>
            </div>
          </div>
        </Section>
      </form>
    </>
  )
}
