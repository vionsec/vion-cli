export const SEV = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_PT = { critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo', info: 'Info' }
export const STATUS_PT = { suspected: 'Suspeito', confirmed: 'Confirmado', false_positive: 'Falso positivo' }
export const REMED_PT = { open: 'Aberto', applied: 'Corrigido', rejected: 'Rejeitado', wont_fix: 'Fora do código' }
export const AUDIT_PT = { pending: 'Na fila', running: 'Em execução', completed: 'Concluída', failed: 'Falhou', stopped: 'Interrompida' }
export const TASK_PT = { planned: 'Planejada', running: 'Executando', done: 'Concluída', failed: 'Falhou', skipped: 'Pulada' }

export function fmtDate(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  return d.toLocaleString('pt-BR', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export function fmtNum(n) {
  return n == null ? '—' : Number(n).toLocaleString('pt-BR')
}

export function fmtCost(v) {
  return v == null ? '—' : `US$ ${Number(v).toFixed(v < 1 ? 4 : 2)}`
}

export function shortPath(p, max = 48) {
  if (!p) return '—'
  return p.length > max ? `…${p.slice(-(max - 1))}` : p
}

export function loc(f) {
  return f.file_path ? `${f.file_path}${f.line ? `:${f.line}` : ''}` : f.asset || '—'
}

export function Sev({ s }) {
  return <span className={`sev sev-${s}`}>{SEV_PT[s] || s}</span>
}

export function Pill({ kind, children }) {
  return <span className={`pill pill-${kind}`}>{children}</span>
}

export function AuditStatus({ s }) {
  return <Pill kind={s}>{s === 'running' && <span className="pulse" aria-hidden />}{AUDIT_PT[s] || s}</Pill>
}

export function FindingStatus({ s }) {
  return <Pill kind={s}>{STATUS_PT[s] || s}</Pill>
}

export function Empty({ title, children }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
    </div>
  )
}

export function ErrorBox({ error }) {
  if (!error) return null
  return <div className="error-box" role="alert">{error.message || String(error)}</div>
}

export function Loading() {
  return <div className="loading">Carregando…</div>
}

export function Kpi({ label, value, tone, hint }) {
  return (
    <div className={`kpi ${tone ? `kpi-${tone}` : ''}`}>
      <span className="kpi-value">{value}</span>
      <span className="kpi-label">{label}</span>
      {hint && <span className="kpi-hint">{hint}</span>}
    </div>
  )
}

export function SevBar({ counts }) {
  const total = SEV.reduce((s, k) => s + (counts?.[k] || 0), 0)
  if (!total) return <span className="muted">nenhum</span>
  return (
    <span className="sevbar" title={SEV.map(k => `${SEV_PT[k]}: ${counts[k] || 0}`).join(' · ')}>
      {SEV.filter(k => counts[k]).map(k => (
        <span key={k} className={`sevbar-item sev-${k}`}>
          {counts[k]}
        </span>
      ))}
    </span>
  )
}

export function Tabs({ tabs, value, onChange }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map(t => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={value === t.id ? 'tab active' : 'tab'} onClick={() => onChange(t.id)}>
          {t.label}
          {t.count != null && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

export function Section({ title, actions, children }) {
  return (
    <section className="section">
      {(title || actions) && (
        <div className="section-head">
          {title && <h2>{title}</h2>}
          {actions && <div className="section-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  )
}

export function Code({ children }) {
  return <code className="code">{children}</code>
}
