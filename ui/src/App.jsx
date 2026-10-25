import { useRoute } from './router.js'
import { useApi, useConnection } from './api.js'
import { Home } from './pages/Home.jsx'
import { Audits } from './pages/Audits.jsx'
import { NewAudit } from './pages/NewAudit.jsx'
import { AuditDetail } from './pages/AuditDetail.jsx'
import { Findings, FindingDetail } from './pages/Findings.jsx'
import { EvidenceList, EvidenceDetail } from './pages/Evidence.jsx'
import { Agents } from './pages/Agents.jsx'
import { Reports } from './pages/Reports.jsx'
import { Skills } from './pages/Skills.jsx'
import { Settings } from './pages/Settings.jsx'
import { Empty } from './components/ui.jsx'

const NAV = [
  ['/', 'Início'],
  ['/audits', 'Auditorias'],
  ['/agents', 'Agentes'],
  ['/findings', 'Vulnerabilidades'],
  ['/evidence', 'Evidências'],
  ['/reports', 'Relatórios'],
  ['/skills', 'Skills'],
  ['/settings', 'Configurações'],
]

function Page({ route }) {
  const [a, b] = route.parts
  if (!a) return <Home />
  if (a === 'audits' && b === 'new') return <NewAudit />
  if (a === 'audits' && b) return <AuditDetail id={b} tab={route.query.get('tab') || 'overview'} />
  if (a === 'audits') return <Audits />
  if (a === 'findings' && b) return <FindingDetail id={b} />
  if (a === 'findings') return <Findings query={route.query} />
  if (a === 'evidence' && b) return <EvidenceDetail id={b} />
  if (a === 'evidence') return <EvidenceList />
  if (a === 'agents') return <Agents />
  if (a === 'reports') return <Reports />
  if (a === 'skills') return <Skills />
  if (a === 'settings') return <Settings />
  return <Empty title="Página não encontrada" />
}

export function App() {
  const route = useRoute()
  const online = useConnection()
  const { data: status } = useApi('/api/status', { live: e => e.type.startsWith('audit.') })
  const active = '/' + (route.parts[0] || '')
  return (
    <div className="app">
      <aside className="side">
        <div className="brand">
          <span className="brand-mark">V</span>
          <span>
            VION
            <small>local · open source</small>
          </span>
        </div>
        <nav className="nav" aria-label="Principal">
          {NAV.map(([to, label]) => (
            <a key={to} href={`#${to}`} className={active === to ? 'active' : ''}>
              {label}
              {to === '/audits' && status?.running?.length > 0 && <span className="pill pill-running">{status.running.length}</span>}
            </a>
          ))}
        </nav>
        <div className="side-foot">
          <span>
            <span className={`dot ${online ? 'on' : 'off'}`} />
            {online ? 'ao vivo' : 'reconectando…'}
          </span>
          {status && <span>VION v{status.version}</span>}
        </div>
      </aside>
      <main className="main">
        <Page route={route} />
      </main>
    </div>
  )
}
