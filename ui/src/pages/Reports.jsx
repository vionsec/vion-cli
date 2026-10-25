import { useApi } from '../api.js'
import { ErrorBox, Loading } from '../components/ui.jsx'
import { ReportsTab } from './AuditDetail.jsx'

export function Reports() {
  const { data, loading, error } = useApi('/api/reports', { live: e => e.type === 'report.generated' })
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Relatórios</h1>
          <p>Histórico de relatórios gerados localmente (HTML autocontido, Markdown e JSON).</p>
        </div>
      </div>
      <ErrorBox error={error} />
      {loading && !data ? <Loading /> : <ReportsTab reports={data} showAudit />}
    </>
  )
}
