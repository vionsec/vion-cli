import { runWorker } from '../../core/runner.js'
import { finalizeAudit } from '../../core/engine.js'

export async function run({ positionals }) {
  const [id] = positionals
  if (!id) throw new Error('Uso interno: vion worker <audit_id>')
  try {
    await runWorker(id)
  } catch (err) {
    console.error(err.stack || err.message)
    try {
      finalizeAudit(id, { status: 'failed', error: err.message })
    } catch {
      // auditoria pode nao existir
    }
    process.exitCode = 1
  }
}
