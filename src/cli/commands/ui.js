import { startUiServer } from '../../server/server.js'
import { loadConfig } from '../../core/config.js'
import { openInBrowser } from '../open.js'
import { c } from '../term.js'

export async function run({ values }) {
  const port = Number(values.port || loadConfig().ui.port)
  if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Porta invalida (1024-65535)')
  let started
  try {
    started = await startUiServer({ port })
  } catch (err) {
    if (err.code === 'EADDRINUSE') throw new Error(`Porta ${port} em uso. A UI pode ja estar aberta em http://localhost:${port}/ — ou use \`vion ui --port ${port + 1}\`.`)
    throw err
  }
  console.log(`${c.bold('VION UI')} em ${c.cyan(started.url)}  ${c.dim('(somente esta maquina · Ctrl+C para sair)')}`)
  if (!values['no-open']) openInBrowser(started.url)
  const stop = () => {
    started.server.closeAllConnections?.()
    started.server.close(() => process.exit(0))
    setTimeout(() => process.exit(0), 1500).unref()
  }
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}
