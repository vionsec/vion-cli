import { install } from '../../core/install.js'
import { migrateLegacy } from '../../core/legacy.js'
import { c } from '../term.js'

export async function run({ values }) {
  const legacy = values.project ? { actions: [] } : migrateLegacy({ dryRun: values['dry-run'] })
  const res = install({ project: values.project, mcp: !values['no-mcp'], hook: !values['no-hook'], dryRun: values['dry-run'] })
  console.log(c.bold(values['dry-run'] ? 'VION init (simulacao — nada foi alterado)' : 'VION instalado no Claude Code'))
  for (const a of [...legacy.actions, ...res.actions]) console.log(`  ${c.green('•')} ${a}`)
  if (values['dry-run']) return
  console.log('')
  if (res.mcpOk === false) console.log(c.yellow('Atencao: o MCP nao foi registrado; as skills vao funcionar, mas sem salvar resultados na pagina local.'))
  console.log(`Proximos passos:
  1. Reinicie o Claude Code (para carregar skills, agentes e MCP)
  2. ${c.cyan('vion ui')}                  -> http://localhost:3333
  3. No Claude Code: ${c.cyan('/vion:auditoria')}   ou no terminal: ${c.cyan('vion audit .')}
  Diagnostico: ${c.cyan('vion doctor')}`)
}
