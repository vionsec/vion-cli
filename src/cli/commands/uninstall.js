import { uninstall } from '../../core/install.js'
import { paths } from '../../core/paths.js'
import { c } from '../term.js'

export async function run({ values }) {
  const actions = uninstall({ project: values.project })
  console.log(c.bold('VION removido do Claude Code'))
  for (const a of actions) console.log(`  ${c.green('•')} ${a}`)
  console.log(c.dim(`Dados locais mantidos em ${paths().root} (apague com \`vion data delete --all --yes\`).`))
}
