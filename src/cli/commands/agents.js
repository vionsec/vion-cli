import fs from 'node:fs'
import path from 'node:path'
import { listAgents } from '../../core/agents.js'
import { table, printJson, c } from '../term.js'

export async function run({ positionals, values }) {
  const [sub = 'list'] = positionals
  if (sub !== 'list') throw new Error(`Subcomando desconhecido: ${sub}. Use list.`)
  const agents = listAgents()
  if (values.json) return printJson(agents)
  console.log(table(agents.map(a => [a.name, a.model, a.installed ? c.green('sim') : c.yellow('nao'), a.role]), ['Agente', 'Modelo', 'Instalado', 'Papel']))
  console.log(c.dim('\nTrocar modelo: vion config set models.<papel> <opus|sonnet|haiku> && vion init'))
}
