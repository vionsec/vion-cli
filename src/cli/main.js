// ── Despacho de comandos: valida opcoes contra o registry antes de executar ──

import { parseArgs } from 'node:util'
import { findCommand } from './registry.js'
import { VERSION } from '../core/version.js'

function toParseOptions(options) {
  const out = {}
  for (const [name, o] of Object.entries(options || {})) {
    out[name] = { type: o.type === 'boolean' ? 'boolean' : 'string', ...(o.multiple ? { multiple: true } : {}), ...(o.short ? { short: o.short } : {}) }
  }
  out.help = { type: 'boolean', short: 'h' }
  return out
}

export async function main(argv) {
  const [first, ...rest] = argv
  if (!first || first === '--help' || first === '-h') return (await import('./commands/help.js')).run({ positionals: [], values: {} })
  if (first === '--version' || first === '-v' || first === 'version') {
    console.log(`@vionsec/cli ${VERSION}`)
    return
  }
  const cmd = findCommand(first)
  if (!cmd) throw new Error(`Comando desconhecido: ${first}. Rode \`vion help\`.`)

  let parsed
  try {
    parsed = parseArgs({ args: rest, options: toParseOptions(cmd.options), allowPositionals: true, strict: true })
  } catch (err) {
    const opt = /Unknown option '([^']+)'/.exec(err.message)
    const missing = /Option '([^']+)'.*argument missing/.exec(err.message)
    const msg = opt ? `Opcao desconhecida: ${opt[1]}` : missing ? `Opcao ${missing[1]} precisa de um valor` : err.message
    throw new Error(`${msg}\nUso: ${cmd.usage}\nVeja: vion help ${cmd.name}`)
  }
  if (parsed.values.help) return (await import('./commands/help.js')).run({ positionals: [cmd.name], values: {} })

  for (const [name, o] of Object.entries(cmd.options || {})) {
    const v = parsed.values[name]
    if (v !== undefined && o.values && !o.values.includes(v)) throw new Error(`--${name} aceita: ${o.values.join(', ')}`)
  }
  const mod = await cmd.run()
  return mod.run(parsed, cmd)
}
