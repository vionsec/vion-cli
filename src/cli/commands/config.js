import { loadConfig, getKey, setKey, SETTABLE } from '../../core/config.js'
import { paths } from '../../core/paths.js'
import { printJson, c } from '../term.js'

export async function run({ positionals, values }) {
  const [sub = 'get', key, value] = positionals
  if (sub === 'path') return console.log(paths().config)
  if (sub === 'get') {
    const cfg = loadConfig()
    const v = key ? getKey(cfg, key) : cfg
    if (v === undefined) throw new Error(`Chave desconhecida: ${key}. Validas: ${Object.keys(SETTABLE).join(', ')}`)
    return typeof v === 'object' || values.json ? printJson(v) : console.log(v)
  }
  if (sub === 'set') {
    if (!key || value === undefined) throw new Error('Uso: vion config set <chave> <valor>')
    const cfg = setKey(key, value)
    console.log(`${c.green('ok')} ${key} = ${getKey(cfg, key)}`)
    if (key.startsWith('models.')) console.log(c.dim('Rode `vion init` para atualizar os subagentes instalados no Claude Code.'))
    return
  }
  throw new Error(`Subcomando desconhecido: ${sub}. Use get, set ou path.`)
}
