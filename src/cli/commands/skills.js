import { renderSkillsHelp, renderSkillDetail } from '../help.js'
import { getSkill, SKILLS } from '../skills-meta.js'
import { printJson } from '../term.js'

export async function run({ positionals, values }) {
  const [sub = 'list', name] = positionals
  if (sub === 'list') return values.json ? printJson(SKILLS) : console.log(renderSkillsHelp())
  if (sub === 'show') {
    if (!name) throw new Error('Uso: vion skills show <nome>')
    const s = getSkill(name)
    if (!s) throw new Error(`Skill desconhecida: ${name}. Veja \`vion skills list\`.`)
    return values.json ? printJson(s) : console.log(renderSkillDetail(s))
  }
  throw new Error(`Subcomando desconhecido: ${sub}. Use list ou show.`)
}
