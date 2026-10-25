import { renderGeneralHelp, renderCommandHelp, renderSkillsHelp } from '../help.js'

export async function run({ positionals }) {
  const [topic] = positionals
  if (!topic) return console.log(renderGeneralHelp())
  if (topic === 'skills') return console.log(`${renderCommandHelp('skills')}

${renderSkillsHelp()}`)
  const text = renderCommandHelp(topic)
  if (!text) throw new Error(`Comando desconhecido: ${topic}. Rode \`vion help\`.`)
  console.log(text)
}
