// Gera os artefatos derivados das fontes unicas (registry.js + skills-meta.js):
//  - frontmatter de assets/skills/*.md
//  - assets/skills/{auditoria,orquestrar,status,ajuda,vion}.md
//  - docs/COMMANDS.md
// Uso: node scripts/gen-docs.js [--check]   (--check falha se algo estiver desatualizado)

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { SKILLS, GROUPS, INTERNAL_SKILLS, getSkill } from '../src/cli/skills-meta.js'
import { renderMarkdownDocs } from '../src/cli/help.js'
import { renderOrchestrator, renderStatus } from '../src/core/prompts.js'
import { DEFAULT_AUDIT_PLAN } from '../src/core/checklists.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const SKILLS_DIR = path.join(ROOT, 'assets', 'skills')
const check = process.argv.includes('--check')
const stale = []

function write(file, content) {
  const prev = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null
  if (prev === content) return
  if (check) return stale.push(path.relative(ROOT, file))
  fs.writeFileSync(file, content)
  console.log('gerado', path.relative(ROOT, file))
}

function frontmatter(name) {
  const s = getSkill(name)
  const lines = ['---', `name: vion:${name}`]
  if (s) {
    lines.push(`description: VION /${name} — ${s.summary}`)
    if (s.argumentHint) lines.push(`argument-hint: ${s.argumentHint}`)
    if (s.model) lines.push(`model: ${s.model}`)
  } else {
    lines.push(`description: VION — fragmento interno (${name}), nao e um comando de uso.`)
  }
  lines.push('---', '')
  return lines.join('\n')
}

const stripFm = t => t.replace(/\r\n/g, '\n').replace(/^---\n[\s\S]*?\n---\n\n?/, '')

function menu() {
  const W = 60
  const row = (s = '') => `|  ${s.padEnd(W - 4)}|`
  const bar = `+${'-'.repeat(W - 2)}+`
  const out = [bar, row('VION — Vulnerable Investigator Orchestrator Network'), row('open source · local-first · multiagente'), bar]
  for (const [g, title] of GROUPS) {
    const items = SKILLS.filter(s => s.group === g)
    if (!items.length) continue
    out.push(row(), row(`${title.toUpperCase()}:`))
    for (const s of items) {
      const left = `  /vion:${s.name} `
      const short = s.menu
      out.push(row(`${left.padEnd(22, '.')} ${short}`))
    }
  }
  out.push(row(), bar, row('Terminal: vion help · Resultados: vion ui (:3333)'), bar)
  return out.join('\n')
}

function menuSkill(name) {
  const header = fs.readFileSync(path.join(SKILLS_DIR, 'novo.md'), 'utf8')
  const ctx = stripFm(header).match(/## CONTEXTO DE EXECUÇÃO \(OBRIGATÓRIO\)\n[\s\S]*?\n---\n/)[0]
  return `${frontmatter(name)}${ctx}
## /vion:${name} — Menu de Comandos

Exiba EXATAMENTE este bloco:

\`\`\`
${menu()}
\`\`\`

Depois, em uma linha: "Detalhes de qualquer comando: \`vion skills show <nome>\` no terminal."
`
}

// 1) skills importadas: so o frontmatter e regenerado
const GENERATED = new Set(['auditoria', 'orquestrar', 'status', 'ajuda', 'vion'])
for (const f of fs.readdirSync(SKILLS_DIR).filter(f => f.endsWith('.md'))) {
  const name = f.replace(/\.md$/, '')
  if (GENERATED.has(name)) continue
  if (!getSkill(name) && !INTERNAL_SKILLS.includes(name)) throw new Error(`assets/skills/${f} sem metadados em skills-meta.js`)
  const file = path.join(SKILLS_DIR, f)
  write(file, frontmatter(name) + stripFm(fs.readFileSync(file, 'utf8')))
}
for (const s of SKILLS) {
  if (!GENERATED.has(s.name) && !fs.existsSync(path.join(SKILLS_DIR, `${s.name}.md`))) throw new Error(`skills-meta.js declara ${s.name} mas assets/skills/${s.name}.md nao existe`)
}

// 2) skills geradas
write(path.join(SKILLS_DIR, 'auditoria.md'), frontmatter('auditoria') + renderOrchestrator({ skill: 'auditoria', plan: DEFAULT_AUDIT_PLAN }))
write(path.join(SKILLS_DIR, 'orquestrar.md'), frontmatter('orquestrar') + renderOrchestrator({ skill: 'orquestrar', plan: DEFAULT_AUDIT_PLAN }))
write(path.join(SKILLS_DIR, 'status.md'), frontmatter('status') + renderStatus())
write(path.join(SKILLS_DIR, 'ajuda.md'), menuSkill('ajuda'))
write(path.join(SKILLS_DIR, 'vion.md'), menuSkill('vion'))

// 3) docs
fs.mkdirSync(path.join(ROOT, 'docs'), { recursive: true })
write(path.join(ROOT, 'docs', 'COMMANDS.md'), renderMarkdownDocs().replace(/\x1b\[[0-9;]*m/g, '') + '\n')

if (check && stale.length) {
  console.error(`Desatualizados (rode npm run gen:docs):\n  ${stale.join('\n  ')}`)
  process.exit(1)
}
