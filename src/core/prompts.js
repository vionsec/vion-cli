// ── Prompts: renderizacao do orquestrador e das skills (usado pelo gen-docs e pelo runner) ──

import fs from 'node:fs'
import path from 'node:path'
import { PKG_ROOT } from './paths.js'
import { DEFAULT_AUDIT_PLAN } from './checklists.js'
import { SKILLS } from '../cli/skills-meta.js'

const TEMPLATES = path.join(PKG_ROOT, 'assets', 'templates')
const SKILLS_DIR = path.join(PKG_ROOT, 'assets', 'skills')
const AGENTS_DIR = path.join(PKG_ROOT, 'assets', 'agents')

const CONTEXT_HEADER = fs
  .readFileSync(path.join(SKILLS_DIR, 'novo.md'), 'utf8')
  .replace(/^---\n[\s\S]*?\n---\n/, '')
  .match(/## CONTEXTO DE EXECUÇÃO \(OBRIGATÓRIO\)\n[\s\S]*?\n---\n/)[0]

export function renderOrchestrator({ skill = 'auditoria', plan = DEFAULT_AUDIT_PLAN } = {}) {
  const intro =
    skill === 'auditoria'
      ? 'Auditoria completa multiagente. O orquestrador (voce) planeja e revisa; subagentes mais baratos varrem cada area.'
      : 'Orquestracao multiagente sob medida: rode as checklists/skills pedidas nos argumentos (ou o plano padrao).'
  const body = fs
    .readFileSync(path.join(TEMPLATES, 'orquestrador.md'), 'utf8')
    .replace('{{INTRO}}', intro)
    .replaceAll('{{SKILL}}', skill)
    .replace('{{PLANO}}', `recon -> ${plan.join(', ')} -> validacao -> correlacao -> relatorio`)
  return `${CONTEXT_HEADER}\n${body}`
}

export function renderStatus() {
  const fases = SKILLS.filter(s => !['vion', 'ajuda', 'status', 'ciclo', 'orquestrar', 'fixes'].includes(s.name))
  return fs
    .readFileSync(path.join(TEMPLATES, 'status.md'), 'utf8')
    .replace('{{FASES}}', fases.map(s => `[ ] /vion:${s.name.padEnd(13)} ${s.summary.split(':')[0].slice(0, 60)}`).join('\n'))
    .replace('{{TOTAL}}', String(fases.length))
}

/** Corpo de uma skill instalada (sem frontmatter), com $ARGUMENTS ja substituido. */
export function skillPrompt(name, args = '') {
  const file = path.join(SKILLS_DIR, `${name}.md`)
  if (!fs.existsSync(file)) throw new Error(`Skill desconhecida: ${name}`)
  return fs.readFileSync(file, 'utf8').replace(/^---\n[\s\S]*?\n---\n/, '').replaceAll('$ARGUMENTS', args)
}

function parseFrontmatter(text) {
  const m = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text.replace(/\r\n/g, '\n'))
  if (!m) return { meta: {}, body: text }
  const meta = {}
  for (const line of m[1].split('\n')) {
    const kv = /^([\w-]+):\s*(.*)$/.exec(line)
    if (kv) meta[kv[1]] = kv[2].trim()
  }
  return { meta, body: m[2].trim() }
}

/** Definicao dos subagentes no formato de `claude --agents`. */
export function agentsJson(models) {
  const out = {}
  for (const f of fs.readdirSync(AGENTS_DIR).filter(f => f.endsWith('.md'))) {
    const { meta, body } = parseFrontmatter(fs.readFileSync(path.join(AGENTS_DIR, f), 'utf8'))
    const role = meta.name.replace(/^vion-/, '')
    const model = models[role] || 'inherit'
    out[meta.name] = {
      description: meta.description,
      prompt: body,
      tools: meta.tools.split(',').map(s => s.trim()).filter(Boolean),
      ...(model !== 'inherit' ? { model } : {}),
    }
  }
  return out
}
