// ── Catalogo de checklists servidas aos subagentes (via MCP checklist_get) ──
// Fatias da auditoria (assets/checklists) + skills especializadas usadas como checklist.
// O texto e enxugado (sem cabecalho de contexto e sem secoes de relatorio) para gastar menos tokens.

import fs from 'node:fs'
import path from 'node:path'
import { PKG_ROOT } from './paths.js'

const CHECKLIST_DIR = path.join(PKG_ROOT, 'assets', 'checklists')
const SKILL_DIR = path.join(PKG_ROOT, 'assets', 'skills')

// Skills que tambem funcionam como checklist delegavel.
const SKILL_CHECKLISTS = {
  ai: 'Seguranca de IA/LLM (prompt injection, tools, RAG)',
  lgpd: 'Privacidade e LGPD',
  landing: 'Landing page: performance e seguranca frontend',
  'supply-chain': 'Supply chain completo (multi-gerenciador)',
  'dev-seguro': 'Gates de desenvolvimento seguro (A-K)',
  debug: 'Bugs de logica (ultrathink)',
  'unified-scan': 'Triagem crypto/IaC/SRI/taint/BOLA',
  'pre-deploy': 'Checklist pre-deploy',
  monitorar: 'Lacunas de monitoramento',
}

export const DEFAULT_AUDIT_PLAN = ['segredos', 'auth', 'injecao', 'banco', 'api', 'config-infra', 'logica-negocio', 'resiliencia', 'dependencias']

export function listChecklists() {
  const out = []
  for (const f of fs.readdirSync(CHECKLIST_DIR).filter(f => f.endsWith('.md')).sort()) {
    const name = f.replace(/\.md$/, '')
    const first = fs.readFileSync(path.join(CHECKLIST_DIR, f), 'utf8').split('\n')[0]
    out.push({ name, title: first.replace(/^#\s*Checklist VION\s*—\s*/, ''), source: 'auditoria' })
  }
  for (const [name, title] of Object.entries(SKILL_CHECKLISTS)) {
    if (fs.existsSync(path.join(SKILL_DIR, `${name}.md`))) out.push({ name, title, source: 'skill' })
  }
  return out
}

function slim(text) {
  let t = text.replace(/\r\n/g, '\n')
  t = t.replace(/^---\n[\s\S]*?\n---\n/, '')
  t = t.replace(/## CONTEXTO DE EXECUÇÃO \(OBRIGATÓRIO\)\n[\s\S]*?\n---\n/, '')
  // corta relatorio de terminal, registro e fluxo pos-auditoria (o subagente tem o seu)
  const cut = t.search(/\n## (REPORT|POS-|RELATORIO OFENSIVO)|\n### Registro local/)
  if (cut > 0) t = t.slice(0, cut)
  return t.trim() + '\n'
}

export function getChecklist(name) {
  const n = String(name || '').replace(/[^a-z0-9-]/gi, '')
  const file = fs.existsSync(path.join(CHECKLIST_DIR, `${n}.md`))
    ? path.join(CHECKLIST_DIR, `${n}.md`)
    : SKILL_CHECKLISTS[n] && path.join(SKILL_DIR, `${n}.md`)
  if (!file || !fs.existsSync(file)) return null
  return slim(fs.readFileSync(file, 'utf8'))
}
