// ── Catalogo dos agentes (orquestrador + subagentes), usado por CLI e UI ──

import fs from 'node:fs'
import path from 'node:path'
import { PKG_ROOT } from './paths.js'
import { loadConfig } from './config.js'
import { targets, readManifest } from './install.js'

const ROLE_DESC = {
  orquestrador: 'Interpreta o objetivo, planeja, distribui tarefas, revisa achados criticos e consolida o relatorio.',
  recon: 'Mapeia stack, endpoints, integracoes e arquivos sensiveis; registra ativos.',
  vuln: 'Executa uma checklist por vez e registra achados com evidencia.',
  investigador: 'Valida ou descarta suspeitas lendo o fluxo source -> sink no codigo.',
  'threat-intel': 'Dependencias: audits nativos, CVE/GHSA com procedencia.',
  correlacao: 'Resolve quase-duplicatas, cadeias e contradicoes entre achados.',
  relatorio: 'Escreve o resumo executivo a partir dos dados do store.',
}

export function listAgents({ project = false } = {}) {
  const cfg = loadConfig()
  const t = targets({ project })
  const out = [{ name: 'orquestrador', role: ROLE_DESC.orquestrador, model: cfg.models.orquestrador, installed: !!readManifest(t), key: 'orquestrador' }]
  for (const f of fs.readdirSync(path.join(PKG_ROOT, 'assets', 'agents')).filter(f => f.endsWith('.md')).sort()) {
    const name = f.replace(/\.md$/, '')
    const key = name.replace(/^vion-/, '')
    const installedFile = path.join(t.agents, f)
    let installedModel = null
    if (fs.existsSync(installedFile)) installedModel = /^model:\s*(\S+)/m.exec(fs.readFileSync(installedFile, 'utf8'))?.[1] || null
    out.push({ name, key, role: ROLE_DESC[key] || '', model: cfg.models[key] || 'inherit', installed: !!installedModel, installedModel })
  }
  return out
}
