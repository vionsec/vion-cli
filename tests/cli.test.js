import { describe, it, expect } from 'vitest'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { COMMANDS, publicCommands } from '../src/cli/registry.js'
import { SKILLS } from '../src/cli/skills-meta.js'
import { listChecklists, getChecklist } from '../src/core/checklists.js'

describe('registry (fonte unica do help)', () => {
  it('todo comando publico tem documentacao completa', () => {
    for (const c of publicCommands()) {
      expect(c.summary, c.name).toBeTruthy()
      expect(c.usage, c.name).toMatch(/^vion /)
      expect(c.description.length, c.name).toBeGreaterThan(40)
      expect(Array.isArray(c.errors), c.name).toBe(true)
      expect(typeof c.run, c.name).toBe('function')
      if (c.name !== 'help') expect(c.examples.length, c.name).toBeGreaterThan(0)
    }
  })
  it('todo comando aponta para um modulo existente', async () => {
    for (const c of COMMANDS) {
      const mod = await c.run()
      expect(typeof mod.run, c.name).toBe('function')
    }
  })
})

describe('skills', () => {
  it('toda skill declarada existe em assets/skills e vice-versa', () => {
    const files = fs.readdirSync('assets/skills').filter(f => f.endsWith('.md')).map(f => f.replace('.md', ''))
    for (const s of SKILLS) expect(files, s.name).toContain(s.name)
    for (const f of files) if (!f.startsWith('_') && f !== 'welcome') expect(SKILLS.map(s => s.name), f).toContain(f)
  })
  it('nenhuma skill depende do backend SaaS', () => {
    for (const f of fs.readdirSync('assets/skills')) {
      const t = fs.readFileSync(path.join('assets/skills', f), 'utf8')
      expect(t, f).not.toMatch(/machine binding|validateApiKeyWithMachine|api\.vionsec\.com|vion-report\.json.*envie|PLAN_QUOTAS|ip_bans/i)
    }
  })
  it('artefatos gerados estao em dia (npm run gen:docs)', () => {
    execFileSync(process.execPath, ['scripts/gen-docs.js', '--check'], { stdio: 'pipe' })
  })
  it('checklists carregam e vem enxutas', () => {
    for (const c of listChecklists()) {
      const body = getChecklist(c.name)
      expect(body, c.name).toBeTruthy()
      expect(body, c.name).not.toMatch(/## CONTEXTO DE EXECUÇÃO|### Registro local/)
    }
  })
})

describe('CLI', () => {
  const run = (...args) => execFileSync(process.execPath, ['bin/vion.js', ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } })
  it('help geral lista comandos', () => {
    const out = run('help')
    for (const c of publicCommands()) expect(out).toContain(c.name)
  })
  it('help de cada comando', () => {
    for (const c of publicCommands()) expect(run('help', c.name)).toContain(c.usage)
  })
  it('opcao desconhecida falha com mensagem em portugues', () => {
    expect(() => execFileSync(process.execPath, ['bin/vion.js', 'audit', '--xyz'], { stdio: 'pipe' })).toThrow(/Opcao desconhecida/)
  })
})
