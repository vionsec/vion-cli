import fs from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { PKG_ROOT, ensureHome } from '../../core/paths.js'
import { loadConfig } from '../../core/config.js'
import { openDb, schemaVersion, LATEST_SCHEMA } from '../../core/db.js'
import { targets, readManifest, readSettings, hasVionHook, claudeAvailable, runClaude } from '../../core/install.js'
import { VERSION } from '../../core/version.js'
import { detectLegacy } from '../../core/legacy.js'
import { c, printJson } from '../term.js'

function portFree(port) {
  return new Promise(resolve => {
    const srv = net.createServer()
    srv.once('error', () => resolve(false))
    srv.listen(port, '127.0.0.1', () => srv.close(() => resolve(true)))
  })
}

export async function run({ values }) {
  const checks = []
  const add = (status, name, detail, fix) => checks.push({ status, name, detail, fix })

  const [maj, min] = process.versions.node.split('.').map(Number)
  add(maj > 22 || (maj === 22 && min >= 13) ? 'ok' : 'error', 'Node.js', process.versions.node, 'Instale Node.js 22.13+ (LTS).')

  try {
    const home = ensureHome()
    fs.accessSync(home.root, fs.constants.W_OK)
    add('ok', 'Diretorio de dados', home.root)
    const db = openDb()
    const v = schemaVersion(db)
    add(v === LATEST_SCHEMA ? 'ok' : 'error', 'Banco SQLite', `schema v${v}`, 'Atualize o pacote @vionsec/cli.')
  } catch (err) {
    add('error', 'Diretorio/banco', err.message, 'Verifique permissoes ou defina VION_HOME.')
  }

  const claude = claudeAvailable()
  add(claude ? 'ok' : 'error', 'Claude Code', claude || 'nao encontrado no PATH', 'Instale o Claude Code: https://docs.claude.com/claude-code')

  const cfg = loadConfig()
  for (const project of [false, true]) {
    const t = targets({ project })
    const m = readManifest(t)
    if (project && !m) continue
    const label = project ? ' (projeto)' : ''
    if (!m) {
      add('error', `Instalacao${label}`, 'skills/agentes nao instalados', 'Rode `vion init`.')
      continue
    }
    add(m.version === VERSION ? 'ok' : 'warn', `Instalacao${label}`, `v${m.version} em ${t.base}`, 'Versao diferente do pacote: rode `vion init`.')
    const drift = Object.keys(cfg.models).filter(k => m.models?.[k] !== cfg.models[k])
    if (drift.length) add('warn', `Modelos${label}`, `config mudou (${drift.join(', ')})`, 'Rode `vion init` para atualizar os subagentes.')
    try {
      add(hasVionHook(readSettings(t.settings)) ? 'ok' : 'error', `Hook de escopo${label}`, t.settings, 'Rode `vion init` (sem --no-hook).')
    } catch (err) {
      add('error', `Hook de escopo${label}`, err.message)
    }
    if (claude) {
      const r = runClaude(['mcp', 'get', 'vion'], { cwd: process.cwd() })
      add(r.ok ? 'ok' : 'error', `MCP "vion"${label}`, r.ok ? 'registrado' : 'nao registrado', 'Rode `vion init`.')
      if (r.ok && !r.stdout.includes(path.join(PKG_ROOT, 'bin', 'vion.js').replace(/\\/g, '\\')) && !r.stdout.replace(/\\/g, '/').includes(path.join(PKG_ROOT, 'bin', 'vion.js').replace(/\\/g, '/'))) {
        add('warn', 'MCP aponta para outra instalacao', 'o servidor registrado nao e este pacote', 'Rode `vion init` para apontar para esta versao.')
      }
    }
  }

  const legacy = detectLegacy()
  if (legacy) add('warn', 'Restos do CLI antigo (SaaS)', `${legacy.dir}${legacy.watcherRunning ? `, fix-watcher rodando (PID ${legacy.watcherPid})` : ''}`, 'Rode `vion init`: ele para o fix-watcher e renomeia a pasta antiga.')

  if (/[\\/]_npx[\\/]/.test(PKG_ROOT)) add('warn', 'Execucao via npx', PKG_ROOT, 'O cache do npx e temporario. Instale com `npm i -g @vionsec/cli` e rode `vion init` de novo.')

  const ui = fs.existsSync(path.join(PKG_ROOT, 'dist', 'ui', 'index.html'))
  add(ui ? 'ok' : 'error', 'UI compilada', ui ? 'dist/ui' : 'ausente', 'No codigo-fonte: `npm run build:ui`.')
  const free = await portFree(cfg.ui.port)
  add(free ? 'ok' : 'warn', `Porta ${cfg.ui.port}`, free ? 'livre' : 'em uso (a UI pode ja estar aberta)', `Use \`vion ui --port ${cfg.ui.port + 1}\` se for outro programa.`)

  if (values.json) return printJson(checks)
  const icon = { ok: c.green('OK   '), warn: c.yellow('AVISO'), error: c.red('ERRO ') }
  console.log(c.bold(`VION doctor — @vionsec/cli ${VERSION}`))
  for (const ch of checks) {
    console.log(`  ${icon[ch.status]} ${ch.name}: ${ch.detail}`)
    if (ch.status !== 'ok' && ch.fix) console.log(c.dim(`         -> ${ch.fix}`))
  }
  if (checks.some(x => x.status === 'error')) process.exitCode = 1
}
