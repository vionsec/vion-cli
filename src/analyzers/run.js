// ── Execucao local dos analisadores deterministicos (0 tokens) sobre um diretorio ──

import fs from 'node:fs'
import path from 'node:path'
import { unifiedScan } from './unified-scanner.js'
import { detectSecrets } from './detect/secrets.js'
import { detectAuth } from './detect/auth.js'
import { detectInjection } from './detect/injection.js'
import { detectDatabase } from './detect/database.js'
import { detectEndpoints } from './detect/endpoints.js'
import { detectConfig } from './detect/config.js'

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', 'coverage',
  '.turbo', '.cache', '.vercel', '.output', 'vendor', '__pycache__', '.venv', 'venv', 'target', '.idea', '.vscode',
])
const CODE_EXT = new Set([
  '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.go', '.java', '.rb', '.php', '.html', '.htm',
  '.tf', '.yml', '.yaml', '.json', '.env', '.sql', '.toml', '.ini', '.conf', '.vue', '.svelte',
])
const MAX_FILE_BYTES = 512 * 1024
const MAX_FILES = 6000

export const ANALYZERS = {
  iac: 'Infraestrutura como codigo (Terraform/CloudFormation/YAML)',
  crypto: 'Criptografia fraca e chaves hardcoded',
  sri: 'Subresource Integrity em scripts/estilos de CDN',
  taint: 'Fluxo source -> sink (SQLi, XSS, command injection, path traversal)',
  bola: 'IDOR/BOLA: handlers por id sem filtro de dono',
  secrets: 'Segredos e credenciais no codigo',
  auth: 'Padroes de autenticacao/autorizacao fracos',
  injection: 'Padroes de injecao (eval, SQL concatenado, exec)',
  database: 'SQL/migrations: RLS, permissoes, dados sensiveis',
  endpoints: 'Endpoints sem auth/rate limit/validacao',
  config: 'Configuracao (.gitignore, CORS, headers, debug)',
}

function isEnvFile(name) {
  return name === '.env' || name.startsWith('.env.')
}

export function collectFiles(root) {
  const files = []
  let truncated = false
  const walk = dir => {
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const e of entries) {
      if (files.length >= MAX_FILES) {
        truncated = true
        return
      }
      const full = path.join(dir, e.name)
      if (e.isSymbolicLink()) continue
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) walk(full)
        continue
      }
      const ext = path.extname(e.name).toLowerCase()
      if (!CODE_EXT.has(ext) && !isEnvFile(e.name) && e.name !== 'Dockerfile') continue
      if (e.name === 'package-lock.json' || e.name.endsWith('.min.js')) continue
      let size = 0
      try {
        size = fs.statSync(full).size
      } catch {
        continue
      }
      if (size > MAX_FILE_BYTES) continue
      try {
        files.push({ path: path.relative(root, full).replace(/\\/g, '/'), content: fs.readFileSync(full, 'utf8') })
      } catch {
        // arquivo ilegivel: ignora
      }
    }
  }
  walk(root)
  return { files, truncated }
}

function splitFileRef(ref) {
  if (!ref) return { file_path: null, line: null }
  const m = /^(.*?):(\d+)$/.exec(ref)
  return m ? { file_path: m[1], line: Number(m[2]) } : { file_path: ref, line: null }
}

function fromUnified(f) {
  return {
    title: f.title,
    description: f.description,
    severity: f.severity,
    category: f.category,
    confidence: f.confidence || 'medium',
    file_path: f.file_path || null,
    line: f.line_number || null,
    code_snippet: f.code_snippet || null,
    recommendation: f.fix,
    cwe: f.cwe || null,
    rule: f.rule_id || f.id || `${f.analyzer}:${f.title}`,
    analyzer: f.analyzer,
  }
}

function fromDetect(analyzer, f) {
  const { file_path, line } = splitFileRef(f.file)
  return {
    title: f.title,
    description: f.description,
    severity: f.severity,
    category: f.category,
    confidence: 'low',
    file_path,
    line,
    code_snippet: f.code_snippet || null,
    recommendation: f.fix,
    rule: `${analyzer}:${f.title}`,
    analyzer,
  }
}

/**
 * Roda os analisadores sobre `root`. Retorna findings normalizados (ainda nao gravados)
 * e estatisticas. `only` limita a um subconjunto de ANALYZERS.
 */
export async function runAnalyzers(root, { only = null } = {}) {
  const { files, truncated } = collectFiles(root)
  const want = name => !only || only.includes(name)
  const out = []
  const stats = {}

  const unifiedFiles = files.filter(f => !f.path.endsWith('.json'))
  const { findings, analyzerResults } = await unifiedScan(unifiedFiles)
  for (const f of findings) if (want(f.analyzer)) out.push(fromUnified(f))
  Object.assign(stats, analyzerResults)

  const filesMap = Object.fromEntries(files.filter(f => !f.path.endsWith('.sql')).map(f => [f.path, f.content]))
  const data = {
    files: filesMap,
    sql_files: Object.fromEntries(files.filter(f => f.path.endsWith('.sql')).map(f => [f.path, f.content])),
    gitignore: files.find(f => f.path === '.gitignore')?.content ?? safeRead(path.join(root, '.gitignore')),
    package_json: files.find(f => f.path === 'package.json')?.content || '',
  }
  const detectors = { secrets: detectSecrets, auth: detectAuth, injection: detectInjection, database: detectDatabase, endpoints: detectEndpoints, config: detectConfig }
  for (const [name, fn] of Object.entries(detectors)) {
    if (!want(name)) continue
    try {
      const res = fn(data)
      for (const f of res) out.push(fromDetect(name, f))
      stats[name] = { status: 'completed', count: res.length }
    } catch (err) {
      stats[name] = { status: 'failed', error: err.message }
    }
  }

  return { findings: out, stats, filesScanned: files.length, truncated }
}

function safeRead(p) {
  try {
    return fs.readFileSync(p, 'utf8')
  } catch {
    return ''
  }
}
