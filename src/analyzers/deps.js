// ── Audit de dependencias executado pelo motor (argumentos fixos, sem shell do modelo) ──

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const SEV = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' }

function run(cmd, args, cwd) {
  // npm/pnpm sao .cmd no Windows: shell com argumentos fixos (nenhum vem do modelo)
  const res = spawnSync(cmd, args, { cwd, encoding: 'utf8', shell: process.platform === 'win32', timeout: 120000, maxBuffer: 64 * 1024 * 1024, windowsHide: true })
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '', error: res.error }
}

function parseNpmAudit(json, manifest) {
  const out = []
  for (const [name, v] of Object.entries(json.vulnerabilities || {})) {
    const advisories = (v.via || []).filter(x => typeof x === 'object')
    if (!advisories.length) continue // so transitivo: o advisory aparece no pacote de origem
    for (const a of advisories) {
      const fix = v.fixAvailable === true ? 'npm audit fix' : v.fixAvailable?.name ? `atualizar ${v.fixAvailable.name} para ${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? ' (major: revisar breaking changes)' : ''}` : 'sem correcao publicada: avaliar substituir o pacote'
      const ghsa = /GHSA-[\w-]+/.exec(a.url || '')?.[0]
      out.push({
        title: `${name} ${a.range || v.range || ''} — ${a.title}`.trim(),
        description: `${a.title}. Advisory ${ghsa || a.source} (${a.url || 'sem URL'}). Dependencia ${v.isDirect ? 'direta' : 'transitiva'}; fonte: npm audit.`,
        severity: SEV[a.severity] || 'medium',
        cwe: (a.cwe || [])[0] || null,
        asset: name,
        file_path: manifest,
        category: 'Dependencies',
        recommendation: fix,
        rule: ghsa || `npm-advisory:${a.source}`,
        confidence: 'high',
        validation_method: 'advisory oficial do registro npm (npm audit)',
      })
    }
  }
  return out
}

/** Retorna { findings, notes[], raw } para o diretorio. */
export function auditDependencies(root) {
  const notes = []
  const findings = []
  const raws = []
  const pkg = path.join(root, 'package.json')
  if (fs.existsSync(pkg)) {
    const has = f => fs.existsSync(path.join(root, f))
    let res = null
    let tool = null
    if (has('package-lock.json') || has('npm-shrinkwrap.json')) {
      tool = 'npm audit'
      res = run('npm', ['audit', '--json'], root)
    } else if (has('pnpm-lock.yaml')) {
      tool = 'pnpm audit'
      res = run('pnpm', ['audit', '--json'], root)
    } else if (has('yarn.lock')) {
      notes.push('yarn.lock encontrado: rode `yarn npm audit` (berry) ou `yarn audit` (v1) manualmente; o VION nao executa yarn automaticamente.')
    } else {
      notes.push('package.json sem lockfile: npm audit precisa de lockfile. Sem ele as versoes instaladas nao sao reprodutiveis (risco de supply chain). Gere com `npm install --package-lock-only`.')
      findings.push({
        title: 'Projeto sem lockfile de dependencias',
        description: 'package.json existe mas nao ha package-lock.json/pnpm-lock.yaml/yarn.lock. Cada instalacao pode resolver versoes diferentes (incluindo versoes comprometidas) e nao e possivel auditar CVEs das versoes reais.',
        severity: 'medium',
        cwe: 'CWE-1357',
        file_path: 'package.json',
        category: 'Dependencies',
        recommendation: 'Gerar e versionar o lockfile (`npm install --package-lock-only`) e usar `npm ci` no build.',
        rule: 'deps:no-lockfile',
        confidence: 'high',
        validation_method: 'verificacao de arquivos no diretorio do projeto',
      })
    }
    if (res) {
      if (res.error) notes.push(`${tool} nao executou: ${res.error.message}`)
      else {
        try {
          const json = JSON.parse(res.stdout)
          if (json.error) notes.push(`${tool}: ${json.error.summary || json.error.code}`)
          else {
            findings.push(...parseNpmAudit(json, 'package.json'))
            raws.push({ tool, output: JSON.stringify(json.metadata || {}, null, 1) + '\n' + Object.entries(json.vulnerabilities || {}).map(([n, v]) => `${n}: ${v.severity} ${v.range || ''}`).join('\n') })
          }
        } catch {
          notes.push(`${tool} retornou saida invalida: ${(res.stderr || res.stdout).slice(0, 200)}`)
        }
      }
    }
  }
  for (const f of ['requirements.txt', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'Gemfile', 'pom.xml', 'composer.json']) {
    if (fs.existsSync(path.join(root, f))) notes.push(`${f} encontrado: audit automatico ainda nao suportado pelo VION (use pip-audit/govulncheck/cargo audit/bundle audit).`)
  }
  return { findings, notes, raws }
}
