/**
 * VION Dependencies Detector — Server-side proprietary logic
 * Parses npm audit output and classifies dependency vulnerabilities.
 */

/**
 * Detect dependency vulnerabilities from npm audit output
 * @param {Object} data - { npm_audit: "string output", package_json: "string" }
 * @returns {Array} findings
 */
export function detectDependencies(data) {
  const findings = []
  const auditOutput = data.npm_audit || ''
  const packageJson = data.package_json || ''

  if (!auditOutput || auditOutput.includes('found 0 vulnerabilities')) {
    return findings
  }

  // Parse npm audit text output
  const criticalMatch = auditOutput.match(/(\d+)\s+critical/i)
  const highMatch = auditOutput.match(/(\d+)\s+high/i)
  const moderateMatch = auditOutput.match(/(\d+)\s+moderate/i)
  const lowMatch = auditOutput.match(/(\d+)\s+low/i)

  const critical = criticalMatch ? parseInt(criticalMatch[1]) : 0
  const high = highMatch ? parseInt(highMatch[1]) : 0
  const moderate = moderateMatch ? parseInt(moderateMatch[1]) : 0
  const low = lowMatch ? parseInt(lowMatch[1]) : 0

  if (critical > 0) {
    findings.push({
      severity: 'critico',
      title: `${critical} vulnerabilidade(s) critica(s) em dependencias`,
      description: 'Dependencias com vulnerabilidades criticas podem ser exploradas remotamente.',
      fix: 'Executar npm audit fix. Se requer --force, avaliar breaking changes antes.',
      category: 'Dependencies',
    })
  }

  if (high > 0) {
    findings.push({
      severity: 'alto',
      title: `${high} vulnerabilidade(s) alta(s) em dependencias`,
      description: 'Dependencias com vulnerabilidades altas devem ser atualizadas.',
      fix: 'Executar npm audit fix para corrigir automaticamente.',
      category: 'Dependencies',
    })
  }

  if (moderate > 0) {
    findings.push({
      severity: 'medio',
      title: `${moderate} vulnerabilidade(s) moderada(s) em dependencias`,
      description: 'Vulnerabilidades moderadas em dependencias.',
      fix: 'Avaliar npm audit fix ou atualizar pacotes individualmente.',
      category: 'Dependencies',
    })
  }

  if (low > 0) {
    findings.push({
      severity: 'baixo',
      title: `${low} vulnerabilidade(s) baixa(s) em dependencias`,
      description: 'Vulnerabilidades de baixo risco em dependencias.',
      fix: 'Atualizar pacotes na proxima oportunidade.',
      category: 'Dependencies',
    })
  }

  // Extract individual CVE/GHSA references
  const ghsaMatches = [...auditOutput.matchAll(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/g)]
  const packageMatches = [...auditOutput.matchAll(/^(\S+)\s+[\d.]+\s*-\s*[\d.]+/gm)]

  // Check for outdated critical packages in package.json
  try {
    const pkg = JSON.parse(packageJson)
    const deps = { ...pkg.dependencies, ...pkg.devDependencies }

    // Known insecure packages
    const insecurePackages = {
      'request': 'Pacote "request" esta deprecated e nao recebe patches de seguranca. Usar "got" ou "node-fetch".',
      'node-uuid': 'Pacote "node-uuid" esta deprecated. Usar "uuid".',
      'crypto-js': 'CryptoJS tem vulnerabilidades conhecidas. Usar Web Crypto API nativa.',
    }

    for (const [pkg, message] of Object.entries(insecurePackages)) {
      if (deps[pkg]) {
        findings.push({
          severity: 'medio',
          title: `Pacote inseguro/deprecated: ${pkg}`,
          file: 'package.json',
          description: message,
          fix: `Substituir "${pkg}" por alternativa segura.`,
          category: 'Dependencies',
        })
      }
    }
  } catch {}

  return findings
}
