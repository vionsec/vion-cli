/**
 * VION Config Detector — Server-side proprietary logic
 * Detects debug mode, source maps, exposed headers, security TODOs.
 */

/**
 * Detect configuration and exposure vulnerabilities
 * @param {Object} data - { files, gitignore }
 * @returns {Array} findings
 */
export function detectConfig(data) {
  const findings = []
  const files = data.files || {}
  const gitignore = data.gitignore || ''

  // Check .gitignore for .env
  if (!gitignore.includes('.env')) {
    findings.push({
      severity: 'critico',
      title: '.env nao esta no .gitignore',
      file: '.gitignore',
      description: 'Arquivos .env podem ser commitados acidentalmente, expondo todas as secrets.',
      fix: 'Adicionar .env, .env.local, .env.production ao .gitignore imediatamente.',
      category: 'Config',
    })
  }

  for (const [filePath, content] of Object.entries(files)) {
    if (/(__tests__|\.test\.|node_modules)/i.test(filePath)) continue

    // Source maps in production build files
    if (/dist\/|build\/|\.min\./i.test(filePath) && /sourceMappingURL/i.test(content)) {
      findings.push({
        severity: 'medio',
        title: 'Source maps em producao',
        file: filePath,
        description: 'Source maps permitem engenharia reversa do codigo-fonte em producao.',
        fix: 'Desabilitar source maps no build de producao (vite: build.sourcemap = false).',
        category: 'Config',
      })
    }

    // Debug mode enabled
    if (/(debug|DEBUG)\s*[:=]\s*(true|1|["']true["'])/g.test(content)) {
      if (!/\.test\.|\.spec\.|__tests__/i.test(filePath)) {
        findings.push({
          severity: 'medio',
          title: 'Modo debug ativo',
          file: filePath,
          description: 'Debug mode pode expor informacoes internas em producao.',
          fix: 'Usar variaveis de ambiente para controlar debug. Garantir que seja false em producao.',
          category: 'Config',
        })
      }
    }

    // X-Powered-By header (server revealing stack)
    if (/x-powered-by/i.test(content) && !/disable|remove|hide/i.test(content)) {
      findings.push({
        severity: 'baixo',
        title: 'Header X-Powered-By pode revelar stack',
        file: filePath,
        description: 'O header X-Powered-By revela a tecnologia do servidor.',
        fix: 'Usar app.disable("x-powered-by") ou helmet() para remover.',
        category: 'Config',
      })
    }

    // Security TODOs
    const todoMatches = [...content.matchAll(/(TODO|FIXME|HACK|XXX).*secur/gi)]
    for (const match of todoMatches) {
      const lineNum = content.substring(0, match.index).split('\n').length
      findings.push({
        severity: 'medio',
        title: 'Nota de seguranca pendente (TODO/FIXME)',
        file: `${filePath}:${lineNum}`,
        description: `Encontrado: "${match[0].slice(0, 60)}"`,
        fix: 'Resolver a pendencia de seguranca ou criar issue para acompanhamento.',
        category: 'Config',
      })
    }
  }

  return findings
}
