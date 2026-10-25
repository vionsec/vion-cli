/**
 * VION Endpoints Detector — Server-side proprietary logic
 * Detects CORS, rate limiting, security headers, and API exposure issues.
 */

/**
 * Detect API endpoint vulnerabilities
 * @param {Object} data - { files }
 * @returns {Array} findings
 */
export function detectEndpoints(data) {
  const findings = []
  const files = data.files || {}
  const allContent = Object.values(files).join('\n')

  for (const [filePath, content] of Object.entries(files)) {
    if (/(__tests__|\.test\.|node_modules)/i.test(filePath)) continue

    // CORS wildcard with credentials
    if (/origin\s*:\s*["']\*["']/i.test(content) || /Access-Control-Allow-Origin.*\*/i.test(content)) {
      if (/credentials/i.test(content)) {
        findings.push({
          severity: 'critico',
          title: 'CORS wildcard com credentials',
          file: filePath,
          description: 'Access-Control-Allow-Origin: * com credentials permite roubo de sessao cross-origin.',
          fix: 'Definir whitelist de origens permitidas. Nunca usar wildcard com credentials.',
          category: 'CORS',
        })
      } else {
        findings.push({
          severity: 'medio',
          title: 'CORS com wildcard origin',
          file: filePath,
          description: 'CORS permite qualquer origem. Pode facilitar ataques cross-origin.',
          fix: 'Restringir CORS a origens especificas do seu dominio.',
          category: 'CORS',
        })
      }
    }

    // Stack traces in error responses
    if (/res\.(json|send)\s*\([^)]*err\.(message|stack)/gi.test(content)) {
      findings.push({
        severity: 'medio',
        title: 'Stack trace exposto em resposta de erro',
        file: filePath,
        description: 'Mensagens de erro internas podem revelar detalhes da implementacao.',
        fix: 'Retornar mensagens genericas ao cliente. Logar detalhes apenas no servidor.',
        category: 'Info Disclosure',
      })
    }

    // Sensitive data in console.log
    if (/console\.(log|error|warn)\s*\([^)]*(?:password|token|secret|key|credential)/gi.test(content)) {
      findings.push({
        severity: 'baixo',
        title: 'Dados sensiveis em console.log',
        file: filePath,
        description: 'Logs podem conter informacoes sensiveis em producao.',
        fix: 'Remover logs com dados sensiveis ou usar logger estruturado com mascaramento.',
        category: 'Info Disclosure',
      })
    }

    // File uploads without validation
    if (/(multer|formidable|busboy|upload)/i.test(content) && !/fileFilter|mimetype|allowedTypes/i.test(content)) {
      findings.push({
        severity: 'alto',
        title: 'Upload de arquivos sem validacao de tipo',
        file: filePath,
        description: 'Uploads sem filtragem de mimetype podem permitir upload de scripts maliciosos.',
        fix: 'Adicionar fileFilter para restringir tipos permitidos (ex: apenas imagens).',
        category: 'File Upload',
      })
    }
  }

  // Global checks
  const hasHelmet = /(helmet|security-headers)/i.test(allContent)
  const hasRateLimit = /(rate.?limit|throttle|brute)/i.test(allContent)

  if (!hasHelmet) {
    findings.push({
      severity: 'medio',
      title: 'Sem security headers (helmet/CSP)',
      description: 'Ausencia de X-Frame-Options, CSP, HSTS e outros headers de seguranca.',
      fix: 'Adicionar helmet() ao Express ou configurar headers via vercel.json.',
      category: 'Headers',
    })
  }

  if (!hasRateLimit) {
    findings.push({
      severity: 'alto',
      title: 'Sem rate limiting detectado',
      description: 'Ausencia de rate limiting permite brute force e abuso de API.',
      fix: 'Adicionar rate limiting com express-rate-limit ou implementacao custom.',
      category: 'Rate Limiting',
    })
  }

  return findings
}
