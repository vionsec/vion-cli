/**
 * VION Secrets Detector — Server-side proprietary logic
 * Detects hardcoded secrets, API keys, tokens, and credentials in source code.
 */

const PATTERNS = [
  { regex: /password\s*=\s*["'][^"']{8,}["']/gi, type: 'password', severity: 'critico', title: 'Senha hardcoded no codigo' },
  { regex: /(api[_-]?key|apikey)\s*[:=]\s*["'][a-zA-Z0-9_\-]{10,}["']/gi, type: 'api_key', severity: 'critico', title: 'API key hardcoded' },
  { regex: /(secret|token)\s*[:=]\s*["'][a-zA-Z0-9_\-]{10,}["']/gi, type: 'secret', severity: 'critico', title: 'Secret/token hardcoded' },
  { regex: /(AWS_ACCESS|aws_access|AWS_SECRET|aws_secret)[_A-Z]*\s*[:=]\s*["'][^"']+["']/g, type: 'aws', severity: 'critico', title: 'Credenciais AWS hardcoded' },
  { regex: /(firebase|supabase|stripe)[A-Za-z_]*\s*[:=]\s*["'][a-zA-Z0-9_\-]{10,}["']/gi, type: 'service_key', severity: 'critico', title: 'Chave de servico hardcoded' },
  { regex: /-----BEGIN\s+(RSA|EC|DSA|PRIVATE)\s+KEY-----/g, type: 'private_key', severity: 'critico', title: 'Chave privada no codigo' },
  { regex: /mongodb(\+srv)?:\/\/[^\s"']{10,}/g, type: 'connection_string', severity: 'critico', title: 'Connection string MongoDB exposta' },
  { regex: /postgres(ql)?:\/\/[^\s"']{10,}/g, type: 'connection_string', severity: 'critico', title: 'Connection string PostgreSQL exposta' },
  { regex: /mysql:\/\/[^\s"']{10,}/g, type: 'connection_string', severity: 'critico', title: 'Connection string MySQL exposta' },
  { regex: /(sk_live|pk_live|rk_live)[_a-zA-Z0-9]{10,}/g, type: 'stripe_live', severity: 'critico', title: 'Chave Stripe LIVE no codigo' },
  { regex: /(sk_test)[_a-zA-Z0-9]{10,}/g, type: 'stripe_test', severity: 'alto', title: 'Chave Stripe TEST no codigo' },
  { regex: /(ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{10,}/g, type: 'github_token', severity: 'critico', title: 'Token GitHub hardcoded' },
  { regex: /xox[bporas]-[a-zA-Z0-9\-]{10,}/g, type: 'slack_token', severity: 'critico', title: 'Token Slack hardcoded' },
  { regex: /Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*/g, type: 'bearer', severity: 'alto', title: 'Token Bearer hardcoded' },
  { regex: /process\.env\.\w+\s*\|\|\s*["'][a-zA-Z0-9_\-]{8,}["']/g, type: 'env_fallback', severity: 'alto', title: 'Fallback de env com valor real' },
]

// False positive filters
const PLACEHOLDER_PATTERNS = [
  /your[-_]?.*[-_]?key/i, /xxx+/i, /placeholder/i, /example/i,
  /change[-_]?me/i, /insert[-_]?here/i, /todo/i, /fixme/i,
  /sk_test_xxx/i, /your[-_]?.*[-_]?here/i, /dummy/i, /fake/i,
]

function isPlaceholder(value) {
  return PLACEHOLDER_PATTERNS.some(p => p.test(value))
}

function isTestFile(filePath) {
  return /(__tests__|\.test\.|\.spec\.|test\/|tests\/|\.mock\.|mock\/|fixture)/i.test(filePath)
}

/**
 * Detect secrets in project files
 * @param {Object} data - { files: { path: content }, grep_results: { passwords: [...] } }
 * @returns {Array} findings
 */
export function detectSecrets(data) {
  const findings = []
  const files = data.files || {}

  for (const [filePath, content] of Object.entries(files)) {
    if (isTestFile(filePath)) continue

    for (const pattern of PATTERNS) {
      const matches = content.matchAll(pattern.regex)
      for (const match of matches) {
        const value = match[0]
        if (isPlaceholder(value)) continue

        const lineNum = content.substring(0, match.index).split('\n').length
        findings.push({
          severity: pattern.severity,
          title: pattern.title,
          file: `${filePath}:${lineNum}`,
          description: `${pattern.type} detectado: "${value.slice(0, 40)}..."`,
          fix: pattern.type === 'env_fallback'
            ? 'Remover valor padrao do fallback. Usar apenas process.env.VARIAVEL sem ||.'
            : 'Mover para variavel de ambiente. Nunca incluir secrets no codigo-fonte.',
          category: 'Secrets',
          code_snippet: value.slice(0, 80),
        })
      }
    }
  }

  return findings
}
