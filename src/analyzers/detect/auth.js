/**
 * VION Auth Detector — Server-side proprietary logic
 * Detects authentication and authorization vulnerabilities.
 */

const AUTH_PATTERNS = [
  { regex: /(verify|decode|sign)(Token|JWT|Jwt)\s*\(/g, type: 'jwt_impl', check: 'implementation' },
  { regex: /algorithm\s*[:=]\s*["'](none|HS256)["']/gi, type: 'weak_algo', severity: 'critico', title: 'Algoritmo JWT fraco (none/HS256)', fix: 'Usar RS256 ou ES256 em vez de HS256/none.' },
  { regex: /expiresIn\s*[:=]\s*["'](\d+d|\d{5,})["']/g, type: 'long_expiry', check: 'expiry' },
  { regex: /localStorage\.(set|get)Item\s*\([^)]*token/gi, type: 'localstorage_token', severity: 'alto', title: 'Token armazenado em localStorage', fix: 'Usar httpOnly cookies para armazenar tokens de sessao.' },
  { regex: /\.skip\s*\(\s*.*auth|noAuth|public\s*[:=]\s*true/gi, type: 'auth_bypass', severity: 'alto', title: 'Bypass de autenticacao detectado', fix: 'Remover bypass. Todas as rotas devem exigir autenticacao explicitamente.' },
  { regex: /role\s*[:=]\s*["'](admin|user|public)["']/gi, type: 'role_check', check: 'frontend_role' },
]

const ROUTE_REGEX = /(app|router)\.(get|post|put|patch|delete)\s*\(\s*["'][^"']+["']/gi
const AUTH_MIDDLEWARE_REGEX = /(isAdmin|isAuth|requireAuth|protect|authenticate|verifyToken|checkAuth)/gi

/**
 * Detect auth vulnerabilities in project files
 * @param {Object} data - { files: { path: content } }
 * @returns {Array} findings
 */
export function detectAuth(data) {
  const findings = []
  const files = data.files || {}
  const allContent = Object.values(files).join('\n')

  // Check each file
  for (const [filePath, content] of Object.entries(files)) {
    if (/(__tests__|\.test\.|\.spec\.)/i.test(filePath)) continue

    for (const pattern of AUTH_PATTERNS) {
      const matches = [...content.matchAll(pattern.regex)]
      if (matches.length === 0) continue

      for (const match of matches) {
        const lineNum = content.substring(0, match.index).split('\n').length

        if (pattern.severity) {
          findings.push({
            severity: pattern.severity,
            title: pattern.title,
            file: `${filePath}:${lineNum}`,
            description: `Padrao detectado: ${match[0].slice(0, 60)}`,
            fix: pattern.fix,
            category: 'Authentication',
            code_snippet: match[0].slice(0, 80),
          })
        }

        // Special checks
        if (pattern.check === 'expiry') {
          const val = match[1]
          const days = val.endsWith('d') ? parseInt(val) : parseInt(val) / 86400
          if (days > 1) {
            findings.push({
              severity: 'alto',
              title: 'Token JWT com expiracao muito longa',
              file: `${filePath}:${lineNum}`,
              description: `expiresIn definido como "${val}" (~${Math.round(days)} dias). Access tokens devem expirar em <24h.`,
              fix: 'Reduzir expiresIn para 15m-1h para access tokens. Usar refresh tokens para sessoes longas.',
              category: 'Authentication',
            })
          }
        }

        if (pattern.check === 'frontend_role') {
          // Check if this is a frontend file (not API)
          if (/src\/|components\/|pages\/|views\//i.test(filePath)) {
            findings.push({
              severity: 'medio',
              title: 'Verificacao de role apenas no frontend',
              file: `${filePath}:${lineNum}`,
              description: 'Roles verificados no frontend podem ser manipulados. Validacao deve ser no backend.',
              fix: 'Mover verificacao de role para middleware do backend. Frontend so esconde UI.',
              category: 'Authorization',
            })
          }
        }
      }
    }
  }

  // Check for routes without auth middleware
  const routeFiles = Object.entries(files).filter(([p]) =>
    /api\/|routes\/|router\/|server\./i.test(p) && !/(__tests__|\.test\.)/i.test(p)
  )

  for (const [filePath, content] of routeFiles) {
    const routes = [...content.matchAll(ROUTE_REGEX)]
    const hasAuthMiddleware = AUTH_MIDDLEWARE_REGEX.test(content)

    if (routes.length > 0 && !hasAuthMiddleware) {
      findings.push({
        severity: 'alto',
        title: 'Rotas de API sem middleware de autenticacao',
        file: filePath,
        description: `${routes.length} rotas definidas sem middleware de auth visivel.`,
        fix: 'Adicionar middleware de autenticacao (ex: requireAuth) em todas as rotas protegidas.',
        category: 'Authentication',
      })
    }
  }

  // Check if JWT is used without signature verification
  const hasJwtSign = /jwt\.sign\s*\(/i.test(allContent)
  const hasJwtVerify = /jwt\.verify\s*\(/i.test(allContent)
  if (hasJwtSign && !hasJwtVerify) {
    findings.push({
      severity: 'critico',
      title: 'JWT gerado mas sem verificacao de assinatura',
      description: 'O projeto gera tokens JWT mas nao verifica a assinatura. Tokens podem ser forjados.',
      fix: 'Sempre usar jwt.verify() antes de confiar nos dados do token.',
      category: 'Authentication',
    })
  }

  return findings
}
