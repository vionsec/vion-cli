/**
 * Redaction de campos sensíveis antes de logar/persistir.
 *
 * Caso de uso: honeypot + admin_master gravam body_preview em security_events.
 * Atacante pode mandar POST com password/api_key real (ex: pra testar reuso).
 * Esses campos não podem ser persistidos em texto plano — viram [REDACTED].
 *
 * Lista de keys consideradas sensíveis (case-insensitive substring match):
 *   password, passwd, pwd, secret, token, api_key, apikey, authorization,
 *   bearer, jwt, refresh, session, credit, cvv, cvc, ssn
 */

const SENSITIVE_PATTERNS = [
  /pass(word|wd)?/i,
  /pwd/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /authoriz(e|ation)/i,
  /bearer/i,
  /jwt/i,
  /refresh/i,
  /session/i,
  /credit/i,
  /cvv|cvc/i,
  /ssn/i,
  /cpf|cnpj/i,
]

function isSensitiveKey(key) {
  if (typeof key !== 'string') return false
  return SENSITIVE_PATTERNS.some(re => re.test(key))
}

/**
 * Recursivamente substitui valores de campos sensíveis por [REDACTED].
 * Limita profundidade pra evitar recursão infinita.
 */
export function redact(obj, depth = 0) {
  if (depth > 5 || obj == null) return obj
  if (typeof obj !== 'object') return obj
  if (Array.isArray(obj)) return obj.map(v => redact(v, depth + 1))

  const out = {}
  for (const [k, v] of Object.entries(obj)) {
    if (isSensitiveKey(k)) {
      out[k] = '[REDACTED]'
    } else if (typeof v === 'object' && v !== null) {
      out[k] = redact(v, depth + 1)
    } else {
      out[k] = v
    }
  }
  return out
}

/**
 * Versão de body_preview que sanitiza antes de virar string.
 * Use no lugar de `JSON.stringify(req.body)?.slice(0, 500)`.
 */
export function safeBodyPreview(body, maxLen = 500) {
  if (body == null) return null
  if (typeof body === 'string') {
    // Em strings cruas, mascara substrings que parecem credenciais
    return body
      .replace(/("?(password|passwd|pwd|secret|token|api[_-]?key|authorization|bearer|jwt)"?\s*[:=]\s*"?)([^",&\s}]+)/gi, '$1[REDACTED]')
      .slice(0, maxLen)
  }
  try {
    return JSON.stringify(redact(body)).slice(0, maxLen)
  } catch {
    return '[unparseable]'
  }
}
