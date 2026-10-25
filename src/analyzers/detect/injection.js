/**
 * VION Injection Detector — Server-side proprietary logic
 * Detects SQL injection, XSS, command injection, path traversal, SSRF.
 */

const PATTERNS = [
  // SQL Injection
  { regex: /(query|exec|raw)\s*\([^)]*(\+|`|\$\{)[^)]*req\.(body|query|params)/gi, severity: 'critico', title: 'SQL Injection via concatenacao', fix: 'Usar queries parametrizadas. Nunca concatenar input do usuario em SQL.', category: 'SQL Injection' },
  { regex: /\$\{[^}]*req\.(body|query|params)[^}]*\}/g, severity: 'alto', title: 'Template literal com input do usuario em query', fix: 'Substituir template literals por prepared statements com placeholders.', category: 'SQL Injection' },

  // XSS
  { regex: /innerHTML\s*=/g, severity: 'alto', title: 'XSS via innerHTML', fix: 'Usar textContent em vez de innerHTML. Se necessario HTML, usar DOMPurify.sanitize().', category: 'XSS' },
  { regex: /dangerouslySetInnerHTML/g, severity: 'alto', title: 'XSS via dangerouslySetInnerHTML (React)', fix: 'Evitar dangerouslySetInnerHTML. Se necessario, sanitizar com DOMPurify antes.', category: 'XSS' },
  { regex: /document\.write\s*\(/g, severity: 'alto', title: 'XSS via document.write', fix: 'Substituir document.write por manipulacao segura do DOM.', category: 'XSS' },

  // Code Injection
  { regex: /eval\s*\([^)]*(?:req\.|input|user|data|param|body|query)/gi, severity: 'critico', title: 'Code injection via eval() com input', fix: 'Remover eval(). Usar JSON.parse() para dados ou alternativas seguras.', category: 'Code Injection' },
  { regex: /new\s+Function\s*\([^)]*(?:req\.|input|user|data)/gi, severity: 'critico', title: 'Code injection via new Function() com input', fix: 'Remover new Function(). Usar abordagem declarativa.', category: 'Code Injection' },

  // Command Injection
  { regex: /(?:child_process\.)?exec\s*\([^)]*(?:req\.|input|user|param|\+|`|\$\{)/gi, severity: 'critico', title: 'Command injection via exec() com input', fix: 'Usar execFile() com array de argumentos em vez de exec() com string.', category: 'Command Injection' },
  { regex: /(?:child_process\.)?spawn\s*\([^)]*(?:req\.|input|user)/gi, severity: 'alto', title: 'Possivel command injection via spawn() com input', fix: 'Validar e sanitizar argumentos. Usar allowlist de comandos permitidos.', category: 'Command Injection' },

  // Path Traversal
  { regex: /(readFile|createReadStream|readFileSync)\s*\([^)]*req\.(body|query|params)/gi, severity: 'critico', title: 'Path traversal via leitura de arquivo com input', fix: 'Validar e normalizar paths. Usar path.resolve() e verificar se esta dentro do diretorio permitido.', category: 'Path Traversal' },
  { regex: /\.\.\/[^)]*req\.|req\.[^)]*\.\.\//g, severity: 'alto', title: 'Possivel path traversal com ../', fix: 'Rejeitar input contendo ../. Usar path.normalize() e validar.', category: 'Path Traversal' },

  // Open Redirect
  { regex: /(redirect|location)\s*[:=][^;]*req\.(body|query|params)/gi, severity: 'medio', title: 'Open redirect com input do usuario', fix: 'Validar URL de redirect contra allowlist de dominos permitidos.', category: 'Open Redirect' },

  // SSRF
  { regex: /(fetch|axios|got|request|http\.get)\s*\([^)]*req\.(body|query|params)/gi, severity: 'critico', title: 'SSRF via URL controlada pelo usuario', fix: 'Validar URL contra allowlist. Bloquear IPs privados (10.x, 192.168.x, 127.x).', category: 'SSRF' },
  { regex: /(url|uri|endpoint|host)\s*[:=]\s*req\.(body|query|params)/gi, severity: 'alto', title: 'URL/host definido por input do usuario', fix: 'Nunca usar input do usuario diretamente como URL. Validar contra allowlist.', category: 'SSRF' },

  // Deserialization
  { regex: /(unserialize|deserialize|pickle\.loads|yaml\.load\s*\((?!.*Loader))/gi, severity: 'critico', title: 'Desserializacao insegura', fix: 'Usar formatos seguros (JSON). Se YAML, usar yaml.safeLoad(). Nunca desserializar input nao confiavel.', category: 'Deserialization' },
]

/**
 * Detect injection vulnerabilities in project files
 * @param {Object} data - { files: { path: content } }
 * @returns {Array} findings
 */
export function detectInjection(data) {
  const findings = []
  const files = data.files || {}

  for (const [filePath, content] of Object.entries(files)) {
    if (/(__tests__|\.test\.|\.spec\.|node_modules)/i.test(filePath)) continue

    for (const pattern of PATTERNS) {
      const matches = [...content.matchAll(pattern.regex)]
      for (const match of matches) {
        const lineNum = content.substring(0, match.index).split('\n').length

        // Check context: is there sanitization nearby?
        const contextStart = Math.max(0, match.index - 200)
        const contextEnd = Math.min(content.length, match.index + 200)
        const context = content.substring(contextStart, contextEnd)

        const hasSanitization = /(sanitize|escape|validate|DOMPurify|parameterize|prepared|placeholder|\$\d)/i.test(context)
        if (hasSanitization) continue

        findings.push({
          severity: pattern.severity,
          title: pattern.title,
          file: `${filePath}:${lineNum}`,
          description: `Padrao vulneravel detectado sem sanitizacao proxima.`,
          fix: pattern.fix,
          category: pattern.category,
          code_snippet: match[0].slice(0, 80),
        })
      }
    }
  }

  return findings
}
