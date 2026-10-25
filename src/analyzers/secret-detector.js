// ── Secret Detector: pure-function secret detection returning Finding-contract-compliant objects ──

export const SECRET_PATTERNS = [
  { id: 'SEC-001', name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critico', confidence: 'high' },
  { id: 'SEC-002', name: 'Private Key', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/, severity: 'critico', confidence: 'high' },
  { id: 'SEC-003', name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'critico', confidence: 'medium' },
  { id: 'SEC-004', name: 'API Key Assignment', regex: /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9_\-]{10,}/i, severity: 'critico', confidence: 'medium' },
  { id: 'SEC-005', name: 'Generic Secret', regex: /(secret|password|token)\s*[:=]\s*['"][^\s'"]{8,}/i, severity: 'critico', confidence: 'medium' },
  { id: 'SEC-006', name: 'Env Var Secret', regex: /(API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|TOKEN|AWS_SECRET)\s*=\s*[^\s]{8,}/, severity: 'critico', confidence: 'medium' },
]

/**
 * Detect secrets in content by scanning each line against known patterns.
 * Returns an array of Finding objects compliant with the finding-schema contract.
 * @param {string} content - file content to scan
 * @param {string} filePath - path of the file being scanned
 * @returns {Array<object>} findings array
 */
export function detectSecrets(content, filePath) {
  if (!content) return []

  const lines = content.split('\n')
  const findings = []
  let inBlockComment = false

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()
    const lineNum = i + 1

    // Track block comment state
    if (trimmed.includes('/*') && !trimmed.includes('*/')) {
      inBlockComment = true
      continue
    }
    if (inBlockComment) {
      if (trimmed.includes('*/')) {
        inBlockComment = false
      }
      continue
    }
    // Single-line block comment
    if (trimmed.startsWith('/*') && trimmed.includes('*/')) {
      continue
    }

    // Skip single-line comments
    if (trimmed.startsWith('#') || trimmed.startsWith('//')) {
      continue
    }

    // Test each pattern against non-comment lines
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.regex.test(line)) {
        findings.push({
          severity: pattern.severity,
          title: pattern.name,
          description: `Secret detected: ${pattern.name} in ${filePath}:${lineNum}`,
          fix: 'Remove the hardcoded secret and use environment variables or a secrets manager instead.',
          category: 'Hardcoded Secrets',
          confidence: pattern.confidence,
          file_path: filePath,
          line_number: lineNum,
          code_snippet: trimmed,
        })
      }
    }
  }

  return findings
}
