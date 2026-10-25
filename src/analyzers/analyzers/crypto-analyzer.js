// ── Crypto Weakness Detector ──
// Pure function: analyzeCrypto(content, filePath, language?) -> Finding[]
// Detects insecure cryptographic algorithms (MD5, SHA1, DES, RC4) in JS/TS/Python

const JS_CRYPTO_PATTERNS = [
  // Node.js crypto module - hash
  {
    pattern: /crypto\.createHash\(\s*['"`](md5|sha1|sha-1)['"`]\s*\)/i,
    algorithm: m => m[1].toUpperCase().replace('SHA-1', 'SHA1'),
    type: 'hash',
  },
  // Node.js crypto module - cipher
  {
    pattern: /crypto\.createCipher(?:iv)?\(\s*['"`](des|des-ede|des-ede3|rc4|rc2|blowfish)['"`]/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'cipher',
  },
  // Node.js crypto module - hmac
  {
    pattern: /crypto\.createHmac\(\s*['"`](md5|sha1|sha-1)['"`]/i,
    algorithm: m => `HMAC-${m[1].toUpperCase().replace('SHA-1', 'SHA1')}`,
    type: 'hmac',
  },
  // Web Crypto API
  {
    pattern: /subtle\.digest\(\s*['"`](MD5|SHA-1)['"`]/i,
    algorithm: m => m[1].toUpperCase().replace('SHA-1', 'SHA1'),
    type: 'hash',
  },
  // CryptoJS library
  {
    pattern: /CryptoJS\.(MD5|SHA1|DES|RC4|TripleDES)\s*\(/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'library',
  },
  // forge library
  {
    pattern: /forge\.(md5|sha1)\.create\(\)/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'library',
  },
]

const PYTHON_CRYPTO_PATTERNS = [
  // hashlib direct
  {
    pattern: /hashlib\.(md5|sha1)\s*\(/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'hash',
  },
  // hashlib.new
  {
    pattern: /hashlib\.new\(\s*['"`](md5|sha1|sha-1)['"`]\s*\)/i,
    algorithm: m => m[1].toUpperCase().replace('SHA-1', 'SHA1'),
    type: 'hash',
  },
  // PyCryptodome cipher imports
  {
    pattern: /from\s+Crypto\.Cipher\s+import\s+(DES|DES3|ARC4|Blowfish)/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'cipher',
  },
  // PyCryptodome hash imports
  {
    pattern: /from\s+Crypto\.Hash\s+import\s+(MD5|SHA1|SHA)\b/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'hash',
  },
  // Cipher .new() calls
  {
    pattern: /(DES|ARC4|Blowfish)\.new\s*\(/i,
    algorithm: m => m[1].toUpperCase(),
    type: 'cipher',
  },
  // hmac module
  {
    pattern: /hmac\.new\(.*?['"`](md5|sha1)['"`]/i,
    algorithm: m => `HMAC-${m[1].toUpperCase()}`,
    type: 'hmac',
  },
]

const AUTH_CONTEXT_KEYWORDS = [
  /\b(password|passwd|pwd|credential|auth|authenticate|login|signin|sign_in)\b/i,
  /\b(session|token|jwt|bearer|cookie|csrf|xsrf)\b/i,
  /\b(sign|verify|signature|certificate|cert|hmac)\b/i,
  /\b(store|save|persist|database|db|insert|update)\b/i,
  /\b(user_?id|email|username|account)\b/i,
]

const AUTH_FILE_PATTERNS = [
  /auth/i, /login/i, /session/i, /password/i, /credential/i,
  /token/i, /jwt/i, /security/i, /middleware/i,
]

/**
 * Detect language from file extension
 * @param {string} filePath
 * @returns {'javascript' | 'python'}
 */
function detectLanguage(filePath) {
  if (/\.py$/.test(filePath)) return 'python'
  return 'javascript'
}

/**
 * Check if a line is inside a comment
 * @param {string[]} lines - all lines of the file
 * @param {number} lineIndex - zero-based index
 * @param {string} lang - 'javascript' or 'python'
 * @returns {boolean}
 */
function isInsideComment(lines, lineIndex, lang) {
  const line = lines[lineIndex].trim()

  // Single-line comments
  if (lang === 'javascript' && /^\s*\/\//.test(lines[lineIndex])) return true
  if (lang === 'python' && /^\s*#/.test(lines[lineIndex])) return true

  // Block comment detection - scan from start to current line
  if (lang === 'javascript') {
    let inBlock = false
    for (let i = 0; i <= lineIndex; i++) {
      const l = lines[i]
      if (!inBlock) {
        const openIdx = l.indexOf('/*')
        if (openIdx !== -1) {
          const closeIdx = l.indexOf('*/', openIdx + 2)
          if (closeIdx === -1) {
            inBlock = true
          }
          // If open and close on same line, not entering block
        }
      } else {
        if (l.includes('*/')) {
          inBlock = false
        }
      }
    }
    if (inBlock) return true
    // Also check if line starts with * (common in block comments)
    if (line.startsWith('*')) return true
  }

  if (lang === 'python') {
    let inBlock = false
    let blockChar = null
    for (let i = 0; i <= lineIndex; i++) {
      const l = lines[i]
      if (!inBlock) {
        if (l.includes('"""')) {
          const count = (l.match(/"""/g) || []).length
          if (count === 1) {
            inBlock = true
            blockChar = '"""'
          }
        } else if (l.includes("'''")) {
          const count = (l.match(/'''/g) || []).length
          if (count === 1) {
            inBlock = true
            blockChar = "'''"
          }
        }
      } else {
        if (l.includes(blockChar)) {
          inBlock = false
          blockChar = null
        }
      }
    }
    if (inBlock) return true
  }

  return false
}

/**
 * Check if auth context is detected near a line
 * @param {string[]} lines - all lines of the file
 * @param {number} lineIndex - zero-based index of the match
 * @param {string} filePath - file path for heuristic check
 * @returns {boolean}
 */
function hasAuthContext(lines, lineIndex, filePath) {
  // Check file path heuristics
  for (const pat of AUTH_FILE_PATTERNS) {
    if (pat.test(filePath)) return true
  }

  // Check keyword proximity (10 lines above/below)
  const start = Math.max(0, lineIndex - 10)
  const end = Math.min(lines.length - 1, lineIndex + 10)

  for (let i = start; i <= end; i++) {
    for (const kw of AUTH_CONTEXT_KEYWORDS) {
      if (kw.test(lines[i])) return true
    }
  }

  return false
}

/**
 * Determine severity based on algorithm type and context
 * @param {string} algorithm
 * @param {string} type - 'hash', 'cipher', 'hmac', 'library'
 * @param {boolean} isAuth - whether auth context was detected
 * @returns {{ severity: string, confidence: string }}
 */
function classifySeverity(algorithm, type, isAuth) {
  const isCipher = type === 'cipher' ||
    ['DES', 'RC4', 'ARC4', 'BLOWFISH', 'DES-EDE', 'DES-EDE3', 'RC2'].includes(algorithm)

  if (isAuth) {
    return { severity: 'critico', confidence: 'high' }
  }

  if (isCipher) {
    return { severity: 'alto', confidence: 'medium' }
  }

  // Hash or hmac without auth context
  return { severity: 'medio', confidence: 'medium' }
}

/**
 * Generate title for a finding
 * @param {string} algorithm
 * @param {boolean} isAuth
 * @returns {string}
 */
function generateTitle(algorithm, isAuth) {
  if (isAuth) {
    return `Insecure algorithm ${algorithm} used in authentication context`
  }
  return `Insecure algorithm ${algorithm} detected`
}

/**
 * Generate description for a finding
 * @param {string} algorithm
 * @param {string} type
 * @param {boolean} isAuth
 * @returns {string}
 */
function generateDescription(algorithm, type, isAuth) {
  const algoType = type === 'cipher' ? 'cipher' : 'hash'
  if (isAuth) {
    return `The insecure ${algoType} algorithm ${algorithm} is used in an authentication-related context. This is critically dangerous as it can be exploited to compromise credentials or session integrity.`
  }
  return `The insecure ${algoType} algorithm ${algorithm} was detected. While not in an authentication context, this algorithm is cryptographically broken and should be replaced.`
}

/**
 * Generate fix recommendation
 * @param {string} algorithm
 * @param {string} type
 * @returns {string}
 */
function generateFix(algorithm, type) {
  if (type === 'cipher' || ['DES', 'RC4', 'ARC4', 'BLOWFISH'].includes(algorithm)) {
    return 'Replace with AES-256-GCM or ChaCha20-Poly1305 for encryption.'
  }
  if (type === 'hmac') {
    return 'Replace with HMAC-SHA256 or HMAC-SHA512.'
  }
  return 'Replace with SHA-256, SHA-512, or bcrypt/argon2 for password hashing.'
}

/**
 * Analyze source code for insecure cryptographic algorithm usage.
 * Pure function with no side effects.
 *
 * @param {string} content - source code content
 * @param {string} filePath - file path for language detection and context
 * @param {string} [language] - optional language override ('javascript' or 'python')
 * @returns {Array<object>} findings conforming to Finding contract
 */
export function analyzeCrypto(content, filePath, language) {
  const lang = language || detectLanguage(filePath)
  const patterns = lang === 'python' ? PYTHON_CRYPTO_PATTERNS : JS_CRYPTO_PATTERNS
  const lines = content.split('\n')
  const findings = []

  for (let i = 0; i < lines.length; i++) {
    // Skip comments
    if (isInsideComment(lines, i, lang)) continue

    for (const pat of patterns) {
      const match = lines[i].match(pat.pattern)
      if (!match) continue

      const algorithm = pat.algorithm(match)
      const isAuth = hasAuthContext(lines, i, filePath)
      const context = isAuth ? 'auth' : 'legacy'
      const { severity, confidence } = classifySeverity(algorithm, pat.type, isAuth)

      findings.push({
        severity,
        confidence,
        title: generateTitle(algorithm, isAuth),
        description: generateDescription(algorithm, pat.type, isAuth),
        fix: generateFix(algorithm, pat.type),
        category: 'Cryptography',
        file_path: filePath,
        line_number: i + 1,
        code_snippet: lines[i].trim(),
        algorithm,
        context,
      })
    }
  }

  return findings
}
