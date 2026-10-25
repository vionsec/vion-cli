// ── BOLA/IDOR Detector: broken object level authorization analysis ──

import { validateFinding } from './finding-schema.js'

/**
 * Patterns for detecting ID extraction from request objects.
 */
const ID_ACCESS_PATTERNS = [
  { pattern: /req\.params\.(\w*id\w*)/i, type: 'route_param' },
  { pattern: /req\.query\.(\w*id\w*)/i, type: 'query_param' },
  { pattern: /req\.body\.(\w*id\w*)/i, type: 'body_param' },
  { pattern: /\.eq\s*\(\s*['"]id['"]\s*,\s*req\./, type: 'direct_eq' },
]

/**
 * Patterns for detecting database queries.
 */
const DB_QUERY_PATTERNS = [
  /\.(?:select|find|findOne|findById|get)\s*\(/,
  /\.eq\s*\(\s*['"]id['"]/,
  /\.from\s*\([^)]+\)/,
  /db\.query\s*\(/,
  /\.query\s*\(/,
  /SELECT\s+.*\s+FROM/i,
]

/**
 * Patterns for detecting ownership validation.
 */
const OWNERSHIP_PATTERNS = [
  /\.eq\s*\(\s*['"]user_id['"]/,
  /WHERE\s+.*user_id\s*=/i,
  /\.filter\s*\(.*user_id/,
  /\.where\s*\(\s*['"]user_id['"]/,
  /requireAuth|isAuthenticated|verifyOwnership|checkOwner/i,
  /req\.user\.id\s*[!=]==?\s*/,
]

/**
 * Patterns indicating enumerable (numeric) IDs.
 */
const ENUMERABLE_ID_PATTERNS = [
  /parseInt\s*\(\s*req\.(params|query|body)/,
  /Number\s*\(\s*req\.(params|query|body)/,
]

/**
 * Patterns indicating UUID-based IDs.
 */
const UUID_PATTERNS = [
  /isUUID/i,
  /validateUUID/i,
  /uuid/i,
]

const FUNCTION_START = /(?:function\s+\w+\s*\(|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>|(?:async\s+)?function\s*\(|(\w+)\s*\([^)]*\)\s*\{)/

/**
 * Detect BOLA/IDOR vulnerabilities in source code.
 * Identifies API endpoints that access records by user-supplied ID without ownership validation.
 * @param {string} content - Source code to analyze
 * @param {string} filePath - File path for reporting
 * @returns {Array<object>} Array of Finding objects that pass validateFinding()
 */
export function detectBOLA(content, filePath) {
  if (!content || typeof content !== 'string' || content.trim() === '') return []

  const lines = content.split('\n')
  const scopes = extractFunctionScopes(lines)
  const findings = []

  for (const scope of scopes) {
    const scopeFindings = analyzeScope(scope, lines, filePath)
    findings.push(...scopeFindings)
  }

  // If no scopes found, treat entire content as one scope
  if (scopes.length === 0) {
    const globalScope = { startLine: 0, endLine: lines.length - 1 }
    findings.push(...analyzeScope(globalScope, lines, filePath))
  }

  return findings
}

/**
 * Extract function scope boundaries from lines.
 */
function extractFunctionScopes(lines) {
  const scopes = []
  let i = 0

  while (i < lines.length) {
    const line = lines[i]
    if (FUNCTION_START.test(line)) {
      const startLine = i
      let braceDepth = 0
      let foundOpen = false

      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === '{') { braceDepth++; foundOpen = true }
          if (ch === '}') braceDepth--
        }
        if (foundOpen && braceDepth <= 0) {
          scopes.push({ startLine, endLine: j })
          i = j + 1
          break
        }
        if (j === lines.length - 1) {
          scopes.push({ startLine, endLine: j })
          i = j + 1
        }
      }
      continue
    }
    i++
  }

  return scopes
}

/**
 * Analyze a single function scope for BOLA vulnerabilities.
 */
function analyzeScope(scope, lines, filePath) {
  const findings = []
  const scopeLines = lines.slice(scope.startLine, scope.endLine + 1)
  const scopeText = scopeLines.join('\n')

  // Step 1: Find ID access patterns
  const idAccesses = findIdAccesses(scopeLines, scope.startLine)
  if (idAccesses.length === 0) return []

  // Step 2: Find DB query patterns
  const hasDbQuery = DB_QUERY_PATTERNS.some(p => p.test(scopeText))
  if (!hasDbQuery) return []

  // Step 3: Check for ownership validation
  const hasOwnership = OWNERSHIP_PATTERNS.some(p => p.test(scopeText))
  if (hasOwnership) return []

  // Step 4: Check for enumerable vs UUID IDs
  const isEnumerable = ENUMERABLE_ID_PATTERNS.some(p => p.test(scopeText))
  const isUUID = UUID_PATTERNS.some(p => p.test(scopeText))

  // Step 5: Determine confidence
  let confidence = 'high'
  if (isUUID) confidence = 'medium'

  // Step 6: Build findings for each ID access
  for (const access of idAccesses) {
    const actualLine = scope.startLine + access.lineIndex + 1

    const finding = {
      severity: 'alto',
      title: `BOLA/IDOR: ${filePath} accesses record by ${access.type} without ownership validation`,
      description: `Endpoint fetches data using ID from ${access.type} at line ${actualLine} without checking if the requesting user owns the record.`,
      fix: 'Add .eq("user_id", authenticatedUser.id) to the database query or add middleware that validates ownership.',
      category: 'BOLA/IDOR',
      confidence,
      file_path: filePath,
      line_number: actualLine,
      code_snippet: scopeLines[access.lineIndex].trim(),
    }

    findings.push(finding)
    break // one finding per scope to avoid duplicates
  }

  return findings
}

/**
 * Find ID access patterns in scope lines.
 */
function findIdAccesses(scopeLines, baseLineOffset) {
  const accesses = []

  for (let i = 0; i < scopeLines.length; i++) {
    const line = scopeLines[i]
    for (const pattern of ID_ACCESS_PATTERNS) {
      if (pattern.pattern.test(line)) {
        accesses.push({
          type: pattern.type,
          lineIndex: i,
        })
        break
      }
    }
  }

  return accesses
}
