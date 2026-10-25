// ── Taint Tracker: source-to-sink data flow analysis ──

import { validateFinding } from './finding-schema.js'

/**
 * Patterns for detecting user-controlled input sources.
 * @type {Array<{ pattern: RegExp, type: string }>}
 */
export const SOURCE_PATTERNS = [
  { pattern: /req\.body\b(?:\.(\w+)|\[['"](\w+)['"]\])?/, type: 'request_body' },
  { pattern: /req\.query\b(?:\.(\w+)|\[['"](\w+)['"]\])?/, type: 'request_query' },
  { pattern: /req\.params\b(?:\.(\w+)|\[['"](\w+)['"]\])?/, type: 'request_params' },
  { pattern: /req\.headers\b(?:\.(\w+)|\[['"](\w+)['"]\])?/, type: 'request_headers' },
  { pattern: /(?:const|let|var)\s*\{([^}]+)\}\s*=\s*req\.(body|query|params|headers)/, type: 'destructured_input' },
]

/**
 * Patterns for detecting dangerous sinks.
 * @type {Array<{ pattern: RegExp, type: string, vuln: string }>}
 */
export const SINK_PATTERNS = [
  { pattern: /\.query\s*\(\s*`[^`]*\$\{/, type: 'sql_template_literal', vuln: 'sqli' },
  { pattern: /\.query\s*\(\s*['"][^'"]*['"]\s*\+/, type: 'sql_concatenation', vuln: 'sqli' },
  { pattern: /(?:db|pool|client|connection|knex|sequelize|prisma)\.\$?(?:query|execute|raw|rawQuery)\s*\(/, type: 'sql_query', vuln: 'sqli' },
  { pattern: /\.innerHTML\s*=/, type: 'innerHTML', vuln: 'xss' },
  { pattern: /document\.write\s*\(/, type: 'document_write', vuln: 'xss' },
  { pattern: /res\.send\s*\(.*\+/, type: 'response_concatenation', vuln: 'xss' },
  { pattern: /(?<!execFile\s*\()(?:^|[^.])eval\s*\(/, type: 'eval', vuln: 'command_injection' },
  { pattern: /execSync\s*\(/, type: 'execSync', vuln: 'command_injection' },
  { pattern: /(?<![a-zA-Z.])exec\s*\(/, type: 'exec', vuln: 'command_injection' },
]

/**
 * Patterns for detecting sanitization or mitigation.
 * @type {Array<{ pattern: RegExp, mitigates: string }>}
 */
export const SANITIZATION_PATTERNS = [
  { pattern: /\?\s*,\s*\[/, mitigates: 'sqli' },
  { pattern: /\$\d+\s*[,)]/, mitigates: 'sqli' },
  { pattern: /\.prepare\s*\(/, mitigates: 'sqli' },
  { pattern: /DOMPurify\.sanitize/i, mitigates: 'xss' },
  { pattern: /(?:encode|escape)(?:HTML|Html|Uri|URIComponent)/i, mitigates: 'all' },
  { pattern: /parseInt\s*\(/, mitigates: 'sqli' },
  { pattern: /Number\s*\(/, mitigates: 'sqli' },
  { pattern: /parseFloat\s*\(/, mitigates: 'sqli' },
  { pattern: /shell-escape|shellescape|escapeshellarg/i, mitigates: 'command_injection' },
  { pattern: /execFile\s*\(/, mitigates: 'command_injection' },
  { pattern: /validator\.\w+/, mitigates: 'all' },
  { pattern: /joi\.validate|zod\.parse|yup\.validate/i, mitigates: 'all' },
]

const MAX_CHAIN_HOPS = 5

const FUNCTION_START = /(?:function\s+\w+\s*\(|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>|(?:async\s+)?function\s*\(|(\w+)\s*\([^)]*\)\s*\{)/

/**
 * Analyze source code for taint flows from user-controlled sources to dangerous sinks.
 * @param {string} content - Source code to analyze
 * @param {string} filePath - File path for reporting
 * @returns {Array<object>} Array of Finding objects that pass validateFinding()
 */
export function analyzeTaint(content, filePath) {
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
 * Analyze a single function scope for taint flows.
 */
function analyzeScope(scope, lines, filePath) {
  const findings = []
  const scopeLines = lines.slice(scope.startLine, scope.endLine + 1)
  const scopeText = scopeLines.join('\n')

  // Step 1: Find all source assignments in this scope
  const taintedVars = findSourceAssignments(scopeLines, scope.startLine)

  if (taintedVars.length === 0) return []

  // Step 2: Build variable chains (up to MAX_CHAIN_HOPS)
  const taintChains = buildTaintChains(taintedVars, scopeLines, scope.startLine)

  // Step 3: Find sinks in this scope
  const sinks = findSinks(scopeLines, scope.startLine)

  if (sinks.length === 0) return []

  // Step 4: Check if tainted variables reach sinks
  for (const sink of sinks) {
    const sinkLine = scopeLines[sink.lineIndex]
    const reachingChain = findReachingChain(taintChains, sinkLine, sink.lineIndex, scopeLines)

    if (!reachingChain) continue

    // Step 5: Check for parameterized query (no finding at all)
    if (isParameterizedQuery(sinkLine, scopeLines, sink.lineIndex)) continue

    // Step 6: Check for sanitization between source and sink
    const sanitized = checkSanitization(
      scopeLines,
      reachingChain.sourceLineIndex,
      sink.lineIndex,
      sink.vuln
    )

    // Step 7: Build finding
    const severity = sanitized
      ? 'medio'
      : (sink.vuln === 'xss' ? 'alto' : 'critico')

    const confidence = sanitized ? 'low' : 'high'

    const actualLine = scope.startLine + sink.lineIndex + 1 // 1-based

    const finding = {
      severity,
      title: `${sink.vuln.toUpperCase()}: unsanitized ${reachingChain.sourceType} flows to ${sink.type}`,
      description: `User input from ${reachingChain.sourceName} reaches ${sink.type} at line ${actualLine}${sanitized ? ' (sanitization detected but may be insufficient)' : ' without sanitization'}.`,
      fix: getFix(sink.vuln),
      category: 'Taint Analysis',
      confidence,
      file_path: filePath,
      line_number: actualLine,
      code_snippet: sinkLine.trim(),
      source_type: reachingChain.sourceType,
      source_location: `${filePath}:${scope.startLine + reachingChain.sourceLineIndex + 1}`,
      sink_type: sink.type,
      sink_location: `${filePath}:${actualLine}`,
      vulnerability_type: sink.vuln,
      has_sanitization: sanitized,
      path_details: {
        chain: reachingChain.chain,
        hops: reachingChain.hops,
        scope: 'function',
      },
    }

    findings.push(finding)
  }

  return findings
}

/**
 * Find variables assigned from taint sources.
 */
function findSourceAssignments(scopeLines, baseLineOffset) {
  const taintedVars = []

  for (let i = 0; i < scopeLines.length; i++) {
    const line = scopeLines[i]

    for (const sp of SOURCE_PATTERNS) {
      const match = line.match(sp.pattern)
      if (!match) continue

      if (sp.type === 'destructured_input') {
        // Extract all destructured variable names
        const varsStr = match[1]
        const varNames = varsStr.split(',').map(v => v.trim().split(':')[0].split('=')[0].trim()).filter(Boolean)
        for (const varName of varNames) {
          taintedVars.push({
            name: varName,
            sourceType: sp.type,
            sourceName: `req.${match[2]}`,
            lineIndex: i,
            hop: 0,
          })
        }
      } else {
        // Find the variable being assigned
        const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=/)
        if (assignMatch) {
          taintedVars.push({
            name: assignMatch[1],
            sourceType: sp.type,
            sourceName: match[0],
            lineIndex: i,
            hop: 0,
          })
        }
      }
    }
  }

  return taintedVars
}

/**
 * Build taint chains by following variable reassignments.
 */
function buildTaintChains(taintedVars, scopeLines, baseLineOffset) {
  const chains = [...taintedVars]

  for (let hop = 1; hop <= MAX_CHAIN_HOPS; hop++) {
    const currentVarNames = chains.filter(v => v.hop === hop - 1).map(v => v.name)
    if (currentVarNames.length === 0) break

    for (let i = 0; i < scopeLines.length; i++) {
      const line = scopeLines[i]
      const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*(.+)/)
      if (!assignMatch) continue

      const newVar = assignMatch[1]
      const rhs = assignMatch[2]

      // Skip if this variable is already tracked
      if (chains.some(v => v.name === newVar)) continue

      // Check if any current tainted var appears on the RHS
      for (const taintedName of currentVarNames) {
        const rhsPattern = new RegExp(`\\b${escapeRegex(taintedName)}\\b`)
        if (rhsPattern.test(rhs)) {
          // Find the source chain entry
          const sourceEntry = chains.find(v => v.name === taintedName)
          chains.push({
            name: newVar,
            sourceType: sourceEntry.sourceType,
            sourceName: sourceEntry.sourceName,
            lineIndex: sourceEntry.lineIndex,
            hop: hop,
            chain: [...(sourceEntry.chain || [sourceEntry.sourceName, sourceEntry.name]), newVar],
          })
          break
        }
      }
    }
  }

  return chains
}

/**
 * Find all sinks in scope lines.
 */
function findSinks(scopeLines, baseLineOffset) {
  const sinks = []

  for (let i = 0; i < scopeLines.length; i++) {
    const line = scopeLines[i]
    for (const sp of SINK_PATTERNS) {
      if (sp.pattern.test(line)) {
        sinks.push({
          type: sp.type,
          vuln: sp.vuln,
          lineIndex: i,
        })
        break // one sink per line
      }
    }
  }

  return sinks
}

/**
 * Check if a tainted variable reaches the sink line.
 */
function findReachingChain(taintChains, sinkLine, sinkLineIndex, scopeLines) {
  for (const chain of taintChains) {
    if (chain.hop >= MAX_CHAIN_HOPS) continue

    const varPattern = new RegExp(`\\b${escapeRegex(chain.name)}\\b`)
    if (varPattern.test(sinkLine)) {
      return {
        sourceType: chain.sourceType,
        sourceName: chain.sourceName,
        sourceLineIndex: chain.lineIndex,
        hops: chain.hop + 1,
        chain: chain.chain || [chain.sourceName, chain.name],
      }
    }
  }

  return null
}

/**
 * Check if the sink line uses a parameterized query.
 */
function isParameterizedQuery(sinkLine, scopeLines, sinkLineIndex) {
  // Check current line and the next line for parameterized patterns
  const linesToCheck = [sinkLine]
  if (sinkLineIndex + 1 < scopeLines.length) {
    linesToCheck.push(scopeLines[sinkLineIndex + 1])
  }

  const combined = linesToCheck.join('\n')

  // Parameterized: query('SELECT ?', [val]) or query('SELECT $1', val)
  if (/\?\s*['"`]\s*,\s*\[/.test(combined)) return true
  if (/\$\d+['"`]\s*,\s*\[/.test(combined)) return true
  // Simpler check: ?, [ on same line
  if (/\?\s*,\s*\[/.test(combined)) return true

  return false
}

/**
 * Check for sanitization patterns between source line and sink line.
 */
function checkSanitization(scopeLines, sourceLineIndex, sinkLineIndex, vulnType) {
  for (let i = sourceLineIndex; i <= sinkLineIndex; i++) {
    const line = scopeLines[i]
    for (const sp of SANITIZATION_PATTERNS) {
      if (sp.pattern.test(line)) {
        if (sp.mitigates === 'all' || sp.mitigates === vulnType) {
          return true
        }
      }
    }
  }
  return false
}

/**
 * Get fix recommendation for a vulnerability type.
 */
function getFix(vulnType) {
  switch (vulnType) {
    case 'sqli':
      return 'Use parameterized queries: db.query("SELECT * FROM t WHERE id = $1", [value])'
    case 'xss':
      return 'Sanitize output with DOMPurify.sanitize() or use textContent instead of innerHTML'
    case 'command_injection':
      return 'Use execFile() with argument arrays instead of exec() with string interpolation'
    default:
      return 'Validate and sanitize all user input before use in sensitive operations'
  }
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
