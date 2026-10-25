// ── IaC Security Analyzer: pure function static analysis engine ──

import { parseLines } from './iac-comment-filter.js'
import { IAC_RULES } from './iac-rules.js'

/**
 * Analyze IaC content for security issues.
 * @param {string} content - Raw file content
 * @param {string} iacType - 'terraform' | 'cloudformation' | 'ansible'
 * @param {string} filePath - Original file path (for finding metadata)
 * @returns {Array<Object>} Array of Finding-contract-compliant objects
 */
export function analyzeIaC(content, iacType, filePath) {
  if (!content) return []

  const lines = parseLines(content, iacType)
  const applicableRules = IAC_RULES.filter(r => r.iacTypes.includes(iacType))
  const findings = []

  for (const rule of applicableRules) {
    const pattern = rule.patterns[iacType]
    if (!pattern) continue

    for (const line of lines) {
      if (line.isComment) continue

      // Reset regex lastIndex for global/sticky patterns
      if (pattern.lastIndex !== undefined) pattern.lastIndex = 0

      if (pattern.test(line.text)) {
        findings.push({
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          fix: rule.fix,
          category: rule.category,
          confidence: adjustConfidence(rule.confidence, line.text, iacType),
          file_path: filePath,
          line_number: line.lineNum,
          code_snippet: line.text.trim(),
          rule_id: rule.id,
        })
      }
    }
  }

  return findings
}

/**
 * Adjust confidence based on variable interpolation context.
 * @param {string} base - Base confidence level from rule
 * @param {string} lineText - The matched line text
 * @param {string} iacType - IaC type for context-specific patterns
 * @returns {string} Adjusted confidence level
 */
function adjustConfidence(base, lineText, iacType) {
  if (iacType === 'terraform' && /\$\{/.test(lineText)) return downgrade(base)
  if (iacType === 'cloudformation' && /!(?:Ref|Sub|GetAtt|Select)/.test(lineText)) return downgrade(base)
  if (iacType === 'ansible' && /\{\{/.test(lineText)) return downgrade(base)
  return base
}

/**
 * Downgrade confidence by one level.
 * @param {string} level - Current confidence level
 * @returns {string} Downgraded confidence level
 */
function downgrade(level) {
  if (level === 'high') return 'medium'
  if (level === 'medium') return 'low'
  return 'low'
}
