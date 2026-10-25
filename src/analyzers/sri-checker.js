// ── SRI (Subresource Integrity) Checker ──
// Pure function: checkSRI(htmlContent, filePath?) -> Finding[]
// No side effects, no network calls, no DB access.

import crypto from 'crypto'

const VALID_SRI_ALGORITHMS = ['sha256', 'sha384', 'sha512']

const SCRIPT_TAG_REGEX = /<script\b([^>]*)(?:>[\s\S]*?<\/script>|\/?>)/gi
const LINK_TAG_REGEX = /<link\b([^>]*)\/?\s*>/gi

const EXPECTED_HASH_LENGTHS = { sha256: 44, sha384: 64, sha512: 88 }

// ── Internal helpers ──

function extractAttributes(tagContent) {
  return {
    src: tagContent.match(/\bsrc\s*=\s*['"]([^'"]+)['"]/i)?.[1] || null,
    href: tagContent.match(/\bhref\s*=\s*['"]([^'"]+)['"]/i)?.[1] || null,
    integrity: tagContent.match(/\bintegrity\s*=\s*['"]([^'"]+)['"]/i)?.[1] || null,
    crossorigin: tagContent.match(/\bcrossorigin\b/i) ? 'present' : null,
    type: tagContent.match(/\btype\s*=\s*['"]([^'"]+)['"]/i)?.[1] || null,
    rel: tagContent.match(/\brel\s*=\s*['"]([^'"]+)['"]/i)?.[1] || null,
  }
}

function isExternalResource(url) {
  if (!url) return false
  return url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')
}

function needsSRI(attrs) {
  const url = attrs.src || attrs.href
  if (!url || !isExternalResource(url)) return false
  if (attrs.src) return true
  if (attrs.href && attrs.rel === 'stylesheet') return true
  return false
}

function getLineNumber(content, position) {
  const before = content.slice(0, position)
  return (before.match(/\n/g) || []).length + 1
}

// ── Exported functions ──

/**
 * Parse an SRI integrity string into algorithm-hash pairs.
 * @param {string} integrity - e.g. "sha384-abc123 sha512-def456"
 * @returns {Array<{ algorithm: string, hash: string, raw: string }>}
 */
export function parseSRIHashes(integrity) {
  if (!integrity) return []
  const trimmed = integrity.trim()
  if (trimmed === '') return []
  return trimmed.split(/\s+/).map(token => {
    const dashIdx = token.indexOf('-')
    if (dashIdx === -1) return { algorithm: token.toLowerCase(), hash: '', raw: token }
    const algo = token.slice(0, dashIdx)
    const hash = token.slice(dashIdx + 1)
    return { algorithm: algo.toLowerCase(), hash, raw: token }
  })
}

/**
 * Validate SRI hash format (not content).
 * @param {string} integrity
 * @returns {{ valid: boolean, errors: string[], hashes: Array }}
 */
export function validateSRIFormat(integrity) {
  const hashes = parseSRIHashes(integrity)
  const errors = []

  if (hashes.length === 0) {
    errors.push('Empty integrity attribute')
    return { valid: false, errors, hashes }
  }

  for (const h of hashes) {
    if (!VALID_SRI_ALGORITHMS.includes(h.algorithm)) {
      errors.push(`Unsupported algorithm '${h.algorithm}' -- use sha256, sha384, or sha512`)
    }
    if (h.hash && !/^[A-Za-z0-9+/]+=*$/.test(h.hash)) {
      errors.push(`Invalid base64 hash for ${h.algorithm}`)
    }
    if (h.hash && EXPECTED_HASH_LENGTHS[h.algorithm] && h.hash.length !== EXPECTED_HASH_LENGTHS[h.algorithm]) {
      errors.push(`Hash length mismatch for ${h.algorithm}: expected ${EXPECTED_HASH_LENGTHS[h.algorithm]} chars, got ${h.hash.length}`)
    }
  }

  return { valid: errors.length === 0, errors, hashes }
}

/**
 * Compute SRI hash for content using Node.js crypto.createHash.
 * @param {string} content
 * @param {string} algorithm - default 'sha384'
 * @returns {string} e.g. "sha384-abc123..."
 */
export function computeSRIHash(content, algorithm = 'sha384') {
  const hash = crypto.createHash(algorithm).update(content).digest('base64')
  return `${algorithm}-${hash}`
}

/**
 * Verify that content matches a declared SRI integrity string.
 * @param {string} content
 * @param {string} integrity
 * @returns {{ valid: boolean, matched: string|null }}
 */
export function verifySRI(content, integrity) {
  const hashes = parseSRIHashes(integrity)
  for (const h of hashes) {
    try {
      const computed = crypto.createHash(h.algorithm).update(content).digest('base64')
      if (computed === h.hash) return { valid: true, matched: h.raw }
    } catch {
      // unsupported algorithm, skip
    }
  }
  return { valid: false, matched: null }
}

/**
 * Analyze HTML content for SRI issues on external script and link tags.
 * @param {string} htmlContent - raw HTML string
 * @param {string} [filePath='unknown.html'] - file path for findings
 * @returns {Array<import('./finding-schema.js').Finding>}
 */
export function checkSRI(htmlContent, filePath = 'unknown.html') {
  const findings = []

  const processTag = (match, tagContent, position, tagType) => {
    const attrs = extractAttributes(tagContent)
    const url = attrs.src || attrs.href

    if (!needsSRI(attrs)) return

    const lineNumber = getLineNumber(htmlContent, position)
    const snippet = match.length > 200 ? match.slice(0, 200) + '...' : match

    if (!attrs.integrity) {
      // Missing SRI
      const isScript = tagType === 'script'
      findings.push({
        severity: 'alto',
        title: isScript
          ? 'Script externo sem SRI (Subresource Integrity)'
          : 'Stylesheet externo sem SRI (Subresource Integrity)',
        description: `O ${isScript ? 'script' : 'stylesheet'} carregado de ${url} nao possui atributo integrity. Isso permite ataques de supply-chain caso o CDN seja comprometido.`,
        fix: `Adicionar integrity="sha384-..." e crossorigin="anonymous" ao tag <${isScript ? 'script' : 'link'}>.`,
        category: 'Integrity',
        confidence: 'high',
        file_path: filePath,
        line_number: lineNumber,
        code_snippet: snippet,
      })
      return
    }

    // Has integrity -- validate format
    const validation = validateSRIFormat(attrs.integrity)
    if (!validation.valid) {
      findings.push({
        severity: 'medio',
        title: 'Hash SRI com formato invalido',
        description: `O atributo integrity em ${url} possui formato invalido: ${validation.errors.join('; ')}.`,
        fix: 'Regenerar o hash SRI usando: openssl dgst -sha384 -binary <file> | openssl base64 -A',
        category: 'Integrity',
        confidence: 'high',
        file_path: filePath,
        line_number: lineNumber,
        code_snippet: snippet,
      })
      return
    }

    // Valid integrity but missing crossorigin
    if (!attrs.crossorigin) {
      findings.push({
        severity: 'baixo',
        title: 'Atributo crossorigin ausente em tag com SRI',
        description: `O tag com integrity em ${url} nao possui atributo crossorigin. O navegador pode ignorar a verificacao SRI sem crossorigin="anonymous".`,
        fix: 'Adicionar crossorigin="anonymous" ao tag.',
        category: 'Integrity',
        confidence: 'medium',
        file_path: filePath,
        line_number: lineNumber,
        code_snippet: snippet,
      })
    }
  }

  // Process script tags
  let match
  const scriptRegex = new RegExp(SCRIPT_TAG_REGEX.source, SCRIPT_TAG_REGEX.flags)
  while ((match = scriptRegex.exec(htmlContent)) !== null) {
    processTag(match[0], match[1], match.index, 'script')
  }

  // Process link tags
  const linkRegex = new RegExp(LINK_TAG_REGEX.source, LINK_TAG_REGEX.flags)
  while ((match = linkRegex.exec(htmlContent)) !== null) {
    processTag(match[0], match[1], match.index, 'link')
  }

  return findings
}
