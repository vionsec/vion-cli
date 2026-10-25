// ── Security Score Calculator: composite 3-component scoring engine ──

export const SCAN_TYPES = ['url_scan', 'iac', 'crypto', 'sri', 'taint', 'bola', 'recon']

export const SEVERITY_WEIGHTS = { critico: 10, alto: 5, medio: 2, baixo: 0.5 }

export const TIER_THRESHOLDS = { maximo: 75, avancado: 40 }

/**
 * Classify a numeric score (0-100) into a security tier.
 * @param {number} score - security score between 0 and 100
 * @returns {'basico' | 'avancado' | 'maximo'}
 */
export function classifyTier(score) {
  if (score >= TIER_THRESHOLDS.maximo) return 'maximo'
  if (score >= TIER_THRESHOLDS.avancado) return 'avancado'
  return 'basico'
}

/**
 * Calculate a composite security score from scan history, finding counts, and patch stats.
 * Pure function -- no database calls or side effects.
 * @param {object} params
 * @param {string[]} params.scanHistory - array of scan_type strings (may have duplicates)
 * @param {{ critico?: number, alto?: number, medio?: number, baixo?: number }} params.findingCounts
 * @param {{ total?: number, remediated?: number }} params.patchStats
 * @returns {{ score: number, tier: string, breakdown: { coverage: number, severity: number, remediation: number } }}
 */
export function calculateScore({ scanHistory = [], findingCounts = {}, patchStats = {} } = {}) {
  // 1. Coverage (0-30): distinct scan types out of 7
  const distinctTypes = new Set(scanHistory).size
  const coverage = (distinctTypes / SCAN_TYPES.length) * 30

  // 2. Severity (0-50): starts at 50, deducts by weighted findings
  const critico = findingCounts.critico || 0
  const alto = findingCounts.alto || 0
  const medio = findingCounts.medio || 0
  const baixo = findingCounts.baixo || 0
  const penalty = (critico * SEVERITY_WEIGHTS.critico)
    + (alto * SEVERITY_WEIGHTS.alto)
    + (medio * SEVERITY_WEIGHTS.medio)
    + (baixo * SEVERITY_WEIGHTS.baixo)
  const severity = Math.max(0, 50 - penalty)

  // 3. Remediation (0-20): ratio of remediated findings, or 20 if no findings
  const total = patchStats.total || 0
  const remediated = patchStats.remediated || 0
  const remediation = total === 0 ? 20 : (remediated / total) * 20

  // 4. Final: round, clamp, classify
  const raw = coverage + severity + remediation
  const score = Math.round(Math.max(0, Math.min(100, raw)))
  const tier = classifyTier(score)

  return {
    score,
    tier,
    breakdown: {
      coverage: Math.round(coverage * 10) / 10,
      severity: Math.round(severity * 10) / 10,
      remediation: Math.round(remediation * 10) / 10,
    },
  }
}
