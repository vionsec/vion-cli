import { describe, it, expect } from 'vitest'
import { calculateScore, classifyTier } from '../score-calculator.js'

describe('score-calculator', () => {
  describe('classifyTier', () => {
    it('returns basico for score 0', () => {
      expect(classifyTier(0)).toBe('basico')
    })

    it('returns basico for score 39', () => {
      expect(classifyTier(39)).toBe('basico')
    })

    it('returns avancado for score 40', () => {
      expect(classifyTier(40)).toBe('avancado')
    })

    it('returns avancado for score 74', () => {
      expect(classifyTier(74)).toBe('avancado')
    })

    it('returns maximo for score 75', () => {
      expect(classifyTier(75)).toBe('maximo')
    })

    it('returns maximo for score 100', () => {
      expect(classifyTier(100)).toBe('maximo')
    })
  })

  describe('coverage component (30 points)', () => {
    it('returns 0 coverage for empty scan history', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: {},
      })
      expect(result.breakdown.coverage).toBe(0)
    })

    it('returns ~4.3 coverage for 1 of 7 scan types', () => {
      const result = calculateScore({
        scanHistory: ['url_scan'],
        findingCounts: {},
        patchStats: {},
      })
      expect(result.breakdown.coverage).toBeCloseTo(4.3, 1)
    })

    it('returns 30 coverage for all 7 scan types', () => {
      const result = calculateScore({
        scanHistory: ['url_scan', 'iac', 'crypto', 'sri', 'taint', 'bola', 'recon'],
        findingCounts: {},
        patchStats: {},
      })
      expect(result.breakdown.coverage).toBe(30)
    })

    it('counts only distinct scan types', () => {
      const result = calculateScore({
        scanHistory: ['url_scan', 'url_scan', 'url_scan', 'iac', 'iac'],
        findingCounts: {},
        patchStats: {},
      })
      const expected = Math.round((2 / 7) * 30 * 10) / 10
      expect(result.breakdown.coverage).toBe(expected)
    })
  })

  describe('severity component (50 points)', () => {
    it('returns 50 for zero findings', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(50)
    })

    it('deducts 10 per critico finding', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 2 },
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(30)
    })

    it('deducts 5 per alto finding', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { alto: 3 },
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(35)
    })

    it('deducts 2 per medio finding', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { medio: 5 },
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(40)
    })

    it('deducts 0.5 per baixo finding', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { baixo: 4 },
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(48)
    })

    it('floors at 0 for extreme finding counts', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 10 },
        patchStats: {},
      })
      expect(result.breakdown.severity).toBe(0)
    })

    it('handles mixed severity counts correctly', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 1, alto: 2, medio: 3, baixo: 4 },
        patchStats: {},
      })
      // penalty = (1*10) + (2*5) + (3*2) + (4*0.5) = 10 + 10 + 6 + 2 = 28
      expect(result.breakdown.severity).toBe(22)
    })
  })

  describe('remediation component (20 points)', () => {
    it('returns 20 when no findings exist (perfect by default)', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: { total: 0, remediated: 0 },
      })
      expect(result.breakdown.remediation).toBe(20)
    })

    it('returns 0 when findings exist but none remediated', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: { total: 10, remediated: 0 },
      })
      expect(result.breakdown.remediation).toBe(0)
    })

    it('returns 10 when half of findings remediated', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: { total: 10, remediated: 5 },
      })
      expect(result.breakdown.remediation).toBe(10)
    })

    it('returns 20 when all findings remediated', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: {},
        patchStats: { total: 10, remediated: 10 },
      })
      expect(result.breakdown.remediation).toBe(20)
    })
  })

  describe('calculateScore composite', () => {
    it('returns score 0 and basico for no activity', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 5 },
        patchStats: { total: 10, remediated: 0 },
      })
      // coverage=0, severity=max(0,50-50)=0, remediation=0 => score=0
      expect(result.score).toBe(0)
      expect(result.tier).toBe('basico')
    })

    it('returns score 100 and maximo for perfect posture', () => {
      const result = calculateScore({
        scanHistory: ['url_scan', 'iac', 'crypto', 'sri', 'taint', 'bola', 'recon'],
        findingCounts: {},
        patchStats: { total: 0, remediated: 0 },
      })
      // coverage=30, severity=50, remediation=20 => score=100
      expect(result.score).toBe(100)
      expect(result.tier).toBe('maximo')
    })

    it('clamps score to 0-100 range', () => {
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 20 },
        patchStats: { total: 100, remediated: 0 },
      })
      expect(result.score).toBeGreaterThanOrEqual(0)
      expect(result.score).toBeLessThanOrEqual(100)
    })

    it('returns correct breakdown with all 3 components', () => {
      const result = calculateScore({
        scanHistory: ['url_scan', 'iac', 'crypto'],
        findingCounts: { alto: 2 },
        patchStats: { total: 4, remediated: 2 },
      })
      // coverage = (3/7)*30 = 12.857... => 12.9
      // severity = max(0, 50 - (2*5)) = 40
      // remediation = (2/4)*20 = 10
      expect(result.breakdown).toHaveProperty('coverage')
      expect(result.breakdown).toHaveProperty('severity')
      expect(result.breakdown).toHaveProperty('remediation')
      expect(result.breakdown.coverage).toBeCloseTo(12.9, 1)
      expect(result.breakdown.severity).toBe(40)
      expect(result.breakdown.remediation).toBe(10)
    })

    it('returns rounded integer score', () => {
      const result = calculateScore({
        scanHistory: ['url_scan'],
        findingCounts: { baixo: 1 },
        patchStats: { total: 1, remediated: 1 },
      })
      expect(Number.isInteger(result.score)).toBe(true)
    })

    it('handles boundary case: score exactly 40 is avancado', () => {
      // Need: coverage + severity + remediation = 40
      // coverage = (2/7)*30 = 8.571
      // severity = max(0, 50 - penalty), need severity ~11.4
      // remediation = 20 (no findings)
      // 8.571 + 11.429 + 20 = 40
      // penalty for severity 11.429: 50 - 11.429 = 38.571
      // That's hard to hit exactly. Let's try different combo:
      // coverage = 0, severity = 20, remediation = 20 => 40
      // severity = 20 means penalty = 30: e.g. critico=3 => 30
      const result = calculateScore({
        scanHistory: [],
        findingCounts: { critico: 3 },
        patchStats: { total: 0, remediated: 0 },
      })
      // coverage=0, severity=max(0,50-30)=20, remediation=20 => score=40
      expect(result.score).toBe(40)
      expect(result.tier).toBe('avancado')
    })

    it('handles boundary case: score exactly 75 is maximo', () => {
      // coverage = (3/7)*30 = 12.857
      // severity = max(0, 50 - penalty)
      // remediation = 20
      // Need: 12.857 + severity + 20 = 75 => severity = 42.143
      // penalty = 50 - 42.143 = 7.857 -- hard to get exact
      // Try: coverage=(5/7)*30=21.43, severity=50-penalty, remediation=20
      // 21.43 + severity + 20 = 75 => severity = 33.57 => penalty = 16.43
      // Try simpler: all 7 scans (30), severity with penalty=15 (35), remediation=10
      // 30 + 35 + 10 = 75
      // penalty=15: alto=3 => 15
      // remediation=10: total=2, remediated=1
      const result = calculateScore({
        scanHistory: ['url_scan', 'iac', 'crypto', 'sri', 'taint', 'bola', 'recon'],
        findingCounts: { alto: 3 },
        patchStats: { total: 2, remediated: 1 },
      })
      // coverage=30, severity=max(0,50-15)=35, remediation=(1/2)*20=10 => score=75
      expect(result.score).toBe(75)
      expect(result.tier).toBe('maximo')
    })
  })
})
