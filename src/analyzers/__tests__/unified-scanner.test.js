import { vi, describe, it, expect, beforeEach } from 'vitest'

// Mock all analyzers to avoid full integration in unit tests
vi.mock('../iac-analyzer.js', () => ({
  analyzeIaC: vi.fn(() => []),
}))
vi.mock('../analyzers/crypto-analyzer.js', () => ({
  analyzeCrypto: vi.fn(() => []),
}))
vi.mock('../sri-checker.js', () => ({
  checkSRI: vi.fn(() => []),
}))
vi.mock('../taint-tracker.js', () => ({
  analyzeTaint: vi.fn(() => []),
}))
vi.mock('../bola-detector.js', () => ({
  detectBOLA: vi.fn(() => []),
}))

import { unifiedScan, routeFiles } from '../unified-scanner.js'
import { validateFinding } from '../finding-schema.js'
import { analyzeIaC } from '../iac-analyzer.js'
import { analyzeCrypto } from '../analyzers/crypto-analyzer.js'
import { checkSRI } from '../sri-checker.js'
import { analyzeTaint } from '../taint-tracker.js'
import { detectBOLA } from '../bola-detector.js'

// Helper: create a valid finding fixture
function makeFinding(overrides = {}) {
  return {
    severity: 'alto',
    title: 'Test Finding',
    description: 'Test description',
    fix: 'Test fix',
    category: 'test',
    confidence: 'high',
    file_path: 'test.js',
    line_number: 1,
    ...overrides,
  }
}

describe('unified-scanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('routeFiles', () => {
    it('routes .tf files to iac analyzer with terraform type', () => {
      const result = routeFiles([{ path: 'main.tf', content: 'resource {}' }])
      expect(result).toHaveLength(1)
      expect(result[0].analyzers).toEqual(['iac'])
      expect(result[0].iacType).toBe('terraform')
    })

    it('routes .yml/.yaml files to iac analyzer with cloudformation type', () => {
      const yml = routeFiles([{ path: 'stack.yml', content: 'AWSTemplateFormatVersion: ...' }])
      expect(yml[0].analyzers).toEqual(['iac'])
      expect(yml[0].iacType).toBe('cloudformation')

      const yaml = routeFiles([{ path: 'stack.yaml', content: 'Resources: ...' }])
      expect(yaml[0].analyzers).toEqual(['iac'])
      expect(yaml[0].iacType).toBe('cloudformation')
    })

    it('routes .js/.ts/.jsx/.tsx files to crypto, taint, bola analyzers', () => {
      for (const ext of ['.js', '.ts', '.jsx', '.tsx']) {
        const result = routeFiles([{ path: `file${ext}`, content: 'code' }])
        expect(result[0].analyzers).toEqual(['crypto', 'taint', 'bola'])
      }
    })

    it('routes .py files to crypto, taint analyzers', () => {
      const result = routeFiles([{ path: 'app.py', content: 'import os' }])
      expect(result[0].analyzers).toEqual(['crypto', 'taint'])
    })

    it('routes .html/.htm files to sri analyzer', () => {
      for (const ext of ['.html', '.htm']) {
        const result = routeFiles([{ path: `page${ext}`, content: '<html>' }])
        expect(result[0].analyzers).toEqual(['sri'])
      }
    })

    it('routes .go/.java/.rb files to crypto analyzer', () => {
      for (const ext of ['.go', '.java', '.rb']) {
        const result = routeFiles([{ path: `file${ext}`, content: 'code' }])
        expect(result[0].analyzers).toEqual(['crypto'])
      }
    })

    it('returns empty analyzer set for unknown extensions', () => {
      const result = routeFiles([{ path: 'readme.txt', content: 'hello' }])
      expect(result[0].analyzers).toEqual([])
    })

    it('handles files without extensions gracefully', () => {
      const result = routeFiles([{ path: 'Makefile', content: 'all:' }])
      expect(result[0].analyzers).toEqual([])
    })
  })

  describe('unifiedScan', () => {
    it('returns empty array for empty files input', async () => {
      const result = await unifiedScan([])
      expect(result.findings).toEqual([])
      expect(result.analyzerResults).toBeDefined()
    })

    it('calls correct analyzers based on file routing', async () => {
      const files = [{ path: 'main.tf', content: 'resource "aws_s3_bucket" {}' }]
      await unifiedScan(files)
      expect(analyzeIaC).toHaveBeenCalledWith('resource "aws_s3_bucket" {}', 'terraform', 'main.tf')
      expect(analyzeCrypto).not.toHaveBeenCalled()
      expect(checkSRI).not.toHaveBeenCalled()
      expect(analyzeTaint).not.toHaveBeenCalled()
      expect(detectBOLA).not.toHaveBeenCalled()
    })

    it('runs analyzers in parallel via Promise.allSettled', async () => {
      // Provide files that route to multiple analyzers
      const files = [
        { path: 'app.js', content: 'const x = 1' },
        { path: 'index.html', content: '<script src="x"></script>' },
      ]
      await unifiedScan(files)
      // crypto, taint, bola called for .js; sri called for .html
      expect(analyzeCrypto).toHaveBeenCalled()
      expect(analyzeTaint).toHaveBeenCalled()
      expect(detectBOLA).toHaveBeenCalled()
      expect(checkSRI).toHaveBeenCalled()
    })

    it('tags each finding with source analyzer name', async () => {
      analyzeIaC.mockReturnValue([makeFinding({ category: 'iac', file_path: 'main.tf' })])

      const result = await unifiedScan([{ path: 'main.tf', content: 'resource {}' }])
      expect(result.findings[0].analyzer).toBe('iac')
    })

    it('merges results from multiple analyzers into single array', async () => {
      analyzeCrypto.mockReturnValue([makeFinding({ category: 'crypto', file_path: 'app.js', line_number: 1 })])
      analyzeTaint.mockReturnValue([makeFinding({ category: 'taint', file_path: 'app.js', line_number: 5 })])
      detectBOLA.mockReturnValue([makeFinding({ category: 'bola', file_path: 'app.js', line_number: 10 })])

      const result = await unifiedScan([{ path: 'app.js', content: 'code' }])
      expect(result.findings.length).toBe(3)
      const categories = result.findings.map(f => f.analyzer)
      expect(categories).toContain('crypto')
      expect(categories).toContain('taint')
      expect(categories).toContain('bola')
    })

    it('deduplicates findings by file_path + line_number + category', async () => {
      const dup = makeFinding({ category: 'crypto', file_path: 'app.js', line_number: 5 })
      analyzeCrypto.mockReturnValue([dup, { ...dup, title: 'Duplicate' }])

      const result = await unifiedScan([{ path: 'app.js', content: 'code' }])
      const cryptoFindings = result.findings.filter(f => f.category === 'crypto' && f.line_number === 5)
      expect(cryptoFindings.length).toBe(1)
      // Keeps first occurrence
      expect(cryptoFindings[0].title).toBe('Test Finding')
    })

    it('handles analyzer rejection gracefully without losing other results', async () => {
      analyzeCrypto.mockImplementation(() => { throw new Error('Crypto exploded') })
      analyzeTaint.mockReturnValue([makeFinding({ category: 'taint', file_path: 'app.js', line_number: 3 })])
      detectBOLA.mockReturnValue([makeFinding({ category: 'bola', file_path: 'app.js', line_number: 7 })])

      const result = await unifiedScan([{ path: 'app.js', content: 'code' }])
      // taint and bola results should survive
      expect(result.findings.length).toBe(2)
      expect(result.analyzerResults.crypto.status).toBe('failed')
      expect(result.analyzerResults.taint.status).toBe('completed')
    })

    it('processes mixed file types correctly', async () => {
      analyzeIaC.mockReturnValue([makeFinding({ category: 'iac', file_path: 'main.tf', line_number: 1 })])
      checkSRI.mockReturnValue([makeFinding({ category: 'sri', file_path: 'index.html', line_number: 1 })])
      analyzeCrypto.mockReturnValue([makeFinding({ category: 'crypto', file_path: 'app.py', line_number: 1 })])
      analyzeTaint.mockReturnValue([makeFinding({ category: 'taint', file_path: 'app.py', line_number: 2 })])

      const result = await unifiedScan([
        { path: 'main.tf', content: 'resource {}' },
        { path: 'index.html', content: '<html>' },
        { path: 'app.py', content: 'import hashlib' },
      ])
      expect(result.findings.length).toBe(4)
    })
  })

  describe('finding contract compliance', () => {
    it('every finding from unified scan passes validateFinding()', async () => {
      analyzeIaC.mockReturnValue([makeFinding({ category: 'iac', file_path: 'main.tf', line_number: 1 })])
      analyzeCrypto.mockReturnValue([makeFinding({ category: 'crypto', file_path: 'app.js', line_number: 1 })])

      const result = await unifiedScan([
        { path: 'main.tf', content: 'resource {}' },
        { path: 'app.js', content: 'code' },
      ])

      for (const finding of result.findings) {
        const { valid, errors } = validateFinding(finding)
        expect(valid, `Finding failed validation: ${errors.join(', ')}`).toBe(true)
      }
    })
  })
})
