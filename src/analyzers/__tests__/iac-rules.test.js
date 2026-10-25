import { describe, it, expect } from 'vitest'
import { IAC_RULES } from '../iac-rules.js'
import { VALID_SEVERITIES, VALID_CONFIDENCES } from '../finding-schema.js'

describe('iac-rules', () => {
  it('exports exactly 15 rules', () => {
    expect(IAC_RULES).toHaveLength(15)
  })

  it('every rule has required properties: id, category, iacTypes, patterns, severity, confidence, title, description, fix', () => {
    const requiredProps = ['id', 'category', 'iacTypes', 'patterns', 'severity', 'confidence', 'title', 'description', 'fix']
    for (const rule of IAC_RULES) {
      for (const prop of requiredProps) {
        expect(rule).toHaveProperty(prop)
      }
    }
  })

  it('every rule id matches format IAC-NNN', () => {
    for (const rule of IAC_RULES) {
      expect(rule.id).toMatch(/^IAC-\d{3}$/)
    }
  })

  it('every severity is valid per Finding contract', () => {
    for (const rule of IAC_RULES) {
      expect(VALID_SEVERITIES).toContain(rule.severity)
    }
  })

  it('every confidence is valid per Finding contract', () => {
    for (const rule of IAC_RULES) {
      expect(VALID_CONFIDENCES).toContain(rule.confidence)
    }
  })

  it('every iacType in rule.iacTypes has a corresponding RegExp in rule.patterns', () => {
    for (const rule of IAC_RULES) {
      for (const iacType of rule.iacTypes) {
        expect(rule.patterns).toHaveProperty(iacType)
        expect(rule.patterns[iacType]).toBeInstanceOf(RegExp)
      }
    }
  })

  it('patterns values are all RegExp instances', () => {
    for (const rule of IAC_RULES) {
      for (const key of Object.keys(rule.patterns)) {
        expect(rule.patterns[key]).toBeInstanceOf(RegExp)
      }
    }
  })

  it('covers all 5 categories', () => {
    const categories = new Set(IAC_RULES.map(r => r.category))
    expect(categories).toContain('Excessive Permissions')
    expect(categories).toContain('Public Storage')
    expect(categories).toContain('Missing Encryption')
    expect(categories).toContain('Open Security Groups')
    expect(categories).toContain('Hardcoded Secrets')
    expect(categories.size).toBe(5)
  })

  it('has 3 rules for Excessive Permissions', () => {
    const rules = IAC_RULES.filter(r => r.category === 'Excessive Permissions')
    expect(rules).toHaveLength(3)
  })

  it('has 3 rules for Public Storage', () => {
    const rules = IAC_RULES.filter(r => r.category === 'Public Storage')
    expect(rules).toHaveLength(3)
  })

  it('has 4 rules for Missing Encryption', () => {
    const rules = IAC_RULES.filter(r => r.category === 'Missing Encryption')
    expect(rules).toHaveLength(4)
  })

  it('has 3 rules for Open Security Groups', () => {
    const rules = IAC_RULES.filter(r => r.category === 'Open Security Groups')
    expect(rules).toHaveLength(3)
  })

  it('has 2+ rules for Hardcoded Secrets', () => {
    const rules = IAC_RULES.filter(r => r.category === 'Hardcoded Secrets')
    expect(rules.length).toBeGreaterThanOrEqual(2)
  })

  describe('pattern smoke tests', () => {
    it('IAC-001 terraform pattern matches actions = ["*"]', () => {
      const rule = IAC_RULES.find(r => r.id === 'IAC-001')
      expect(rule.patterns.terraform.test('actions = ["*"]')).toBe(true)
    })

    it('IAC-001 cloudformation pattern matches Action: "*"', () => {
      const rule = IAC_RULES.find(r => r.id === 'IAC-001')
      expect(rule.patterns.cloudformation.test('Action: "*"')).toBe(true)
    })

    it('IAC-010 terraform pattern matches acl = "public-read"', () => {
      const rule = IAC_RULES.find(r => r.id === 'IAC-010')
      expect(rule.patterns.terraform.test('acl = "public-read"')).toBe(true)
    })

    it('IAC-030 terraform pattern matches cidr_blocks = ["0.0.0.0/0"]', () => {
      const rule = IAC_RULES.find(r => r.id === 'IAC-030')
      expect(rule.patterns.terraform.test('cidr_blocks = ["0.0.0.0/0"]')).toBe(true)
    })

    it('IAC-040 pattern matches AKIA followed by 16 chars', () => {
      const rule = IAC_RULES.find(r => r.id === 'IAC-040')
      expect(rule.patterns.terraform.test('access_key = "AKIAIOSFODNN7EXAMPLE"')).toBe(true)
    })
  })
})
