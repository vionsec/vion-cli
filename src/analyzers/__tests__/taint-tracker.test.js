import { describe, it, expect } from 'vitest'
import { analyzeTaint, SOURCE_PATTERNS, SINK_PATTERNS, SANITIZATION_PATTERNS } from '../taint-tracker.js'
import { validateFinding } from '../finding-schema.js'

describe('analyzeTaint', () => {
  // === 1. Source detection tests ===

  describe('source detection', () => {
    it('detects req.body source flowing to db.query concatenation', () => {
      const code = `
function handler(req, res) {
  const name = req.body.name
  db.query('SELECT * FROM users WHERE name = ' + name)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].source_type).toBe('request_body')
      expect(findings[0].vulnerability_type).toBe('sqli')
    })

    it('detects req.query source flowing to eval', () => {
      const code = `
function handler(req, res) {
  const search = req.query.search
  eval(search)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].source_type).toBe('request_query')
      expect(findings[0].vulnerability_type).toBe('command_injection')
    })

    it('detects req.params source flowing to exec', () => {
      const code = `
function handler(req, res) {
  const id = req.params.id
  exec('rm -rf /tmp/' + id)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].source_type).toBe('request_params')
      expect(findings[0].vulnerability_type).toBe('command_injection')
    })

    it('detects req.headers source flowing to db.query', () => {
      const code = `
function handler(req, res) {
  const token = req.headers['x-token']
  db.query('SELECT * FROM sessions WHERE token = ' + token)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].source_type).toBe('request_headers')
    })

    it('detects destructured input source', () => {
      const code = `
function handler(req, res) {
  const { name, email } = req.body
  db.query('INSERT INTO users VALUES (' + name + ')')
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].source_type).toBe('destructured_input')
    })
  })

  // === 2. Sink detection and classification tests ===

  describe('sink detection and classification', () => {
    it('classifies db.query with template literal as sqli/critico', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query(\`SELECT * FROM users WHERE id = \${id}\`)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('sqli')
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies db.query with concatenation as sqli/critico', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM users WHERE id = ' + id)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('sqli')
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies eval as command_injection/critico', () => {
      const code = `
function handler(req, res) {
  const input = req.body.code
  eval(input)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('command_injection')
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies exec as command_injection/critico', () => {
      const code = `
function handler(req, res) {
  const cmd = req.body.command
  exec(cmd)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('command_injection')
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies execSync as command_injection/critico', () => {
      const code = `
function handler(req, res) {
  const cmd = req.body.command
  execSync(cmd)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('command_injection')
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies innerHTML as xss/alto', () => {
      const code = `
function handler(req, res) {
  const input = req.body.html
  element.innerHTML = input
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('xss')
      expect(findings[0].severity).toBe('alto')
    })

    it('classifies document.write as xss/alto', () => {
      const code = `
function handler(req, res) {
  const input = req.body.html
  document.write(input)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('xss')
      expect(findings[0].severity).toBe('alto')
    })

    it('classifies res.send with concatenation as xss/alto', () => {
      const code = `
function handler(req, res) {
  const name = req.body.name
  res.send('<h1>' + name + '</h1>')
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].vulnerability_type).toBe('xss')
      expect(findings[0].severity).toBe('alto')
    })
  })

  // === 3. Sanitization detection tests ===

  describe('sanitization detection', () => {
    it('detects DOMPurify.sanitize as sanitization', () => {
      const code = `
function handler(req, res) {
  const input = req.body.html
  const clean = DOMPurify.sanitize(input)
  element.innerHTML = clean
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].has_sanitization).toBe(true)
      expect(findings[0].severity).toBe('medio')
      expect(findings[0].confidence).toBe('low')
    })

    it('does not flag parameterized queries', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM users WHERE id = ?', [id])
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBe(0)
    })

    it('detects escapeHtml as sanitization', () => {
      const code = `
function handler(req, res) {
  const name = req.body.name
  const safe = escapeHtml(name)
  res.send('<h1>' + safe + '</h1>')
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].has_sanitization).toBe(true)
    })

    it('detects parseInt as sanitization for SQL', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  const safeId = parseInt(id)
  db.query('SELECT * FROM users WHERE id = ' + safeId)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].has_sanitization).toBe(true)
    })
  })

  // === 4. Variable chain tracing tests ===

  describe('variable chain tracing', () => {
    it('traces 2-hop chain', () => {
      const code = `
function handler(req, res) {
  const x = req.body.name
  const y = x.trim()
  db.query('SELECT * FROM users WHERE name = ' + y)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
    })

    it('traces 5-hop chain (at limit)', () => {
      const code = `
function handler(req, res) {
  const a = req.body.x
  const b = a
  const c = b
  const d = c
  const e = d
  db.query('SELECT * FROM t WHERE v = ' + e)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
    })

    it('rejects 6-hop chain (over limit)', () => {
      const code = `
function handler(req, res) {
  const a = req.body.x
  const b = a
  const c = b
  const d = c
  const e = d
  const f = e
  db.query('SELECT * FROM t WHERE v = ' + f)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBe(0)
    })

    it('does not flag hardcoded variable in sink', () => {
      const code = `
function handler(req, res) {
  const x = 'hardcoded'
  db.query('SELECT * FROM users WHERE name = ' + x)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBe(0)
    })
  })

  // === 5. Contract compliance tests ===

  describe('contract compliance', () => {
    it('every finding passes validateFinding()', () => {
      const code = `
function handler(req, res) {
  const name = req.body.name
  db.query('SELECT * FROM users WHERE name = ' + name)
  const cmd = req.query.cmd
  exec(cmd)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        const result = validateFinding(finding)
        expect(result.valid).toBe(true)
      }
    })

    it('sets category to Taint Analysis for all findings', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM users WHERE id = ' + id)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        expect(finding.category).toBe('Taint Analysis')
      }
    })

    it('sets file_path to the filePath argument', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM users WHERE id = ' + id)
}`
      const findings = analyzeTaint(code, 'api/users.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        expect(finding.file_path).toBe('api/users.js')
      }
    })

    it('sets line_number to a positive integer pointing to the sink line', () => {
      const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM users WHERE id = ' + id)
}`
      const findings = analyzeTaint(code, 'test.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        expect(finding.line_number).toBeGreaterThan(0)
        expect(Number.isInteger(finding.line_number)).toBe(true)
      }
    })
  })

  // === 6. Edge cases ===

  describe('edge cases', () => {
    it('returns empty array for empty content', () => {
      expect(analyzeTaint('', 'test.js')).toEqual([])
    })

    it('returns empty array for content with no sources', () => {
      const code = `
function handler(req, res) {
  const x = 'hello'
  res.json({ message: x })
}`
      expect(analyzeTaint(code, 'test.js')).toEqual([])
    })

    it('returns empty array for content with sources but no sinks', () => {
      const code = `
function handler(req, res) {
  const name = req.body.name
  console.log(name)
}`
      expect(analyzeTaint(code, 'test.js')).toEqual([])
    })

    it('returns empty array for content with sinks but no sources', () => {
      const code = `
function handler(req, res) {
  db.query('SELECT * FROM users WHERE id = 1')
}`
      expect(analyzeTaint(code, 'test.js')).toEqual([])
    })
  })

  // === Exported patterns ===

  describe('exported patterns', () => {
    it('exports SOURCE_PATTERNS as an array', () => {
      expect(Array.isArray(SOURCE_PATTERNS)).toBe(true)
      expect(SOURCE_PATTERNS.length).toBeGreaterThan(0)
    })

    it('exports SINK_PATTERNS as an array', () => {
      expect(Array.isArray(SINK_PATTERNS)).toBe(true)
      expect(SINK_PATTERNS.length).toBeGreaterThan(0)
    })

    it('exports SANITIZATION_PATTERNS as an array', () => {
      expect(Array.isArray(SANITIZATION_PATTERNS)).toBe(true)
      expect(SANITIZATION_PATTERNS.length).toBeGreaterThan(0)
    })
  })
})
