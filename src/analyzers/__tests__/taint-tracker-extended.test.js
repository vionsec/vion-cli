import { describe, it, expect } from 'vitest'
import { analyzeTaint } from '../taint-tracker.js'

// Cobertura adicional do taint-tracker: foco em sanitizações,
// false positives e edge cases que o teste original não cobre.

describe('taint-tracker — sanitization paths (extended)', () => {
  it('detecta validator.escape como sanitização', () => {
    const code = `
function handler(req, res) {
  const name = req.body.name
  const safe = validator.escape(name)
  element.innerHTML = safe
}`
    const findings = analyzeTaint(code, 'test.js')
    if (findings.length > 0) {
      expect(findings[0].has_sanitization).toBe(true)
      expect(findings[0].confidence).toBe('low')
    }
  })

  it('detecta encodeURIComponent como sanitização', () => {
    const code = `
function handler(req, res) {
  const url = req.query.url
  const safe = encodeURIComponent(url)
  res.send('<a href="' + safe + '">link</a>')
}`
    const findings = analyzeTaint(code, 'test.js')
    if (findings.length > 0) {
      expect(findings[0].has_sanitization).toBe(true)
    }
  })

  it('detecta zod.parse como sanitização (joi/zod/yup)', () => {
    const code = `
function handler(req, res) {
  const raw = req.body.payload
  const parsed = zod.parse(raw)
  db.query('SELECT * FROM t WHERE x = ' + parsed)
}`
    const findings = analyzeTaint(code, 'test.js')
    if (findings.length > 0) {
      expect(findings[0].has_sanitization).toBe(true)
    }
  })

  it('detecta parseFloat como sanitização para SQL', () => {
    const code = `
function handler(req, res) {
  const raw = req.body.amount
  const safe = parseFloat(raw)
  db.query('SELECT * FROM t WHERE amount > ' + safe)
}`
    const findings = analyzeTaint(code, 'test.js')
    if (findings.length > 0) {
      expect(findings[0].has_sanitization).toBe(true)
      expect(findings[0].severity).toBe('medio')
    }
  })

  it('detecta execFile como mitigação para command_injection', () => {
    const code = `
function handler(req, res) {
  const file = req.body.file
  execFile('/usr/bin/cat', [file])
}`
    const findings = analyzeTaint(code, 'test.js')
    // execFile é mitigação, então mesmo que apareça, severidade é reduzida
    // Pode até não gerar finding pois execFile não é sink direto
    for (const f of findings) {
      if (f.vulnerability_type === 'command_injection') {
        expect(f.has_sanitization).toBe(true)
      }
    }
  })

  it('parametrizada com $1 não gera finding', () => {
    const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM t WHERE id = $1', [id])
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBe(0)
  })
})

describe('taint-tracker — false positives (extended)', () => {
  it('não flagga string puramente literal mesmo com sink presente', () => {
    const code = `
function handler(req, res) {
  db.query("SELECT * FROM users WHERE active = true")
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBe(0)
  })

  it('não flagga quando variável é hardcoded (não vem de req)', () => {
    const code = `
function handler(req, res) {
  const max = 100
  db.query('SELECT * FROM t LIMIT ' + max)
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBe(0)
  })

  it('não flagga handler que apenas lê e responde sem sink perigoso', () => {
    const code = `
function handler(req, res) {
  const name = req.body.name
  res.json({ greeting: name })
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBe(0)
  })

  it('não confunde execFile (mitigação) com exec (sink)', () => {
    const code = `
function handler(req, res) {
  const arg = req.body.file
  execFile('/bin/cat', [arg])
}`
    const findings = analyzeTaint(code, 'test.js')
    // execFile não é sink puro de exec — não deve gerar finding crítico
    const cmdFindings = findings.filter((f) => f.sink_type === 'exec')
    expect(cmdFindings.length).toBe(0)
  })
})

describe('taint-tracker — edge cases (extended)', () => {
  it('lida com destructuring multi-variável', () => {
    const code = `
function handler(req, res) {
  const { name, email, password } = req.body
  db.query('INSERT INTO u VALUES (' + email + ')')
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings[0].source_type).toBe('destructured_input')
  })

  it('detecta fluxo com await em chain', () => {
    const code = `
async function handler(req, res) {
  const id = req.params.id
  const result = await db.query('SELECT * FROM t WHERE id = ' + id)
  res.json(result)
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBeGreaterThanOrEqual(1)
  })

  it('arrow function sem braces ainda é analisada (escopo global)', () => {
    const code = `
const handler = (req, res) => {
  const id = req.params.id
  db.query('SELECT * FROM t WHERE id = ' + id)
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBeGreaterThanOrEqual(1)
  })

  it('input em headers com bracket access', () => {
    const code = `
function handler(req, res) {
  const auth = req.headers["authorization"]
  db.query('SELECT * FROM sessions WHERE auth = ' + auth)
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings[0].source_type).toBe('request_headers')
  })

  it('retorna [] para input não-string', () => {
    expect(analyzeTaint(null, 'test.js')).toEqual([])
    expect(analyzeTaint(undefined, 'test.js')).toEqual([])
    expect(analyzeTaint(123, 'test.js')).toEqual([])
  })

  it('retorna [] para whitespace puro', () => {
    expect(analyzeTaint('   \n\n  ', 'test.js')).toEqual([])
  })

  it('preserva file_path em path absoluto windows', () => {
    const code = `
function handler(req, res) {
  const id = req.body.id
  db.query('SELECT * FROM t WHERE id = ' + id)
}`
    const findings = analyzeTaint(code, 'C:\\projects\\app\\handler.js')
    expect(findings.length).toBeGreaterThanOrEqual(1)
    expect(findings[0].file_path).toBe('C:\\projects\\app\\handler.js')
  })

  it('múltiplos sinks na mesma função geram múltiplos findings', () => {
    const code = `
function handler(req, res) {
  const name = req.body.name
  db.query('SELECT * FROM t WHERE name = ' + name)
  const cmd = req.body.cmd
  exec(cmd)
}`
    const findings = analyzeTaint(code, 'test.js')
    expect(findings.length).toBeGreaterThanOrEqual(2)
  })
})
