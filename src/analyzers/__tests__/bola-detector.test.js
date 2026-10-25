import { describe, it, expect } from 'vitest'
import { detectBOLA } from '../bola-detector.js'
import { validateFinding } from '../finding-schema.js'

describe('detectBOLA', () => {
  // === 1. Basic BOLA detection ===

  describe('basic BOLA detection', () => {
    it('detects req.params.id in .eq without user_id check', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('alto')
      expect(findings[0].confidence).toBe('high')
    })

    it('detects req.query.userId in raw SQL without user_id check', () => {
      const code = `
async function handler(req, res) {
  const userId = req.query.userId
  const result = db.query('SELECT * FROM orders WHERE id = ' + userId)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
    })
  })

  // === 2. Ownership validation (no finding) ===

  describe('ownership validation suppresses findings', () => {
    it('no finding when .eq user_id is present', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
    .eq('user_id', user.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBe(0)
    })

    it('no finding when WHERE user_id is present', () => {
      const code = `
async function handler(req, res) {
  const id = req.params.id
  db.query('SELECT * FROM orders WHERE id = $1 AND user_id = $2', [id, user.id])
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBe(0)
    })

    it('no finding when requireAuth middleware is referenced', () => {
      const code = `
const requireAuth = require('./middleware/auth')
async function handler(req, res) {
  requireAuth(req, res)
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBe(0)
    })
  })

  // === 3. Enumerable ID detection ===

  describe('enumerable ID detection', () => {
    it('assigns high confidence for parseInt ID without ownership', () => {
      const code = `
async function handler(req, res) {
  const id = parseInt(req.params.id)
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].confidence).toBe('high')
    })

    it('assigns high confidence for Number() coercion without ownership', () => {
      const code = `
async function handler(req, res) {
  const id = Number(req.query.id)
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].confidence).toBe('high')
    })
  })

  // === 4. UUID-based ID (lower confidence) ===

  describe('UUID-based ID access', () => {
    it('assigns medium confidence when UUID validation is present', () => {
      const code = `
async function handler(req, res) {
  const id = req.params.id
  if (!isUUID(id)) return res.status(400).json({ error: 'Invalid ID' })
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].confidence).toBe('medium')
    })
  })

  // === 5. Contract compliance ===

  describe('contract compliance', () => {
    it('every finding passes validateFinding()', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        const result = validateFinding(finding)
        expect(result.valid).toBe(true)
      }
    })

    it('sets category to BOLA/IDOR', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        expect(finding.category).toBe('BOLA/IDOR')
      }
    })

    it('sets file_path to the filePath argument', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        expect(finding.file_path).toBe('api/orders.js')
      }
    })

    it('sets line_number to a positive integer', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
    .eq('id', req.params.id)
}`
      const findings = detectBOLA(code, 'api/orders.js')
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
      expect(detectBOLA('', 'test.js')).toEqual([])
    })

    it('returns empty array for content with no ID extraction', () => {
      const code = `
async function handler(req, res) {
  const { data } = await supabase
    .from('orders')
    .select('*')
}`
      expect(detectBOLA(code, 'test.js')).toEqual([])
    })

    it('returns empty array for content with ID extraction but no DB query', () => {
      const code = `
async function handler(req, res) {
  const id = req.params.id
  console.log(id)
}`
      expect(detectBOLA(code, 'test.js')).toEqual([])
    })
  })
})
