import { describe, it, expect } from 'vitest'
import { analyzeCrypto } from '../analyzers/crypto-analyzer.js'
import { validateFinding } from '../finding-schema.js'

describe('analyzeCrypto', () => {
  // === SCAN-05: Detection ===

  describe('JS/TS detection', () => {
    it('detects crypto.createHash("md5")', () => {
      const code = `const hash = crypto.createHash('md5')`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'MD5')).toBe(true)
    })

    it('detects crypto.createHash("sha1")', () => {
      const code = `const hash = crypto.createHash('sha1')`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'SHA1')).toBe(true)
    })

    it('detects crypto.createCipher("des", key)', () => {
      const code = `const cipher = crypto.createCipher('des', key)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'DES')).toBe(true)
    })

    it('detects crypto.createCipher("rc4", key)', () => {
      const code = `const cipher = crypto.createCipher('rc4', key)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'RC4')).toBe(true)
    })

    it('detects CryptoJS.MD5()', () => {
      const code = `const hash = CryptoJS.MD5(data)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'MD5')).toBe(true)
    })

    it('detects CryptoJS.SHA1()', () => {
      const code = `const hash = CryptoJS.SHA1(data)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'SHA1')).toBe(true)
    })

    it('detects subtle.digest("SHA-1", ...)', () => {
      const code = `const hash = await subtle.digest('SHA-1', buffer)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'SHA1')).toBe(true)
    })

    it('detects crypto.createHmac("md5", ...)', () => {
      const code = `const hmac = crypto.createHmac('md5', secret)`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm.includes('MD5'))).toBe(true)
    })

    it('detects forge.md5.create()', () => {
      const code = `const md = forge.md5.create()`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'MD5')).toBe(true)
    })
  })

  describe('Python detection', () => {
    it('detects hashlib.md5()', () => {
      const code = `h = hashlib.md5(data)`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'MD5')).toBe(true)
    })

    it('detects hashlib.sha1()', () => {
      const code = `h = hashlib.sha1(data)`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'SHA1')).toBe(true)
    })

    it('detects hashlib.new("sha1")', () => {
      const code = `h = hashlib.new('sha1')`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'SHA1')).toBe(true)
    })

    it('detects from Crypto.Cipher import DES', () => {
      const code = `from Crypto.Cipher import DES`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'DES')).toBe(true)
    })

    it('detects DES.new(...)', () => {
      const code = `cipher = DES.new(key, DES.MODE_ECB)`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm === 'DES')).toBe(true)
    })

    it('detects hmac.new(..., "md5")', () => {
      const code = `h = hmac.new(key, msg, 'md5')`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.algorithm.includes('MD5'))).toBe(true)
    })
  })

  it('returns empty array for safe algorithms (sha256, aes)', () => {
    const code = `
      const hash = crypto.createHash('sha256')
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
      const h2 = crypto.createHash('sha512')
    `
    const findings = analyzeCrypto(code, 'file.js')
    expect(findings).toEqual([])
  })

  it('detects multiple algorithms in one file', () => {
    const code = `
      const h1 = crypto.createHash('md5')
      const h2 = crypto.createHash('sha1')
      const c1 = crypto.createCipher('des', key)
    `
    const findings = analyzeCrypto(code, 'file.js')
    expect(findings.length).toBeGreaterThanOrEqual(3)
    const algos = findings.map(f => f.algorithm)
    expect(algos).toContain('MD5')
    expect(algos).toContain('SHA1')
    expect(algos).toContain('DES')
  })

  // === SCAN-06: Context classification ===

  describe('context classification', () => {
    it('classifies as critico when near password keyword', () => {
      const code = `
        const password = req.body.password
        const hash = crypto.createHash('md5')
        hash.update(password)
      `
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies as critico when near token/jwt keyword', () => {
      const code = `
        const token = jwt.sign(payload)
        const hash = crypto.createHash('sha1')
        hash.update(token)
      `
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies as critico when file path contains auth/', () => {
      const code = `const hash = crypto.createHash('md5')`
      const findings = analyzeCrypto(code, 'src/auth/hash.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('critico')
    })

    it('classifies as medio for MD5/SHA1 hash without auth context', () => {
      const code = `const checksum = crypto.createHash('md5')`
      const findings = analyzeCrypto(code, 'utils/checksum.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('medio')
    })

    it('classifies as alto for DES/RC4 cipher without auth context', () => {
      const code = `const cipher = crypto.createCipher('des', key)`
      const findings = analyzeCrypto(code, 'utils/legacy.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings[0].severity).toBe('alto')
    })

    it('sets context to "auth" for auth-context findings', () => {
      const code = `
        const password = req.body.password
        const hash = crypto.createHash('md5')
      `
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings[0].context).toBe('auth')
    })

    it('sets context to "legacy" for non-auth findings', () => {
      const code = `const checksum = crypto.createHash('md5')`
      const findings = analyzeCrypto(code, 'utils/checksum.js')
      expect(findings[0].context).toBe('legacy')
    })
  })

  // === False positive avoidance ===

  describe('false positive avoidance', () => {
    it('skips matches inside JS single-line comments', () => {
      const code = `// const hash = crypto.createHash('md5')`
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings).toEqual([])
    })

    it('skips matches inside JS block comments', () => {
      const code = `
        /*
         * const hash = crypto.createHash('md5')
         */
      `
      const findings = analyzeCrypto(code, 'file.js')
      expect(findings).toEqual([])
    })

    it('skips matches inside Python comments (#)', () => {
      const code = `# h = hashlib.md5(data)`
      const findings = analyzeCrypto(code, 'file.py')
      expect(findings).toEqual([])
    })
  })

  // === Finding contract compliance ===

  describe('finding contract', () => {
    const sampleCode = `
      const hash = crypto.createHash('md5')
      const cipher = crypto.createCipher('des', key)
    `

    it('all findings pass validateFinding()', () => {
      const findings = analyzeCrypto(sampleCode, 'file.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      for (const finding of findings) {
        const result = validateFinding(finding)
        expect(result.valid).toBe(true)
      }
    })

    it('each finding has algorithm field', () => {
      const findings = analyzeCrypto(sampleCode, 'file.js')
      for (const finding of findings) {
        expect(finding.algorithm).toBeDefined()
        expect(typeof finding.algorithm).toBe('string')
      }
    })

    it('each finding has context field', () => {
      const findings = analyzeCrypto(sampleCode, 'file.js')
      for (const finding of findings) {
        expect(finding.context).toBeDefined()
        expect(typeof finding.context).toBe('string')
      }
    })

    it('each finding has category "Cryptography"', () => {
      const findings = analyzeCrypto(sampleCode, 'file.js')
      for (const finding of findings) {
        expect(finding.category).toBe('Cryptography')
      }
    })

    it('each finding has file_path and line_number', () => {
      const findings = analyzeCrypto(sampleCode, 'file.js')
      for (const finding of findings) {
        expect(finding.file_path).toBeDefined()
        expect(finding.line_number).toBeDefined()
        expect(typeof finding.line_number).toBe('number')
        expect(finding.line_number).toBeGreaterThan(0)
      }
    })
  })
})
