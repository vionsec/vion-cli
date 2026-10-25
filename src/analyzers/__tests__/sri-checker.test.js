import { describe, it, expect } from 'vitest'
import { checkSRI, computeSRIHash, verifySRI, parseSRIHashes, validateSRIFormat } from '../sri-checker.js'
import { validateFinding } from '../finding-schema.js'

describe('checkSRI', () => {
  describe('missing SRI detection (SCAN-07)', () => {
    it('flags external script without integrity attribute', () => {
      const html = '<script src="https://cdn.example.com/lib.js"></script>'
      const findings = checkSRI(html)
      expect(findings).toHaveLength(1)
      expect(findings[0].severity).toBe('alto')
      expect(findings[0].category).toBe('Integrity')
      expect(findings[0].confidence).toBe('high')
    })

    it('flags external stylesheet without integrity', () => {
      const html = '<link rel="stylesheet" href="https://cdn.example.com/style.css">'
      const findings = checkSRI(html)
      expect(findings).toHaveLength(1)
      expect(findings[0].severity).toBe('alto')
    })

    it('does not flag same-origin scripts', () => {
      const html = '<script src="/assets/bundle.js"></script>'
      expect(checkSRI(html)).toEqual([])
    })

    it('does not flag inline scripts', () => {
      const html = '<script>console.log("hello")</script>'
      expect(checkSRI(html)).toEqual([])
    })

    it('does not flag scripts with valid integrity', () => {
      const html = '<script src="https://cdn.example.com/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'
      expect(checkSRI(html)).toEqual([])
    })

    it('does not flag link tags with rel="icon"', () => {
      const html = '<link rel="icon" href="https://cdn.example.com/favicon.ico">'
      expect(checkSRI(html)).toEqual([])
    })

    it('flags multiple external scripts without SRI', () => {
      const html = `
        <script src="https://cdn.example.com/a.js"></script>
        <script src="https://cdn.example.com/b.js"></script>
        <script src="https://cdn.example.com/c.js"></script>
      `
      const findings = checkSRI(html)
      expect(findings).toHaveLength(3)
    })
  })

  describe('hash validation (SCAN-08)', () => {
    it('accepts valid sha256 hash format', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" crossorigin="anonymous"></script>'
      const findings = checkSRI(html)
      expect(findings).toEqual([])
    })

    it('accepts valid sha384 hash format', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'
      expect(checkSRI(html)).toEqual([])
    })

    it('accepts valid sha512 hash format', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha512-7iaw3Ur350mqGo7jwQrpkj9hiYB3Lkc/iBml1JQODbJ6wYX4oOHV+E+IvIh/1nsUNzLDBMxfqa2Ob1f1ACio/w==" crossorigin="anonymous"></script>'
      expect(checkSRI(html)).toEqual([])
    })

    it('flags invalid algorithm (sha1 not allowed for SRI)', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha1-abc123" crossorigin="anonymous"></script>'
      const findings = checkSRI(html)
      expect(findings.length).toBeGreaterThan(0)
      expect(findings[0].title).toMatch(/invalido|invalid/i)
      expect(findings[0].severity).toBe('medio')
    })

    it('flags malformed base64 hash', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha384-!!invalid!!" crossorigin="anonymous"></script>'
      const findings = checkSRI(html)
      expect(findings.length).toBeGreaterThan(0)
    })

    it('flags hash length mismatch for declared algorithm', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha384-dG9vc2hvcnQ=" crossorigin="anonymous"></script>'
      const findings = checkSRI(html)
      expect(findings.length).toBeGreaterThan(0)
    })

    it('accepts multiple hash algorithms in one integrity attribute', () => {
      const html = '<script src="https://example.com/x.js" integrity="sha256-K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols= sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" crossorigin="anonymous"></script>'
      const missingSRI = checkSRI(html).filter(f => f.title.includes('sem SRI'))
      expect(missingSRI).toHaveLength(0)
    })
  })

  describe('hash computation (SCAN-08)', () => {
    it('computeSRIHash returns correctly formatted hash string', () => {
      const content = 'console.log("hello")'
      const hash = computeSRIHash(content, 'sha384')
      expect(hash).toMatch(/^sha384-[A-Za-z0-9+/]+=*$/)
    })

    it('verifySRI returns valid for matching hash', () => {
      const content = 'test content'
      const hash = computeSRIHash(content, 'sha256')
      const result = verifySRI(content, hash)
      expect(result.valid).toBe(true)
    })

    it('verifySRI returns invalid for mismatching hash', () => {
      const result = verifySRI('real content', 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
      expect(result.valid).toBe(false)
    })
  })

  describe('crossorigin attribute', () => {
    it('flags missing crossorigin on SRI-protected external tag', () => {
      const html = '<script src="https://cdn.example.com/lib.js" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"></script>'
      const findings = checkSRI(html)
      expect(findings).toHaveLength(1)
      expect(findings[0].severity).toBe('baixo')
      expect(findings[0].confidence).toBe('medium')
    })
  })

  describe('finding contract compliance', () => {
    it('all findings pass validateFinding()', () => {
      const html = `
        <script src="https://cdn.example.com/a.js"></script>
        <script src="https://cdn.example.com/b.js" integrity="sha1-bad" crossorigin="anonymous"></script>
        <link rel="stylesheet" href="https://cdn.example.com/style.css">
      `
      const findings = checkSRI(html)
      expect(findings.length).toBeGreaterThan(0)
      for (const f of findings) {
        const result = validateFinding(f)
        expect(result.valid, `Finding failed validation: ${JSON.stringify(result.errors)} for ${JSON.stringify(f)}`).toBe(true)
      }
    })
  })
})

describe('parseSRIHashes', () => {
  it('parses single hash', () => {
    const result = parseSRIHashes('sha384-abc123')
    expect(result).toHaveLength(1)
    expect(result[0].algorithm).toBe('sha384')
    expect(result[0].hash).toBe('abc123')
  })

  it('parses multiple hashes', () => {
    const result = parseSRIHashes('sha256-aaa= sha384-bbb=')
    expect(result).toHaveLength(2)
  })

  it('returns empty array for empty input', () => {
    expect(parseSRIHashes('')).toEqual([])
    expect(parseSRIHashes(null)).toEqual([])
  })
})

describe('validateSRIFormat', () => {
  it('validates correct sha384 hash', () => {
    const result = validateSRIFormat('sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC')
    expect(result.valid).toBe(true)
  })

  it('rejects invalid algorithm', () => {
    const result = validateSRIFormat('md5-abc123')
    expect(result.valid).toBe(false)
  })

  it('rejects malformed base64', () => {
    const result = validateSRIFormat('sha256-!!invalid!!')
    expect(result.valid).toBe(false)
  })
})
