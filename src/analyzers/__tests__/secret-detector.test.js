import { describe, it, expect } from 'vitest'
import { detectSecrets, SECRET_PATTERNS } from '../secret-detector.js'
import { validateFinding } from '../finding-schema.js'
import {
  FAKE_AWS_KEY,
  FAKE_RSA_HEADER,
  FAKE_EC_HEADER,
  FAKE_PK_HEADER,
  FAKE_JWT_TOKEN,
  FAKE_API_KEY,
  FAKE_PASSWORD,
  FAKE_SECRET,
  FAKE_TOKEN,
  FAKE_ENV_API_KEY,
  FAKE_ENV_AWS_SECRET,
  FAKE_ENV_PASSWORD,
} from './fixtures/secret-detector-fixtures.js'

describe('secret-detector', () => {
  describe('SECRET_PATTERNS export', () => {
    it('exports an array of pattern objects', () => {
      expect(Array.isArray(SECRET_PATTERNS)).toBe(true)
      expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(6)
    })

    it('each pattern has id, name, regex, severity, and confidence fields', () => {
      for (const pattern of SECRET_PATTERNS) {
        expect(pattern).toHaveProperty('id')
        expect(pattern).toHaveProperty('name')
        expect(pattern).toHaveProperty('regex')
        expect(pattern).toHaveProperty('severity')
        expect(pattern).toHaveProperty('confidence')
        expect(pattern.regex).toBeInstanceOf(RegExp)
      }
    })
  })

  describe('AWS access keys', () => {
    it('detects AKIA key in source code', () => {
      const content = `const key = "${FAKE_AWS_KEY}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.length).toBeGreaterThanOrEqual(1)
      expect(findings.some(f => f.title === 'AWS Access Key')).toBe(true)
    })

    it('returns finding with severity critico and confidence high', () => {
      const content = `AWS_KEY=${FAKE_AWS_KEY}`
      const findings = detectSecrets(content, 'env.js')
      const awsFinding = findings.find(f => f.title === 'AWS Access Key')
      expect(awsFinding).toBeDefined()
      expect(awsFinding.severity).toBe('critico')
      expect(awsFinding.confidence).toBe('high')
    })

    it('returns correct line_number and code_snippet', () => {
      const content = `line1\nline2\nconst k = "${FAKE_AWS_KEY}"\nline4`
      const findings = detectSecrets(content, 'test.js')
      const awsFinding = findings.find(f => f.title === 'AWS Access Key')
      expect(awsFinding.line_number).toBe(3)
      expect(awsFinding.code_snippet).toBe(`const k = "${FAKE_AWS_KEY}"`)
    })
  })

  describe('private keys', () => {
    it('detects RSA private key header', () => {
      const content = FAKE_RSA_HEADER
      const findings = detectSecrets(content, 'key.pem')
      expect(findings.some(f => f.title === 'Private Key')).toBe(true)
    })

    it('detects EC private key header', () => {
      const content = FAKE_EC_HEADER
      const findings = detectSecrets(content, 'key.pem')
      expect(findings.some(f => f.title === 'Private Key')).toBe(true)
    })

    it('detects generic private key header', () => {
      const content = FAKE_PK_HEADER
      const findings = detectSecrets(content, 'key.pem')
      expect(findings.some(f => f.title === 'Private Key')).toBe(true)
      expect(findings[0].confidence).toBe('high')
    })
  })

  describe('JWT tokens', () => {
    it('detects JWT token pattern', () => {
      const content = `const token = "${FAKE_JWT_TOKEN}"`
      const findings = detectSecrets(content, 'auth.js')
      expect(findings.some(f => f.title === 'JWT Token')).toBe(true)
    })

    it('returns confidence medium for JWT', () => {
      const content = FAKE_JWT_TOKEN
      const findings = detectSecrets(content, 'auth.js')
      const jwt = findings.find(f => f.title === 'JWT Token')
      expect(jwt.confidence).toBe('medium')
    })
  })

  describe('generic API keys', () => {
    it('detects api_key = "..." assignment', () => {
      const content = `api_key = "FAKE_${FAKE_API_KEY}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'API Key Assignment')).toBe(true)
    })

    it('detects api-key: "..." YAML style', () => {
      const content = `api-key: "FAKE_${FAKE_API_KEY}"`
      const findings = detectSecrets(content, 'config.yml')
      expect(findings.some(f => f.title === 'API Key Assignment')).toBe(true)
    })

    it('does not flag short values under 10 chars', () => {
      const content = 'api_key = "short"'
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'API Key Assignment')).toBe(false)
    })
  })

  describe('generic secrets', () => {
    it('detects password = "..." assignment', () => {
      const content = `password = "${FAKE_PASSWORD}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'Generic Secret')).toBe(true)
    })

    it('detects secret = "..." assignment', () => {
      const content = `secret = "${FAKE_SECRET}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'Generic Secret')).toBe(true)
    })

    it('detects token = "..." assignment', () => {
      const content = `token = "${FAKE_TOKEN}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'Generic Secret')).toBe(true)
    })

    it('does not flag short values under 8 chars', () => {
      const content = 'password = "short"'
      const findings = detectSecrets(content, 'config.js')
      expect(findings.some(f => f.title === 'Generic Secret')).toBe(false)
    })
  })

  describe('environment variable patterns', () => {
    it('detects API_KEY=long_value in env file', () => {
      const content = `API_KEY=${FAKE_ENV_API_KEY}`
      const findings = detectSecrets(content, '.env')
      expect(findings.some(f => f.title === 'Env Var Secret')).toBe(true)
    })

    it('detects AWS_SECRET=long_value', () => {
      const content = `AWS_SECRET=${FAKE_ENV_AWS_SECRET}`
      const findings = detectSecrets(content, '.env')
      expect(findings.some(f => f.title === 'Env Var Secret')).toBe(true)
    })

    it('detects PASSWORD=long_value', () => {
      const content = `PASSWORD=${FAKE_ENV_PASSWORD}`
      const findings = detectSecrets(content, '.env')
      expect(findings.some(f => f.title === 'Env Var Secret')).toBe(true)
    })
  })

  describe('comment filtering', () => {
    it('ignores lines starting with #', () => {
      const content = `# API_KEY=${FAKE_ENV_API_KEY}`
      const findings = detectSecrets(content, '.env')
      expect(findings.length).toBe(0)
    })

    it('ignores lines starting with //', () => {
      const content = `// const key = "${FAKE_AWS_KEY}"`
      const findings = detectSecrets(content, 'config.js')
      expect(findings.length).toBe(0)
    })

    it('ignores secrets inside /* */ block comments', () => {
      const content = [
        '/* config block',
        `api_key = "FAKE_${FAKE_API_KEY}"`,
        `password = "${FAKE_PASSWORD}"`,
        '*/',
        'const clean = true',
      ].join('\n')
      const findings = detectSecrets(content, 'config.js')
      expect(findings.length).toBe(0)
    })
  })

  describe('finding contract compliance', () => {
    const multiSecretFixture = [
      'const config = {',
      `  api_key: "FAKE_${FAKE_API_KEY}",`,
      `  aws_key: "${FAKE_AWS_KEY}",`,
      `  password: "${FAKE_PASSWORD}",`,
      '}',
      '// api_key: "FAKE_this_should_be_ignored"',
    ].join('\n')

    it('every finding from multi-secret fixture passes validateFinding()', () => {
      const findings = detectSecrets(multiSecretFixture, 'config.js')
      expect(findings.length).toBeGreaterThanOrEqual(3)
      for (const finding of findings) {
        const result = validateFinding(finding)
        expect(result.valid).toBe(true)
      }
    })

    it('all findings have category Hardcoded Secrets', () => {
      const findings = detectSecrets(multiSecretFixture, 'config.js')
      for (const finding of findings) {
        expect(finding.category).toBe('Hardcoded Secrets')
      }
    })

    it('all findings have severity critico', () => {
      const findings = detectSecrets(multiSecretFixture, 'config.js')
      for (const finding of findings) {
        expect(finding.severity).toBe('critico')
      }
    })

    it('all findings include file_path from argument', () => {
      const findings = detectSecrets(multiSecretFixture, 'config.js')
      for (const finding of findings) {
        expect(finding.file_path).toBe('config.js')
      }
    })
  })

  describe('edge cases', () => {
    it('returns empty array for clean content', () => {
      const content = 'const x = 42\nfunction hello() { return "world" }'
      const findings = detectSecrets(content, 'clean.js')
      expect(findings).toEqual([])
    })

    it('returns empty array for empty string', () => {
      const findings = detectSecrets('', 'empty.js')
      expect(findings).toEqual([])
    })

    it('handles multiple secrets on different lines', () => {
      const content = [
        `const a = "${FAKE_AWS_KEY}"`,
        'const b = "clean line"',
        FAKE_RSA_HEADER,
      ].join('\n')
      const findings = detectSecrets(content, 'multi.js')
      expect(findings.length).toBeGreaterThanOrEqual(2)
    })

    it('returns correct line numbers for each finding', () => {
      const content = [
        'line1',
        FAKE_AWS_KEY,
        'line3',
        FAKE_PK_HEADER,
      ].join('\n')
      const findings = detectSecrets(content, 'test.js')
      const awsFinding = findings.find(f => f.title === 'AWS Access Key')
      const pkFinding = findings.find(f => f.title === 'Private Key')
      expect(awsFinding.line_number).toBe(2)
      expect(pkFinding.line_number).toBe(4)
    })
  })
})
