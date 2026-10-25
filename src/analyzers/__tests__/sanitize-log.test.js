import { describe, it, expect } from 'vitest'
import { redact, safeBodyPreview } from '../sanitize-log.js'

describe('redact', () => {
  it('redacta password no objeto', () => {
    const result = redact({ user: 'foo', password: 'p4ssw0rd!' })
    expect(result.password).toBe('[REDACTED]')
    expect(result.user).toBe('foo')
  })

  it('redacta token, api_key, secret no mesmo objeto', () => {
    const result = redact({
      token: 'eyJhb',
      api_key: 'vion_abc',
      secret: 'shh',
      apiKey: 'camelCase',
    })
    expect(result.token).toBe('[REDACTED]')
    expect(result.api_key).toBe('[REDACTED]')
    expect(result.secret).toBe('[REDACTED]')
    expect(result.apiKey).toBe('[REDACTED]')
  })

  it('redacta authorization e bearer', () => {
    const result = redact({ authorization: 'Bearer abc', bearer: 'def' })
    expect(result.authorization).toBe('[REDACTED]')
    expect(result.bearer).toBe('[REDACTED]')
  })

  it('redacta CPF/CNPJ', () => {
    const result = redact({ cpf: '123.456.789-00', cnpj: '12.345.678/0001-99' })
    expect(result.cpf).toBe('[REDACTED]')
    expect(result.cnpj).toBe('[REDACTED]')
  })

  it('redacta CVV/CVC e credit fields', () => {
    const result = redact({ cvv: '123', cvc: '456', credit_card: '4111-1111-1111-1111' })
    expect(result.cvv).toBe('[REDACTED]')
    expect(result.cvc).toBe('[REDACTED]')
    expect(result.credit_card).toBe('[REDACTED]')
  })

  it('redacta recursivamente em objetos aninhados', () => {
    const result = redact({
      user: {
        name: 'João',
        password: 'segredo',
        nested: { token: 'xyz' },
      },
    })
    expect(result.user.name).toBe('João')
    expect(result.user.password).toBe('[REDACTED]')
    expect(result.user.nested.token).toBe('[REDACTED]')
  })

  it('redacta dentro de arrays', () => {
    const result = redact({
      users: [
        { name: 'a', password: 'p1' },
        { name: 'b', password: 'p2' },
      ],
    })
    expect(result.users[0].password).toBe('[REDACTED]')
    expect(result.users[1].password).toBe('[REDACTED]')
    expect(result.users[0].name).toBe('a')
  })

  it('preserva valores não-sensíveis intactos', () => {
    const input = { name: 'foo', age: 30, active: true, score: 99.5 }
    const result = redact(input)
    expect(result).toEqual(input)
  })

  it('retorna null para null', () => {
    expect(redact(null)).toBeNull()
  })

  it('retorna undefined para undefined', () => {
    expect(redact(undefined)).toBeUndefined()
  })

  it('retorna primitivos sem alteração', () => {
    expect(redact(42)).toBe(42)
    expect(redact('hello')).toBe('hello')
    expect(redact(true)).toBe(true)
  })

  it('limita profundidade para evitar recursão infinita', () => {
    const obj = {}
    let cur = obj
    for (let i = 0; i < 10; i++) {
      cur.next = { password: 'x' }
      cur = cur.next
    }
    expect(() => redact(obj)).not.toThrow()
  })

  it('case-insensitive: PASSWORD em maiúsculas é redactado', () => {
    const result = redact({ PASSWORD: 'x', Token: 'y' })
    expect(result.PASSWORD).toBe('[REDACTED]')
    expect(result.Token).toBe('[REDACTED]')
  })

  it('redacta jwt, refresh, session', () => {
    const result = redact({ jwt: 'a.b.c', refresh_token: 'r', session_id: 's' })
    expect(result.jwt).toBe('[REDACTED]')
    expect(result.refresh_token).toBe('[REDACTED]')
    expect(result.session_id).toBe('[REDACTED]')
  })
})

describe('safeBodyPreview', () => {
  it('retorna null para body null', () => {
    expect(safeBodyPreview(null)).toBeNull()
  })

  it('retorna null para body undefined', () => {
    expect(safeBodyPreview(undefined)).toBeNull()
  })

  it('serializa objeto JSON e redacta password', () => {
    const result = safeBodyPreview({ user: 'foo', password: 'segredo' })
    expect(result).toContain('foo')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('segredo')
  })

  it('mascara substrings que parecem credenciais em string crua', () => {
    const result = safeBodyPreview('username=foo&password=segredo123&age=30')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('segredo123')
  })

  it('mascara JSON-like string com password', () => {
    const result = safeBodyPreview('{"password": "p1", "user": "joao"}')
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('p1')
  })

  it('respeita maxLen e trunca', () => {
    const big = { data: 'x'.repeat(2000) }
    const result = safeBodyPreview(big, 100)
    expect(result.length).toBeLessThanOrEqual(100)
  })

  it('usa default maxLen=500 se não passado', () => {
    const big = { data: 'x'.repeat(2000) }
    const result = safeBodyPreview(big)
    expect(result.length).toBeLessThanOrEqual(500)
  })

  it('retorna [unparseable] quando JSON.stringify falha (referência circular)', () => {
    const circular = {}
    circular.self = circular
    const result = safeBodyPreview(circular)
    expect(result).toBe('[unparseable]')
  })

  it('preserva campos não-sensíveis no preview', () => {
    const result = safeBodyPreview({ email: 'user@example.com', plan: 'pro' })
    expect(result).toContain('plan')
    expect(result).toContain('pro')
  })

  it('redacta token em form-encoded string', () => {
    const result = safeBodyPreview('action=login&token=abc123xyz&debug=true')
    expect(result).not.toContain('abc123xyz')
    expect(result).toContain('[REDACTED]')
  })

  it('redacta api_key em form-encoded string', () => {
    const result = safeBodyPreview('a=1&api_key=vion_secret_key&b=2')
    expect(result).not.toContain('vion_secret_key')
    expect(result).toContain('[REDACTED]')
  })

  it('serializa array como JSON', () => {
    const result = safeBodyPreview([{ password: 'p' }, { token: 't' }])
    expect(result).toContain('[REDACTED]')
    expect(result).not.toContain('"p"')
    expect(result).not.toContain('"t"')
  })
})
