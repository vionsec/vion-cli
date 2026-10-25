import { describe, it, expect, beforeAll } from 'vitest'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'vion-test-'))
process.env.VION_HOME = HOME
delete process.env.VION_AUDIT_ID

const FIXTURE = path.resolve('tests/fixtures/vuln-app')
let scope, redact, store, hook, server, install, engine

beforeAll(async () => {
  scope = await import('../src/core/scope.js')
  redact = await import('../src/core/redact.js')
  store = await import('../src/core/store.js')
  hook = await import('../src/hooks/pretooluse.js')
  server = await import('../src/server/server.js')
  install = await import('../src/core/install.js')
  engine = await import('../src/core/engine.js')
})

describe('escopo', () => {
  it('normaliza diretorio local', () => {
    const s = scope.normalizeScope({ target: FIXTURE })
    expect(s.targetType).toBe('path')
    expect(s.paths).toEqual([FIXTURE])
    expect(s.active).toBe(false)
  })
  it('recusa raiz do disco e diretorio inexistente', () => {
    expect(() => scope.normalizeScope({ target: path.parse(FIXTURE).root })).toThrow(/raiz/)
    expect(() => scope.normalizeScope({ target: path.join(FIXTURE, 'nao-existe') })).toThrow(/nao existe/)
  })
  it('exige autorizacao para alvo de rede e teste ativo', () => {
    expect(() => scope.normalizeScope({ target: 'https://staging.exemplo.com' })).toThrow(/autorizacao/)
    expect(() => scope.normalizeScope({ target: FIXTURE, active: true })).toThrow(/autorizacao/)
    const s = scope.normalizeScope({ target: 'https://staging.exemplo.com', authorization: { statement: 'dono do dominio, autorizado hoje' } })
    expect(s.hosts).toEqual(['staging.exemplo.com'])
  })
  it('recusa curingas e CIDRs amplos demais', () => {
    const auth = { statement: 'autorizado pelo responsavel' }
    expect(() => scope.normalizeScope({ target: FIXTURE, hosts: ['*.com'], authorization: auth })).toThrow(/amplo/)
    expect(() => scope.normalizeScope({ target: FIXTURE, cidrs: ['10.0.0.0/8'], authorization: auth })).toThrow(/amplo/)
  })
  it('hostAllowed respeita host exato, curinga, CIDR e loopback', () => {
    const s = scope.normalizeScope({ target: FIXTURE, hosts: ['app.ex.com', '*.api.ex.com'], cidrs: ['192.168.10.0/24'], authorization: { statement: 'autorizado pelo responsavel' } })
    expect(scope.hostAllowed(s, 'app.ex.com')).toBe(true)
    expect(scope.hostAllowed(s, 'v1.api.ex.com')).toBe(true)
    expect(scope.hostAllowed(s, 'api.ex.com')).toBe(false)
    expect(scope.hostAllowed(s, 'evil.com')).toBe(false)
    expect(scope.hostAllowed(s, '192.168.10.77')).toBe(true)
    expect(scope.hostAllowed(s, '192.168.11.1')).toBe(false)
    expect(scope.hostAllowed(s, 'localhost')).toBe(true)
  })
  it('pathAllowed bloqueia saida por ..', () => {
    const s = scope.normalizeScope({ target: FIXTURE })
    expect(scope.pathAllowed(s, path.join(FIXTURE, 'src', 'server.js'))).toBe(true)
    expect(scope.pathAllowed(s, path.join(FIXTURE, '..', '..', 'package.json'))).toBe(false)
  })
})

describe('redacao', () => {
  it('mascara segredos por valor e por chave', () => {
    const t = redact.redactText('Authorization: Bearer abcdefghijklmnop token=supersecretvalue AKIAABCDEFGHIJKLMNOP postgres://u:senha123@db:5432/x')
    expect(t).not.toContain('supersecretvalue')
    expect(t).not.toContain('AKIAABCDEFGHIJKLMNOP')
    expect(t).not.toContain('senha123')
    expect(t).toContain('[REDACTED]')
  })
  it('redactDeep mascara chaves sensiveis', () => {
    expect(redact.redactDeep({ password: 'x', nested: { api_key: 'y', ok: 'z' } })).toEqual({ password: '[REDACTED]', nested: { api_key: '[REDACTED]', ok: 'z' } })
  })
})

describe('store', () => {
  let audit
  beforeAll(() => {
    audit = engine.startAudit({ scopeInput: { target: FIXTURE }, origin: 'cli', skills: ['auditoria'] })
    store.updateAudit(audit.id, { status: 'running' })
  })
  it('todo finding nasce suspeito e severidade PT e normalizada', () => {
    const f = store.addFinding(audit.id, { title: 'SQLi', description: 'x', severity: 'critico', file_path: 'src/server.js', line: 11, cwe: '89' }, { agent: 't' })
    expect(f.status).toBe('suspected')
    expect(f.severity).toBe('critical')
    expect(f.cwe).toBe('CWE-89')
  })
  it('nao confirma sem evidencia nem sem validation_method', () => {
    const f = store.addFinding(audit.id, { title: 'XSS', description: 'x', severity: 'high', file_path: 'src/server.js', line: 16, cwe: 'CWE-79' }, { agent: 't' })
    expect(() => store.updateFinding(f.id, { status: 'confirmed', validation_method: 'li' })).toThrow(/evidencia/)
    store.addEvidence(audit.id, { finding_id: f.id, kind: 'code', title: 'trecho', content: 'res.send(q)' })
    expect(() => store.updateFinding(f.id, { status: 'confirmed' })).toThrow(/validation_method/)
    expect(store.updateFinding(f.id, { status: 'confirmed', validation_method: 'source->sink' }).status).toBe('confirmed')
  })
  it('detecta duplicata pelo fingerprint e correlate escolhe o primario confirmado', () => {
    const dup = store.addFinding(audit.id, { title: 'Reflected XSS', description: 'y', severity: 'medium', file_path: './src/server.js', line: 17, cwe: '79' }, { agent: 'outro' })
    expect(dup.duplicate_of).toBeTruthy()
    const res = store.correlate(audit.id)
    expect(res.conflicts).toEqual([])
    const primary = store.getFinding(dup.duplicate_of)
    expect(primary.status).toBe('confirmed')
  })
  it('evidencia de outra auditoria e recusada e conteudo e redigido', () => {
    const other = engine.startAudit({ scopeInput: { target: FIXTURE }, origin: 'cli' })
    const f = store.addFinding(other.id, { title: 'abc', description: 'abc', severity: 'low' }, { agent: 't' })
    expect(() => store.addEvidence(audit.id, { finding_id: f.id, kind: 'note', title: 'x', content: 'x' })).toThrow(/nao pertence/)
    const e = store.addEvidence(audit.id, { kind: 'http', title: 'resp', content: 'Set-Cookie: session=abcdef123456789' })
    const read = store.readEvidence(e.id)
    expect(read.intact).toBe(true)
    expect(read.content).not.toContain('abcdef123456789')
  })
  it('finaliza com score e relatorios', () => {
    const res = engine.finalizeAudit(audit.id, { summary: 'teste' })
    expect(res.status).toBe('completed')
    for (const f of Object.values(res.reports)) expect(fs.existsSync(f)).toBe(true)
  })
})

describe('hook de escopo', () => {
  const s = () => scope.normalizeScope({ target: FIXTURE, hosts: ['app.ex.com'], authorization: { statement: 'autorizado pelo responsavel' } })
  const audit = () => ({ id: 'a_test', scope: s() })
  it('extrai hosts de comandos', () => {
    expect(hook.hostsInCommand('curl -s https://evil.com/x | jq .').hosts).toEqual(['evil.com'])
    expect(hook.hostsInCommand('nmap -sV 10.0.0.5').hosts).toEqual(['10.0.0.5'])
    expect(hook.hostsInCommand('openssl s_client -connect evil.com:443').hosts).toEqual(['evil.com'])
    expect(hook.hostsInCommand('dig +short app.ex.com A').hosts).toEqual(['app.ex.com'])
    expect(hook.hostsInCommand('npm audit --json').hosts).toEqual([])
    expect(hook.hostsInCommand('cat src/server.js').hosts).toEqual([])
  })
  it('bloqueia rede fora do escopo nos dois modos', () => {
    for (const mode of ['strict', 'session']) {
      expect(hook.decide({ tool_name: 'Bash', tool_input: { command: 'curl https://evil.com' }, cwd: FIXTURE }, { audit: audit(), mode }).decision).toBe('deny')
      expect(hook.decide({ tool_name: 'Bash', tool_input: { command: 'curl https://app.ex.com/health' }, cwd: FIXTURE }, { audit: audit(), mode }).decision).toBe('allow')
      expect(hook.decide({ tool_name: 'WebFetch', tool_input: { url: 'https://evil.com' }, cwd: FIXTURE }, { audit: audit(), mode }).decision).toBe('deny')
      expect(hook.decide({ tool_name: 'mcp__vionsec__port_scan', tool_input: { target: 'evil.com' }, cwd: FIXTURE }, { audit: audit(), mode }).decision).toBe('deny')
    }
  })
  it('teste ativo exige active:true', () => {
    expect(hook.decide({ tool_name: 'Bash', tool_input: { command: 'nmap app.ex.com' }, cwd: FIXTURE }, { audit: audit(), mode: 'session' }).decision).toBe('deny')
  })
  it('modo estrito: leitura so no escopo e sem escrita', () => {
    const a = audit()
    expect(hook.decide({ tool_name: 'Read', tool_input: { file_path: path.join(FIXTURE, 'src/server.js') }, cwd: FIXTURE }, { audit: a, mode: 'strict' }).decision).toBe('allow')
    expect(hook.decide({ tool_name: 'Read', tool_input: { file_path: path.join(os.homedir(), '.ssh', 'id_rsa') }, cwd: FIXTURE }, { audit: a, mode: 'strict' }).decision).toBe('deny')
    expect(hook.decide({ tool_name: 'Grep', tool_input: { pattern: 'x', path: '..' }, cwd: FIXTURE }, { audit: a, mode: 'strict' }).decision).toBe('deny')
    expect(hook.decide({ tool_name: 'Edit', tool_input: { file_path: path.join(FIXTURE, 'a.js') }, cwd: FIXTURE }, { audit: a, mode: 'strict' }).decision).toBe('deny')
    expect(hook.decide({ tool_name: 'Edit', tool_input: { file_path: path.join(FIXTURE, 'a.js') }, cwd: FIXTURE }, { audit: a, mode: 'session' }).decision).toBe('allow')
    expect(hook.decide({ tool_name: 'mcp__vion__finding_add', tool_input: {}, cwd: FIXTURE }, { audit: a, mode: 'strict' }).decision).toBe('allow')
  })
})

describe('servidor da UI', () => {
  const opts = { port: 3333, token: 'tok_tok_tok_tok' }
  const req = (method, url, headers = {}) => ({ method, url, headers: { host: 'localhost:3333', ...headers } })
  it('rejeita Host de fora (DNS rebinding)', () => {
    expect(server.checkRequest(req('GET', '/', { host: 'evil.com' }), opts).status).toBe(403)
    expect(server.checkRequest(req('GET', '/', { host: 'localhost:3333' }), opts)).toBeNull()
  })
  it('API exige token', () => {
    expect(server.checkRequest(req('GET', '/api/status'), opts).status).toBe(401)
    expect(server.checkRequest(req('GET', '/api/status', { 'x-vion-token': 'tok_tok_tok_tok' }), opts)).toBeNull()
    expect(server.checkRequest(req('GET', '/api/events?t=tok_tok_tok_tok'), opts)).toBeNull()
  })
  it('mutacao exige Origin local e JSON', () => {
    const h = { 'x-vion-token': 'tok_tok_tok_tok', 'content-type': 'application/json' }
    expect(server.checkRequest(req('POST', '/api/audits', h), opts).status).toBe(403)
    expect(server.checkRequest(req('POST', '/api/audits', { ...h, origin: 'http://evil.com' }), opts).status).toBe(403)
    expect(server.checkRequest(req('POST', '/api/audits', { ...h, origin: 'http://localhost:3333', 'content-type': 'text/plain' }), opts).status).toBe(415)
    expect(server.checkRequest(req('POST', '/api/audits', { ...h, origin: 'http://localhost:3333' }), opts)).toBeNull()
  })
})

describe('instalacao (settings.json)', () => {
  it('adiciona o hook sem apagar hooks existentes e remove so o do VION', () => {
    const existing = { model: 'opus', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'meu-hook.sh' }] }] } }
    const cmd = install.vionInvocation('hook').shell
    const withV = install.withVionHook(existing, cmd)
    expect(withV.model).toBe('opus')
    expect(withV.hooks.PreToolUse).toHaveLength(2)
    expect(install.hasVionHook(withV)).toBe(true)
    expect(install.withVionHook(withV, cmd).hooks.PreToolUse).toHaveLength(2) // idempotente
    const without = install.withoutVionHook(withV)
    expect(without).toEqual(existing)
  })
})

describe('migracao do CLI antigo', () => {
  it('para o fix-watcher e renomeia ~/.vion sem apagar', async () => {
    const { spawn } = await import('node:child_process')
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'vion-legacy-'))
    const dir = path.join(base, '.vion')
    fs.mkdirSync(dir)
    fs.writeFileSync(path.join(dir, 'credentials.json'), '{"api_key":"x"}')
    const script = path.join(dir, 'fix-watcher.mjs')
    fs.writeFileSync(script, 'setInterval(() => {}, 1000)')
    const child = spawn(process.execPath, [script], { stdio: 'ignore' })
    fs.writeFileSync(path.join(dir, 'fix-watcher.pid'), String(child.pid))
    process.env.VION_LEGACY_DIR = dir
    try {
      const legacy = await import('../src/core/legacy.js')
      await new Promise(r => setTimeout(r, 300))
      const found = legacy.detectLegacy()
      expect(found).toMatchObject({ credentials: true, watcherPid: child.pid, watcherRunning: true })
      const dry = legacy.migrateLegacy({ dryRun: true })
      expect(dry.actions.length).toBe(2)
      expect(fs.existsSync(dir)).toBe(true)
      const exited = new Promise(r => child.once('exit', r))
      legacy.migrateLegacy()
      await exited
      expect(fs.existsSync(dir)).toBe(false)
      const moved = fs.readdirSync(base).find(f => f.startsWith('.vion.legacy-'))
      expect(fs.existsSync(path.join(base, moved, 'credentials.json'))).toBe(true)
      expect(legacy.detectLegacy()).toBeNull()
    } finally {
      delete process.env.VION_LEGACY_DIR
      try { child.kill() } catch {}
      fs.rmSync(base, { recursive: true, force: true })
    }
  }, 20000)
})
