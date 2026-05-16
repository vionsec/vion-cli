import crypto from 'node:crypto'
import { loadCredentials } from '../lib/storage.js'
import { error } from '../lib/ui.js'

// Embedded secret — matches VION_CLI_HMAC_SECRET on the server.
const HMAC_SECRET = 'a5c2c74ada66a133a2f531f5f0b1625b07a2c92a13a0db56609cc3ce74b5ff37'

function buildSigHeader() {
  const ts = Math.floor(Date.now() / 1000).toString()
  const hmac = crypto.createHmac('sha256', HMAC_SECRET).update(ts, 'utf8').digest('hex')
  return `${hmac}:${ts}`
}

/**
 * `vion call <phase> [--cli <name>]`
 *
 * Fetches /api/agent-phase?phase=<phase>&cli=<cli> with a fresh HMAC-SHA256
 * signature and prints the response body to stdout. Used by agent slash
 * commands instead of raw `curl -K curlrc` so the API key never appears in
 * the shell command and the sig is always fresh (30s window).
 */
export async function callCommand(phase, opts = {}) {
  const creds = loadCredentials()
  if (!creds?.api_key) {
    error('Não autenticado. Rode `vion login` primeiro.')
    process.exit(1)
  }

  const cli = opts.cli || 'claude'
  const baseUrl = creds.api_url || 'https://app.vionsec.com.br'
  const url = `${baseUrl}/api/agent-phase?phase=${encodeURIComponent(phase)}&cli=${encodeURIComponent(cli)}`

  let res
  try {
    res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${creds.api_key}`,
        'X-Vion-Sig': buildSigHeader(),
        'X-Vion-Agent': cli,
        'User-Agent': '@vionsec/cli',
        Accept: 'application/json, text/markdown, */*',
      },
    })
  } catch (e) {
    error(`Erro de rede: ${e.message}`)
    process.exit(1)
  }

  const text = await res.text()
  process.stdout.write(text)
  if (!res.ok) process.exit(1)
}
