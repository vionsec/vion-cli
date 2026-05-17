import crypto from 'node:crypto'
import { hostname, platform } from 'node:os'
import { loadCredentials, getMachineId } from '../lib/storage.js'
import { error } from '../lib/ui.js'

// Embedded secret — matches VION_CLI_HMAC_SECRET on the server.
const HMAC_SECRET = 'ddc76fe0d4aec606a28ab83342de180110b5b7ea77c2893eeba64797078a88f8'

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
        'X-Vion-Machine': getMachineId(),
        'X-Vion-Hostname': hostname(),
        'X-Vion-Platform': platform(),
        'User-Agent': '@vionsec/cli',
        Accept: 'application/json, text/markdown, */*',
      },
    })
  } catch (e) {
    error(`Erro de rede: ${e.message}`)
    process.exit(1)
  }

  const text = await res.text()
  const exitCode = res.ok ? 0 : 1
  process.stdout.write(text, () => {
    // Avoid calling process.exit() immediately: on Windows (Node 22+) the
    // fetch connection pool still has libuv async handles being torn down,
    // and a synchronous exit triggers UV_HANDLE_CLOSING assertion in
    // src\win\async.c. Setting exitCode + unref'd timeout lets the event
    // loop drain naturally; the timeout is a safety net if handles stall.
    process.exitCode = exitCode
    setTimeout(() => process.exit(exitCode), 500).unref()
  })
}
