import { createHash } from 'node:crypto'
import { hostname, platform } from 'node:os'
import { loadCredentials, getMachineId } from '../lib/storage.js'
import { error } from '../lib/ui.js'

/**
 * `vion call <phase> [--cli <name>]`
 *
 * Fetches /api/agent-phase and prints the response to stdout.
 * Verifies X-Vion-Prompt-Hash (SHA-256) to detect tampering in transit.
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

  // Verify prompt integrity: server sends SHA-256 of the content it produced.
  // Mismatch = response was modified in transit (MitM or proxy tampering).
  const serverHash = res.headers.get('x-vion-prompt-hash')
  if (serverHash && res.ok) {
    const localHash = createHash('sha256').update(text, 'utf8').digest('hex')
    if (localHash !== serverHash) {
      error(
        'Integridade do prompt falhou — o conteúdo foi modificado em trânsito. Abortando.',
      )
      process.exit(2)
    }
  }

  const exitCode = res.ok ? 0 : 1
  process.stdout.write(text, () => {
    // Setting exitCode instead of calling exit() immediately prevents the
    // libuv UV_HANDLE_CLOSING assertion on Windows (Node 22+) caused by
    // fetch connection pool handles still tearing down on synchronous exit.
    process.exitCode = exitCode
    setTimeout(() => process.exit(exitCode), 500).unref()
  })
}
