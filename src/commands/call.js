import { createHash } from 'node:crypto'
import { hostname, platform } from 'node:os'
import { loadCredentials, getMachineId } from '../lib/storage.js'
import { error } from '../lib/ui.js'
import { startWatcher } from './watch.js'

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

  // Self-heal do fix-watcher: o daemon é detached e morre em reboot/logout, então
  // correções aprovadas no app deixavam de ser aplicadas até o próximo `vion install`.
  // Qualquer comando /vion:* agora revive o watcher (startWatcher é idempotente:
  // no-op se já vivo, silencioso se o script ainda não foi instalado).
  // Best-effort e SEM stdout — o agente IA parseia a saída deste comando, então
  // nada aqui pode escrever no stdout nem lançar.
  try {
    startWatcher()
  } catch {
    // watcher é bônus — nunca pode atrapalhar a execução da fase
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

  // Deferred exit: setting exitCode + unref'd timeout (instead of an
  // immediate process.exit) avoids the libuv UV_HANDLE_CLOSING assertion
  // on Windows (Node 22+) when fetch's connection-pool handles are still
  // tearing down. Used by BOTH the success and the abort paths.
  const safeExit = (code) => {
    process.exitCode = code
    setTimeout(() => process.exit(code), 500).unref()
  }

  // Verify prompt integrity: server sends SHA-256 of the ORIGINAL prompt
  // content (X-Vion-Prompt-Hash, computed over agent_prompts.content —
  // no watermark, no CLI render). The served body, however, is always
  // prefixed by the server's watermark block:
  //
  //   <!-- VION Cloud // ... -->
  //   <!-- user:... -->
  //   <!-- vion-trace:XXXX -->
  //   <blank line>
  //   <prompt content>
  //
  // So we must strip that leading comment block before hashing, otherwise
  // SHA-256(body) can NEVER equal SHA-256(content) and EVERY call aborts
  // (regression introduced with the hash check in 0.6.5). For cli=claude
  // the server render is identity, so stripped body === original content.
  // (Non-claude CLIs additionally re-render content server-side; hashing
  // there is a separate known protocol gap, out of scope for this fix.)
  const serverHash = res.headers.get('x-vion-prompt-hash')
  if (serverHash && res.ok) {
    const wm = text.match(/^(?:<!--[^\n]*-->\r?\n){1,6}\r?\n/)
    const body = wm ? text.slice(wm[0].length) : text
    const localHash = createHash('sha256').update(body, 'utf8').digest('hex')
    if (localHash !== serverHash) {
      error(
        'Integridade do prompt falhou — o conteúdo foi modificado em trânsito. Abortando.',
      )
      return safeExit(2)
    }
  }

  const exitCode = res.ok ? 0 : 1
  process.stdout.write(text, () => safeExit(exitCode))
}
