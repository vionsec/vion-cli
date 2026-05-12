import open from 'open'

import { resolveApiUrl } from '../config.js'
import { generatePkcePair } from '../lib/pkce.js'
import { startCallbackServer } from '../lib/callback-server.js'
import { createApi, HttpError } from '../lib/api.js'
import { saveCredentials, loadCredentials, saveCurlrc } from '../lib/storage.js'
import { color, info, success, warn, error, step, header, blank } from '../lib/ui.js'
import { installCommand } from './install.js'

export async function loginCommand(opts) {
  const apiUrl = resolveApiUrl(opts.apiUrl)
  const api = createApi(apiUrl)

  header('VION CLI — Login')
  info(`API: ${color.dim(apiUrl)}`)

  // Warn if there's already a session — login regenerates the API key, which
  // revokes the previous one (server-side).
  const existing = loadCredentials()
  if (existing?.api_key) {
    warn(
      `Já existe uma sessão para ${color.bold(existing.profile?.email || 'este usuário')}. ` +
        `Continuar irá ${color.bold('revogar a key atual')}.`,
    )
  }

  // 1. PKCE pair
  const { verifier, challenge, method } = generatePkcePair()

  // 2. Local callback server
  step('Subindo servidor local de callback...')
  let callback
  try {
    callback = await startCallbackServer()
  } catch (err) {
    error(`Não foi possível abrir uma porta local: ${err.message}`)
    process.exit(1)
  }

  // 3. Initiate session on the server
  step('Iniciando sessão no servidor...')
  let session
  try {
    session = await api.post('/api/cli-auth-init', {
      body: {
        code_challenge: challenge,
        code_challenge_method: method,
        redirect_uri: callback.url,
      },
    })
  } catch (err) {
    callback.close()
    if (err instanceof HttpError) {
      error(err.body?.error || `Falha ao iniciar sessão (HTTP ${err.status}).`)
    } else {
      error(`Erro de rede: ${err.message}`)
      info(color.dim(`  Tente novamente. Se persistir: VION_API_URL=... vion login`))
    }
    process.exit(1)
  }

  // 4. Open browser
  step('Abrindo navegador para autorização...')
  info(color.dim(`Se nada abrir, cole no browser:\n    ${session.auth_url}`))
  try {
    await open(session.auth_url)
  } catch {
    // Fall through — user can copy/paste manually.
  }

  // 5. Wait for callback
  blank()
  info(`${color.cyan('⏳')} Aguardando autorização no navegador...`)

  let code
  try {
    code = await callback.waitForCode()
  } catch (err) {
    callback.close()
    error(err.message)
    process.exit(1)
  }

  // 6. Exchange code for API key
  step('Trocando code por API key...')
  let result
  try {
    result = await api.post('/api/cli-auth-exchange', {
      body: { code, code_verifier: verifier },
    })
  } catch (err) {
    if (err instanceof HttpError) {
      error(err.body?.error || `Falha no exchange (HTTP ${err.status}).`)
    } else {
      error(`Erro de rede: ${err.message}`)
    }
    process.exit(1)
  }

  // 7. Persist
  saveCredentials({
    api_key: result.api_key,
    profile: result.profile,
    api_url: apiUrl,
    issued_at: new Date().toISOString(),
  })
  // Also write a curlrc so slash-command markdown can use `curl -K ~/.vion/curlrc`
  // — keeps the token out of every Bash tool argument shown by the agent IA.
  //
  // Se o user passou --cli=X no login, ja gravamos o agente. Caso contrario
  // 'claude' como default — o install reescreve depois quando o user escolhe
  // outro CLI (Blackbox/Codex/Cursor).
  saveCurlrc(result.api_key, opts.cli || 'claude')

  blank()
  success(
    `Logado como ${color.bold(result.profile.name)} ` +
      `${color.dim(`(${result.profile.email})`)}`,
  )
  info(`Plano: ${color.cyan(result.profile.plan || 'starter')}`)
  info(`Key:   ${color.dim('****' + result.profile.hint?.slice(-4) || '****')}`)
  blank()

  // Auto-chain into install. Commander's --no-install maps to opts.install=false.
  if (opts.install === false) {
    info(color.dim('Próximo: vion install (ou vion install --cli=claude)'))
    blank()
    return
  }

  await installCommand({ cli: opts.cli })
}
