import { loadCredentials, CREDENTIALS_PATH } from '../lib/storage.js'
import { color, info, success, warn, header, blank } from '../lib/ui.js'

export async function statusCommand() {
  header('VION CLI — Status')

  const creds = loadCredentials()
  if (!creds?.api_key) {
    warn('Não autenticado. Rode `vion login` para entrar.')
    blank()
    return
  }

  const p = creds.profile || {}
  success(`Logado como ${color.bold(p.name || '(sem nome)')}`)
  info(`Email:  ${p.email || '—'}`)
  info(`Plano:  ${color.cyan(p.plan || 'starter')}`)
  info(`Role:   ${p.role || 'user'}`)
  info(`Key:    ${color.dim('****' + (p.hint?.slice(-4) || '????'))}`)
  info(`API:    ${color.dim(creds.api_url || 'https://app.vionsec.com.br')}`)
  if (creds.issued_at) {
    info(`Desde:  ${color.dim(creds.issued_at)}`)
  }
  info(`Path:   ${color.dim(CREDENTIALS_PATH)}`)
  blank()
}
