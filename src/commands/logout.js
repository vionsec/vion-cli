import { clearCredentials } from '../lib/storage.js'
import { success, info, color, header, blank } from '../lib/ui.js'

export async function logoutCommand() {
  header('VION CLI — Logout')
  const removed = clearCredentials()
  if (removed) {
    success('Credenciais removidas desta máquina.')
    info(color.dim('A API key continua válida no servidor até você rodar `vion login` de novo'))
    info(color.dim('(que gera nova key e revoga a anterior).'))
  } else {
    info('Nenhuma credencial encontrada — nada a remover.')
  }
  blank()
}
