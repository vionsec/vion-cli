import { spawn } from 'node:child_process'

/** Abre URL/arquivo no navegador padrao, sem shell (evita injecao via argumento). */
export function openInBrowser(target) {
  const [cmd, args] =
    process.platform === 'win32'
      ? ['rundll32.exe', ['url.dll,FileProtocolHandler', target]]
      : process.platform === 'darwin'
        ? ['open', [target]]
        : ['xdg-open', [target]]
  try {
    spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref()
  } catch {
    // sem navegador: o usuario abre manualmente
  }
}
