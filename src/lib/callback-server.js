import { createServer } from 'node:http'

/**
 * Start a one-shot HTTP server on a random ephemeral port. Resolves with
 * { code, port } when /cb is hit, or rejects on timeout / unrecoverable error.
 *
 * The browser is redirected here by /cli-auth after the user clicks Authorize.
 * We respond with a tiny "you can close this window" page.
 *
 * Returns an async-iterable-like object: { url, waitForCode(), close() }.
 */
export function startCallbackServer({ timeoutMs = 5 * 60 * 1000 } = {}) {
  return new Promise((resolve, reject) => {
    let codePromiseResolve
    let codePromiseReject
    const codePromise = new Promise((res, rej) => {
      codePromiseResolve = res
      codePromiseReject = rej
    })

    const timer = setTimeout(() => {
      codePromiseReject(new Error('Login timeout — autorização não recebida em 5 minutos.'))
      try {
        server.close()
      } catch {
        // ignore
      }
    }, timeoutMs)

    const server = createServer((req, res) => {
      try {
        const url = new URL(req.url, `http://localhost`)
        if (url.pathname !== '/cb') {
          res.writeHead(404, { 'Content-Type': 'text/plain' })
          res.end('Not found')
          return
        }

        const code = url.searchParams.get('code')
        if (!code) {
          res.writeHead(400, { 'Content-Type': 'text/html' })
          res.end(landingPage('Erro: code ausente.'))
          return
        }

        // Success — show friendly close page, then notify caller.
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
        res.end(landingPage('Autorizado! Você pode fechar esta janela.'))

        clearTimeout(timer)
        codePromiseResolve(code)

        // Close server soon after the response is flushed.
        setTimeout(() => {
          try {
            server.close()
          } catch {
            // ignore
          }
        }, 100)
      } catch (err) {
        clearTimeout(timer)
        codePromiseReject(err)
        try {
          server.close()
        } catch {
          // ignore
        }
      }
    })

    server.on('error', (err) => {
      clearTimeout(timer)
      reject(err)
    })

    // Bind to 127.0.0.1 explicitly (not 0.0.0.0) — only the local browser
    // should be able to reach this. Port 0 = OS picks a free ephemeral port.
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address()
      resolve({
        url: `http://127.0.0.1:${port}/cb`,
        waitForCode: () => codePromise,
        close: () => {
          clearTimeout(timer)
          try {
            server.close()
          } catch {
            // ignore
          }
        },
      })
    })
  })
}

function landingPage(message) {
  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>VION CLI — Autorização</title>
<style>
  html, body { margin: 0; height: 100%; background: #020410; color: #EDEDED;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, Inter, sans-serif; }
  body { display: flex; align-items: center; justify-content: center; }
  .card { max-width: 400px; padding: 32px; text-align: center; }
  .icon { font-size: 36px; margin-bottom: 16px; }
  h1 { font-size: 18px; margin: 0 0 12px; font-weight: 700; }
  p { color: #94a3b8; font-size: 14px; line-height: 1.6; margin: 0; }
  small { display: block; color: #475569; font-size: 11px; margin-top: 24px;
    font-family: ui-monospace, "JetBrains Mono", monospace; }
</style>
</head>
<body>
  <div class="card">
    <div class="icon">✓</div>
    <h1>${escapeHtml(message)}</h1>
    <p>O CLI já recebeu a autorização. Volte para o terminal.</p>
    <small>VION Security · @vionsec/cli</small>
  </div>
</body>
</html>`
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
