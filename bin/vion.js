#!/usr/bin/env node
// VION — Vulnerable Investigator Orchestrator Network (@vionsec/cli)

const [major, minor] = process.versions.node.split('.').map(Number)
if (major < 22 || (major === 22 && minor < 13)) {
  console.error(`VION precisa de Node.js >= 22.13 (node:sqlite). Versao atual: ${process.versions.node}`)
  process.exit(1)
}

// node:sqlite ainda emite ExperimentalWarning em algumas versoes; nao polui a saida do CLI/MCP.
const emitWarning = process.emitWarning
process.emitWarning = (warning, ...rest) => {
  const msg = typeof warning === 'string' ? warning : warning?.message
  if (/SQLite is an experimental feature/i.test(msg || '')) return
  return emitWarning.call(process, warning, ...rest)
}

const { main } = await import('../src/cli/main.js')
main(process.argv.slice(2)).catch(err => {
  console.error(`erro: ${err.message}`)
  if (process.env.VION_DEBUG) console.error(err.stack)
  process.exit(1)
})
