#!/usr/bin/env node
import { Command } from 'commander'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import { loginCommand } from '../src/commands/login.js'
import { installCommand } from '../src/commands/install.js'
import { logoutCommand } from '../src/commands/logout.js'
import { statusCommand } from '../src/commands/status.js'
import { watchCommand } from '../src/commands/watch.js'

const here = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'))

const program = new Command()

program
  .name('vion')
  .description('VION Security CLI — secure-by-default installer for the VION agent.')
  .version(pkg.version, '-v, --version', 'Show version and exit.')

program
  .command('login')
  .description('Authenticate with VION via browser (OAuth/PKCE) and install the agent.')
  .option('--api-url <url>', 'Override VION API URL (default https://app.vionsec.com.br).')
  .option(
    '--cli <name>',
    'Target CLI for install (claude | blackbox | codex | terminal). Sem flag: prompt interativo após login.',
  )
  .option('--no-install', 'Skip the auto-install step after login.')
  .action(loginCommand)

program
  .command('install')
  .description('Install agent files for the chosen CLI.')
  .option(
    '--cli <name>',
    'Target CLI: claude | blackbox | codex | terminal. Sem flag: prompt interativo.',
  )
  .action(installCommand)

program
  .command('logout')
  .description('Remove credentials from this machine.')
  .action(logoutCommand)

program
  .command('status')
  .description('Show login status, plan, and installed CLIs.')
  .action(statusCommand)

const watch = program.command('watch').description('Manage the fix-watcher daemon.')

watch
  .command('start')
  .description('Start the fix-watcher in the background.')
  .action(() => watchCommand('start'))

watch
  .command('stop')
  .description('Stop the running fix-watcher.')
  .action(() => watchCommand('stop'))

watch
  .command('status')
  .description('Show fix-watcher status.')
  .action(() => watchCommand('status'))

program.parseAsync(process.argv).catch((err) => {
  console.error(`\n  vion: ${err?.message || err}\n`)
  process.exit(1)
})
