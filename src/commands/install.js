import { createApi, HttpError } from '../lib/api.js'
import {
  loadCredentials,
  saveCurlrc,
  writeFileFromBase64,
  WATCHER_SCRIPT_PATH,
} from '../lib/storage.js'
import { writeFileSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline/promises'
import { color, info, success, warn, error, step, header, blank, printBanner } from '../lib/ui.js'
import { SUPPORTED_CLIS } from '../config.js'
import { startWatcher } from './watch.js'
import { bashAvailable } from '../lib/system.js'

const CLI_MENU = [
  { id: 'claude', label: 'Claude Code' },
  { id: 'codex', label: 'OpenAI Codex' },
  { id: 'blackbox', label: 'Blackbox AI' },
  { id: 'terminal', label: 'Terminal (Bash/PowerShell/CMD)' },
]

async function promptCli() {
  if (!process.stdin.isTTY) {
    // Non-interactive environment (CI, Claude Code panel, piped stdin).
    // Default to Claude Code — it's the most common target — and surface
    // the override path so the user knows how to pick another IA.
    warn('Ambiente sem TTY — usando Claude Code como default.')
    info(color.dim('Pra escolher outra IA: vion install --cli=blackbox|codex|terminal'))
    blank()
    return 'claude'
  }

  header('VION CLI — Qual IA você usa?')
  blank()
  for (let i = 0; i < CLI_MENU.length; i++) {
    process.stdout.write(`    ${color.cyan(String(i + 1))}. ${CLI_MENU[i].label}\n`)
  }
  blank()

  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    const ans = (await rl.question('  Escolha (1-4): ')).trim()
    const idx = parseInt(ans, 10) - 1
    if (!Number.isFinite(idx) || idx < 0 || idx >= CLI_MENU.length) {
      error(`Opção inválida: ${ans}. Use 1-${CLI_MENU.length}.`)
      process.exit(1)
    }
    return CLI_MENU[idx].id
  } finally {
    rl.close()
  }
}

async function promptYesNo(question, defaultYes) {
  if (!process.stdin.isTTY) return defaultYes
  const rl = createInterface({ input: process.stdin, output: process.stdout })
  try {
    const hint = defaultYes ? 'S/n' : 's/N'
    const ans = (await rl.question(`  ${question} [${hint}] `)).trim().toLowerCase()
    if (!ans) return defaultYes
    return ans === 's' || ans === 'sim' || ans === 'y' || ans === 'yes'
  } finally {
    rl.close()
  }
}

async function maybeLaunchCli(cli) {
  // terminal = "I just use the terminal directly" — não há binário pra abrir.
  if (cli === 'terminal') {
    info(color.dim('Abra seu terminal e rode `claude` quando quiser usar o agente.'))
    return
  }

  const wantStart = await promptYesNo('Iniciar agora?', true)
  if (!wantStart) {
    blank()
    return
  }

  let cmd
  let args = []

  if (cli === 'claude') {
    cmd = 'claude'
    const wantSkip = await promptYesNo(
      `Usar ${color.yellow('--dangerously-skip-permissions')} (bypassa confirmações)?`,
      false,
    )
    if (wantSkip) args.push('--dangerously-skip-permissions')
  } else if (cli === 'codex') {
    cmd = 'codex'
  } else if (cli === 'blackbox') {
    cmd = 'blackbox'
  }

  if (!cmd) return

  blank()
  step(`Abrindo ${color.bold(cmd + (args.length ? ' ' + args.join(' ') : ''))}...`)
  info(color.dim('Quando o agente abrir, digite /vion para começar.'))
  blank()

  // Windows ships claude/codex/blackbox as `.cmd` shims, which spawn() can't
  // execute directly. We need a shell — but Node 22 deprecated passing args
  // alongside shell:true (DEP0190), so compose the full command string here
  // and pass it as the lone arg. POSIX systems can spawn the binary directly.
  let child
  if (process.platform === 'win32') {
    const fullCmd = [cmd, ...args].map(quoteForCmd).join(' ')
    child = spawn(fullCmd, [], { stdio: 'inherit', shell: true })
  } else {
    child = spawn(cmd, args, { stdio: 'inherit' })
  }

  await new Promise((resolve) => {
    child.on('exit', resolve)
    child.on('error', (e) => {
      error(`Falha ao iniciar ${cmd}: ${e.message}`)
      info(color.dim(`${cmd} está instalado e no PATH? Tente abrir manualmente.`))
      resolve()
    })
  })
}

function quoteForCmd(s) {
  // Wrap in double quotes if the token contains whitespace or quote chars.
  // Internal double quotes are doubled (cmd.exe convention).
  if (!/[\s"]/.test(s)) return s
  return `"${s.replace(/"/g, '""')}"`
}

export async function installCommand(opts) {
  printBanner()

  // Windows pre-flight: the agent's slash commands run curl through bash.
  // On Windows that means Git for Windows must be installed. We point users
  // to Git for Windows specifically — `wsl --install` pulls a full Ubuntu
  // image (~1GB+), way too heavy for what we need (just bash + curl).
  if (!bashAvailable()) {
    warn('Bash não detectado neste sistema.')
    blank()
    info('VION precisa de bash pra rodar comandos no agente IA.')
    blank()
    info(`  ${color.cyan('Git for Windows')}  →  https://git-scm.com/download/win   (~50MB)`)
    blank()
    info('  Inclui Git Bash, exatamente o que o agente VION precisa.')
    info(color.dim('  Após instalar, abra um novo terminal e rode `vion install` de novo.'))
    blank()
    process.exit(1)
  }

  let cli = opts.cli ? opts.cli.toLowerCase() : null

  if (!cli) {
    cli = await promptCli()
  }

  if (!SUPPORTED_CLIS.includes(cli)) {
    error(`CLI inválido: ${cli}. Use: ${SUPPORTED_CLIS.join(', ')}`)
    process.exit(1)
  }

  const creds = loadCredentials()
  if (!creds?.api_key) {
    error('Não autenticado. Rode `vion login` primeiro.')
    process.exit(1)
  }

  const apiUrl = creds.api_url || 'https://app.vionsec.com.br'
  const api = createApi(apiUrl)

  header(`VION CLI — Install (${cli})`)
  step('Buscando templates do servidor...')

  let payload
  try {
    payload = await api.get(`/api/cli-templates?cli=${encodeURIComponent(cli)}`, {
      token: creds.api_key,
    })
  } catch (err) {
    if (err instanceof HttpError) {
      if (err.status === 401 || err.status === 403) {
        error('Token expirado ou inválido. Rode `vion login` para renovar.')
      } else if (err.status === 429) {
        error('Rate limit. Aguarde 1 minuto e tente de novo.')
      } else {
        error(err.body?.error || `Falha ao buscar templates (HTTP ${err.status}).`)
      }
    } else {
      error(`Erro de rede: ${err.message}`)
    }
    process.exit(1)
  }

  // Write each file under the home dir or project dir as the server specified.
  step(`Escrevendo ${payload.files.length} arquivo(s)...`)
  const writtenPaths = []
  try {
    for (const f of payload.files) {
      const abs = writeFileFromBase64(f.path, f.content_b64)
      writtenPaths.push({ logical: f.path, abs })
    }
  } catch (err) {
    error(`Falha ao escrever arquivos: ${err.message}`)
    process.exit(1)
  }

  // Fix-watcher script (always installed under ~/.vion/fix-watcher.mjs).
  if (payload.fix_watcher?.content_b64) {
    writeFileSync(
      WATCHER_SCRIPT_PATH,
      Buffer.from(payload.fix_watcher.content_b64, 'base64'),
    )
  }

  // Re-write curlrc com X-Vion-Agent agora que o CLI foi escolhido. Login
  // grava como 'claude' (default) — se o user trocou em `vion install`,
  // sobrescreve aqui pra que toda chamada futura ja diga ao backend qual
  // dialeto servir, sem precisar de query string.
  saveCurlrc(creds.api_key, cli)

  for (const w of writtenPaths) {
    success(color.dim(w.logical))
  }

  blank()
  success(`VION instalado para ${color.bold(payload.label)}.`)
  info(`Lance com: ${color.cyan(payload.launch_cmd)}`)
  blank()

  // Auto-start the fix-watcher daemon. This is the bridge between the web app
  // (where the user approves fixes in VionFix) and the local IA (Claude/Codex/
  // Blackbox), so it should be running whenever the agent is installed.
  step('Iniciando auto-fix watcher...')
  const w = startWatcher()
  if (w.ok && w.already) {
    info(color.dim(`Watcher já estava rodando (PID ${w.pid}).`))
  } else if (w.ok) {
    success(`Watcher ativo (PID ${w.pid}). Correções aprovadas no app serão aplicadas aqui.`)
  } else if (w.reason === 'script_missing') {
    warn('Watcher script não chegou no payload — auto-fix indisponível nesta instalação.')
  } else {
    warn(`Watcher não iniciou (${w.reason}). Rode \`vion watch start\` manualmente.`)
  }
  blank()

  await maybeLaunchCli(cli)
}
