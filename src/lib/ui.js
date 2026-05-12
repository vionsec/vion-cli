// Minimal terminal UI helpers — ANSI codes only, no deps.
// Auto-disables colors when stdout is not a TTY (CI logs, pipes).

const ON = process.stdout.isTTY && process.env.NO_COLOR == null

const c = (code) => (s) => (ON ? `\x1b[${code}m${s}\x1b[0m` : s)

export const color = {
  dim: c('2'),
  red: c('31'),
  green: c('32'),
  yellow: c('33'),
  blue: c('34'),
  magenta: c('35'),
  cyan: c('36'),
  bold: c('1'),
}

export function info(msg) {
  process.stdout.write(`  ${msg}\n`)
}

export function success(msg) {
  process.stdout.write(`  ${color.green('✓')} ${msg}\n`)
}

export function warn(msg) {
  process.stdout.write(`  ${color.yellow('!')} ${msg}\n`)
}

export function error(msg) {
  process.stderr.write(`  ${color.red('✗')} ${msg}\n`)
}

export function step(msg) {
  process.stdout.write(`  ${color.dim('›')} ${msg}\n`)
}

export function header(title) {
  process.stdout.write(`\n  ${color.bold(title)}\n`)
}

export function blank() {
  process.stdout.write('\n')
}

const VIONSEC_BANNER = String.raw`
██╗   ██╗██╗ ██████╗ ███╗   ██╗███████╗███████╗ ██████╗
██║   ██║██║██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔════╝
██║   ██║██║██║   ██║██╔██╗ ██║███████╗█████╗  ██║
╚██╗ ██╔╝██║██║   ██║██║╚██╗██║╚════██║██╔══╝  ██║
 ╚████╔╝ ██║╚██████╔╝██║ ╚████║███████║███████╗╚██████╗
  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝
`

export function printBanner() {
  process.stdout.write('\n')
  process.stdout.write(`  ${color.dim('Welcome to')}\n`)
  process.stdout.write(color.cyan(VIONSEC_BANNER))
  process.stdout.write(`  ${color.dim('Security Agent · CLI')}\n\n`)
}
