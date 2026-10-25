// ── Saida de terminal: cores (respeita NO_COLOR / nao-TTY) e tabelas simples ──

const useColor = process.stdout.isTTY && !process.env.NO_COLOR
const wrap = code => s => (useColor ? `\x1b[${code}m${s}\x1b[0m` : String(s))

export const c = {
  bold: wrap('1'),
  dim: wrap('2'),
  red: wrap('31'),
  green: wrap('32'),
  yellow: wrap('33'),
  blue: wrap('34'),
  magenta: wrap('35'),
  cyan: wrap('36'),
}

export const SEV_COLOR = { critical: c.red, high: c.magenta, medium: c.yellow, low: c.blue, info: c.dim }
export const SEV_PT = { critical: 'CRITICO', high: 'ALTO', medium: 'MEDIO', low: 'BAIXO', info: 'INFO' }

const strip = s => String(s).replace(/\x1b\[[0-9;]*m/g, '')

export function table(rows, headers) {
  const all = headers ? [headers, ...rows] : rows
  const widths = []
  for (const r of all) r.forEach((cell, i) => (widths[i] = Math.max(widths[i] || 0, strip(cell ?? '').length)))
  const line = r => r.map((cell, i) => String(cell ?? '') + ' '.repeat(widths[i] - strip(cell ?? '').length)).join('  ').trimEnd()
  const out = []
  if (headers) out.push(c.bold(line(headers)), c.dim(widths.map(w => '-'.repeat(w)).join('  ')))
  for (const r of rows) out.push(line(r))
  return out.join('\n')
}

export function wrapText(text, width = 78, indent = '') {
  const words = String(text).split(/\s+/)
  const lines = []
  let cur = ''
  for (const w of words) {
    if ((cur + ' ' + w).trim().length > width - indent.length) {
      lines.push(indent + cur.trim())
      cur = w
    } else cur += ' ' + w
  }
  if (cur.trim()) lines.push(indent + cur.trim())
  return lines.join('\n')
}

export function printJson(data) {
  process.stdout.write(JSON.stringify(data, null, 2) + '\n')
}
