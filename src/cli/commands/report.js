import fs from 'node:fs'
import path from 'node:path'
import { getAudit } from '../../core/store.js'
import { buildReportData, renderHtml, renderMarkdown, generateReports } from '../../core/report.js'
import { openInBrowser } from '../open.js'
import { c } from '../term.js'

export async function run({ positionals, values }) {
  const [id] = positionals
  if (!id) throw new Error('Uso: vion report <id>  (IDs em `vion audit history`)')
  if (!getAudit(id)) throw new Error(`Auditoria nao encontrada: ${id}`)
  const format = values.format || (values.open ? 'html' : 'md')

  if (values.out) {
    const d = buildReportData(id)
    const body = format === 'html' ? renderHtml(d) : format === 'json' ? JSON.stringify(d, null, 2) : renderMarkdown(d)
    fs.writeFileSync(path.resolve(values.out), body)
    return console.log(`${c.green('ok')} ${path.resolve(values.out)}`)
  }
  if (format === 'md' && !values.open) return process.stdout.write(renderMarkdown(buildReportData(id)))
  const files = generateReports(id, null, [format])
  console.log(files[format])
  if (values.open) openInBrowser(files[format])
}
