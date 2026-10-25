import fs from 'node:fs'
import path from 'node:path'
import { paths, ensureHome } from '../../core/paths.js'
import { openDb } from '../../core/db.js'
import { getAudit, listAudits, deleteAudit } from '../../core/store.js'
import { buildReportData, renderHtml, renderMarkdown } from '../../core/report.js'
import { c } from '../term.js'

export async function run({ positionals, values }) {
  const [sub, id] = positionals
  const home = ensureHome()

  if (!sub || sub === 'path') return console.log(paths().root)

  if (sub === 'export') {
    if (!id || !getAudit(id)) throw new Error('Uso: vion data export <id> [--out dir]')
    const out = path.resolve(values.out || `vion-${id}`)
    fs.mkdirSync(out, { recursive: true })
    const d = buildReportData(id)
    fs.writeFileSync(path.join(out, 'auditoria.json'), JSON.stringify(d, null, 2))
    fs.writeFileSync(path.join(out, 'relatorio.html'), renderHtml(d))
    fs.writeFileSync(path.join(out, 'relatorio.md'), renderMarkdown(d))
    const ev = path.join(home.evidence, id)
    if (fs.existsSync(ev)) fs.cpSync(ev, path.join(out, 'evidencias'), { recursive: true })
    return console.log(`${c.green('ok')} exportado para ${out}`)
  }

  if (sub === 'backup') {
    const out = path.resolve(values.out || `vion-backup-${new Date().toISOString().slice(0, 10)}.sqlite`)
    if (fs.existsSync(out)) throw new Error(`Ja existe: ${out}`)
    openDb().exec(`VACUUM INTO '${out.replace(/'/g, "''")}'`)
    return console.log(`${c.green('ok')} backup do banco em ${out} (evidencias ficam em ${home.evidence})`)
  }

  if (sub === 'prune') {
    const days = Number(values['older-than'])
    if (!Number.isFinite(days) || days < 1) throw new Error('Uso: vion data prune --older-than <dias>')
    const limit = Date.now() - days * 86400000
    const old = listAudits({ limit: 100000 }).filter(a => ['completed', 'failed', 'stopped'].includes(a.status) && Date.parse(a.created_at) < limit)
    for (const a of old) deleteAudit(a.id)
    return console.log(`${c.green('ok')} ${old.length} auditoria(s) com mais de ${days} dias apagada(s)`)
  }

  if (sub === 'delete') {
    if (!values.yes) throw new Error('Exclusao irreversivel: repita com --yes (faca `vion data backup` antes).')
    if (values.all) {
      const all = listAudits({ limit: 100000 })
      for (const a of all) deleteAudit(a.id)
      return console.log(`${c.green('ok')} ${all.length} auditoria(s) apagada(s). Config mantida em ${paths().config}`)
    }
    if (!id || !getAudit(id)) throw new Error('Uso: vion data delete <id> --yes  |  vion data delete --all --yes')
    deleteAudit(id)
    return console.log(`${c.green('ok')} auditoria ${id} apagada`)
  }

  throw new Error(`Subcomando desconhecido: ${sub}. Use export, backup, prune, delete ou path.`)
}
