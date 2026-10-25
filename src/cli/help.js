// ── Renderizacao da ajuda (terminal e Markdown) a partir do registry ──

import { publicCommands, findCommand } from './registry.js'
import { SKILLS, GROUPS } from './skills-meta.js'
import { c, wrapText } from './term.js'
import { VERSION } from '../core/version.js'

export function renderGeneralHelp() {
  const cmds = publicCommands()
  const w = Math.max(...cmds.map(x => x.name.length)) + 2
  return [
    `${c.bold('VION')} ${c.dim(`v${VERSION}`)} — Vulnerable Investigator Orchestrator Network`,
    wrapText('Agente de seguranca open source e local-first para o Claude Code. Um orquestrador (Opus) planeja e revisa; subagentes mais baratos (Sonnet/Haiku) e analisadores deterministicos fazem o trabalho pesado. Resultados, evidencias e relatorios ficam na sua maquina e aparecem em http://localhost:3333.'),
    '',
    c.bold('Uso'),
    '  vion <comando> [opcoes]',
    '',
    c.bold('Comandos'),
    ...cmds.map(x => `  ${c.cyan(x.name.padEnd(w))}${x.summary}`),
    '',
    c.bold('Comece por aqui'),
    `  1. ${c.cyan('vion init')}        instala skills, agentes, MCP e hook no Claude Code`,
    `  2. ${c.cyan('vion ui')}          abre http://localhost:3333`,
    `  3. ${c.cyan('vion audit .')}     audita o projeto atual (ou /vion:auditoria dentro do Claude Code)`,
    '',
    `Ajuda de um comando: ${c.cyan('vion help <comando>')}   Skills do Claude Code: ${c.cyan('vion help skills')}`,
  ].join('\n')
}

export function renderCommandHelp(name) {
  const cmd = findCommand(name)
  if (!cmd) return null
  const out = [`${c.bold(`vion ${cmd.name}`)} — ${cmd.summary}`, '', c.bold('Sintaxe'), `  ${cmd.usage}`, '', c.bold('Descricao'), wrapText(cmd.description, 80, '  ')]
  if (cmd.args?.length) {
    out.push('', c.bold('Argumentos'))
    for (const a of cmd.args) out.push(`  ${c.cyan(a.required ? `<${a.name}>` : `[${a.name}]`)}  ${a.desc}${a.required ? '' : c.dim(' (opcional)')}`)
  }
  const opts = Object.entries(cmd.options || {})
  if (opts.length) {
    out.push('', c.bold('Opcoes'))
    const w = Math.max(...opts.map(([n, o]) => n.length + (o.type === 'boolean' ? 0 : 8))) + 4
    for (const [n, o] of opts) {
      const flag = `--${n}${o.type === 'boolean' ? '' : ' <valor>'}`
      out.push(`  ${c.cyan(flag.padEnd(w))}${o.desc}${o.values ? c.dim(` [${o.values.join('|')}]`) : ''}${o.multiple ? c.dim(' (repetivel)') : ''}`)
    }
  }
  if (cmd.examples?.length) out.push('', c.bold('Exemplos'), ...cmd.examples.map(e => `  $ ${e}`))
  if (cmd.prereqs?.length) out.push('', c.bold('Pre-requisitos'), ...cmd.prereqs.map(p => `  - ${p}`))
  if (cmd.permissions?.length) out.push('', c.bold('Permissoes'), ...cmd.permissions.map(p => `  - ${p}`))
  if (cmd.outputs) out.push('', c.bold('Saida'), `  ${cmd.outputs}`)
  if (cmd.errors?.length) {
    out.push('', c.bold('Erros comuns'))
    for (const e of cmd.errors) out.push(`  ${c.yellow(e.error)}`, wrapText(e.fix, 80, '    '))
  }
  if (cmd.cautions?.length) out.push('', c.bold('Cuidados'), ...cmd.cautions.map(x => `  ! ${x}`))
  return out.join('\n')
}

const PERM_PT = {
  read: 'le o codigo',
  write: 'edita arquivos',
  'bash-local': 'roda ferramentas locais',
  'network-passive': 'consulta rede (passivo)',
  'network-active': 'teste ativo de rede',
}

export function renderSkillsHelp() {
  const out = [
    c.bold('Skills do VION no Claude Code'),
    wrapText('Use dentro do Claude Code digitando /vion:<nome>. Todas registram os resultados no store local (veja em `vion ui`). Detalhes: `vion skills show <nome>`.'),
  ]
  for (const [g, title] of GROUPS) {
    const items = SKILLS.filter(s => s.group === g)
    if (!items.length) continue
    out.push('', c.bold(title))
    for (const s of items) out.push(`  ${c.cyan(`/vion:${s.name}`.padEnd(20))}${s.summary}`)
  }
  return out.join('\n')
}

export function renderSkillDetail(s) {
  const out = [
    `${c.bold(`/vion:${s.name}`)} — ${s.summary}`,
    '',
    wrapText(s.details, 80, '  '),
    '',
    `${c.bold('Quando usar:')} ${s.whenToUse}`,
    `${c.bold('Resultado:')}   ${s.outputs}`,
    `${c.bold('Permissoes:')}  ${s.permissions.length ? s.permissions.map(p => PERM_PT[p] || p).join(', ') : 'nenhuma'}`,
    `${c.bold('Escopo:')}      ${s.scope === 'host' ? 'URL/dominio declarado + autorizacao' : s.scope === 'path' ? 'diretorio do projeto' : '—'}`,
  ]
  if (s.agents) out.push(`${c.bold('Agentes:')}     orquestrador (${s.model || 'opus'}) + ${s.agents.join(', ')}`)
  if (s.argumentHint) out.push(`${c.bold('Argumentos:')}  /vion:${s.name} ${s.argumentHint}`)
  return out.join('\n')
}

// ── Markdown (docs/COMMANDS.md) ──

export function renderMarkdownDocs() {
  const md = ['# VION — Referencia de comandos', '', '> Gerado de `src/cli/registry.js` e `src/cli/skills-meta.js` por `npm run gen:docs`. Nao edite a mao.', '', '## CLI (`vion`)', '']
  md.push('| Comando | O que faz |', '|---|---|', ...publicCommands().map(x => `| \`vion ${x.name}\` | ${x.summary} |`), '')
  for (const cmd of publicCommands()) {
    md.push(`### \`vion ${cmd.name}\``, '', cmd.summary, '', '```', cmd.usage, '```', '', cmd.description, '')
    const opts = Object.entries(cmd.options || {})
    if (opts.length) md.push('| Opcao | Descricao |', '|---|---|', ...opts.map(([n, o]) => `| \`--${n}\` | ${o.desc}${o.values ? ` (${o.values.join(', ')})` : ''} |`), '')
    if (cmd.examples?.length) md.push('Exemplos:', '', '```bash', ...cmd.examples, '```', '')
    if (cmd.prereqs?.length) md.push('Pre-requisitos: ' + cmd.prereqs.join(' '), '')
    if (cmd.errors?.length) md.push('Erros comuns:', '', ...cmd.errors.map(e => `- **${e.error}** — ${e.fix}`), '')
    if (cmd.cautions?.length) md.push('Cuidados:', '', ...cmd.cautions.map(x => `- ${x}`), '')
  }
  md.push('## Skills do Claude Code (`/vion:*`)', '')
  for (const [g, title] of GROUPS) {
    const items = SKILLS.filter(s => s.group === g)
    if (!items.length) continue
    md.push(`### ${title}`, '')
    for (const s of items) {
      md.push(`#### \`/vion:${s.name}\`${s.argumentHint ? ` \`${s.argumentHint}\`` : ''}`, '', `**${s.summary}**`, '', s.details, '', `- Quando usar: ${s.whenToUse}`, `- Resultado: ${s.outputs}`)
      if (s.permissions.length) md.push(`- Permissoes: ${s.permissions.map(p => PERM_PT[p] || p).join(', ')}`)
      if (s.agents) md.push(`- Agentes: orquestrador (${s.model || 'opus'}) + ${s.agents.join(', ')}`)
      md.push('')
    }
  }
  return md.join('\n')
}
