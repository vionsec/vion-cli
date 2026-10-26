# VION — Vulnerable Investigator Orchestrator Network

Agente de segurança **open source** e **local-first** para o [Claude Code](https://docs.claude.com/claude-code).

Um orquestrador (Opus) planeja, delega e revisa. Subagentes mais baratos (Sonnet/Haiku) e analisadores determinísticos fazem o trabalho pesado. Auditorias, evidências e relatórios ficam na **sua máquina** e aparecem numa interface web local em `http://localhost:3333`. Não tem login, Supabase nem backend hospedado.

```bash
npm install -g @vionsec/cli
vion init          # instala skills /vion:*, subagentes, MCP e hook no Claude Code
vion ui            # abre http://localhost:3333
vion audit .       # audita o projeto atual (ou /vion:auditoria dentro do Claude Code)
```

> Requisitos: Node.js 22.13+ e Claude Code instalado e autenticado. Os analisadores determinísticos (`vion audit . --analyzers-only`) funcionam sem o Claude.

### Atualizando do `@vionsec/cli` 0.6 (versão SaaS)

A 0.7 não usa mais conta, API key nem servidor: `vion login`, `vion install`, `vion call` e `vion watch` deixaram de existir. Depois de `npm install -g @vionsec/cli@latest`, rode `vion init`. Ele:

- para o `fix-watcher` antigo, se estiver rodando;
- renomeia `~/.vion` para `~/.vion.legacy-<data>` (lá fica a API key antiga; apague quando quiser e revogue a chave no painel antigo);
- move os comandos antigos de `~/.claude/commands/vion` para `vion.bak-<data>` e instala os novos.

Nada é apagado. `vion doctor` avisa se sobrar algo da versão antiga.

---

## O que vem no pacote

| Componente | O que é |
|---|---|
| **Skills `/vion:*`** | 22 comandos para o Claude Code: auditoria, correção, pentest, recon, LGPD, IA/LLM, supply chain, pre-deploy, incidente… (`vion help skills`) |
| **CLI `vion`** | `help`, `init`, `ui`, `audit`, `report`, `agents`, `skills`, `config`, `doctor`, `data`. Tudo documentado em `vion help <comando>` e em [docs/COMMANDS.md](docs/COMMANDS.md) |
| **UI local** | Início, Auditorias (criar, acompanhar ao vivo, parar), Agentes, Vulnerabilidades, Evidências, Relatórios, Skills e Configurações |
| **Motor multiagente** | Orquestrador + 6 subagentes, servidor MCP `vion` (ponte com o store), hook de escopo e runner headless |
| **Analisadores** | Segredos, crypto fraca, IaC, SRI, taint (source→sink), BOLA/IDOR, auth, injeção, config: 0 tokens |

## Como uma auditoria funciona

```
vion audit . / UI / /vion:auditoria
        │
        ▼
 escopo autorizado ──► hook PreToolUse bloqueia o que estiver fora
        │
        ▼
 analisadores determinísticos (0 tokens) ──► findings "suspeitos"
        │
        ▼
 ORQUESTRADOR (opus) ── plano ──┬─► vion-recon        (haiku)  ativos e stack
                                ├─► vion-vuln × N     (sonnet) uma checklist cada, em paralelo
                                ├─► vion-threat-intel (haiku)  dependências/CVE
                                ├─► vion-investigador (sonnet) valida suspeitas com evidência
                                ├─► vion-correlacao   (haiku)  duplicatas e cadeias
                                └─► vion-relatorio    (haiku)  resumo executivo
        │
        ▼
 store local (SQLite + arquivos) ──► UI ao vivo + relatório HTML/MD/JSON
```

**Economia de tokens:**
- os analisadores rodam primeiro e cobrem os padrões óbvios sem gastar tokens;
- cada subagente recebe só `audit_id`, `task_id` e o nome da checklist, e busca o resto pelo MCP;
- o orquestrador lê resumos de até 200 palavras e IDs, nunca o conteúdo bruto;
- a revisão do Opus fica restrita aos achados críticos e aos conflitos;
- `--max-cost` (ou `limits.maxCostUsd`) encerra a execução no teto.

**Rigor:**
- todo achado nasce `suspected`;
- o motor recusa `confirmed` sem evidência anexada e sem `validation_method`;
- o relatório separa confirmados, suspeitos e falsos positivos.

Os modelos de cada papel são configuráveis:

```bash
vion config set models.vuln haiku
vion config set models.orquestrador sonnet
vion init   # atualiza os subagentes das skills interativas
```

## Segurança do próprio VION

- A UI escuta **só em 127.0.0.1**, valida `Host` (contra DNS rebinding), exige token de sessão em `/api`, `Origin` local e JSON em mutações, e usa CSP estrita.
- O **escopo é aplicado pelo motor**, não pelo prompt. O hook PreToolUse bloqueia hosts fora do escopo e ferramentas de teste ativo sem autorização. Em auditorias headless, bloqueia também leitura fora do diretório e qualquer escrita.
- O headless roda com `--restricted`, `--permission-mode dontAsk`, lista fechada de ferramentas e só o MCP `vion`.
- Segredos são mascarados antes de ir para o banco, as evidências e os relatórios. As evidências têm sha256 para conferir integridade.
- Alvo de rede, host extra ou teste ativo exigem declaração de autorização, registrada no escopo e no relatório.

Detalhes e como reportar falhas: [SECURITY.md](SECURITY.md).

## Dados locais

| SO | Diretório |
|---|---|
| Windows | `%LOCALAPPDATA%\vion` |
| macOS | `~/Library/Application Support/vion` |
| Linux | `$XDG_DATA_HOME/vion` (ou `~/.local/share/vion`) |

Sobrescreva com `VION_HOME`. Conteúdo: `vion.sqlite`, `evidence/`, `reports/`, `audits/` (prompts e logs de cada execução), `logs/` e `config.json`.

```bash
vion data backup              # cópia consistente do banco
vion data export <id>         # auditoria + evidências + relatórios numa pasta
vion data prune --older-than 90
vion config set retention.days 180   # retenção automática
```

## O que é local e o que não é

- **Código:** MIT, em [jvncodez/VionSecurityAgent](https://github.com/jvncodez/VionSecurityAgent).
- **Execução, interface e armazenamento:** 100% na sua máquina.
- **Modelos de IA:** os agentes rodam no Claude Code e usam a sua conta Anthropic (com o custo correspondente). O VION não envia dados a nenhum serviço próprio. Os analisadores determinísticos funcionam offline.
- **Rede:** só o que a skill pede e o escopo permite, por exemplo `npm audit`, que consulta o registro npm.

## Instalar direto do GitHub

Sem passar pelo npm, com o mesmo conteúdo publicado:

```bash
npm install -g github:jvncodez/VionSecurityAgent
vion init
```

Para testar uma mudança sua antes de abrir o PR: clone o repositório e, dentro dele, rode `npm install --omit=dev`, depois `npm install -g .` e `vion doctor`.

## Sugestões, issues e PRs

O pacote no npm é publicado só pelo mantenedor. Sugestões de mudança, bugs e ideias vão em **[github.com/jvncodez/VionSecurityAgent](https://github.com/jvncodez/VionSecurityAgent)**: abra uma issue ou um PR lá. O mantenedor revisa e, se aprovar, a mudança entra na próxima versão publicada.

Veja [CONTRIBUTING.md](CONTRIBUTING.md).

## Licença

[MIT](LICENSE). Use apenas em sistemas seus ou com autorização documentada.
