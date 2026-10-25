# VION — Referencia de comandos

> Gerado de `src/cli/registry.js` e `src/cli/skills-meta.js` por `npm run gen:docs`. Nao edite a mao.

## CLI (`vion`)

| Comando | O que faz |
|---|---|
| `vion help` | Ajuda geral ou de um comando especifico. |
| `vion init` | Instala skills, subagentes, MCP e hook do VION no Claude Code. |
| `vion uninstall` | Remove do Claude Code o que o `vion init` instalou. |
| `vion skills` | Lista as skills /vion:* ou mostra os detalhes de uma. |
| `vion agents` | Lista os agentes do motor multiagente e o modelo de cada um. |
| `vion ui` | Sobe a interface web local em http://localhost:3333 (sem login). |
| `vion audit` | Inicia, acompanha, lista e para auditorias autorizadas. |
| `vion report` | Gera, exibe ou exporta o relatorio de uma auditoria. |
| `vion config` | Le e altera a configuracao local (modelos por papel, limites, porta). |
| `vion doctor` | Verifica Node, Claude Code, instalacao, MCP, hook, banco e porta. |
| `vion data` | Exporta, faz backup, limpa por idade ou apaga dados locais. |

### `vion help`

Ajuda geral ou de um comando especifico.

```
vion help [comando]
```

Sem argumento, lista todos os comandos com descricao curta. Com um comando, mostra finalidade, sintaxe, parametros, exemplos, pre-requisitos, permissoes, saidas, erros comuns e cuidados. `vion help skills` lista as skills /vion:* do Claude Code.

Exemplos:

```bash
vion help
vion help audit
vion help skills
```

Erros comuns:

- **Comando desconhecido** — Rode `vion help` para ver a lista de comandos.

### `vion init`

Instala skills, subagentes, MCP e hook do VION no Claude Code.

```
vion init [--project] [--no-mcp] [--no-hook] [--dry-run]
```

Copia as skills /vion:* para ~/.claude/commands/vion/ (com backup da versao anterior), os subagentes para ~/.claude/agents/ (com o modelo de cada papel definido em `vion config`), registra o servidor MCP `vion` (via `claude mcp add`) e o hook PreToolUse de escopo em ~/.claude/settings.json, fazendo merge sem apagar o que ja existe. Rode de novo depois de `vion config set models.*` ou de atualizar o pacote.

| Opcao | Descricao |
|---|---|
| `--project` | instala em ./.claude do projeto atual em vez de ~/.claude |
| `--no-mcp` | nao registra o servidor MCP |
| `--no-hook` | nao registra o hook de escopo |
| `--dry-run` | mostra o que seria feito sem alterar nada |

Exemplos:

```bash
vion init
vion init --project
vion init --dry-run
```

Pre-requisitos: Claude Code instalado (`claude` no PATH) para registrar o MCP.

Erros comuns:

- **`claude` nao encontrado** — Instale o Claude Code ou rode com --no-mcp e registre depois: `claude mcp add vion -s user -- vion mcp`.
- **settings.json invalido** — Corrija o JSON de ~/.claude/settings.json; o VION nao sobrescreve arquivo invalido.

Cuidados:

- Substitui ~/.claude/commands/vion/ (a versao anterior vai para vion.bak-<data>).

### `vion uninstall`

Remove do Claude Code o que o `vion init` instalou.

```
vion uninstall [--project] [--keep-data]
```

Remove as skills /vion:*, os subagentes vion-*, o registro MCP `vion` e o hook. Por padrao, mantem os dados locais (auditorias, evidencias). Para apagar os dados, use `vion data delete --all`.

| Opcao | Descricao |
|---|---|
| `--project` | remove de ./.claude do projeto atual |

Exemplos:

```bash
vion uninstall
```

### `vion skills`

Lista as skills /vion:* ou mostra os detalhes de uma.

```
vion skills list | vion skills show <nome>
```

As skills sao os comandos que voce usa dentro do Claude Code (ex: /vion:auditoria). `list` agrupa por fase; `show` mostra o que a skill faz, quando usar, as saidas, as permissoes, o escopo exigido e os agentes envolvidos.

| Opcao | Descricao |
|---|---|
| `--json` | saida em JSON |

Exemplos:

```bash
vion skills list
vion skills show auditoria
vion skills show vion:lgpd
```

Erros comuns:

- **Skill desconhecida** — Veja os nomes com `vion skills list`.

### `vion agents`

Lista os agentes do motor multiagente e o modelo de cada um.

```
vion agents list
```

Mostra o orquestrador e os subagentes (recon, vuln, investigador, threat-intel, correlacao, relatorio), o papel, o modelo configurado e se ja estao instalados no Claude Code. Para trocar o modelo: `vion config set models.<papel> <opus|sonnet|haiku>` e depois `vion init`.

| Opcao | Descricao |
|---|---|
| `--json` | saida em JSON |

Exemplos:

```bash
vion agents list
```

### `vion ui`

Sobe a interface web local em http://localhost:3333 (sem login).

```
vion ui [--port 3333] [--no-open]
```

Servidor local (escuta so em 127.0.0.1) com as paginas Inicio, Auditorias (criar, acompanhar ao vivo, parar), Agentes, Vulnerabilidades, Evidencias, Relatorios, Skills e Configuracoes. Nao tem login porque so aceita conexoes da propria maquina, rejeita Host/Origin de fora (protecao contra DNS rebinding) e exige token CSRF por sessao nas acoes.

| Opcao | Descricao |
|---|---|
| `--port` | porta (padrao: ui.port do config, 3333) |
| `--no-open` | nao abre o navegador |

Exemplos:

```bash
vion ui
vion ui --port 4000 --no-open
```

Pre-requisitos: Para iniciar auditorias pela UI: Claude Code instalado e `vion init` executado.

Erros comuns:

- **EADDRINUSE** — A porta esta em uso: `vion ui --port 3334` ou feche o outro processo.
- **dist/ui ausente** — Instalacao a partir do codigo-fonte: rode `npm run build:ui`.

Cuidados:

- Nao exponha a porta com proxy/tunel: a UI nao tem login por design.

### `vion audit`

Inicia, acompanha, lista e para auditorias autorizadas.

```
vion audit <diretorio|url> [opcoes] | vion audit status <id> | vion audit history | vion audit stop <id>
```

Cria a auditoria no store local, grava o escopo autorizado e roda o orquestrador (Opus) em modo headless (`claude -p`), que delega a subagentes mais baratos. O motor aplica o escopo por hook (leitura so dentro do diretorio, sem escrita, rede so para os hosts declarados). Tokens e custo sao registrados por modelo. O progresso aparece ao vivo no terminal e na UI. Alvo URL ou teste ativo exigem --authorization.

| Opcao | Descricao |
|---|---|
| `--skills` | skills/checklists separadas por virgula (padrao: auditoria completa) |
| `--scope` | arquivo JSON de escopo { target, paths, hosts, cidrs, active, authorization } |
| `--host` | host adicional autorizado |
| `--active` | autoriza testes ativos (scan/exploracao controlada) |
| `--authorization` | declaracao de autorizacao (obrigatoria para URL/host/--active) |
| `--max-cost` | teto de custo em USD (padrao: limits.maxCostUsd) |
| `--detach` | nao acompanha no terminal (segue em segundo plano) |
| `--analyzers-only` | roda so os analisadores deterministicos (0 tokens, sem Claude) |
| `--limit` | history: quantidade de itens |
| `--json` | saida em JSON |

Exemplos:

```bash
vion audit .
vion audit ./meu-app --skills auditoria,ai,lgpd
vion audit . --analyzers-only
vion audit https://staging.meuapp.com --skills recon --active --authorization "Sou dono do dominio, teste em staging autorizado em 25/10/2026"
vion audit history
vion audit status a_lx2k9f0a1b2c3d4e5
vion audit stop a_lx2k9f0a1b2c3d4e5
```

Pre-requisitos: Claude Code instalado e autenticado. `vion init` executado (skills, agentes, MCP e hook).

Erros comuns:

- **Teste em alvo de rede exige declaracao de autorizacao** — Passe --authorization "texto" descrevendo quem autorizou e quando.
- **Diretorio nao existe** — Confira o caminho; ele precisa ser um diretorio.
- **Limite de auditorias simultaneas** — Aguarde ou pare uma auditoria (`vion audit stop <id>`), ou ajuste limits.maxConcurrentAudits.
- **MCP vion nao conectado** — Rode `vion init` e `vion doctor`.

Cuidados:

- Audite apenas sistemas seus ou com autorizacao escrita.
- O custo de tokens e cobrado na sua conta do Claude; use --max-cost para limitar.

### `vion report`

Gera, exibe ou exporta o relatorio de uma auditoria.

```
vion report <id> [--format html|md|json] [--out arquivo] [--open]
```

Regera o relatorio a partir do store local: confirmados separados de suspeitos e falsos positivos, evidencias referenciadas, limitacoes, agentes e tarefas. HTML autocontido (imprima como PDF pelo navegador), Markdown ou JSON.

| Opcao | Descricao |
|---|---|
| `--format` | html | md | json (padrao: md no terminal) (html, md, json) |
| `--out` | grava neste arquivo |
| `--open` | abre o HTML no navegador |

Exemplos:

```bash
vion report a_lx2k9f0a1b2c3d4e5
vion report a_lx2k9f0a1b2c3d4e5 --format html --open
vion report a_lx2k9f0a1b2c3d4e5 --format json --out laudo.json
```

Erros comuns:

- **Auditoria nao encontrada** — Liste os IDs com `vion audit history`.

Cuidados:

- Segredos ja sao mascarados no store, mas revise o relatorio antes de compartilhar.

### `vion config`

Le e altera a configuracao local (modelos por papel, limites, porta).

```
vion config get [chave] | vion config set <chave> <valor> | vion config path
```

Configuracao em VION_HOME/config.json. Chaves: models.<orquestrador|recon|vuln|investigador|threat-intel|correlacao|relatorio> (opus|sonnet|haiku|inherit), limits.maxCostUsd, limits.maxConcurrentAudits, limits.timeoutMinutes, retention.days (0 = nunca apagar), ui.port.

| Opcao | Descricao |
|---|---|
| `--json` | saida em JSON |

Exemplos:

```bash
vion config get
vion config get models
vion config set models.vuln haiku
vion config set limits.maxCostUsd 2
```

Erros comuns:

- **Chave desconhecida / valor invalido** — Veja as chaves e valores aceitos em `vion help config`.

Cuidados:

- Depois de mudar models.*, rode `vion init` para atualizar os subagentes instalados.

### `vion doctor`

Verifica Node, Claude Code, instalacao, MCP, hook, banco e porta.

```
vion doctor
```

Diagnostico local: versao do Node (>= 22.13 por causa do node:sqlite), `claude` no PATH, skills/agentes instalados e atualizados, MCP `vion` registrado, hook presente, banco acessivel com o schema atual, diretorio de dados com permissao, porta da UI livre e UI compilada.

| Opcao | Descricao |
|---|---|
| `--json` | saida em JSON |

Exemplos:

```bash
vion doctor
```

### `vion data`

Exporta, faz backup, limpa por idade ou apaga dados locais.

```
vion data export <id> [--out dir] | vion data backup [--out arquivo] | vion data prune --older-than <dias> | vion data delete <id|--all> --yes | vion data path
```

Gerencia o VION_HOME: `export` copia auditoria, evidencias e relatorios para uma pasta; `backup` copia o banco SQLite (consistente, via VACUUM INTO); `prune` apaga auditorias concluidas mais antigas que N dias; `delete` apaga uma auditoria ou todos os dados.

| Opcao | Descricao |
|---|---|
| `--out` | destino |
| `--older-than` | prune: idade em dias |
| `--all` | delete: todos os dados |
| `--yes` | confirma a exclusao |

Exemplos:

```bash
vion data path
vion data export a_lx2k9f0a1b2c3d4e5 --out ./laudo
vion data backup --out vion-backup.sqlite
vion data prune --older-than 90
vion data delete a_lx2k9f0a1b2c3d4e5 --yes
```

Erros comuns:

- **Exclusao sem --yes** — Repita com --yes para confirmar.

Cuidados:

- `delete` e irreversivel. Faca `vion data backup` antes.

## Skills do Claude Code (`/vion:*`)

### Comece por aqui

#### `/vion:vion`

**Menu principal do VION (mesmo conteudo do /vion:ajuda).**

Mostra o mapa de todos os comandos agrupados pela fase do ciclo de vida do projeto e indica por onde comecar.

- Quando usar: Primeiro contato com o VION ou quando nao lembrar o nome de um comando.
- Resultado: Menu no terminal.

#### `/vion:ajuda`

**Menu de todos os comandos /vion:* com o que cada um faz.**

Lista cada skill com uma descricao curta, agrupada por fase (novo, existente, pre-producao, pos-producao, especializados, privacidade, utilidades). E gerado a partir da mesma fonte do `vion help`, entao nunca diverge do que esta instalado.

- Quando usar: Para descobrir qual comando usar.
- Resultado: Menu no terminal.

#### `/vion:ciclo`

**Ciclo guiado: roda as fases do VION em sequencia, perguntando entre cada uma.**

Pergunta se o projeto e novo ou existente e conduz pela ordem prevencao (novo -> auditoria -> corrigir), validacao (ensinar -> pre-deploy -> pentest) e operacao (supply-chain -> monitorar -> incidente), sugerindo fases extras (landing, debug, ai, recon, lgpd) quando fazem sentido para a stack.

- Quando usar: Quando quer um passo a passo completo sem decidir a ordem.
- Resultado: Cada fase registra seus achados na pagina local; ao final, resumo com score por fase.
- Permissoes: le o codigo

### Projeto novo

#### `/vion:novo`

**Security by design: desenha a fundacao segura ANTES de escrever codigo.**

Entrevista curta sobre o sistema (o que faz, quem usa, dados, stack) e entrega 6 blocos: threat modeling, auth/authz, modelo de dados seguro (RLS, tenant), arquitetura de API, fluxo de dados e stack segura. Termina com o documento "Fundacao de Seguranca" com prioridades e checklist.

- Quando usar: Inicio de projeto, antes da primeira linha de codigo, ou ao desenhar um modulo novo grande.
- Resultado: Documento de arquitetura no terminal + recomendacoes registradas na pagina local.
- Permissoes: le o codigo

#### `/vion:dev-seguro`

**Guardrails de desenvolvimento seguro enquanto voce escreve, revisa ou refatora codigo.**

Aplica gates A-K (OWASP ASVS, API Top 10, NIST SSDF, privacy by design) em cada mudanca: inspeciona antes de editar, prefere a solucao nativa e minima, valida entrada/saida, autorizacao em dois niveis, logs sem segredo. Pode implementar, revisar um diff ou auditar um fluxo especifico (login, upload, pagamento).

- Quando usar: Durante o desenvolvimento do dia a dia e em code review.
- Resultado: Codigo/diff revisado e achados com correcao registrados na pagina local.
- Permissoes: le o codigo, edita arquivos

### Projeto existente

#### `/vion:auditoria` `[foco opcional, ex: "so auth e banco"]`

**Auditoria completa multiagente: orquestrador Opus + agentes especialistas mais baratos.**

O coracao do VION. Roda primeiro os analisadores deterministicos (0 tokens: segredos, crypto, IaC, SRI, taint, BOLA, config), depois o orquestrador (Opus) planeja e delega checklists a subagentes (recon/threat-intel/correlacao em Haiku, vulnerabilidades/investigacao em Sonnet): segredos, auth e zero trust, injecao/XSS, banco e RLS, API, config/infra/CI, logica de negocio SaaS, resiliencia, dependencias. Cada suspeita e validada no codigo antes de virar "confirmada"; duplicatas sao correlacionadas; o relatorio final fica na pagina local.

- Quando usar: Projeto existente, antes de um release, ou periodicamente.
- Resultado: Auditoria em http://localhost:3333 com findings (confirmados/suspeitos/falsos positivos), evidencias, agentes, tokens e relatorio HTML/MD/JSON.
- Permissoes: le o codigo, roda ferramentas locais
- Agentes: orquestrador (opus) + vion-recon, vion-vuln, vion-investigador, vion-threat-intel, vion-correlacao, vion-relatorio

#### `/vion:orquestrar` `<checklists/skills separados por espaco>`

**Orquestrador generico: roda qualquer combinacao de checklists/skills em modo multiagente.**

Mesmo motor da /vion:auditoria, mas voce escolhe o que entra no plano (ex.: "ai lgpd supply-chain"). Util para auditorias focadas mantendo a economia de tokens (analisadores primeiro, subagentes baratos, orquestrador so revisa o que e critico).

- Quando usar: Auditoria focada em algumas areas, ou para combinar skills especializadas numa unica auditoria.
- Resultado: Auditoria na pagina local.
- Permissoes: le o codigo, roda ferramentas locais
- Agentes: orquestrador (opus) + vion-recon, vion-vuln, vion-investigador, vion-threat-intel, vion-correlacao, vion-relatorio

#### `/vion:unified-scan`

**Varredura unificada rapida: crypto, IaC, SRI, taint (source->sink) e BOLA/IDOR.**

Executa os analisadores deterministicos do VION localmente (sem gastar tokens nos padroes obvios) e usa o modelo so para triar os resultados: descartar falsos positivos e explicar os reais.

- Quando usar: Checagem rapida e barata, em CI local ou antes de abrir um PR.
- Resultado: Findings na pagina local.
- Permissoes: le o codigo

#### `/vion:pentester`

**Pentest estatico do codigo local, com score e relatorio.**

Coleta package.json, configs, handlers e SQL (sem ler o .env real) e analisa como um atacante leria o codigo: segredos, injecao, auth, exposicao. Versao enxuta de agente unico, sem orquestracao.

- Quando usar: Quando quer uma leitura ofensiva rapida sem o custo da auditoria completa.
- Resultado: Findings e score na pagina local.
- Permissoes: le o codigo

#### `/vion:corrigir`

**Corrige vulnerabilidades direto no codigo, por severidade.**

Le os findings abertos da ultima auditoria do projeto (ou os que voce indicar) e corrige com edicoes cirurgicas, preservando a logica de negocio, preferindo solucao nativa do framework, rodando os testes e relendo cada arquivo alterado. Marca cada finding como aplicado.

- Quando usar: Depois de uma auditoria, para fechar os achados.
- Resultado: Arquivos corrigidos + status "aplicado" na pagina local.
- Permissoes: le o codigo, edita arquivos, roda ferramentas locais

#### `/vion:fixes`

**Revisa e aplica, com sua aprovacao, as correcoes pendentes salvas no VION.**

Busca no store local os findings com correcao sugerida e status "aberto", mostra cards de aprovacao (aprovar todas / uma por uma / rejeitar) e aplica as aprovadas. Rejeicoes ficam registradas.

- Quando usar: Para aplicar em lote as correcoes de auditorias anteriores.
- Resultado: Arquivos corrigidos + status atualizado na pagina local.
- Permissoes: le o codigo, edita arquivos

#### `/vion:ensinar`

**Seguranca alem do codigo: WAF, IAM, rotacao de chaves, backup, processos.**

Para o que a auditoria marcou como "fora do escopo automatizado", explica o que e, por que nao esta no codigo, o risco, como configurar na sua stack e como validar.

- Quando usar: Depois da auditoria, para cuidar das camadas de infra, negocio e IAM.
- Resultado: Guia pratico no terminal + itens registrados na pagina local.
- Permissoes: le o codigo

### Pre-producao

#### `/vion:pre-deploy`

**Portao final antes do deploy: secrets, correcoes criticas, deps, headers, build.**

Checklist automatizado + manual: nenhum segredo versionado, correcoes criticas/altas aplicadas, npm audit sem critico/alto, configuracao de producao (CSP, CORS, debug off), tratamento global de erro e rate limit.

- Quando usar: Imediatamente antes de publicar uma versao.
- Resultado: Checklist aprovado/reprovado e pendencias na pagina local.
- Permissoes: le o codigo, roda ferramentas locais

#### `/vion:supply-chain`

**Auditoria de dependencias e cadeia de suprimentos (npm, pip, go, cargo, maven...).**

Detecta os gerenciadores do projeto, roda os audits nativos, avalia lockfile, typosquatting, scripts de install, pacotes abandonados e CVEs/GHSA com procedencia.

- Quando usar: Antes de releases e sempre que adicionar dependencias.
- Resultado: Findings de dependencias na pagina local.
- Permissoes: le o codigo, roda ferramentas locais, consulta rede (passivo)

#### `/vion:pentest`

**Pentest ofensivo guiado (PTES + MITRE ATT&CK) contra alvo autorizado.**

Recon, modelagem de ameaca, analise de vulnerabilidades, exploracao controlada com PoC minima (sem dano) e pos-exploracao demonstrativa. Exige escopo declarado com autorizacao: o motor bloqueia qualquer host fora dele. Proibido destrutivo, DoS e exfiltracao real.

- Quando usar: Em staging/local ou producao com autorizacao escrita, antes de expor o sistema.
- Resultado: Cadeia de ataque, PoCs como evidencia e findings confirmados na pagina local.
- Permissoes: le o codigo, roda ferramentas locais, teste ativo de rede

### Pos-producao

#### `/vion:monitorar`

**Observabilidade e alertas de seguranca pos-deploy.**

Define o que logar (e o que nunca logar), formato estruturado, stack de coleta e retencao, alertas por severidade e verifica no codigo se as protecoes e eventos de seguranca existem de fato.

- Quando usar: Depois do primeiro deploy, ou quando nao ha alertas de seguranca.
- Resultado: Plano de monitoramento e lacunas na pagina local.
- Permissoes: le o codigo

#### `/vion:incidente`

**Resposta a incidentes: classificacao P1-P4, contencao, erradicacao, recuperacao.**

Guia (ou plano preventivo) por fase com SLAs, preservacao de evidencias, rotacao de credenciais, comunicacao (incluindo LGPD/ANPD quando aplicavel) e post-mortem.

- Quando usar: Durante um incidente real, ou para preparar o playbook antes.
- Resultado: Playbook/linha do tempo e acoes na pagina local.
- Permissoes: le o codigo, roda ferramentas locais

### Especializados

#### `/vion:recon`

**Reconhecimento externo: DNS, subdominios, portas, TLS, headers, exposicao.**

Usa ferramentas reais (dig, nmap, openssl, curl) contra o dominio declarado: registros DNS, subdominios comuns e takeover, portas e servicos, certificado e cifras, headers de seguranca, rotas administrativas expostas.

- Quando usar: Dominio em producao/staging que voce controla.
- Resultado: Ativos e findings de exposicao na pagina local.
- Permissoes: roda ferramentas locais, teste ativo de rede

#### `/vion:debug`

**Ultrathink: caca profunda de bugs de logica que testes nao pegam.**

Le cada arquivo relevante por inteiro, monta o modelo mental do que o codigo deveria fazer e compara com o que faz: race conditions, estados impossiveis, erros engolidos, off-by-one, timezones, precisao numerica, caminhos de erro.

- Quando usar: Bugs intermitentes ou antes de uma entrega critica.
- Resultado: Bugs com evidencia (arquivo:linha) na pagina local.
- Permissoes: le o codigo

#### `/vion:ai`

**Seguranca de IA/LLM: prompt injection, jailbreak, exfiltracao, abuso de tools, RAG.**

Detecta integracoes com LLMs e frameworks de agentes e avalia system prompts, separacao de dados x instrucoes, tool use com privilegio, RAG e vector stores, streaming, custo/abuso e vazamento de chaves.

- Quando usar: Projetos com chatbot, agente, RAG ou qualquer chamada a modelo.
- Resultado: Findings de AI security na pagina local.
- Permissoes: le o codigo

#### `/vion:landing`

**Landing pages: performance (Core Web Vitals), seguranca frontend e mobile.**

Avalia HTML/CSS/JS/imagens/fontes: LCP/CLS/INP, peso e formato de imagens, fontes, scripts de terceiros, SRI, CSP, formularios e responsividade.

- Quando usar: Sites e landing pages antes de campanhas ou lancamentos.
- Resultado: Findings e otimizacoes na pagina local.
- Permissoes: le o codigo, consulta rede (passivo)

### Privacidade

#### `/vion:lgpd`

**Privacidade e protecao de dados: LGPD + Marco Civil (e GDPR/EUA quando aplicavel).**

Achados tecnicos com evidencia sobre coleta, bases legais, retencao, direitos dos titulares, cookies/trackers, fornecedores, transferencia internacional e incidentes. Separa achado tecnico de conclusao juridica; nunca declara "100% conforme".

- Quando usar: Produtos que tratam dados pessoais de brasileiros (ou de UE/EUA).
- Resultado: Achados FAIL/PARTIAL/NOT EVIDENCED na pagina local; itens juridicos ficam sem correcao automatica.
- Permissoes: le o codigo

### Utilidades

#### `/vion:status`

**Progresso das fases do VION no projeto atual (lido do historico local).**

Consulta as auditorias salvas para o diretorio atual e mostra quais fases ja rodaram, quando, quantos achados abertos e qual a proxima fase recomendada.

- Quando usar: Para saber onde parou.
- Resultado: Painel de status no terminal.

