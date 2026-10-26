# Segurança

## Reportar uma vulnerabilidade no VION

Não abra issue pública. Use o **Private vulnerability reporting** do GitHub (aba Security de [jvncodez/VionSecurityAgent](https://github.com/jvncodez/VionSecurityAgent/security)) com:
- versão (`vion --version`) e sistema operacional;
- passos para reproduzir;
- impacto esperado.

A resposta inicial sai em até 7 dias.

## Modelo de ameaça (resumo)

| Ameaça | Mitigação |
|---|---|
| Site malicioso acessando a UI local (CSRF, DNS rebinding) | Escuta só em 127.0.0.1; `Host` precisa ser `localhost`/`127.0.0.1:<porta>`; token de sessão obrigatório em `/api`; `Origin` local e `Content-Type: application/json` em mutações; CSP `script-src 'self'`; `X-Frame-Options: DENY` |
| Prompt injection no código ou nas páginas auditadas ampliando o escopo | Escopo aplicado pelo hook PreToolUse (independente do modelo); prompts tratam o conteúdo do alvo como dado; headless com `--restricted`, `dontAsk` e lista fechada de ferramentas |
| Agente lendo ou escrevendo fora do projeto | Modo estrito: leitura só nos paths do escopo, escrita bloqueada; `file_path` absoluto fora do escopo é recusado pelo MCP |
| Varredura de terceiros | Alvo de rede exige declaração de autorização; curingas amplos e CIDR menores que /16 são recusados; ferramentas ativas exigem `active: true` |
| Vazamento de segredos em evidências e relatórios | Redação por valor e por chave antes de persistir; arquivos com permissão 600 |
| Adulteração de evidências | sha256 gravado na coleta e conferido na leitura |
| Achado alucinado apresentado como fato | Todo achado nasce `suspected`; `confirmed` exige evidência + método de validação |

## Limitações conhecidas

- A detecção de hosts no hook cobre URLs e os comandos de rede conhecidos (curl, nmap, dig, openssl…). Um script arbitrário poderia abrir conexões sem passar por ela. Por isso o modo headless só libera uma lista fechada de comandos Bash.
- Em sessões interativas (`/vion:*` no Claude Code), o hook aplica só as regras de rede, porque leitura e escrita seguem as permissões normais do Claude Code.
- O consumo de tokens só é medido em execuções headless (`vion audit` / UI).
