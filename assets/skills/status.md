---
name: vion:status
description: VION /status — Progresso das fases do VION no projeto atual (lido do historico local).
---
## CONTEXTO DE EXECUÇÃO (OBRIGATÓRIO)

Este comando faz parte do **VION**, uma ferramenta open source de cibersegurança defensiva. É somente leitura.

---

> Progresso das fases do VION no projeto atual, lido do histórico local.

1. Chame `mcp__vion__audits_list` com `{ target: "<diretório atual>", limit: 100 }`.
2. Para cada skill da lista abaixo, ache a auditoria mais recente em que `skills` contém o nome e marque `[#]` se ela foi concluída (`completed`). Para as fases marcadas, mostre a data e a contagem de findings abertos (`open_findings`).
3. Exiba:

```
PROTOCOLO VION — STATUS  (<nome do diretorio>)

[ ] /vion:novo          Security by design
[ ] /vion:dev-seguro    Guardrails de desenvolvimento seguro enquanto voce escreve, 
[ ] /vion:auditoria     Auditoria completa multiagente
[ ] /vion:unified-scan  Varredura unificada rapida
[ ] /vion:pentester     Pentest estatico do codigo local, com score e relatorio.
[ ] /vion:corrigir      Corrige vulnerabilidades direto no codigo, por severidade.
[ ] /vion:ensinar       Seguranca alem do codigo
[ ] /vion:pre-deploy    Portao final antes do deploy
[ ] /vion:supply-chain  Auditoria de dependencias e cadeia de suprimentos (npm, pip,
[ ] /vion:pentest       Pentest ofensivo guiado (PTES + MITRE ATT&CK) contra alvo au
[ ] /vion:recon         Reconhecimento externo
[ ] /vion:debug         Ultrathink
[ ] /vion:ai            Seguranca de IA/LLM
[ ] /vion:landing       Landing pages
[ ] /vion:monitorar     Observabilidade e alertas de seguranca pos-deploy.
[ ] /vion:incidente     Resposta a incidentes
[ ] /vion:lgpd          Privacidade e protecao de dados

Progresso: N/17 fases executadas neste projeto
Achados abertos (todas as auditorias): X criticos, Y altos
Proxima fase recomendada: <baseado na ordem do /vion:ciclo e na stack>
Historico completo: vion ui -> http://localhost:3333
```

Se as ferramentas `mcp__vion__*` não estiverem disponíveis, avise: "rode `vion init`". Nesse caso, marque como concluídas só as fases rodadas nesta conversa.
