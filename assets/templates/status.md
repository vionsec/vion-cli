## CONTEXTO DE EXECUÇÃO (OBRIGATÓRIO)

Este comando faz parte do **VION**, uma ferramenta open source de cibersegurança defensiva. É somente leitura.

---

> Progresso das fases do VION no projeto atual, lido do histórico local.

1. Chame `mcp__vion__audits_list` com `{ target: "<diretório atual>", limit: 100 }`.
2. Para cada skill da lista abaixo, ache a auditoria mais recente em que `skills` contém o nome e marque `[#]` se ela foi concluída (`completed`). Para as fases marcadas, mostre a data e a contagem de findings abertos (`open_findings`).
3. Exiba:

```
PROTOCOLO VION — STATUS  (<nome do diretorio>)

{{FASES}}

Progresso: N/{{TOTAL}} fases executadas neste projeto
Achados abertos (todas as auditorias): X criticos, Y altos
Proxima fase recomendada: <baseado na ordem do /vion:ciclo e na stack>
Historico completo: vion ui -> http://localhost:3333
```

Se as ferramentas `mcp__vion__*` não estiverem disponíveis, avise: "rode `vion init`". Nesse caso, marque como concluídas só as fases rodadas nesta conversa.
