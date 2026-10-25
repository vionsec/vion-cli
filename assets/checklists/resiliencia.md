# Checklist VION — Bugs silenciosos e resiliencia

### ETAPA 3.13 — BUGS OPERACIONAIS SILENCIOSOS (ERRO ENGOLIDO, COLUNA ERRADA)

Um processo que nao crasha, nao loga erro e nao afeta requisicoes visiveis pode
estar 100% quebrado ha tempo sem ninguem notar — o sintoma ("a feature X nao
roda") e indistinguivel de "nao ha trabalho a fazer agora".

```
Grep: const\s*\{\s*data\s*\}\s*=\s*await\s+supabase   → destructuring SEM error
```

1. Para TODA chamada ao cliente Supabase/ORM: confirme que TANTO `data` QUANTO
   `error` sao desestruturados e que `error` e checado ANTES de usar `data`.
   `const { data } = await supabase...` sem checar erro e sempre suspeito — a
   query pode falhar silenciosamente (retorna `data: null`, nao lanca excecao).
2. Para nomes de coluna usados em filtros (`.eq()`, `.select()`): se houver
   acesso MCP ao banco real (ver ETAPA 5.5), confirme o nome da coluna DIRETO NA
   FONTE (`information_schema.columns`) antes de aceitar que o codigo bate com a
   migration — schema real diverge de migration quando ha ambientes multiplos ou
   alteracoes manuais.
3. Trate "esta chamado num `setInterval`/cron/worker mas nunca ha log de
   sucesso nem de erro" como sinal de alerta ATIVO, nao como ausencia de
   problema — peca pra confirmar que o efeito esperado (ex: jobs enfileirados,
   registros atualizados) esta de fato acontecendo.

### ETAPA 9.7 — RESILIENCIA E RAIO DE EXPLOSAO (NAO E SO "QUEM PODE ACESSAR")

Reporte junto aos achados de seguranca — nao e "inseguro" no sentido classico,
mas afeta se o sistema aguenta uso real:

1. **Rate limit por custo, nao por rota generica**: uma rota cara (relatorios,
   exports, scans, geracao de PDF/IA) com o MESMO teto de um GET simples e um
   vetor de abuso/DoS. `Grep: rate.?limit|throttle` — para cada rota
   identificada como pesada (I/O, calculo, chamada externa), o teto e
   proporcional ao custo?
2. **Handler global de erro assincrono**: sem `process.on('unhandledRejection')`
   e `process.on('uncaughtException')`, um erro isolado em UMA requisicao pode
   derrubar o processo inteiro — todos os tenants juntos.
   `Grep: unhandledRejection|uncaughtException` — se ausente, reporte como
   achado (blast radius, nao autorizacao).
3. **MIME validado so por Content-Type declarado**: `Content-Type` vem do
   cliente e e falsificavel. `Grep: req\.file.*mimetype|Content-Type.*upload` —
   uploads devem validar por magic bytes (assinatura real do arquivo), nao so
   pelo header declarado. Se parte do projeto ja valida por magic bytes e outra
   parte nao, reporte a inconsistencia — um padrao correto existindo em algum
   lugar do codigo NAO garante que foi aplicado em todo lugar que deveria.
4. **N+1 queries**: `Grep: for\s*\(.*of.*\)|\.map\(async` seguido de query
   dentro do loop — especialmente em endpoints de listagem/configuracao e em
   crons.
