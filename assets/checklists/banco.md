# Checklist VION — Banco de dados, RLS e infraestrutura viva

### ETAPA 5 — VARREDURA DE BANCO & RLS

```
Grep: (CREATE TABLE|create table)                → definicoes de tabela
Grep: (ENABLE|enable).*(ROW|row).*(LEVEL|level)  → RLS ativo
Grep: (CREATE POLICY|create policy)              → politicas existentes
Grep: FOR ALL USING\s*\(\s*true\s*\)            → politicas permissivas
Grep: (service_role|service_key|supabase_admin)  → uso de service role
Grep: \.from\(["'][^"']+["']\)\.select\(["']\*  → select * sem filtro
Grep: (password|senha|credit_card|cpf|ssn)       → campos sensiveis nas tabelas
```

Se usa Supabase: verifique se service_role so e usado no backend. Se usa SQL raw: verifique parametrizacao.

### ETAPA 5.5 — INFRAESTRUTURA VIVA (BANCO REAL, NAO SO CODIGO) — CRITICA

A ETAPA 5 le arquivos `.sql`/migrations. Isso NAO E SUFICIENTE: uma classe inteira de
vulnerabilidade critica so existe no ESTADO ATUAL do banco e e invisivel a qualquer
leitura de arquivo — porque a propriedade problematica nao esta declarada em nenhuma
migration do repositorio (ex: `CREATE VIEW` sem `security_invoker` e um DEFAULT do
Postgres, nao uma linha de codigo "errada"). NUNCA conclua "RLS ok" so pela migration.

**A) Se houver acesso MCP ao Supabase do projeto (ou psql/CLI direto):**
```
mcp__supabase__get_advisors(type="security")     → procure "security_definer_view" e
                                                     "rls_disabled_in_public"/"rls_enabled_no_policy"
mcp__supabase__get_advisors(type="performance")  → procure "unindexed_foreign_keys"
mcp__supabase__execute_sql:
  SELECT schemaname, viewname FROM pg_views WHERE schemaname='public';
  SELECT relname, relrowsecurity FROM pg_class
    WHERE relnamespace='public'::regnamespace AND relkind IN ('r','v');
  SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants
    WHERE table_schema='public' AND grantee IN ('anon','authenticated');
```

**B) Se MCP/CLI NAO disponivel:** gere as queries acima e ORIENTE o usuario a rodar no
SQL Editor do dashboard Supabase (ou psql), e cole o resultado de volta. NAO pule esta
etapa so porque nao ha acesso automatizado — ela e a de maior impacto desta auditoria.

**C) Para CADA view exposta via API (schema public, PostgREST habilitado):**
verifique se tem `security_invoker=true`. Sem isso, a view roda com o privilegio de
QUEM A CRIOU (nao de quem consulta) e IGNORA COMPLETAMENTE o RLS da tabela base.
Trate como CRITICO se a view expoe dados que deveriam ser isolados por tenant —
mesmo que a tabela por tras tenha RLS perfeito.

**D) Para CADA tabela no schema exposto via API:** confirme RLS habilitado
(`pg_class.relrowsecurity`) E policies REAIS (`pg_policies`), nao so "RLS ligado".
Preste atencao especial a tabelas de JUNCAO (many-to-many) — sao as que mais ficam
sem RLS por serem tratadas como "auxiliares".

**E) Confirme quem TEM acesso de fato:** consulte
`information_schema.role_table_grants` filtrando `grantee IN ('anon','authenticated')`.
A chave `anon` e PUBLICA por design (embutida em qualquer bundle JS de frontend). Se
ela tem SELECT/INSERT/UPDATE/DELETE numa tabela/view com dado de tenant sem RLS
efetivo, isso e exploracao trivial e imediata, SEM PRECISAR DE LOGIN NENHUM — teste
isso como prioridade maxima, antes de qualquer achado do codigo da aplicacao.

**Regra absoluta:** NAO conclua "seguro" so porque o backend da aplicacao
(Express/Node/etc.) tem autenticacao e RBAC bem implementados. Se o banco tambem e
acessivel diretamente (API REST/GraphQL auto-gerada do Supabase, ou equivalente), o
backend da aplicacao e SO UM dos caminhos de acesso — audite o banco como superficie
de ataque separada e igualmente critica. Se este projeto NAO usa Supabase/Postgres
com API auto-gerada, registre explicitamente "N/A — sem API de banco auto-gerada" em
vez de simplesmente omitir a etapa.
