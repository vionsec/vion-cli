# Checklist VION — Configuracao, containers, CI/CD

### ETAPA 7 — VARREDURA DE CONFIGURACAO & EXPOSICAO

```
Grep: (source.?map|sourceMappingURL)             → source maps em producao
Grep: (debug|DEBUG)\s*[:=]\s*(true|1|["']true)   → debug mode ativo
Grep: (x-powered-by|server:)                     → headers reveladores
Grep: (TODO|FIXME|HACK|XXX).*secur               → notas de seguranca pendentes
Bash: git log --all --diff-filter=D -- "*.env*"  → .env deletado mas no historico
Bash: git log --all -p -S "password" --           → senhas no historico git (limitar a 20 resultados)
```

### ETAPA 8 — VARREDURA DE CONTAINERS & INFRA

```
Glob: **/Dockerfile*                                → Dockerfiles
Glob: **/docker-compose*.{yml,yaml}                 → Compose files
Glob: **/.dockerignore                              → Docker ignore
Grep: FROM.*:latest                                 → imagem sem tag fixa (supply chain risk)
Grep: (USER|user)\s+(root|0)                        → container rodando como root
Grep: (EXPOSE|expose)\s+(22|3306|5432|27017)        → portas sensiveis expostas
Grep: (ADD|COPY)\s+\.\s+                            → copiando tudo (pode incluir .env, .git)
Grep: (--privileged|privileged:\s*true)              → container privilegiado
Grep: (cap_add|SYS_ADMIN|NET_ADMIN)                 → capabilities perigosas
Grep: (secrets|password|token).*environment:         → secrets em compose como env vars
```

Se Dockerfile existir:
- Verificar se `.dockerignore` exclui `.env`, `.git`, `node_modules`
- Verificar multi-stage build (imagem final nao deve ter ferramentas de build)
- Verificar se usa usuario nao-root (`USER app` ou similar)

### ETAPA 9 — VARREDURA DE CI/CD & WORKFLOWS

```
Glob: **/.github/workflows/*.{yml,yaml}             → GitHub Actions
Glob: **/.gitlab-ci.yml                             → GitLab CI
Glob: **/Jenkinsfile                                → Jenkins
Glob: **/.circleci/config.yml                       → CircleCI
Grep: \$\{\{\s*secrets\.                            → uso de secrets em workflows
Grep: (actions/checkout|uses:).*@(master|main|v\d)  → actions sem hash pinning
Grep: (npm publish|docker push|deploy)              → acoes de deploy
Grep: (curl|wget).*\|\s*(bash|sh)                   → pipe to shell (RCE risk)
Grep: (pull_request_target|workflow_dispatch)        → triggers perigosos
Grep: (permissions:\s*write-all|contents:\s*write)  → permissoes excessivas
Grep: (GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)           → tokens em logs
```

Para cada workflow:
- Verificar se actions usam SHA pinning (`@sha256:xxx` em vez de `@v3`)
- Verificar se `pull_request_target` tem checkout seguro
- Verificar se secrets nao sao logados (`echo $SECRET`)
- Verificar permissoes minimas (principle of least privilege)

### ETAPA 3.12 — CONFIG DE PRODUCAO vs DEV (CSP/CORS/ENV PIPELINE)

Rodar/testar em dev nunca revela este tipo de bug — o fallback de dev mascara o
problema. Pergunte explicitamente: "se eu fizesse o primeiro deploy real agora,
com o dominio de producao, isso funcionaria?" — nao so "isso esta seguro?".

1. Para toda config de seguranca client-side que lista origens/dominios (CSP
   `connect-src`, `CORS_ORIGIN`, allowlist de redirect): confirme que o DOMINIO
   DE PRODUCAO REAL esta presente, nao so `localhost`/IPs de dev. Se a config
   vem de env var, confirme que ela e de fato POPULADA no pipeline de deploy
   (Dockerfile `ARG`/`ENV`, docker-compose `environment`/`args`,
   `.env.prod.example`) — nao assuma que "existe uma env var" significa "esta
   conectada ponta a ponta".
   ```
   Grep: connect-src|CORS_ORIGIN|COOKIE_DOMAIN|NEXT_PUBLIC_BASE_DOMAIN|ALLOWED_ORIGINS
   ```
2. Para toda feature que depende de multiplos subdominios/hosts (SSO,
   white-label, multi-regiao): enumere TODOS os hosts envolvidos (grep no proxy
   reverso/Caddyfile/nginx.conf/vercel.json) e confirme que CADA um esta
   coberto pela allowlist de CORS/CSP — nao so o host "principal".
3. Se encontrar env var declarada em `.env.example` mas ausente do
   Dockerfile/docker-compose/pipeline de deploy: reporte como achado de
   "prontidao pra producao" mesmo que nao seja um bug de seguranca classico — a
   feature pode estar perfeitamente segura E completamente nao-funcional em prod.
