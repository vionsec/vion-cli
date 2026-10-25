# Checklist VION — Reconhecimento e superficie de ataque

### ETAPA 1 — RECONHECIMENTO (execute tudo em paralelo)

Use Glob e Read para mapear o projeto:
- `Glob("**/package.json")` — identificar stack e dependencias
- `Glob("**/*.env*")` e `Glob("**/.env*")` — arquivos de ambiente
- `Glob("**/.gitignore")` — verificar se .env esta ignorado
- `Glob("**/docker-compose*.{yml,yaml}")` — configs de infra
- `Glob("**/{tsconfig,vite,next,nuxt,webpack}.config.*")` — configs de build
- `Glob("**/middleware*")` e `Glob("**/auth*")` — arquivos de autenticacao
- `Glob("**/{routes,router,api}/**")` — endpoints
- `Glob("**/migrations/**")` e `Glob("**/schema*")` — banco de dados
- Leia o `package.json` principal para entender frameworks e scripts

Entregue: resumo da stack, estrutura do projeto, superficie de ataque identificada.
