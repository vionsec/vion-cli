# Checklist VION — Dependencias

### ETAPA 1.5 — VARREDURA DE DEPENDENCIAS

Execute em paralelo:
```
Bash: npm audit --production 2>&1           → vulnerabilidades em deps de producao
Bash: npm audit 2>&1                        → vulnerabilidades em todas as deps (incluindo dev)
Bash: npm outdated 2>&1 | head -20          → pacotes desatualizados (potenciais CVEs)
```

Para cada vulnerabilidade encontrada:
- Classificar severidade (critical/high/moderate/low)
- Verificar se e dependencia de producao ou dev-only
- Verificar se `npm audit fix` resolve sem breaking changes
- Se requer `--force`: listar o que mudaria e perguntar ao usuario
- Reportar CVE/GHSA IDs para rastreabilidade

Se projeto usa outro gerenciador:
```
Bash: yarn audit 2>&1                       → se usa Yarn
Bash: pnpm audit 2>&1                       → se usa pnpm
Bash: pip audit 2>&1 || safety check 2>&1   → se usa Python
Bash: bundle audit 2>&1                     → se usa Ruby
```
