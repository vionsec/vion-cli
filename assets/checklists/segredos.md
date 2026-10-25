# Checklist VION — Segredos e credenciais

### ETAPA 2 — VARREDURA DE SECRETS (execute buscas em paralelo)

Use Grep para buscar padroes perigosos em todo o projeto (excluindo node_modules, .git, dist, build):

```
Grep: password\s*=\s*["'][^"']+["']          → senhas hardcoded
Grep: (api[_-]?key|apikey)\s*[:=]\s*["'][^"']+  → API keys hardcoded
Grep: (secret|token)\s*[:=]\s*["'][^"']+["']   → secrets/tokens hardcoded
Grep: (AWS_ACCESS|aws_access|AWS_SECRET)        → credenciais AWS
Grep: (firebase|supabase|stripe)[A-Za-z_]*\s*[:=]\s*["'] → chaves de servico
Grep: -----BEGIN\s+(RSA|EC|DSA|PRIVATE)         → chaves privadas
Grep: mongodb(\+srv)?://[^/\s]+                  → connection strings
Grep: postgres(ql)?://[^/\s]+                    → connection strings
Grep: mysql://[^/\s]+                            → connection strings
Grep: (sk_live|pk_live|sk_test|rk_live)          → chaves Stripe
Grep: (ghp_|gho_|ghu_|ghs_|ghr_)               → tokens GitHub
Grep: xox[bporas]-                               → tokens Slack
Grep: Bearer\s+[A-Za-z0-9\-._~+/]+=*           → tokens Bearer hardcoded
Grep: process\.env\.\w+\s*\|\|\s*["'][^"']+     → fallbacks perigosos com valor real
```

Para cada achado: verifique se e valor real ou placeholder. Reporte apenas valores reais ou fallbacks perigosos.
