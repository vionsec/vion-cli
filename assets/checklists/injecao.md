# Checklist VION — Injecao e XSS

### ETAPA 4 — VARREDURA DE INJECTION & XSS

```
Grep: \$\{.*req\.(body|query|params)             → template literals com input
Grep: (query|exec|raw)\s*\(.*(\+|`|\$\{)        → SQL injection (concatenacao)
Grep: innerHTML\s*=                               → XSS via innerHTML
Grep: dangerouslySetInnerHTML                     → XSS em React
Grep: document\.write\s*\(                        → XSS via document.write
Grep: eval\s*\(                                   → code injection
Grep: new\s+Function\s*\(                         → code injection
Grep: child_process|exec\s*\(|spawn\s*\(         → command injection
Grep: (readFile|createReadStream).*req\.(body|query|params)  → path traversal
Grep: \.\.\/ .*req\.|req\..*\.\.\/               → path traversal
Grep: (serialize|deserialize|pickle|marshal)      → deserialization
Grep: (redirect|location)\s*=.*req\.              → open redirect
Grep: (fetch|axios|got|request)\s*\(.*req\.(body|query|params)  → SSRF (Server-Side Request Forgery)
Grep: (url|uri|endpoint|host)\s*[:=]\s*req\.(body|query|params) → SSRF via input controlado
Grep: (net\.connect|dns\.lookup|http\.get)\s*\(.*req\.          → SSRF via modulos nativos
```

Para cada achado: leia o contexto completo (10 linhas antes e depois) para confirmar se e vulneravel ou se ja tem sanitizacao.
