# Checklist VION — API e endpoints

### ETAPA 6 — VARREDURA DE API & ENDPOINTS

```
Grep: (app|router)\.(get|post|put|patch|delete)\s*\(  → rotas definidas
Grep: cors\(                                     → configuracao CORS
Grep: origin:\s*["']\*["']|origin:\s*true        → CORS permissivo
Grep: (helmet|security-headers|csp)              → headers de seguranca
Grep: (rate.?limit|throttle|brute)               → rate limiting
Grep: (upload|multer|formidable|busboy)          → upload de arquivos
Grep: res\.(json|send)\(.*\{.*error.*stack       → stack trace em response
Grep: console\.(log|error|warn)\(.*password      → log de dados sensiveis
Grep: catch.*res\.(json|send).*err\.(message|stack)  → erro expondo internals
```

Para cada rota encontrada: verifique se tem auth middleware, validacao de input, rate limiting.
