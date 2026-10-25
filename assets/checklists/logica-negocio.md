# Checklist VION — Logica de negocio (SaaS BR)

### ETAPA 9.5 — VULNERABILIDADES SAAS BR (KatrinaSec 2026)

12 falhas mais comuns em SaaS brasileiros — scanner automatico NAO acha. Verifique CADA uma sistematicamente.

#### CATEGORIA A — Logica de negocio

**[CRITICO] V_BR_01 — IDOR (Insecure Direct Object Reference)**
- Endpoints com IDs sequenciais nao validam ownership do recurso
- Detecte:
  - Grep: `/api/.*\\[id\\]|/api/.*/:id|app\\.get\\(.*:id` — todos os handlers de GET por id
  - Para cada: o codigo filtra por userId/orgId do JWT ANTES de retornar?
  - Padroes vulneraveis: `db.find(id)` sem `WHERE owner_id = currentUser.id`
  - Padroes seguros: `db.findOne({ id, owner_id: currentUser.id })` ou RLS no DB
  - NAO amostre alguns endpoints e conclua "o padrao esta sendo seguido". ENUMERE
    TODOS: liste TODAS as rotas `:id` (GET/PUT/PATCH/DELETE) do projeto e, para
    CADA uma, confirme se o filtro de tenant/owner esta de fato no WHERE/eq() da
    query — nao apenas presente na assinatura da funcao sem ser usado.
  - Se este projeto ja corrigiu IDOR numa rodada anterior (padrao ja estabelecido
    em alguns modulos), procure EXPLICITAMENTE os modulos que ficaram de fora
    dessa correcao — normalmente sao os mais recentes ou os "auxiliares"
    (configuracao, catalogos, papeis/roles), nao os modulos de negocio principais
    ja auditados.
  - Reporte a contagem como prova, nao como formalidade: "checados N/N endpoints
    :id, M passaram, K falharam". "O padrao existe no projeto" sozinho NAO e
    prova de seguranca.
- Cenario de teste: login conta A, capture URL `/api/orders/9981`, cole na sessao da conta B
- Impacto: vazamento direto entre tenants, multa LGPD ate R$ 50mi

**[CRITICO] V_BR_02 — Race condition em fluxo de pagamento / credito**
- Fluxos "uma vez por usuario" (cupom, free trial, indicacao, credito) sem lock atomico
- Detecte:
  - Grep: `cupom|coupon|credito|credit|trial|indicacao|referral|redeem`
  - Para cada match: o codigo usa transacao ou WHERE com condicao de check no UPDATE?
  - Padroes vulneraveis: `SELECT used FROM coupons; if (!used) { UPDATE used=true; apply() }` (TOCTOU)
  - Padroes seguros: `UPDATE coupons SET used=true WHERE id=$1 AND used=false RETURNING *` (atomico)
- Cenario de teste: 50 requests em paralelo no Burp Intruder modo Pitchfork
- Impacto: dano financeiro direto

**[ALTO] V_BR_03 — Bypass de plano (frontend feature flag)**
- Frontend esconde feature do plano superior, backend NAO revalida
- Detecte:
  - Grep: `hasAccess|isLocked|plan\\.has|plan\\.maxPhase|features\\.`
  - Para cada match: o endpoint correspondente revalida plano server-side via DB (nao do JWT/cookie)?
  - Tente: `curl -X POST /api/feature-do-plano-superior` com conta do plano inferior — retorna 200?
- Impacto: erosao de receita silenciosa, cliente Starter usando recursos Pro

#### CATEGORIA B — Autenticacao

**[CRITICO] V_BR_04 — JWT mal implementado**
- Tres erros classicos: `alg: none` aceito, secret fraco, sem expiracao
- Detecte:
  - Grep: `jwt\\.verify|verifyJwt|decodeToken`
  - No codigo: `algorithm` esta EXPLICITO como ['HS256'] (nao incluindo 'none')?
  - Grep: `JWT_SECRET` — vem de env? Tem fallback hardcoded? Length >= 32?
  - Grep: `expiresIn` — todo token tem? Access token <= 1h? Refresh com rotacao?
  - Tente: pegue token, mude header pra `{"alg":"none"}`, remova signature, mande na request
- Impacto: account takeover total

**[CRITICO] V_BR_05 — 2FA bypass**
- Race no codigo OTP, recuperacao sem 2FA, OAuth/SSO sem 2FA
- Detecte:
  - Grep: `totp|2fa|two.?factor|otp_code|verifyCode`
  - Endpoint de verificacao tem rate limit (max 5 tentativas/min/conta)?
  - Fluxo /reset-password — apos reset, sessao nova requer 2FA?
  - Callback OAuth — 2FA e exigido na federacao tambem?
- Impacto: account takeover

**[CRITICO] V_BR_06 — Password reset poisoning (Host header)**
- Link de reset construido com `req.headers.host`, atacante manda `Host: evil.com`
- Detecte:
  - Grep: `req\\.headers\\.host|req\\.host|req\\.get\\(['"]host`
  - Para cada match: e usado em construcao de URL/email/redirect?
  - Padrao seguro: usar `PUBLIC_APP_URL` fixo de env, NUNCA `req.headers.host`
- Cenario de teste: `POST /password-reset` com header `Host: evil.com` — link no email aponta pra onde?
- Impacto: phishing assinado pelo proprio dominio

#### CATEGORIA C — API e dados

**[CRITICO] V_BR_07 — SSRF (Server-Side Request Forgery)**
- App aceita URL do user e faz fetch server-side (avatar, webhook, import-de-URL)
- Detecte:
  - Grep: `fetch\\(|axios\\(|got\\(|http\\.get\\(.*req\\.(body|query|params)`
  - Grep: `webhook_url|callback_url|avatar_url|import_url`
  - Para cada: tem allowlist? Bloqueia `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `169.254.169.254` (AWS metadata), `localhost`?
- Cenario de teste: aponte feature pra `http://localhost:3001/api/` ou `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- Impacto: vazamento de credenciais cloud, acesso a servicos internos

**[ALTO] V_BR_08 — GraphQL com introspection em producao**
- Query `__schema` retorna estrutura inteira da API
- Detecte:
  - Grep: `GraphQL|apollo|graphql-yoga|mercurius`
  - Se existir: `NODE_ENV=production` desliga introspection? (`introspection: false`)
  - Tente: `POST /graphql` com `{"query":"{ __schema { types { name } } }"}` — retorna schema completo?
  - Bonus: queries aninhadas profundas (10+ niveis) sem rate limit causam DoS
- Impacto: reconhecimento facilitado pra atacante

**[ALTO] V_BR_09 — Exposicao de PII em logs**
- Codigo loga `req.body` inteiro com password, CPF, cartao, token
- Detecte:
  - Grep: `console\\.(log|info|error)\\(.*req\\.body|logger\\..*req\\.body`
  - Grep: `JSON\\.stringify\\(req\\.body|JSON\\.stringify\\(user\\b`
  - Tem util de redact? (`redact(password|token|api_key|cpf|card_number)`)
  - Em logs reais (Sentry/CloudWatch/DataDog): busca `\\d{11}` (CPF), `password`, `Authorization: Bearer`, `card_number`
- Impacto: compliance LGPD/PCI quebrado, vazamento subnotificado

#### CATEGORIA D — Permissao e isolamento

**[CRITICO] V_BR_10 — Privilege escalation via mass assignment**
- Endpoint `PATCH /users/me` aceita body inteiro, ORM faz assign automatico em todos os campos
- Detecte:
  - Grep: `PATCH|PUT.*users.*me|profiles?\\.update|user\\.update`
  - Para cada update endpoint: tem allowlist EXPLICITA de campos?
  - Padroes vulneraveis: `User.update(req.body)` ou `Object.assign(user, req.body)` ou `User.update({...req.body})`
  - Padroes seguros: `pickAllowed(req.body, ['name','email','avatar_url'])`
- Cenario de teste: `PATCH /users/me` com body `{"role":"admin","plan":"enterprise","is_admin":true,"verified_at":"2026-01-01"}` — algum campo foi aplicado?
- Impacto: cliente vira admin do proprio sistema

**[CRITICO] V_BR_11 — Multi-tenancy leak**
- `WHERE tenant_id = X` esquecido em alguma query rara (relatorio consolidado, exports, busca)
- Detecte:
  - Grep: `\\.from\\(|\\.find\\(|\\.select\\(|\\.aggregate\\(` — TODAS as queries
  - Para cada: tem filtro por tenant_id/org_id/user_id no WHERE/JOIN?
  - Se Supabase: RLS esta ATIVO em TODAS as tabelas com dados de cliente? `SELECT tablename, rowsecurity FROM pg_tables`
- Cenario de teste: crie 2 contas em tenants A e B, crie dado "TESTE_LEAK_B" no tenant B, use cada feature (relatorios, exports, busca, listagens) com a conta A — procure "TESTE_LEAK_B"
- Impacto: vazamento entre clientes B2B, contrato destruido

**[CRITICO] V_BR_12 — Endpoint admin / interno exposto**
- Rotas `/admin`, `/api/internal`, `/debug`, `/swagger`, `/metrics`, `/.git`, `/_health` acessiveis publicamente
- Detecte:
  - Grep: rotas `admin|internal|debug|swagger|metrics` — cada uma tem middleware de auth admin?
  - Source maps em prod? `Glob: **/dist/**/*.map` — se existirem em prod, vazam codigo
  - `.env` no servidor estatico? `/dist/.env`, `/public/.env`?
  - Em prod tente: `GET /.env`, `GET /.git/config`, `GET /backup.zip`, `GET /dump.sql`
- Impacto: alta a critica, dependendo do que esta exposto

---

**Score adicional desta etapa:**
- Se 5+ vulnerabilidades V_BR_* presentes: score base maximo 40/100
- Cada V_BR_* CRITICO encontrado: -10 pontos
- Cada V_BR_* ALTO encontrado: -5 pontos
- Reporte cada um no JSON final como `{"severity":"critico|alto", "title":"V_BR_NN — Titulo", "file":"...", "fix":"..."}`

### ETAPA 9.6 — LOGICA DE NEGOCIO PROFUNDA (V_BR_13..V_BR_19)

Extensao da 9.5 — falhas de regra de negocio que scanner NAO acha (exigem entender o FLUXO do sistema). Verifique CADA uma. Reporte cada achado com o CWE id.

**[CRITICO] V_BR_13 — Bypass de maquina de estados / fluxo multi-etapas (CWE-841)**
- Endpoint de uma etapa pode ser chamado sem completar as anteriores: marcar "pago" sem pagar, concluir onboarding sem verificar e-mail, pular KYC/aprovacao.
- Detecte:
  - Grep: status\s*[:=]\s*['"](paid|approved|active|completed|verified|shipped) — transicoes de estado
  - Grep: rotas /checkout|/confirm|/finalize|/activate|/approve|/complete — cada uma valida no DB que a etapa anterior ocorreu (nao confia no body)?
  - Padrao vulneravel: order.status = req.body.status, ou setar estado final sem checar o estado atual
  - Padrao seguro: maquina de estados server-side (if (order.status !== 'pending') reject) + transicao atomica
- Cenario de teste: chame POST /orders/:id/finalize direto, sem passar por /pay — o pedido vira pago?
- Impacto: fraude, produto/servico liberado sem pagamento

**[CRITICO] V_BR_14 — Adulteracao de valor, preco e quantidade (CWE-840)**
- Valor/preco/quantidade vem do cliente e e usado sem revalidar no servidor.
- Detecte:
  - Grep: (amount|price|total|qty|quantity|valor|preco|desconto)\s*[:=]\s*req\.(body|query)
  - Quantidade negativa, zero, decimal ou overflow sao rejeitadas? O preco e SEMPRE recalculado server-side a partir do catalogo (nunca confiado do body)? Soma de descontos pode passar de 100%?
  - Padrao seguro: price = catalog[productId].price no servidor; if (!Number.isInteger(qty) || qty <= 0) reject
- Cenario de teste: POST /cart com {"price":0.01} ou {"qty":-5} (gera credito/refund?) — o servidor aceita?
- Impacto: dano financeiro direto

**[ALTO] V_BR_15 — Enumeracao de contas (CWE-204)**
- Login/registro/esqueci-senha revelam se um e-mail existe (mensagem OU tempo de resposta diferentes).
- Detecte:
  - Grep: mensagens que distinguem (nao encontrado|not found|usuario inexistente|ja existe|already exists)
  - Login com user inexistente: msg/status/tempo difere de senha errada? (timing: se o bcrypt so roda quando o user existe, vira oraculo temporal)
  - /forgot-password responde "enviamos um e-mail" SEMPRE, mesmo pra e-mail inexistente?
  - Padrao seguro: resposta generica identica; rodar hash dummy em constant-time mesmo pra user inexistente
- Cenario de teste: compare 2 logins (e-mail real vs inexistente) em corpo, status e latencia
- Impacto: lista valida de clientes pra phishing/credential stuffing

**[ALTO] V_BR_16 — Replay e falta de idempotencia (CWE-294)**
- Requisicao repetida gera efeito duplicado (cobranca/recurso dobrado) ou webhook/OTP reusado.
- Detecte:
  - Grep: rotas webhook — validam assinatura E timestamp (rejeitam evento antigo)? Dedupe por event_id?
  - Grep: idempotency|Idempotency-Key — mutacoes financeiras aceitam/exigem chave de idempotencia?
  - OTP/token de reset: invalidado apos 1 uso? Expira?
  - Padrao seguro: INSERT ... ON CONFLICT (event_id) DO NOTHING; OTP single-use; guard de double-submit
- Cenario de teste: reenvie o mesmo webhook 5x; reenvie POST /pay 2x sem idempotency-key
- Impacto: cobranca/credito duplicado, replay de eventos

**[CRITICO] V_BR_17 — BFLA: autorizacao em nivel de funcao (CWE-862)**
- IDOR (V_BR_01) e sobre OBJETO; BFLA e sobre ACAO — role inferior chama uma FUNCAO privilegiada.
- Detecte:
  - Grep: handlers de acao sensivel (delete-user|update-plan|refund|impersonate|export|invite|change-role|approve)
  - Para CADA: alem de autenticar, valida o ROLE/permissao da ACAO no servidor (nao so ownership do objeto)?
  - Verbo escondido: o front so mostra o botao pra admin, mas o endpoint aceita qualquer usuario autenticado?
  - Padrao seguro: requireRole('admin') no proprio handler, lido do DB
- Cenario de teste: como user comum, chame POST /api/<acao-de-admin> direto — retorna 200?
- Impacto: escalada vertical de privilegio

**[ALTO] V_BR_18 — Entitlement persiste apos downgrade/cancelamento (CWE-613)**
- Usuario faz downgrade/cancela mas mantem features do plano antigo enquanto a sessao/token durar.
- Detecte:
  - O plano/role e lido do JWT/cookie (estatico ate expirar) ou revalidado do DB a cada acao sensivel?
  - Grep: plan_status|subscription_status|canceled|past_due — features pagas checam o status ATUAL antes de liberar?
  - Apos webhook de cancelamento, sessoes ativas perdem acesso na hora ou so no proximo login?
  - Padrao seguro: gate le plan_status do DB em tempo real; encurtar/revogar sessao no downgrade
- Cenario de teste: logue, cancele via painel/Stripe e continue usando feature paga na mesma aba
- Impacto: erosao de receita, uso pago apos cancelar

**[ALTO] V_BR_19 — Abuso de funcionalidade legitima / exfiltracao em massa (CWE-799)**
- Conta legitima usa um recurso valido em VOLUME desumano pra raspar/exfiltrar dados ou ativos do servidor.
- Detecte:
  - Endpoints que servem ativos de valor (relatorios, prompts, listas, exports, conteudo pago): tem teto de VOLUME por conta/dia, alem do rate-limit por minuto?
  - Ha deteccao de padrao anomalo (1 conta consumindo N x a media; varredura sequencial de IDs; horario robotico)?
  - Conteudo sensivel tem marca dagua/rastreio por usuario pra atribuir vazamento?
  - Padrao seguro: quota de volume por conta + alerta de anomalia + watermark por usuario
- Cenario de teste: com 1 conta paga, itere/baixe o maximo de um recurso de valor — existe teto e alerta?
- Impacto: roubo de propriedade intelectual por dentro (abuso por conta paga)

**Score adicional desta etapa:**
- Cada V_BR_* CRITICO: -10 | cada V_BR_* ALTO: -5
- Reporte cada achado com o CWE id e, no JSON final, como {"severity":"critico|alto","title":"V_BR_NN — ...","file":"...","fix":"..."}
