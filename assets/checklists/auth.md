# Checklist VION — Autenticacao, autorizacao e zero trust

### ETAPA 3 — VARREDURA DE AUTENTICACAO & AUTORIZACAO

```
Grep: (verify|decode|sign)(Token|JWT|Jwt)       → implementacao de JWT
Grep: algorithm.*["'](none|HS256)["']           → algoritmos fracos
Grep: expiresIn.*["'](\d+d|\d{5,})["']          → expiracao longa
Grep: localStorage\.(set|get)Item.*token         → tokens em localStorage
Grep: (req\.user|req\.session|currentUser)       → pontos de autenticacao
Grep: (isAdmin|isAuth|requireAuth|protect)       → middleware de auth
Grep: role.*["'](admin|user|public)["']          → controle de roles
Grep: \.skip\(.*auth|noAuth|public.*true         → bypass de auth
```

Leia cada arquivo encontrado e analise:
- JWT sem verificacao de assinatura
- Tokens sem expiracao ou com expiracao >24h para access tokens
- Ausencia de refresh token rotation
- Roles verificados apenas no frontend
- Rotas de API sem middleware de auth
- Ausencia de rate limiting em login/register

### ETAPA 3.5 — ZERO TRUST: INTERCEPTACAO BURP SUITE (OBRIGATORIA)

O backend NUNCA confia no frontend. Qualquer resposta da API pode ser interceptada via Burp Suite, modificada, e o frontend aceitar. Verifique TODOS estes pontos:

**A) Logica de negocio no frontend**
```
Grep: plan\.maxPhase|plan\.hasAgent|plan\.hasMonitoring|hasAccess|isLocked  → flags que controlam acesso no frontend
Grep: (PLANS|plans)\s*[=\{]                                                → objetos de plano hardcoded no JS
Grep: getUserPlan|buildUser|user\.plan|user\.role.*===                      → decisoes baseadas em dados da API
Grep: disabled.*quota|disabled.*can_scan|disabled.*remaining               → botoes desabilitados por dados da API
Grep: (price|preco|valor).*=.*[0-9]                                        → precos calculados no frontend
```

**B) Para cada achado, verifique:**
1. O frontend usa esse valor para BLOQUEAR acesso ou apenas para EXIBIR?
2. Se bloqueia: o backend valida INDEPENDENTEMENTE no endpoint correspondente?
3. Um atacante com Burp Suite pode modificar a resposta da API e desbloquear?
4. O endpoint alvo rejeita a requisicao se o plano real nao permite?

**C) Cenarios de ataque obrigatorios (adapte aos nomes reais do projeto):**
- Interceptar o endpoint de perfil/sessao (ex.: `/api/me`) e trocar o plano/tier por um superior — o que desbloqueia?
- Interceptar a resposta de quota/limite e trocar `false` por `true` — o botao habilita e o backend aceita?
- Trocar `role: "user"` por `role: "admin"` na resposta — o painel admin aparece? As chamadas admin passam?

**D) Enforcement server-side em CADA endpoint protegido:**
```
Grep: (plan|tier|role|quota|limit|credits)  nos handlers do backend → a decisao e tomada no servidor, com dado do banco?
Read: cada handler de acao paga/admin/limitada → valida plano/role/quota ANTES de executar?
```

**Regra absoluta:** Se o frontend decide acesso baseado em dados da API sem enforcement server-side, e CRITICO. O frontend e SOMENTE visual — toda decisao de acesso e do backend.

### ETAPA 3.10 — IDOR EM ENDPOINTS DO USUARIO (/my-*)

Endpoints que retornam dados do usuario autenticado NUNCA devem:
1. Aceitar `user_id` como query param ou body param
2. Filtrar por IP em vez de userId (IPs sao compartilhados em redes corporativas)
3. Retornar metadata que contenha dados de outros usuarios
4. Permitir que um usuario veja strikes/alertas de outro

Verifique:
```
Read: cada endpoint "meu/minha" (/me, /my-*, /account) → userId vem APENAS do token? Nunca de query/body?
Grep: req.query.user_id|req.body.user_id|req.params.user → nenhum endpoint /my-* deve aceitar isso
```

**Regra:** Dados do usuario = extraidos do token server-side. NUNCA do request.
**Se algum endpoint /my-* aceitar user_id externo:** CRITICO.

### ETAPA 3.11 — FAIL-OPEN EM CODIGO DE SEGURANCA (TABELA-VERDADE OBRIGATORIA)

Para TODO trecho de codigo de seguranca (checagem de permissao, ativo/inativo,
allowlist/denylist, validacao de token, feature flag) que usa optional chaining
(`?.`) combinado com comparacao (`!==`, `===`, `==`, `!=`): pare e avalie
EXPLICITAMENTE o caso em que o valor a esquerda do `?.` e `null`/`undefined`.

Exemplo do bug real que este check existe pra pegar: `const ativo = data?.ativo !== false`
— quando `data` e `null` (entidade nao encontrada), a expressao avalia pra `true`
(trata como ATIVA), o OPOSTO do que um comentario ao lado costuma afirmar ("trata
como inativa"). O comentario engana quem so le; o teste nao.

```
Grep: \?\.\w+\s*(!==|===|==|!=)\s*(true|false|null|undefined)
```

Para CADA match: escreva a tabela-verdade das 2-3 combinacoes possiveis (valor
real, `null`, `undefined`) e confirme que o resultado bate com a intencao
declarada (comentario, nome da variavel, uso downstream). Trate qualquer
divergencia como achado CRITICO se o trecho controla acesso/autorizacao, mesmo
que pareca edge case raro — em codigo de autorizacao, "raro" ainda e exploravel
(basta o registro nao existir, o que um atacante pode forcar).
