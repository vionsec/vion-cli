# Contribuindo com o VION

1. `npm install`, `npm run build:ui` e `npm test` devem passar.
2. **Comandos do CLI**: edite `src/cli/registry.js` (a ajuda e o `docs/COMMANDS.md` saem de la) e crie `src/cli/commands/<nome>.js` exportando `run({ positionals, values })`.
3. **Skills**:
   - o corpo fica em `assets/skills/<nome>.md`;
   - os metadados ficam em `src/cli/skills-meta.js`;
   - rode `npm run gen:docs` (o frontmatter e regenerado);
   - toda skill que gera achados termina com o bloco "Registro local" (MCP `vion`).
4. **Checklists** para subagentes: `assets/checklists/<nome>.md`. Elas aparecem no `checklist_list` e na UI automaticamente.
5. **Subagentes**: `assets/agents/vion-<papel>.md`, com `model: {{MODEL}}`. Adicione o papel em `ROLES`/`DEFAULT_CONFIG` (`src/core/config.js`).
6. **Analisadores**: funcoes puras em `src/analyzers/`, com teste em `src/analyzers/__tests__/`. Registre em `src/analyzers/run.js`.
7. Seguranca primeiro: nada de rede nova sem passar pelo escopo; nada de persistir texto sem `redactText`.

Commits pequenos e descritivos. Use issues para discutir mudancas grandes antes do PR.
