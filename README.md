# @vionsec/cli

> 🚧 **Pre-release placeholder.** This package is reserved while the real release is being built. Do not install yet.

VION Security CLI — secure-by-default installer and orchestrator for the VION Security agent.

## What this will be

A first-class command-line tool to install, authenticate, and operate the VION Security agent across:

- **Claude Code** (Anthropic)
- **Blackbox AI**
- **OpenAI Codex CLI**
- Generic terminal (Bash / PowerShell / Zsh)

It replaces the legacy `curl | bash` installer with:

```bash
npm install -g @vionsec/cli   # signed package, integrity-checked
vion login                    # OAuth/PKCE — token never touches the shell
vion install --cli=claude     # install agent files for the chosen CLI
vion watch start              # background fix-watcher
```

## Why a CLI

The current installer flow has well-known security issues that contradict VION's value proposition:

- `curl | bash` enables remote code execution.
- API tokens passed via `-H` leak to shell history, `ps`, telemetry.
- `--dangerously-skip-permissions` bypasses Claude Code safety controls.
- HTTP without TLS allows local MITM.

`@vionsec/cli` fixes all four by design.

## Status

`0.0.1` — name reservation only. The real public release will be `0.1.0+`. Track progress at https://vionsec.com.br.

## License

Apache-2.0 © 2026 VION Security
