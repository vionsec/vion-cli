# @vionsec/cli

> First public release — `0.1.0`. Beta. Bug reports → https://github.com/vionsec/vion-cli/issues

VION Security CLI — secure-by-default installer and orchestrator for the VION
Security agent across Claude Code, Blackbox AI, OpenAI Codex, and generic terminals.

```bash
npm install -g @vionsec/cli
vion login                       # OAuth/PKCE — token never touches the shell
vion install --cli=claude        # writes agent files for the chosen CLI
vion watch start                 # background fix-watcher (auto-applies approvals)
```

## Why a CLI

The legacy `curl | bash` installer combined four well-known anti-patterns that
contradict VION's value proposition:

| Anti-pattern | Risk | `@vionsec/cli` fixes by |
|---|---|---|
| `curl ... \| bash` | Remote code execution | npm package with integrity check |
| Bearer token in `-H` | Token leaks to `~/.bash_history`, `ps`, terminal telemetry | OAuth/PKCE — token only ever lives in the CLI process and `~/.vion/credentials.json` (chmod 600) |
| `claude --dangerously-skip-permissions` | Bypasses Claude Code safety controls | The CLI no longer auto-launches with that flag in onboarding |
| `http://` without TLS | Local MITM | Default API URL is HTTPS; HTTP only allowed for localhost dev |

## Commands

### `vion login`
Browser-based OAuth flow with PKCE (RFC 7636). Generates a fresh API key
server-side; any previous key is revoked.

```bash
vion login
vion login --api-url http://localhost:3001     # dev
VION_API_URL=https://staging.vionsec.com.br vion login
```

### `vion install --cli=<name>`
Generates the orchestration files for one of:

- `claude` — writes `~/.claude/commands/vion/*.md`
- `blackbox` — writes `.blackbox/skills/vion/SKILL.md` (cwd-relative)
- `codex` — writes `~/.codex/prompts/vion/*.md`
- `terminal` — same as `claude` (generic Claude Code via terminal)

### `vion logout`
Removes `~/.vion/credentials.json`. The server-side key remains valid until you
log in again (which generates a new one and revokes the old).

### `vion status`
Show login state, plan, and key fingerprint.

### `vion watch start | stop | status`
Manages the background fix-watcher daemon — polls for approved fixes and
applies them through the local Claude Code instance.

## Storage

```
~/.vion/credentials.json    # api_key + profile + api_url    (chmod 600 on Unix)
~/.vion/fix-watcher.mjs     # watcher script (installed by vion install)
~/.vion/fix-watcher.pid     # daemon pid (when running)
~/.vion/fix-watcher.log     # daemon stdout/stderr
```

## Requirements

- Node.js ≥ 18
- A VION account at [vionsec.com.br](https://vionsec.com.br)
- For `vion install --cli=claude`: Claude Code installed
- For `--cli=blackbox`: Blackbox CLI installed
- For `--cli=codex`: OpenAI Codex CLI installed

## License

Apache-2.0 © 2026 VION Security
