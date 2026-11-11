# VaultMCP Doctor (`$0+` MIT CLI)

Read-only `<10s` preflight & diagnostic CLI for **Obsidian + Claude Code + MCP** vaults.

Zero external Python dependencies (100% stdlib), zero telemetry, never modifies your vault, and never echoes secret values.

---

## 1-Command Quickstart

### macOS / Linux / WSL
```bash
bash install.sh /path/to/your/obsidian-vault
```

### Windows (PowerShell)
```powershell
.\install.ps1 -VaultPath "C:\Path\To\Your\Vault"
```

### Zero-Install Run (from extracted folder)
```bash
PYTHONPATH=src python3 -m vaultmcp_doctor --vault /path/to/your/vault
```

### Strict JSON Report (for CI or automation)
```bash
PYTHONPATH=src python3 -m vaultmcp_doctor --vault /path/to/your/vault --json --output report.json
```

---

## What VaultMCP Doctor Checks

| Check Area | Verified Ecosystem Failure Caught | Exit Behavior |
|---|---|---|
| **Obsidian CLI 1.12 Preflight** | Silent exit-code-`0` errors (`base:views`), `properties format=json` YAML mismatch, `tasks todo total` silent `0`, and `content=` UTF-8 8 KB corruption | `warn` / `fail` |
| **Transport, Timeouts & Paths** | Unenforced 10+ min stdio hangs (`MCP_TOOL_TIMEOUT`), fragile SSE / `mcp-remote` drops, Windows `npx` vs `npx.cmd`, missing binaries, WSL/Windows path casing mismatches, CRLF script endings | `warn` / `fail` |
| **Auth Env-Var Collisions** | Stale `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` shadowing Claude subscription auth; plaintext `.env` inside vault root (values always redacted) | `warn` / `fail` |
| **Known MCP Bugs & Security** | `mcp-obsidian` open path traversal (`#150`), `mcp>=2.0` SDK startup crash (`#156`), `obsidian-local-rest-api` 5.x header & `If-Match` risks (`#166`, `#286`), archived `obsidian-mcp-tools` plugin, symlinks escaping vault root | `warn` / `fail` |
| **Privacy & Context-Bloat Audit** | Missing `.vaultignore`, exposed `#private`/`#secret` or `private: true` notes, note token-count histogram (`<1k`, `1k-4k`, `4k-16k`, `>16k`), oversized notes, and MCP tool-schema token overhead | `warn` / `fail` |

### Exit Codes
- `0`: Healthy (zero `fail` findings; add `--strict` to also fail on `warn`)
- `1`: One or more `fail` findings detected (or `warn` with `--strict`)
- `2`: Invalid CLI arguments or missing vault directory (never fails silently with `0`)

---

## CLI Options

```text
--vault PATH        Path to Obsidian vault directory (default: .)
--mcp-config PATH   Optional path to .mcp.json or ~/.claude.json
--probe-sse         Run a bounded 2s TCP reachability check on SSE/HTTP MCP URLs
--json              Print strict JSON report to stdout
--output PATH       Write JSON report to file
--strict            Exit non-zero on warnings as well as failures
--no-color          Disable ANSI terminal colors
--version           Show version and exit
```

---

## Compatibility Matrix

| Platform / Tool | Supported Versions | Notes |
|---|---|---|
| **Python** | `3.10`, `3.11`, `3.12`, `3.13` | 100% Python standard library; zero `pip` dependencies required |
| **OS** | Linux, macOS, WSL2, Windows 11 | Works headless over SSH and in CI without Obsidian Desktop running |
| **Obsidian** | Vaults on any version; CLI `1.12+` trap checks | Read-only vault scan; safe with Obsidian open or closed |
| **Claude Code / MCP** | `.mcp.json` & `~/.claude.json` | Optional `--probe-sse` bounded at 2.0s timeout |

---

## Self-Tests & Reproducible Packaging

Run the automated test suite:
```bash
python3 -m unittest discover -s tests -v
```

Rebuild the deterministic release archive:
```bash
python3 scripts/build_release.py
```

---

## Upgrade Path: Replacing Fragile Bridges

`VaultMCP Doctor` (`$0+`, MIT) diagnoses setup, security, concurrency, and context-bloat traps. When you are ready to replace fragile community bridges with a deterministic runtime + ops vault:

| Tier | Price | What You Unlock |
|---|---:|---|
| **VaultMCP Doctor** | **$0+** | Read-only `<10s` diagnostic CLI + JSON audit + remediation guide (this package) |
| **Starter / Core** | **$29** | Zero-Electron direct-filesystem MCP bridge, SHA-256 `If-Match` concurrency lock (`412 Conflict`), strict `realpath` jail + secret redactor, atomic UTF-8 writer, hard per-tool timeouts, token-budgeted snippet search |
| **Pro (Recommended)** | **$59** | Everything in Starter/Core + pre-wired PARA Ops Vault, dynamic MCP tool-profile switcher, AST heading section chunker, git/snapshot rollback ledger, declarative tag firewall, tested `CLAUDE.md` + `SKILL.md` slash commands |
| **Team / Studio** | **$129** | Everything in Pro + multi-vault isolated router, CI/pre-commit broken-wikilink & schema linter, team/agency SOP pack, 5-seat commercial license |

---

## License

MIT License - see `LICENSE`.
