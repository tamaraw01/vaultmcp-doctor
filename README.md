# VaultMCP Doctor (`$0+` MIT CLI)

Read-only `<10s` preflight & diagnostic CLI for **Obsidian + Claude Code + MCP** vaults.

Zero external Python dependencies (100% stdlib), zero telemetry, never modifies your vault, and never echoes secret values.

- Packaged ZIP release (`$0+` MIT): [Download VaultMCP Doctor on Gumroad](https://aditama1.gumroad.com/l/vaultmcp-doctor)
- Full replacement MCP server & Ops Vault: [VaultMCP OS ($29 / $59 / $129)](https://aditama1.gumroad.com/l/vaultmcp-os) (use code `DOCTOR25` for 25% off Pro `$59` or Team `$129`)

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

## Sample Output

Captured from running `vaultmcp-doctor` on a sample vault with `.mcp.json` pointing at `mcp-obsidian` and an environment with `mcp==2.0.0` installed:

```text
$ PYTHONPATH=src python3 -m vaultmcp_doctor --vault ./obsidian-vault --mcp-config ./.mcp.json --no-color
VaultMCP Doctor v1.0.0 - Vault: obsidian-vault (18.3 ms)
Summary: 1 pass | 2 warn | 4 fail
Vault Context: 2 notes (~17 tokens) | Buckets [<1k:2, 1k-4k:0, 4k-16k:0, >16k:0] | MCP Schema Overhead: ~850 tokens (1 server(s))

Findings:
  [FAIL] CLI_YAML_JSON_MISMATCH (Pain #1 / #8): Obsidian CLI properties format=json trap detected
         Detail: Obsidian CLI 1.12 returns YAML even when `format=json` is passed, breaking JSON parsers silently. Matched in: CLAUDE.md.
         Fix:    Parse YAML/stdout defensively for `Error:` lines and avoid trusting exit code 0 alone, or switch to a direct-filesystem atomic MCP server (VaultMCP Core $29).
  [WARN] TRANSPORT_TIMEOUT_UNENFORCED (Pain #3): No bounded 10s per-tool MCP timeout configured
         Detail: Claude Code ignores server startup timeouts on individual tool calls (claude-code#53641), risking 10+ minute hangs.
         Fix:    Set MCP_TOOL_TIMEOUT=10000 and prefer a direct-filesystem MCP server with hard per-call deadlines.
  [PASS] AUTH_ENV_CLEAN (Pain #9): No auth env-var shadowing or vault .env exposure detected
         Detail: ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are unset; no .env in vault root.
  [FAIL] DEP_MCP_OBSIDIAN_PATH_TRAVERSAL (Pain #6): mcp-obsidian open path-traversal exposure (#150)
         Detail: Detected mcp-obsidian (configured). Upstream concatenates filepath directly into /vault/{filepath}, allowing ../../ escapes across 7 tools.
         Fix:    Replace mcp-obsidian with a realpath-jailed direct-disk MCP server (VaultMCP Core $29) or restrict filesystem permissions.
  [FAIL] DEP_MCP_SDK_V2_CRASH (Pain #7): mcp==2.0.0 breaks legacy Python MCP servers (#156)
         Detail: Python `mcp>=2.0` removed Server.list_tools signature compatibility, causing AttributeError startup crashes.
         Fix:    Pin `mcp<2.0` in a dedicated virtualenv or upgrade to a zero-dependency/pinned MCP runtime.
  [WARN] PRIVACY_MISSING_VAULTIGNORE (Pain #5): Missing .vaultignore privacy firewall in vault root
         Detail: Without .vaultignore, naive MCP file/search tools index private journals, credentials, and drafts.
         Fix:    Add a .vaultignore file excluding Private/, Secrets/, #private, and *.env.
  [FAIL] PRIVACY_EXCLUDED_TAG_EXPOSED (Pain #5): Notes marked private/secret are not shielded by .vaultignore
         Detail: Found 1 private/secret note(s) exposed to cold-start/full scans: SecretNote.md.
         Fix:    List private paths and #private/#secret tags in .vaultignore and use a pre-read tag firewall (VaultMCP Core/Pro).
```

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

`VaultMCP Doctor` (`$0+`, MIT) diagnoses setup, security, concurrency, and context-bloat traps ([Gumroad release](https://aditama1.gumroad.com/l/vaultmcp-doctor)). When you are ready to replace fragile community bridges with a deterministic runtime and ops vault, compare [VaultMCP OS](https://aditama1.gumroad.com/l/vaultmcp-os) tiers (use code `DOCTOR25` at checkout for 25% off Pro `$59` or Team `$129`):

| Tier | Price | What Is Included |
|---|---:|---|
| **[VaultMCP Doctor](https://aditama1.gumroad.com/l/vaultmcp-doctor)** | **$0+** | Read-only `<10s` diagnostic CLI + JSON audit + remediation guide (this package) |
| **[Starter / Core](https://aditama1.gumroad.com/l/vaultmcp-os)** | **$29** | Zero-Electron direct-filesystem MCP bridge, SHA-256 `If-Match` concurrency lock (`412 Conflict`), strict `realpath` jail + secret redactor, atomic UTF-8 writer, hard per-tool timeouts, token-budgeted snippet search |
| **[Pro (Recommended)](https://aditama1.gumroad.com/l/vaultmcp-os)** | **$59** | Everything in Starter/Core + pre-wired PARA Ops Vault, dynamic MCP tool-profile switcher, AST heading section chunker, git/snapshot rollback ledger, declarative tag firewall, tested `CLAUDE.md` + `SKILL.md` slash commands (`$44.25` with `DOCTOR25`) |
| **[Team / Studio](https://aditama1.gumroad.com/l/vaultmcp-os)** | **$129** | Everything in Pro + multi-vault isolated router, CI/pre-commit broken-wikilink & schema linter, team/agency SOP pack, 5-seat commercial license (`$96.75` with `DOCTOR25`) |

---

## License

MIT License - see `LICENSE`.
