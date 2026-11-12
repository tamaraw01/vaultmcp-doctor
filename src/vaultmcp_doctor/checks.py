from __future__ import annotations

import importlib.metadata
import json
import os
import re
import shutil
import socket
import sys
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlparse


_CLI_PREFLIGHT_RULES: tuple[tuple[str, str, str, str, str, re.Pattern[str]], ...] = (
    (
        "CLI_YAML_JSON_MISMATCH",
        "fail",
        "high",
        "Obsidian CLI properties format=json trap detected",
        "Obsidian CLI 1.12 returns YAML even when `format=json` is passed, breaking JSON parsers silently.",
        re.compile(r"obsidian[^\n]*\bproperties\b[^\n]*format=json", re.IGNORECASE),
    ),
    (
        "CLI_EXIT_ZERO_ERROR_TRAP",
        "warn",
        "high",
        "Obsidian CLI command prone to exit-code-0 silent failure",
        "Commands like `obsidian base:views` print `Error:` to stdout while exiting with code 0.",
        re.compile(r"obsidian[^\n]*\b(base:views|backlinks|links|tags)\b", re.IGNORECASE),
    ),
    (
        "CLI_TASKS_TODO_TOTAL_ZERO",
        "warn",
        "high",
        "Obsidian CLI `tasks todo total` silent-zero trap detected",
        "Obsidian CLI 1.12.1 returns `0` for `tasks todo total` instead of the vault-wide count.",
        re.compile(r"obsidian[^\n]*\btasks\s+todo\s+total\b", re.IGNORECASE),
    ),
    (
        "CLI_CONTENT_UTF8_TRUNCATION",
        "warn",
        "high",
        "Obsidian CLI `content=` parameter UTF-8 corruption risk",
        "Obsidian CLI 1.12.7 `content=` corrupts multi-byte UTF-8 at ~8 KB chunk boundaries.",
        re.compile(r"obsidian[^\n]*\bcontent=", re.IGNORECASE),
    ),
)


def _iter_automation_files(vault_path: Path) -> list[Path]:
    candidates: list[Path] = []
    for name in ("CLAUDE.md", "SKILL.md", ".mcp.json"):
        p = vault_path / name
        if p.is_file():
            candidates.append(p)
    for sub in (".claude", "scripts", ".obsidian/plugins"):
        root = vault_path / sub
        if not root.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "__pycache__"}]
            for fname in filenames:
                if fname.endswith((".md", ".sh", ".ps1", ".py", ".json", ".yaml", ".yml")):
                    candidates.append(Path(dirpath) / fname)
    return candidates


def check_obsidian_cli_preflight(vault_path: Path) -> list[dict[str, str]]:
    """Scan agent instructions, hooks, and scripts for Obsidian CLI 1.12 silent-failure traps."""
    hits: dict[str, list[str]] = {}
    for file_path in _iter_automation_files(vault_path):
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(file_path.relative_to(vault_path))
        for rule_id, _, _, _, _, pattern in _CLI_PREFLIGHT_RULES:
            if pattern.search(text):
                hits.setdefault(rule_id, []).append(rel)

    findings: list[dict[str, str]] = []
    for rule_id, status, severity, title, base_detail, _ in _CLI_PREFLIGHT_RULES:
        matched_files = hits.get(rule_id)
        if matched_files:
            remediation = (
                "Parse YAML/stdout defensively for `Error:` lines and avoid trusting exit code 0 alone, "
                "or switch to a direct-filesystem atomic MCP server (VaultMCP Core $29)."
            )
            findings.append(
                _finding(
                    finding_id=rule_id,
                    category="cli_preflight",
                    status=status,
                    severity=severity,
                    title=title,
                    detail=f"{base_detail} Matched in: {', '.join(sorted(set(matched_files))[:5])}.",
                    remediation=remediation,
                    pain_ref="Pain #1 / #8",
                )
            )

    if not findings:
        findings.append(
            _finding(
                finding_id="CLI_PREFLIGHT_CLEAN",
                category="cli_preflight",
                status="pass",
                severity="info",
                title="No Obsidian CLI 1.12 silent-failure patterns found in vault automation files",
                detail="Scanned CLAUDE.md, SKILL.md, .claude/, scripts/, and .mcp.json.",
                remediation="None required.",
                pain_ref="Pain #1",
            )
        )
    return findings


def _finding(
    finding_id: str,
    category: str,
    status: str,
    severity: str,
    title: str,
    detail: str,
    remediation: str,
    pain_ref: str,
) -> dict[str, str]:
    return {
        "id": finding_id,
        "category": category,
        "status": status,
        "severity": severity,
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "pain_ref": pain_ref,
    }


_EMPTY_BEARER_RE = re.compile(
    r"^\s*Bearer(?:\s+\$\{[A-Za-z_][A-Za-z0-9_]*:-\})?\s*$",
    re.IGNORECASE,
)
_GHO_TOKEN_RE = re.compile(r"\bgho_[A-Za-z0-9_]+\b")


def _collect_mcp_sources(
    vault_path: Path,
    mcp_config_path: Path | None,
    active_env: Mapping[str, str],
    home_dir: Path,
) -> dict[str, dict[str, Any]]:
    config_dir = active_env.get("CLAUDE_CONFIG_DIR", "").strip()
    if config_dir:
        root = Path(config_dir).expanduser()
        user_files = [root / ".claude.json", root / "settings.json"]
    else:
        user_files = [home_dir / ".claude.json", home_dir / ".claude" / "settings.json"]
    candidates = user_files + [vault_path / ".mcp.json", vault_path / ".claude" / "settings.json"]
    if mcp_config_path is not None:
        candidates.append(mcp_config_path)

    sources: dict[str, dict[str, Any]] = {}
    for path in candidates:
        if path.is_file() and str(path) not in sources:
            servers = _load_servers(path, vault_path)
            if servers:
                sources[str(path)] = servers
    return sources


def check_auth_env(
    vault_path: Path,
    env: Mapping[str, str] | None = None,
    mcp_config_path: Path | None = None,
    home: Path | None = None,
) -> list[dict[str, str]]:
    """Check auth env shadowing, vault .env exposure, empty HTTP Bearer headers, and gho_ token mismatches."""
    active_env = os.environ if env is None else env
    home_dir = Path.home() if home is None else home
    findings: list[dict[str, str]] = []

    api_key = active_env.get("ANTHROPIC_API_KEY", "").strip()
    if api_key:
        findings.append(
            _finding(
                finding_id="AUTH_ENV_SHADOW_API_KEY",
                category="auth_env",
                status="warn",
                severity="high",
                title="ANTHROPIC_API_KEY set in environment (may shadow Claude subscription auth)",
                detail=f"Detected ANTHROPIC_API_KEY (length={len(api_key)}, value redacted). "
                "Claude Code/Claudian may fail with authentication_failed or bill API credits unexpectedly.",
                remediation="Unset ANTHROPIC_API_KEY in shell/IDE profile if using Claude Pro/Max subscription auth.",
                pain_ref="Pain #9",
            )
        )

    oauth_token = active_env.get("CLAUDE_CODE_OAUTH_TOKEN", "").strip()
    if oauth_token:
        findings.append(
            _finding(
                finding_id="AUTH_ENV_SHADOW_OAUTH",
                category="auth_env",
                status="warn",
                severity="medium",
                title="CLAUDE_CODE_OAUTH_TOKEN set in environment (stale token risk)",
                detail=f"Detected CLAUDE_CODE_OAUTH_TOKEN (length={len(oauth_token)}, value redacted). "
                "Expired OAuth env vars override fresh login sessions.",
                remediation="Unset CLAUDE_CODE_OAUTH_TOKEN and re-authenticate via `claude login` if auth errors occur.",
                pain_ref="Pain #9",
            )
        )

    env_file = vault_path / ".env"
    if env_file.is_file():
        findings.append(
            _finding(
                finding_id="AUTH_VAULT_DOTENV_PRESENT",
                category="auth_env",
                status="fail",
                severity="critical",
                title="Plaintext .env file inside Obsidian vault root",
                detail=f"Found {env_file.name} in vault root. Synced vaults and unguarded MCP readers can expose secrets.",
                remediation="Move .env outside the vault and add `.env` + `*.env` to `.vaultignore`.",
                pain_ref="Pain #6 / #9",
            )
        )

    sources = _collect_mcp_sources(vault_path, mcp_config_path, active_env, home_dir)
    empty_bearer_servers: list[str] = []
    gho_mismatch_servers: list[str] = []
    env_has_gho = any(
        active_env.get(k, "").strip().startswith("gho_")
        for k in ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "GH_TOKEN")
    )

    for src, servers in sources.items():
        src_name = Path(src).name
        for srv_name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            srv_type = str(srv.get("type", "")).strip().lower()
            headers = srv.get("headers")
            if srv_type == "http" and isinstance(headers, dict):
                for hk, hv in headers.items():
                    if str(hk).lower() == "authorization" and isinstance(hv, str) and _EMPTY_BEARER_RE.match(hv):
                        empty_bearer_servers.append(f"{srv_name} ({src_name})")
                        break

            srv_blob = json.dumps(srv)
            is_github = "github" in srv_name.lower() or "github" in srv_blob.lower()
            if is_github:
                auth_blob = json.dumps(
                    {"env": srv.get("env"), "headers": headers, "args": srv.get("args")}
                )
                if _GHO_TOKEN_RE.search(auth_blob) or env_has_gho:
                    gho_mismatch_servers.append(f"{srv_name} ({src_name})")

    if empty_bearer_servers:
        findings.append(
            _finding(
                finding_id="AUTH_EMPTY_BEARER_HEADER",
                category="auth_env",
                status="fail",
                severity="high",
                title="HTTP MCP server has empty Bearer Authorization header (blocks OAuth fallback)",
                detail=(
                    "Server(s) with type='http' set Authorization to an empty Bearer or '${VAR:-}' value: "
                    + ", ".join(sorted(set(empty_bearer_servers)))
                    + ". Claude Code disables OAuth fallback whenever headers.Authorization is present, causing HTTP 401 (claude-code#69758)."
                ),
                remediation="Remove headers.Authorization when using OAuth, or set a non-empty token or headersHelper command.",
                pain_ref="Pain #9",
            )
        )

    if gho_mismatch_servers:
        findings.append(
            _finding(
                finding_id="AUTH_GITHUB_TOKEN_PREFIX_MISMATCH",
                category="auth_env",
                status="fail",
                severity="high",
                title="GitHub MCP server configured with gho_ OAuth token instead of ghp_ / github_pat_ PAT",
                detail=(
                    "Detected gho_ OAuth token for GitHub MCP server(s): "
                    + ", ".join(sorted(set(gho_mismatch_servers)))
                    + " (value redacted). GitHub MCP servers expect a personal access token (ghp_ or github_pat_), so gh CLI OAuth tokens fail auth (claude-code#19281)."
                ),
                remediation="Create a classic PAT (ghp_) or fine-grained PAT (github_pat_) with required scopes and set it in GITHUB_PERSONAL_ACCESS_TOKEN.",
                pain_ref="Pain #9",
            )
        )

    if not findings:
        findings.append(
            _finding(
                finding_id="AUTH_ENV_CLEAN",
                category="auth_env",
                status="pass",
                severity="info",
                title="No auth env-var shadowing or vault .env exposure detected",
                detail="ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN are unset; no .env in vault root.",
                remediation="None required.",
                pain_ref="Pain #9",
            )
        )
    return findings


def _discover_mcp_config(vault_path: Path, explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    local_cfg = vault_path / ".mcp.json"
    if local_cfg.is_file():
        return local_cfg
    home_cfg = Path.home() / ".claude.json"
    if home_cfg.is_file():
        return home_cfg
    return None


def _load_servers(path: Path, vault_path: Path) -> dict[str, Any]:
    """Return mcpServers from a Claude config file, including the vault's project entry in .claude.json."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    servers = dict(raw.get("mcpServers") or {}) if isinstance(raw.get("mcpServers"), dict) else {}
    projects = raw.get("projects")
    if isinstance(projects, dict):
        proj = projects.get(str(vault_path.resolve()))
        if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
            servers.update(proj["mcpServers"])
    return servers


_PORT_RE = re.compile(r"(?:127\.0\.0\.1|localhost):(\d{2,5})")


def _server_ports(srv: Any) -> set[int]:
    """Ports a server points at: URL/args host:port, or OBSIDIAN_PORT (mcp-obsidian defaults to 27124)."""
    if not isinstance(srv, dict):
        return set()
    ports = {int(p) for p in _PORT_RE.findall(json.dumps(srv))}
    env = srv.get("env") if isinstance(srv.get("env"), dict) else {}
    if str(env.get("OBSIDIAN_PORT", "")).isdigit():
        ports.add(int(env["OBSIDIAN_PORT"]))
    elif "mcp-obsidian" in json.dumps(srv) and not ports:
        ports.add(27124)
    return ports


def check_scopes_and_port(
    vault_path: Path,
    mcp_config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> list[dict[str, str]]:
    """Diff MCP servers across .claude.json / settings.json / .mcp.json, CLAUDE_CONFIG_DIR, and REST API port."""
    active_env = os.environ if env is None else env
    home_dir = Path.home() if home is None else home
    config_dir = active_env.get("CLAUDE_CONFIG_DIR", "").strip()
    findings: list[dict[str, str]] = []
    sources = _collect_mcp_sources(vault_path, mcp_config_path, active_env, home_dir)

    by_name: dict[str, list[tuple[str, Any]]] = {}
    for src, servers in sources.items():
        for name, srv in servers.items():
            by_name.setdefault(name, []).append((src, srv))
    for name, entries in sorted(by_name.items()):
        defs = {json.dumps(srv, sort_keys=True) for _, srv in entries}
        if len(entries) > 1 and len(defs) > 1:
            findings.append(
                _finding(
                    finding_id="SCOPE_DUPLICATE_SERVER",
                    category="scopes_port",
                    status="warn",
                    severity="high",
                    title=f"MCP server '{name}' is registered in {len(entries)} scopes with different settings",
                    detail="Defined in: " + ", ".join(Path(s).name for s, _ in entries)
                    + ". Claude Code picks one silently, so edits to the other file have no effect.",
                    remediation=f"Run `claude mcp get {name}` to see the live entry, then delete the stale copy.",
                    pain_ref="Pain #3",
                )
            )

    if config_dir:
        default_servers = _load_servers(home_dir / ".claude.json", vault_path)
        missing = sorted(set(default_servers) - set(by_name))
        if missing:
            findings.append(
                _finding(
                    finding_id="SCOPE_PROFILE_MISMATCH",
                    category="scopes_port",
                    status="warn",
                    severity="medium",
                    title="CLAUDE_CONFIG_DIR hides servers registered in the default profile",
                    detail=f"CLAUDE_CONFIG_DIR is set; these servers exist only in the default ~/.claude.json: {', '.join(missing[:5])}.",
                    remediation="Unset CLAUDE_CONFIG_DIR or re-register the servers under the active profile with `claude mcp add`.",
                    pain_ref="Pain #3",
                )
            )

    obsidian_ports: set[int] = set()
    for entries in by_name.values():
        for _, srv in entries:
            blob = json.dumps(srv).lower()
            if "obsidian" in blob or "2712" in blob:
                obsidian_ports |= _server_ports(srv)

    plugin_cfg = vault_path / ".obsidian" / "plugins" / "obsidian-local-rest-api" / "data.json"
    if obsidian_ports and plugin_cfg.is_file():
        try:
            data = json.loads(plugin_cfg.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        # Plugin defaults: HTTPS on 27124, HTTP on 27123 only when enableInsecureServer is true.
        port, insecure = str(data.get("port", "")), str(data.get("insecurePort", ""))
        live = {int(port) if port.isdigit() else 27124}
        if data.get("enableInsecureServer"):
            live.add(int(insecure) if insecure.isdigit() else 27123)
        stale = sorted(obsidian_ports - live)
        if stale:
            findings.append(
                _finding(
                    finding_id="REST_PORT_MISMATCH",
                    category="scopes_port",
                    status="fail",
                    severity="critical",
                    title="MCP config points at a different port than Obsidian Local REST API",
                    detail=f"MCP config uses port(s) {', '.join(map(str, stale))}; the plugin listens on {', '.join(map(str, sorted(live)))}. "
                    "mcp-obsidian assumes 27124 unless OBSIDIAN_PORT is set, so a correct API key still gets connection refused.",
                    remediation="Set OBSIDIAN_PORT in the server's env (or fix the URL) to match the plugin's port.",
                    pain_ref="Pain #3",
                )
            )

    if obsidian_ports:
        findings.append(
            _finding(
                finding_id="OBSIDIAN_START_ORDER_HINT",
                category="scopes_port",
                status="pass",
                severity="info",
                title="Start Obsidian before launching claude",
                detail="Claude Code fetches the MCP tool list once per session; if Obsidian opens later, the REST bridge exposes no tools.",
                remediation="Open Obsidian first, or run /mcp reconnect or restart claude after opening it.",
                pain_ref="Pain #3",
            )
        )
    elif not findings:
        findings.append(
            _finding(
                finding_id="SCOPES_CLEAN",
                category="scopes_port",
                status="pass",
                severity="info",
                title="No duplicate MCP registrations or profile mismatches found",
                detail=f"Compared {len(sources)} config file(s).",
                remediation="None required.",
                pain_ref="Pain #3",
            )
        )
    return findings


def _has_path_case_mismatch(raw_path: str) -> str | None:
    if raw_path.startswith(("-", "http://", "https://")) or ("/" not in raw_path and "\\" not in raw_path):
        return None
    normalized = raw_path.replace("\\", "/")
    p = Path(normalized)
    if p.exists():
        return None
    parts = p.parts
    if not parts:
        return None
    cur = Path(parts[0]) if p.is_absolute() else Path(".")
    start_idx = 1 if p.is_absolute() else 0
    if not cur.exists():
        return None
    for part in parts[start_idx:]:
        try:
            entries = list(cur.iterdir())
        except OSError:
            return None
        exact = [e for e in entries if e.name == part]
        if exact:
            cur = exact[0]
            continue
        ci = [e for e in entries if e.name.lower() == part.lower()]
        if ci:
            return f"{raw_path} (on-disk case is '{ci[0].name}')"
        return None
    return None


def _probe_tcp_endpoint(url: str, timeout_s: float = 2.0) -> tuple[bool, str]:
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        return False, "invalid URL host"
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True, f"reachable ({host}:{port})"
    except OSError as exc:
        return False, f"unreachable ({host}:{port}): {exc}"


def check_transport_and_paths(
    vault_path: Path,
    mcp_config_path: Path | None = None,
    env: Mapping[str, str] | None = None,
    platform_name: str | None = None,
    which_fn: Callable[[str], str | None] | None = None,
    probe_sse: bool = False,
) -> list[dict[str, str]]:
    """Probe MCP transport timeouts, SSE/mcp-remote fragility, npx.cmd, path casing, and CRLF scripts."""
    active_env = os.environ if env is None else env
    plat = sys.platform if platform_name is None else platform_name
    which = shutil.which if which_fn is None else which_fn
    findings: list[dict[str, str]] = []

    cfg_path = _discover_mcp_config(vault_path, mcp_config_path)
    servers: dict[str, Any] = {}
    if cfg_path is None or not cfg_path.exists():
        findings.append(
            _finding(
                finding_id="MCP_CONFIG_MISSING",
                category="transport_path",
                status="warn",
                severity="medium",
                title="No .mcp.json or ~/.claude.json config found",
                detail="Pass --mcp-config <path> to audit MCP server transport, timeout, and dependency settings.",
                remediation="Create a project .mcp.json or run VaultMCP Doctor with --mcp-config.",
                pain_ref="Pain #3",
            )
        )
    else:
        try:
            raw_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(raw_cfg, dict):
                maybe_servers = raw_cfg.get("mcpServers", {})
                if isinstance(maybe_servers, dict):
                    servers = maybe_servers
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                _finding(
                    finding_id="MCP_CONFIG_INVALID_JSON",
                    category="transport_path",
                    status="fail",
                    severity="critical",
                    title=f"Malformed MCP config JSON: {cfg_path.name}",
                    detail=f"Failed to parse {cfg_path.name}: {exc}",
                    remediation="Fix JSON syntax errors (trailing commas/unescaped Windows backslashes) in MCP config.",
                    pain_ref="Pain #3 / #9",
                )
            )

    # Check global MCP_TOOL_TIMEOUT or per-server timeout
    env_timeout = active_env.get("MCP_TOOL_TIMEOUT", "").strip()
    has_bounded_timeout = False
    if env_timeout.isdigit() and 1000 <= int(env_timeout) <= 15000:
        has_bounded_timeout = True

    sse_urls: list[str] = []
    missing_bins: list[str] = []
    npx_win_servers: list[str] = []
    case_mismatches: list[str] = []

    for srv_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        srv_timeout = srv.get("timeout")
        if isinstance(srv_timeout, (int, float)) and 1000 <= srv_timeout <= 15000:
            has_bounded_timeout = True

        cmd = str(srv.get("command", "")).strip()
        args = [str(a) for a in srv.get("args", [])] if isinstance(srv.get("args"), list) else []
        url = str(srv.get("url", "")).strip()
        srv_type = str(srv.get("type", "")).strip().lower()

        if url:
            sse_urls.append(url)
        for a in args:
            if a.startswith(("http://", "https://")) and ("sse" in a.lower() or "27123" in a or "27124" in a):
                sse_urls.append(a)
            mismatch = _has_path_case_mismatch(a)
            if mismatch:
                case_mismatches.append(f"{srv_name}: {mismatch}")

        if "mcp-remote" in " ".join(args) or srv_type == "sse":
            if not sse_urls:
                sse_urls.append(srv_name)

        if cmd:
            if plat.startswith("win") and cmd.lower() == "npx":
                npx_win_servers.append(srv_name)
            elif not Path(cmd).is_absolute() and which(cmd) is None:
                missing_bins.append(f"{srv_name} ({cmd})")

    if servers and not has_bounded_timeout:
        findings.append(
            _finding(
                finding_id="TRANSPORT_TIMEOUT_UNENFORCED",
                category="transport_path",
                status="warn",
                severity="high",
                title="No bounded 10s per-tool MCP timeout configured",
                detail="Claude Code ignores server startup timeouts on individual tool calls (claude-code#53641), risking 10+ minute hangs.",
                remediation="Set MCP_TOOL_TIMEOUT=10000 and prefer a direct-filesystem MCP server with hard per-call deadlines.",
                pain_ref="Pain #3",
            )
        )

    if sse_urls:
        probe_note = ""
        if probe_sse:
            results = []
            for u in sse_urls[:3]:
                if u.startswith(("http://", "https://")):
                    ok, msg = _probe_tcp_endpoint(u)
                    results.append(f"{u} -> {msg}")
            if results:
                probe_note = " Probe: " + "; ".join(results) + "."
        findings.append(
            _finding(
                finding_id="TRANSPORT_SSE_REMOTE_FRAGILE",
                category="transport_path",
                status="warn",
                severity="high",
                title="Fragile SSE / mcp-remote bridge configured",
                detail="Local REST API SSE streams drop on Windows/idle connections (UND_ERR_HEADERS_TIMEOUT). "
                f"Targets: {', '.join(sse_urls[:3])}.{probe_note}",
                remediation="Use a zero-Electron direct-filesystem stdio MCP server instead of SSE/mcp-remote for vault reads/writes.",
                pain_ref="Pain #3",
            )
        )

    if npx_win_servers:
        findings.append(
            _finding(
                finding_id="PLATFORM_NPX_WINDOWS_CMD",
                category="transport_path",
                status="fail",
                severity="high",
                title="Windows MCP config uses `npx` instead of `npx.cmd`",
                detail=f"Servers using bare `npx` on Windows fail to spawn in non-shell stdio runners: {', '.join(npx_win_servers)}.",
                remediation="Change command from `npx` to `npx.cmd` (or invoke node/python directly with full binary path).",
                pain_ref="Pain #9",
            )
        )

    if missing_bins:
        findings.append(
            _finding(
                finding_id="TRANSPORT_COMMAND_NOT_FOUND",
                category="transport_path",
                status="fail",
                severity="critical",
                title="Configured MCP server executable missing from PATH",
                detail=f"Cannot resolve binary for: {', '.join(missing_bins)}.",
                remediation="Install the runtime or specify the full absolute path to node/python/uvx in .mcp.json.",
                pain_ref="Pain #7 / #9",
            )
        )

    if case_mismatches:
        findings.append(
            _finding(
                finding_id="PLATFORM_PATH_CASE_MISMATCH",
                category="transport_path",
                status="fail",
                severity="high",
                title="Vault/MCP path casing mismatch detected",
                detail=f"Configured path casing differs from disk: {'; '.join(case_mismatches)}. Causes 10+ min hangs in MCP servers.",
                remediation="Match exact on-disk directory casing in .mcp.json arguments and WSL /mnt/<drive> paths.",
                pain_ref="Pain #3 / #9",
            )
        )

    # Check CRLF line endings in shell scripts / hooks
    crlf_files: list[str] = []
    for fpath in _iter_automation_files(vault_path):
        if fpath.suffix in {".sh", ".py"} or fpath.name in {"CLAUDE.md", "SKILL.md"}:
            try:
                raw = fpath.read_bytes()
            except OSError:
                continue
            if b"\r\n" in raw:
                crlf_files.append(str(fpath.relative_to(vault_path)))

    if crlf_files:
        findings.append(
            _finding(
                finding_id="PLATFORM_CRLF_SCRIPTS",
                category="transport_path",
                status="warn",
                severity="medium",
                title="CRLF (Windows) line endings in scripts/hooks",
                detail=f"CRLF breaks bash/WSL hooks and shebangs in: {', '.join(crlf_files[:5])}.",
                remediation="Convert affected files to LF (`dos2unix` or git `eol=lf` in .gitattributes).",
                pain_ref="Pain #9",
            )
        )

    if not findings:
        findings.append(
            _finding(
                finding_id="TRANSPORT_PATHS_CLEAN",
                category="transport_path",
                status="pass",
                severity="info",
                title="MCP transport, timeouts, path casing, and line endings look healthy",
                detail="All configured binaries resolve, timeouts are bounded, and no CRLF/casing issues found.",
                remediation="None required.",
                pain_ref="Pain #3 / #9",
            )
        )
    return findings


def _read_installed_packages() -> dict[str, str]:
    pkgs: dict[str, str] = {}
    for name in ("mcp", "mcp-obsidian"):
        try:
            pkgs[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            pass
    return pkgs


def check_mcp_dependencies(
    vault_path: Path,
    mcp_config_path: Path | None = None,
    installed_packages: Mapping[str, str] | None = None,
) -> list[dict[str, str]]:
    """Audit known MCP bugs (mcp-obsidian #150, mcp>=2.0 #156, REST API 5.x #166, archived plugins, symlinks)."""
    pkgs = _read_installed_packages() if installed_packages is None else dict(installed_packages)
    findings: list[dict[str, str]] = []

    cfg_path = _discover_mcp_config(vault_path, mcp_config_path)
    cfg_text = ""
    if cfg_path and cfg_path.is_file():
        try:
            cfg_text = cfg_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            cfg_text = ""

    uses_mcp_obsidian = ("mcp-obsidian" in cfg_text) or ("mcp-obsidian" in pkgs)
    if uses_mcp_obsidian:
        ver = pkgs.get("mcp-obsidian", "configured")
        findings.append(
            _finding(
                finding_id="DEP_MCP_OBSIDIAN_PATH_TRAVERSAL",
                category="mcp_deps",
                status="fail",
                severity="critical",
                title="mcp-obsidian open path-traversal exposure (#150)",
                detail=f"Detected mcp-obsidian ({ver}). Upstream concatenates filepath directly into /vault/{{filepath}}, allowing ../../ escapes across 7 tools.",
                remediation="Replace mcp-obsidian with a realpath-jailed direct-disk MCP server (VaultMCP Core $29) or restrict filesystem permissions.",
                pain_ref="Pain #6",
            )
        )

    uses_legacy_py_mcp = uses_mcp_obsidian or any(
        k in cfg_text for k in ("mcp-server", "mcp_server", "uvx")
    )
    mcp_ver = pkgs.get("mcp", "")
    if mcp_ver and uses_legacy_py_mcp:
        major_str = mcp_ver.split(".", 1)[0]
        if major_str.isdigit() and int(major_str) >= 2:
            findings.append(
                _finding(
                    finding_id="DEP_MCP_SDK_V2_CRASH",
                    category="mcp_deps",
                    status="fail",
                    severity="high",
                    title=f"mcp=={mcp_ver} breaks legacy Python MCP servers (#156)",
                    detail="Python `mcp>=2.0` removed Server.list_tools signature compatibility, causing AttributeError startup crashes.",
                    remediation="Pin `mcp<2.0` in a dedicated virtualenv or upgrade to a zero-dependency/pinned MCP runtime.",
                    pain_ref="Pain #7",
                )
            )

    plugins_dir = vault_path / ".obsidian" / "plugins"
    rest_manifest = plugins_dir / "obsidian-local-rest-api" / "manifest.json"
    if rest_manifest.is_file():
        try:
            manifest = json.loads(rest_manifest.read_text(encoding="utf-8"))
            rest_ver = str(manifest.get("version", ""))
        except (OSError, json.JSONDecodeError):
            rest_ver = ""
        if rest_ver.startswith("5.") and (uses_mcp_obsidian or "local-rest-api" in cfg_text or "27124" in cfg_text or "27123" in cfg_text or rest_ver):
            findings.append(
                _finding(
                    finding_id="DEP_LOCAL_REST_API_5X_PATCH_BREAK",
                    category="mcp_deps",
                    status="warn",
                    severity="high",
                    title=f"obsidian-local-rest-api v{rest_ver} header & concurrency risks (#166 / #286)",
                    detail="Local REST API 5.x breaks heading/block PATCH without `Markdown-Patch-Version` (#166) and silently ignores `If-Match` (#286).",
                    remediation="Use direct-disk SHA-256 optimistic concurrency (`expected_hash` -> 412 Conflict) for parallel agent writes.",
                    pain_ref="Pain #4 / #7",
                )
            )

    archived_manifest = plugins_dir / "obsidian-mcp-tools" / "manifest.json"
    if archived_manifest.is_file():
        findings.append(
            _finding(
                finding_id="DEP_ARCHIVED_OBSIDIAN_MCP_TOOLS",
                category="mcp_deps",
                status="warn",
                severity="high",
                title="obsidian-mcp-tools plugin is archived (orphaned May 2026)",
                detail="jacksteamdev/obsidian-mcp-tools was archived on 2026-05-13 and receives no security or SDK updates.",
                remediation="Migrate to an actively maintained direct-filesystem MCP bridge (VaultMCP Core $29).",
                pain_ref="Pain #7",
            )
        )

    # Check symlink escapes inside vault
    vault_root = vault_path.resolve()
    escapes: list[str] = []
    for dirpath, dirnames, filenames in os.walk(vault_path, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__"}]
        for name in filenames + dirnames:
            candidate = Path(dirpath) / name
            if candidate.is_symlink():
                try:
                    target = candidate.resolve(strict=False)
                    target.relative_to(vault_root)
                except ValueError:
                    escapes.append(str(candidate.relative_to(vault_path)))
    if escapes:
        findings.append(
            _finding(
                finding_id="SEC_VAULT_SYMLINK_ESCAPE",
                category="mcp_deps",
                status="fail",
                severity="critical",
                title="Symlink escaping vault root detected",
                detail=f"Symlink(s) resolve outside vault boundary: {', '.join(escapes[:5])}. Naive MCP tools can leak external files.",
                remediation="Remove external symlinks or enforce strict canonical realpath containment in your MCP server.",
                pain_ref="Pain #6",
            )
        )

    if not findings:
        findings.append(
            _finding(
                finding_id="DEPS_SECURITY_CLEAN",
                category="mcp_deps",
                status="pass",
                severity="info",
                title="No vulnerable MCP packages, archived plugins, or symlink escapes found",
                detail="Checked .mcp.json, Python MCP packages, .obsidian/plugins, and vault symlinks.",
                remediation="None required.",
                pain_ref="Pain #6 / #7",
            )
        )
    return findings


_PRIVATE_TAG_RE = re.compile(r"(?:^|\s)#(private|secret|confidential)\b", re.IGNORECASE)
_PRIVATE_FM_RE = re.compile(r"^(?:private|secret)\s*:\s*true\b", re.IGNORECASE | re.MULTILINE)


def _load_vaultignore(vault_path: Path) -> tuple[bool, list[str], set[str]]:
    vi_path = vault_path / ".vaultignore"
    if not vi_path.is_file():
        return False, [], set()
    path_globs: list[str] = []
    ignored_tags: set[str] = set()
    try:
        lines = vi_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return True, [], set()
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("#") and s[1:].lower() in {"private", "secret", "confidential"}:
            ignored_tags.add(s.lower())
        elif not s.startswith("#"):
            path_globs.append(s)
    return True, path_globs, ignored_tags


def _is_ignored_path(rel_posix: str, path_globs: list[str]) -> bool:
    for pat in path_globs:
        clean = pat.rstrip("/")
        if rel_posix == clean or rel_posix.startswith(clean + "/") or Path(rel_posix).match(pat):
            return True
    return False


def check_privacy_and_bloat(
    vault_path: Path, mcp_config_path: Path | None = None
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """Audit .vaultignore / excluded-tag exposure, note token histogram, and MCP schema bloat."""
    findings: list[dict[str, str]] = []
    has_vaultignore, path_globs, ignored_tags = _load_vaultignore(vault_path)

    if not has_vaultignore:
        findings.append(
            _finding(
                finding_id="PRIVACY_MISSING_VAULTIGNORE",
                category="privacy_bloat",
                status="warn",
                severity="high",
                title="Missing .vaultignore privacy firewall in vault root",
                detail="Without .vaultignore, naive MCP file/search tools index private journals, credentials, and drafts.",
                remediation="Add a .vaultignore file excluding Private/, Secrets/, #private, and *.env.",
                pain_ref="Pain #5",
            )
        )

    histogram = {"lt_1k": 0, "1k_to_4k": 0, "4k_to_16k": 0, "gt_16k": 0}
    total_notes = 0
    total_bytes = 0
    total_tokens = 0
    note_sizes: list[tuple[int, str]] = []
    exposed_private: list[str] = []

    for dirpath, dirnames, filenames in os.walk(vault_path):
        dirnames[:] = [d for d in dirnames if d not in {".git", ".obsidian", "node_modules", "__pycache__"}]
        for fname in filenames:
            if not fname.endswith(".md"):
                continue
            fpath = Path(dirpath) / fname
            rel_posix = fpath.relative_to(vault_path).as_posix()
            try:
                raw = fpath.read_bytes()
            except OSError:
                continue
            total_notes += 1
            bsize = len(raw)
            total_bytes += bsize
            est_tokens = max(1, bsize // 4) if bsize > 0 else 0
            total_tokens += est_tokens
            note_sizes.append((est_tokens, rel_posix))

            if est_tokens < 1000:
                histogram["lt_1k"] += 1
            elif est_tokens < 4000:
                histogram["1k_to_4k"] += 1
            elif est_tokens <= 16000:
                histogram["4k_to_16k"] += 1
            else:
                histogram["gt_16k"] += 1

            text_head = raw[:16384].decode("utf-8", errors="replace")
            tag_match = _PRIVATE_TAG_RE.search(text_head)
            fm_match = _PRIVATE_FM_RE.search(text_head[:2048])
            if tag_match or fm_match:
                tag_covered = bool(tag_match and f"#{tag_match.group(1).lower()}" in ignored_tags)
                path_covered = _is_ignored_path(rel_posix, path_globs)
                if not (has_vaultignore and (tag_covered or path_covered)):
                    exposed_private.append(rel_posix)

    if exposed_private:
        findings.append(
            _finding(
                finding_id="PRIVACY_EXCLUDED_TAG_EXPOSED",
                category="privacy_bloat",
                status="fail",
                severity="high",
                title="Notes marked private/secret are not shielded by .vaultignore",
                detail=f"Found {len(exposed_private)} private/secret note(s) exposed to cold-start/full scans: {', '.join(exposed_private[:5])}.",
                remediation="List private paths and #private/#secret tags in .vaultignore and use a pre-read tag firewall (VaultMCP Core/Pro).",
                pain_ref="Pain #5",
            )
        )

    note_sizes.sort(reverse=True)
    top_bloated = [{"path": p, "estimated_tokens": t} for t, p in note_sizes[:5]]
    if histogram["gt_16k"] > 0:
        findings.append(
            _finding(
                finding_id="CONTEXT_BLOAT_LARGE_NOTES",
                category="privacy_bloat",
                status="warn",
                severity="high",
                title=f"{histogram['gt_16k']} oversized note(s) (>16k tokens) risk context-window blowup",
                detail=f"Largest note: {top_bloated[0]['path']} (~{top_bloated[0]['estimated_tokens']} tokens). Full-note MCP reads cannot be trimmed by PreToolUse hooks (HN 47201789).",
                remediation="Use token-budgeted snippet search (Core $29) and heading/AST section chunking (Pro $59).",
                pain_ref="Pain #2",
            )
        )

    # Estimate MCP tool-schema overhead from configured servers
    cfg_path = _discover_mcp_config(vault_path, mcp_config_path)
    mcp_server_count = 0
    if cfg_path and cfg_path.is_file():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict):
                mcp_server_count = len(cfg["mcpServers"])
        except (OSError, json.JSONDecodeError):
            pass

    est_schema_tokens = mcp_server_count * 850
    if mcp_server_count >= 4:
        findings.append(
            _finding(
                finding_id="CONTEXT_MCP_SCHEMA_OVERHEAD",
                category="privacy_bloat",
                status="warn",
                severity="medium",
                title=f"High MCP tool-schema context overhead (~{est_schema_tokens} tokens across {mcp_server_count} servers)",
                detail="Every enabled MCP server injects tool JSON schemas into every turn before any note is read (obsidian-mcp-tools#61).",
                remediation="Disable unused servers or use dynamic tool-profile switching (read-only / writer / graph-ops in VaultMCP Pro $59).",
                pain_ref="Pain #2",
            )
        )

    if not findings:
        findings.append(
            _finding(
                finding_id="PRIVACY_CONTEXT_CLEAN",
                category="privacy_bloat",
                status="pass",
                severity="info",
                title="Vault privacy firewall and note token distribution look healthy",
                detail=f"Scanned {total_notes} note(s), ~{total_tokens} total tokens, .vaultignore active.",
                remediation="None required.",
                pain_ref="Pain #2 / #5",
            )
        )

    metrics: dict[str, Any] = {
        "note_count": total_notes,
        "total_bytes": total_bytes,
        "total_estimated_tokens": total_tokens,
        "histogram": histogram,
        "top_bloated_notes": top_bloated,
        "has_vaultignore": has_vaultignore,
        "exposed_private_notes": exposed_private,
        "mcp_server_count": mcp_server_count,
        "estimated_mcp_schema_tokens": est_schema_tokens,
    }
    return findings, metrics
