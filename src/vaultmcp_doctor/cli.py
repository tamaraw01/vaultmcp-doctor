from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from . import __version__
from .checks import (
    check_auth_env,
    check_mcp_dependencies,
    check_obsidian_cli_preflight,
    check_privacy_and_bloat,
    check_scopes_and_port,
    check_transport_and_paths,
)

UPGRADE_PATH: dict[str, Any] = {
    "current_tier": "VaultMCP Doctor ($0+ MIT Lead Magnet - Read-Only Audit)",
    "tiers": [
        {
            "name": "Starter / Core",
            "price_usd": 29,
            "solves": "Direct-filesystem zero-Electron MCP bridge, SHA-256 If-Match concurrency lock, realpath jail + secret redactor, atomic UTF-8 writer, per-call timeouts, token-budgeted search.",
        },
        {
            "name": "Pro (Recommended)",
            "price_usd": 59,
            "solves": "Everything in Starter/Core + PARA Ops Vault, dynamic MCP tool-profile switcher, AST section chunker, git/snapshot rollback ledger, tag firewall, tested SKILL.md commands.",
        },
        {
            "name": "Team / Studio",
            "price_usd": 129,
            "solves": "Everything in Pro + multi-vault isolated router, CI/pre-commit wikilink & schema linter, team/agency SOP pack, 5-seat commercial license.",
        },
    ],
}


def run_audit(
    vault_path: Path,
    mcp_config_path: Path | None = None,
    probe_sse: bool = False,
) -> dict[str, Any]:
    t0 = time.monotonic()
    findings: list[dict[str, str]] = []
    findings.extend(check_obsidian_cli_preflight(vault_path))
    findings.extend(
        check_transport_and_paths(
            vault_path, mcp_config_path=mcp_config_path, probe_sse=probe_sse
        )
    )
    findings.extend(check_scopes_and_port(vault_path, mcp_config_path=mcp_config_path))
    findings.extend(check_auth_env(vault_path, mcp_config_path=mcp_config_path))
    findings.extend(check_mcp_dependencies(vault_path, mcp_config_path=mcp_config_path))
    privacy_findings, metrics = check_privacy_and_bloat(
        vault_path, mcp_config_path=mcp_config_path
    )
    findings.extend(privacy_findings)

    counts = {"pass": 0, "warn": 0, "fail": 0}
    for f in findings:
        st = f.get("status", "warn")
        if st in counts:
            counts[st] += 1

    elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
    return {
        "tool": "vaultmcp-doctor",
        "version": __version__,
        "vault_name": vault_path.name,
        "elapsed_ms": elapsed_ms,
        "summary": counts,
        "metrics": metrics,
        "findings": findings,
        "upgrade_path": UPGRADE_PATH,
    }


def _color(text: str, code: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"\033[{code}m{text}\033[0m"


def format_terminal_report(report: dict[str, Any], use_color: bool = True) -> str:
    s = report["summary"]
    m = report["metrics"]
    h = m["histogram"]
    lines: list[str] = [
        f"VaultMCP Doctor v{report['version']} - Vault: {report['vault_name']} ({report['elapsed_ms']} ms)",
        f"Summary: {s['pass']} pass | {s['warn']} warn | {s['fail']} fail",
        f"Vault Context: {m['note_count']} notes (~{m['total_estimated_tokens']} tokens) | "
        f"Buckets [<1k:{h['lt_1k']}, 1k-4k:{h['1k_to_4k']}, 4k-16k:{h['4k_to_16k']}, >16k:{h['gt_16k']}] | "
        f"MCP Schema Overhead: ~{m['estimated_mcp_schema_tokens']} tokens ({m['mcp_server_count']} server(s))",
        "",
        "Findings:",
    ]

    badge_colors = {"pass": "32", "warn": "33", "fail": "31"}
    for f in report["findings"]:
        st = f["status"].upper()
        badge = _color(f"[{st}]", badge_colors.get(f["status"], "0"), use_color)
        lines.append(f"  {badge} {f['id']} ({f['pain_ref']}): {f['title']}")
        lines.append(f"         Detail: {f['detail']}")
        if f["status"] != "pass":
            lines.append(f"         Fix:    {f['remediation']}")

    if m["top_bloated_notes"]:
        lines.append("")
        lines.append("Largest Notes (Context Bloat Candidates):")
        for item in m["top_bloated_notes"][:3]:
            lines.append(f"  - {item['path']} (~{item['estimated_tokens']} tokens)")

    lines.append("")
    lines.append("Next Step / Flagship Upgrade Path (when ready to replace fragile bridges):")
    for tier in report["upgrade_path"]["tiers"]:
        lines.append(f"  - ${tier['price_usd']} {tier['name']}: {tier['solves']}")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultmcp-doctor",
        description="Read-only preflight & diagnostics for Obsidian + Claude Code + MCP vaults.",
    )
    parser.add_argument(
        "--vault",
        default=".",
        help="Path to the Obsidian vault directory (default: current directory).",
    )
    parser.add_argument(
        "--mcp-config",
        default=None,
        help="Optional path to .mcp.json or claude config JSON.",
    )
    parser.add_argument(
        "--probe-sse",
        action="store_true",
        help="Attempt a bounded 2s TCP reachability check on configured SSE/HTTP MCP URLs.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit strict JSON report to stdout.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write JSON report to the specified file path.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero on warnings as well as failures.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    vault_path = Path(args.vault).expanduser()
    if not vault_path.is_dir():
        print(f"Error: vault path is not a directory: {vault_path}", file=sys.stderr)
        return 2

    mcp_cfg = Path(args.mcp_config).expanduser() if args.mcp_config else None
    report = run_audit(vault_path, mcp_config_path=mcp_cfg, probe_sse=args.probe_sse)

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        print(format_terminal_report(report, use_color=use_color))

    if report["summary"]["fail"] > 0:
        return 1
    if args.strict and report["summary"]["warn"] > 0:
        return 1
    return 0
