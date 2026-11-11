import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"


def _run_cli(args: list[str], env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    env.pop("CLAUDE_CODE_OAUTH_TOKEN", None)
    env["MCP_TOOL_TIMEOUT"] = "10000"
    env["PYTHONPATH"] = str(SRC_DIR)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "vaultmcp_doctor", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
    )


class TestVaultMcpDoctorCli(unittest.TestCase):
    def test_clean_vault_json_report_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / ".vaultignore").write_text("Private/\n", encoding="utf-8")
            (vault / "note.md").write_text("# Clean Note\n", encoding="utf-8")
            mcp_cfg = vault / ".mcp.json"
            mcp_cfg.write_text('{"mcpServers": {"local": {"command": "python3", "timeout": 10000}}}', encoding="utf-8")

            proc = _run_cli(["--vault", str(vault), "--mcp-config", str(mcp_cfg), "--json"])
            self.assertEqual(proc.returncode, 0, msg=proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["tool"], "vaultmcp-doctor")
            self.assertIn("summary", payload)
            self.assertIn("metrics", payload)
            self.assertIn("findings", payload)
            self.assertIn("upgrade_path", payload)
            self.assertEqual(payload["summary"]["fail"], 0)

    def test_broken_vault_returns_nonzero_writes_output_and_redacts_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / ".env").write_text("SECRET=123\n", encoding="utf-8")
            (vault / "secret.md").write_text("#private\n", encoding="utf-8")
            out_json = vault / "report.json"

            proc = _run_cli(
                ["--vault", str(vault), "--json", "--output", str(out_json)],
                env_extra={"ANTHROPIC_API_KEY": "sk-ant-DO_NOT_LEAK_ME"},
            )
            self.assertEqual(proc.returncode, 1)
            self.assertTrue(out_json.is_file())
            written = out_json.read_text(encoding="utf-8")
            self.assertNotIn("sk-ant-DO_NOT_LEAK_ME", written)
            payload = json.loads(written)
            self.assertGreaterEqual(payload["summary"]["fail"], 1)

    def test_missing_vault_returns_exit_2_nonzero(self):
        proc = _run_cli(["--vault", "/tmp/nonexistent-vault-xyz-999999"])
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not a directory", proc.stderr.lower())

    def test_human_terminal_output_contains_summary_and_tier_ladder(self):
        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "note.md").write_text("# Hello\n", encoding="utf-8")
            proc = _run_cli(["--vault", str(vault), "--no-color"])
            self.assertIn(proc.returncode, (0, 1))
            self.assertIn("VaultMCP Doctor", proc.stdout)
            self.assertIn("$29", proc.stdout)
            self.assertIn("$59", proc.stdout)
            self.assertIn("$129", proc.stdout)


class TestReleasePackagingAndCleanExtract(unittest.TestCase):
    def test_reproducible_zip_and_clean_env_extract(self):
        import hashlib
        import zipfile

        build_script = ROOT_DIR / "scripts" / "build_release.py"
        self.assertTrue(build_script.is_file(), "Missing scripts/build_release.py")

        with tempfile.TemporaryDirectory() as out_dir:
            zip_a = Path(out_dir) / "a.zip"
            zip_b = Path(out_dir) / "b.zip"
            subprocess.run([sys.executable, str(build_script), "--output", str(zip_a)], check=True)
            subprocess.run([sys.executable, str(build_script), "--output", str(zip_b)], check=True)

            hash_a = hashlib.sha256(zip_a.read_bytes()).hexdigest()
            hash_b = hashlib.sha256(zip_b.read_bytes()).hexdigest()
            self.assertEqual(hash_a, hash_b, "Release ZIP is not deterministic/reproducible")

            extract_dir = Path(out_dir) / "extracted"
            with zipfile.ZipFile(zip_a, "r") as zf:
                names = zf.namelist()
                self.assertFalse(any("__pycache__" in n or n.endswith(".pyc") for n in names))
                self.assertIn("vaultmcp-doctor/README.md", names)
                self.assertIn("vaultmcp-doctor/LICENSE", names)
                self.assertIn("vaultmcp-doctor/pyproject.toml", names)
                self.assertIn("vaultmcp-doctor/install.sh", names)
                self.assertIn("vaultmcp-doctor/install.ps1", names)
                zf.extractall(extract_dir)

            pkg_root = extract_dir / "vaultmcp-doctor"
            for fpath in pkg_root.rglob("*"):
                if fpath.is_file() and fpath.suffix in {".py", ".sh", ".ps1", ".md", ".toml"}:
                    content = fpath.read_text(encoding="utf-8", errors="replace")
                    self.assertIsNone(
                        re.search(r"/(?:home|Users)/[a-z_][a-z0-9_-]+/", content),
                        f"Hardcoded user path in {fpath}",
                    )

            test_proc = subprocess.run(
                [sys.executable, "-m", "unittest", "tests/test_checks.py", "-v"],
                cwd=pkg_root,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(test_proc.returncode, 0, msg=test_proc.stdout + test_proc.stderr)

            cli_proc = subprocess.run(
                [sys.executable, "-m", "vaultmcp_doctor", "--version"],
                cwd=pkg_root,
                env={**os.environ, "PYTHONPATH": str(pkg_root / "src")},
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(cli_proc.returncode, 0, msg=cli_proc.stderr)
            self.assertIn("1.0.0", cli_proc.stdout)


if __name__ == "__main__":
    unittest.main()
