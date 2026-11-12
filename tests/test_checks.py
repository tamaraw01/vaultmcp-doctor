import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


class TestAuthEnvCheck(unittest.TestCase):
    def test_detects_auth_env_collision_and_redacts_secret(self):
        from vaultmcp_doctor.checks import check_auth_env

        fake_secret = "sk-ant-api03-TEST_SECRET_VALUE_99999"
        env = {
            "ANTHROPIC_API_KEY": fake_secret,
            "CLAUDE_CODE_OAUTH_TOKEN": "oauth-secret-12345",
        }
        with tempfile.TemporaryDirectory() as tmp:
            findings = check_auth_env(Path(tmp), env=env)

        ids = [f["id"] for f in findings]
        self.assertIn("AUTH_ENV_SHADOW_API_KEY", ids)
        self.assertIn("AUTH_ENV_SHADOW_OAUTH", ids)
        serialized = str(findings)
        self.assertNotIn(fake_secret, serialized)
        self.assertNotIn("oauth-secret-12345", serialized)

    def test_clean_env_returns_pass_finding(self):
        from vaultmcp_doctor.checks import check_auth_env

        with tempfile.TemporaryDirectory() as tmp:
            findings = check_auth_env(Path(tmp), env={})

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "pass")
        self.assertEqual(findings[0]["id"], "AUTH_ENV_CLEAN")

    def test_detects_empty_bearer_header_on_http_mcp_server(self):
        from vaultmcp_doctor.checks import check_auth_env

        with tempfile.TemporaryDirectory() as tmp:
            home, vault = Path(tmp) / "home", Path(tmp) / "vault"
            vault.mkdir()
            (vault / ".mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "remote-a": {
                                "type": "http",
                                "url": "https://mcp.example.com/mcp",
                                "headers": {"Authorization": "Bearer ${MCP_API_TOKEN:-}"},
                            },
                            "remote-b": {
                                "type": "http",
                                "url": "https://mcp2.example.com/mcp",
                                "headers": {"authorization": "Bearer "},
                            },
                            "remote-ok": {
                                "type": "http",
                                "url": "https://mcp3.example.com/mcp",
                                "headers": {"Authorization": "Bearer ${VALID_TOKEN}"},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            findings = check_auth_env(vault, env={}, home=home)

        by_id = {f["id"]: f for f in findings}
        self.assertIn("AUTH_EMPTY_BEARER_HEADER", by_id)
        f = by_id["AUTH_EMPTY_BEARER_HEADER"]
        self.assertEqual(f["status"], "fail")
        self.assertIn("remote-a", f["detail"])
        self.assertIn("remote-b", f["detail"])
        self.assertNotIn("remote-ok", f["detail"])

    def test_detects_github_gho_token_prefix_mismatch_and_allows_ghp(self):
        from vaultmcp_doctor.checks import check_auth_env

        fake_gho = "gho_FAKEOAUTHTOKEN1234567890"
        fake_ghp = "ghp_FAKEPATTOKEN1234567890"
        with tempfile.TemporaryDirectory() as tmp:
            home, vault = Path(tmp) / "home", Path(tmp) / "vault"
            settings = vault / ".claude" / "settings.json"
            settings.parent.mkdir(parents=True)
            settings.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "github": {
                                "command": "npx",
                                "args": ["-y", "@modelcontextprotocol/server-github"],
                                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": fake_gho},
                            },
                            "github-ok": {
                                "command": "npx",
                                "args": ["-y", "@modelcontextprotocol/server-github"],
                                "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": fake_ghp},
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            findings = check_auth_env(vault, env={}, home=home)

        by_id = {f["id"]: f for f in findings}
        self.assertIn("AUTH_GITHUB_TOKEN_PREFIX_MISMATCH", by_id)
        f = by_id["AUTH_GITHUB_TOKEN_PREFIX_MISMATCH"]
        self.assertEqual(f["status"], "fail")
        self.assertIn("github", f["detail"])
        self.assertNotIn("github-ok", f["detail"])
        self.assertNotIn(fake_gho, str(findings))

    def test_detects_github_gho_token_from_env_when_github_server_configured(self):
        from vaultmcp_doctor.checks import check_auth_env

        fake_gho = "gho_ENVOAUTHTOKEN9876543210"
        with tempfile.TemporaryDirectory() as tmp:
            home, vault = Path(tmp) / "home", Path(tmp) / "vault"
            vault.mkdir()
            (vault / ".mcp.json").write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "github": {
                                "type": "http",
                                "url": "https://api.githubcopilot.com/mcp/",
                                "headers": {"Authorization": "Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN}"},
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            findings = check_auth_env(
                vault,
                env={"GITHUB_PERSONAL_ACCESS_TOKEN": fake_gho},
                home=home,
            )

        ids = {f["id"] for f in findings}
        self.assertIn("AUTH_GITHUB_TOKEN_PREFIX_MISMATCH", ids)
        self.assertNotIn("AUTH_EMPTY_BEARER_HEADER", ids)
        self.assertNotIn(fake_gho, str(findings))


class TestCliPreflightCheck(unittest.TestCase):
    def test_flags_silent_cli_traps_in_scripts_and_skills(self):
        from vaultmcp_doctor.checks import check_obsidian_cli_preflight

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            skill_dir = vault / ".claude" / "skills" / "ops"
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                "Run:\n"
                "obsidian properties format=json\n"
                "obsidian base:views\n"
                "obsidian tasks todo total\n"
                "obsidian create name=note content='hello'\n",
                encoding="utf-8",
            )
            findings = check_obsidian_cli_preflight(vault)

        ids = {f["id"] for f in findings}
        self.assertIn("CLI_YAML_JSON_MISMATCH", ids)
        self.assertIn("CLI_EXIT_ZERO_ERROR_TRAP", ids)
        self.assertIn("CLI_TASKS_TODO_TOTAL_ZERO", ids)
        self.assertIn("CLI_CONTENT_UTF8_TRUNCATION", ids)

    def test_clean_vault_cli_preflight_passes(self):
        from vaultmcp_doctor.checks import check_obsidian_cli_preflight

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "README.md").write_text("# Clean vault\n", encoding="utf-8")
            findings = check_obsidian_cli_preflight(vault)

        self.assertEqual([f["id"] for f in findings], ["CLI_PREFLIGHT_CLEAN"])


class TestTransportAndPathCheck(unittest.TestCase):
    def test_detects_missing_timeout_sse_risk_crlf_and_path_case(self):
        from vaultmcp_doctor.checks import check_transport_and_paths

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            # Create actual lowercase directory "MyVault" -> actually "myvault"
            actual_dir = vault / "myvault"
            actual_dir.mkdir()
            hook = vault / "scripts"
            hook.mkdir()
            (hook / "run.sh").write_bytes(b"#!/bin/bash\r\necho hi\r\n")
            mcp_cfg = vault / ".mcp.json"
            mcp_cfg.write_text(
                '{\n'
                '  "mcpServers": {\n'
                '    "obsidian-rest": {\n'
                '      "command": "npx",\n'
                '      "args": ["-y", "mcp-remote", "http://127.0.0.1:27123/sse", "'
                + str(vault / "MyVault")
                + '"]\n'
                '    }\n'
                '  }\n'
                '}\n',
                encoding="utf-8",
            )
            findings = check_transport_and_paths(
                vault,
                mcp_config_path=mcp_cfg,
                env={},
                platform_name="win32",
                which_fn=lambda cmd: None if cmd == "npx" else f"/usr/bin/{cmd}",
            )

        ids = {f["id"] for f in findings}
        self.assertIn("TRANSPORT_TIMEOUT_UNENFORCED", ids)
        self.assertIn("TRANSPORT_SSE_REMOTE_FRAGILE", ids)
        self.assertIn("PLATFORM_NPX_WINDOWS_CMD", ids)
        self.assertIn("PLATFORM_PATH_CASE_MISMATCH", ids)
        self.assertIn("PLATFORM_CRLF_SCRIPTS", ids)

    def test_flags_malformed_mcp_json(self):
        from vaultmcp_doctor.checks import check_transport_and_paths

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            mcp_cfg = vault / ".mcp.json"
            mcp_cfg.write_text("{bad json", encoding="utf-8")
            findings = check_transport_and_paths(vault, mcp_config_path=mcp_cfg, env={})

        self.assertTrue(any(f["id"] == "MCP_CONFIG_INVALID_JSON" and f["status"] == "fail" for f in findings))


class TestMcpDependencyAndSecurityAudit(unittest.TestCase):
    def test_detects_mcp_obsidian_sdk2_rest_5x_archived_plugin_and_symlink_escape(self):
        from vaultmcp_doctor.checks import check_mcp_dependencies

        with tempfile.TemporaryDirectory() as outer_tmp, tempfile.TemporaryDirectory() as vault_tmp:
            vault = Path(vault_tmp)
            outside_file = Path(outer_tmp) / "secret.txt"
            outside_file.write_text("top-secret", encoding="utf-8")
            (vault / "escape_link.md").symlink_to(outside_file)

            (vault / ".mcp.json").write_text(
                '{"mcpServers": {"obs": {"command": "uvx", "args": ["mcp-obsidian"]}}}',
                encoding="utf-8",
            )

            rest_dir = vault / ".obsidian" / "plugins" / "obsidian-local-rest-api"
            rest_dir.mkdir(parents=True)
            (rest_dir / "manifest.json").write_text('{"id": "obsidian-local-rest-api", "version": "5.1.0"}', encoding="utf-8")

            archived_dir = vault / ".obsidian" / "plugins" / "obsidian-mcp-tools"
            archived_dir.mkdir(parents=True)
            (archived_dir / "manifest.json").write_text('{"id": "obsidian-mcp-tools", "version": "0.2.27"}', encoding="utf-8")

            findings = check_mcp_dependencies(
                vault,
                installed_packages={"mcp": "2.1.0", "mcp-obsidian": "0.2.2"},
            )

        ids = {f["id"] for f in findings}
        self.assertIn("DEP_MCP_OBSIDIAN_PATH_TRAVERSAL", ids)
        self.assertIn("DEP_MCP_SDK_V2_CRASH", ids)
        self.assertIn("DEP_LOCAL_REST_API_5X_PATCH_BREAK", ids)
        self.assertIn("DEP_ARCHIVED_OBSIDIAN_MCP_TOOLS", ids)
        self.assertIn("SEC_VAULT_SYMLINK_ESCAPE", ids)

    def test_clean_vault_deps_pass(self):
        from vaultmcp_doctor.checks import check_mcp_dependencies

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "note.md").write_text("# Hello", encoding="utf-8")
            findings = check_mcp_dependencies(vault, installed_packages={})

        self.assertEqual([f["id"] for f in findings], ["DEPS_SECURITY_CLEAN"])


class TestPrivacyAndContextBloat(unittest.TestCase):
    def test_detects_missing_vaultignore_exposed_private_tag_huge_note_and_mcp_schema_bloat(self):
        from vaultmcp_doctor.checks import check_privacy_and_bloat

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / "small.md").write_text("# Small\nHello world\n", encoding="utf-8")
            (vault / "secrets_note.md").write_text(
                "---\nprivate: true\n---\n# Keys\n#secret note body\n", encoding="utf-8"
            )
            # >16k tokens => >64 KB
            (vault / "mega_dump.md").write_text("word " * 17000, encoding="utf-8")
            (vault / ".mcp.json").write_text(
                '{"mcpServers": {'
                '"s1": {"command": "node"}, '
                '"s2": {"command": "node"}, '
                '"s3": {"command": "node"}, '
                '"s4": {"command": "node"}'
                "}}",
                encoding="utf-8",
            )
            findings, metrics = check_privacy_and_bloat(vault)

        ids = {f["id"] for f in findings}
        self.assertIn("PRIVACY_MISSING_VAULTIGNORE", ids)
        self.assertIn("PRIVACY_EXCLUDED_TAG_EXPOSED", ids)
        self.assertIn("CONTEXT_BLOAT_LARGE_NOTES", ids)
        self.assertIn("CONTEXT_MCP_SCHEMA_OVERHEAD", ids)
        self.assertEqual(metrics["note_count"], 3)
        self.assertEqual(metrics["histogram"]["gt_16k"], 1)
        self.assertEqual(metrics["histogram"]["lt_1k"], 2)
        self.assertEqual(metrics["mcp_server_count"], 4)
        self.assertGreaterEqual(metrics["estimated_mcp_schema_tokens"], 3000)

    def test_vaultignore_shields_private_notes_and_clean_vault_passes(self):
        from vaultmcp_doctor.checks import check_privacy_and_bloat

        with tempfile.TemporaryDirectory() as tmp:
            vault = Path(tmp)
            (vault / ".vaultignore").write_text("Private/\n#private\n", encoding="utf-8")
            priv = vault / "Private"
            priv.mkdir()
            (priv / "journal.md").write_text("# My entry\n#private\n", encoding="utf-8")
            (vault / "normal.md").write_text("# Normal\nCompact note.\n", encoding="utf-8")
            findings, metrics = check_privacy_and_bloat(vault)

        self.assertEqual([f["id"] for f in findings], ["PRIVACY_CONTEXT_CLEAN"])
        self.assertEqual(metrics["exposed_private_notes"], [])


class TestScopesAndPortCheck(unittest.TestCase):
    def _write(self, path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")

    def test_duplicate_scope_port_mismatch_and_start_hint(self):
        from vaultmcp_doctor.checks import check_scopes_and_port

        with tempfile.TemporaryDirectory() as tmp:
            home, vault = Path(tmp) / "home", Path(tmp) / "vault"
            obs = {"command": "uvx", "args": ["mcp-obsidian"], "env": {"OBSIDIAN_API_KEY": "k"}}
            self._write(home / ".claude.json", {"projects": {str(vault.resolve()): {"mcpServers": {"obsidian": obs}}}})
            self._write(home / ".claude" / "settings.json", {"mcpServers": {"obsidian": {**obs, "env": {"OBSIDIAN_PORT": "27125"}}}})
            self._write(vault / ".obsidian" / "plugins" / "obsidian-local-rest-api" / "data.json", {"port": 27125})
            findings = check_scopes_and_port(vault, env={}, home=home)

        by_id = {f["id"]: f for f in findings}
        self.assertIn("SCOPE_DUPLICATE_SERVER", by_id)
        self.assertIn(".claude.json", by_id["SCOPE_DUPLICATE_SERVER"]["detail"])
        self.assertIn("settings.json", by_id["SCOPE_DUPLICATE_SERVER"]["detail"])
        self.assertIn("27124", by_id["REST_PORT_MISMATCH"]["detail"])
        self.assertIn("OBSIDIAN_START_ORDER_HINT", by_id)
        self.assertNotIn('"k"', str(findings))

    def test_claude_config_dir_profile_mismatch_and_clean(self):
        from vaultmcp_doctor.checks import check_scopes_and_port

        with tempfile.TemporaryDirectory() as tmp:
            home, vault, prof = Path(tmp) / "home", Path(tmp) / "vault", Path(tmp) / "work"
            vault.mkdir()
            self._write(home / ".claude.json", {"mcpServers": {"notes": {"command": "notes-mcp"}}})
            self._write(prof / ".claude.json", {"mcpServers": {"other": {"command": "x"}}})
            switched = check_scopes_and_port(vault, env={"CLAUDE_CONFIG_DIR": str(prof)}, home=home)
            clean = check_scopes_and_port(vault, env={}, home=home)

        self.assertEqual([f["id"] for f in switched], ["SCOPE_PROFILE_MISMATCH"])
        self.assertIn("notes", switched[0]["detail"])
        self.assertEqual([f["id"] for f in clean], ["SCOPES_CLEAN"])


if __name__ == "__main__":
    unittest.main()
