#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_PATH="${1:-$PWD}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Error: python3 (>=3.10) is required." >&2
  exit 2
fi

if command -v uv >/dev/null 2>&1; then
  uv tool install --force "$ROOT_DIR" >/dev/null 2>&1 || true
elif command -v pipx >/dev/null 2>&1; then
  pipx install --force "$ROOT_DIR" >/dev/null 2>&1 || true
fi

if command -v vaultmcp-doctor >/dev/null 2>&1; then
  exec vaultmcp-doctor --vault "$VAULT_PATH"
fi

VENV_DIR="$ROOT_DIR/.venv"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

if "$VENV_DIR/bin/python" -c "import vaultmcp_doctor" >/dev/null 2>&1; then
  exec "$VENV_DIR/bin/python" -m vaultmcp_doctor --vault "$VAULT_PATH"
fi

# Zero-dependency fallback works even offline without pip/setuptools build
PYTHONPATH="$ROOT_DIR/src${PYTHONPATH:+:$PYTHONPATH}" exec python3 -m vaultmcp_doctor --vault "$VAULT_PATH"
