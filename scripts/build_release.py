from __future__ import annotations

import argparse
import hashlib
import os
import zipfile
from pathlib import Path

FIXED_ZIP_TIME = (2026, 11, 11, 0, 0, 0)
EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}
EXCLUDE_SUFFIXES = (".pyc", ".pyo", ".egg-info")


def build_release_zip(root_dir: Path, output_path: Path) -> tuple[Path, str]:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    files_to_pack: list[tuple[Path, str]] = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = sorted(
            d for d in dirnames if d not in EXCLUDE_DIRS and not d.endswith(".egg-info")
        )
        for fname in sorted(filenames):
            if fname.endswith(EXCLUDE_SUFFIXES) or fname == ".DS_Store":
                continue
            full_path = Path(dirpath) / fname
            rel_posix = full_path.relative_to(root_dir).as_posix()
            files_to_pack.append((full_path, f"vaultmcp-doctor/{rel_posix}"))

    files_to_pack.sort(key=lambda item: item[1])

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for src_path, arcname in files_to_pack:
            info = zipfile.ZipInfo(filename=arcname, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = 0o755 if src_path.suffix == ".sh" else 0o644
            info.external_attr = (0o100000 | mode) << 16
            zf.writestr(info, src_path.read_bytes())

    digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
    sha_path = Path(f"{output_path}.sha256")
    sha_path.write_text(f"{digest}  {output_path.name}\n", encoding="utf-8")
    return output_path, digest


def main() -> int:
    root_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Build reproducible VaultMCP Doctor release ZIP.")
    parser.add_argument(
        "--output",
        default=str(root_dir / "dist" / "vaultmcp-doctor-v1.0.0.zip"),
        help="Output ZIP path.",
    )
    args = parser.parse_args()
    zip_path, digest = build_release_zip(root_dir, Path(args.output))
    print(f"Built {zip_path} (sha256: {digest})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
