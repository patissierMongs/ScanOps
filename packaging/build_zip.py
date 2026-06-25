"""Regenerate the air-gapped offline zip (ASCII-only by design).

Bundles the runtime: backend source + requirements, freshly built frontend/dist,
public fonts, packaging (wheelhouse + install/run/start), samples, docs.
Excludes transient/dev dirs (.venv, node_modules, data, caches, git).

Usage: python packaging/build_zip.py
Output: ../ScanOps_offline.zip  (sibling of the ScanOps/ project dir)
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]            # ScanOps/
OUT = ROOT.parent / "ScanOps_offline.zip"
PREFIX = "ScanOps"

EXCLUDE_DIRS = {
    ".venv", "node_modules", "data", "_e2e_data", "_e2e_chrome",
    "__pycache__", ".pytest_cache", ".git", ".vite",
}
EXCLUDE_EXT = {".pyc", ".pyo", ".log", ".png", ".token"}
# Top-level entries to include (everything else at root is skipped).
INCLUDE_TOP = {
    "backend", "frontend", "packaging", "samples", "scripts",
    "START.bat", "README.md", "DESIGN.md", "REBUILD.md", "HANDOFF.md",
    "THIRD_PARTY_NOTICES.md", ".gitignore",
}
# Inside frontend we keep src/dist/public + config, but never node_modules (in EXCLUDE_DIRS).


def keep(path: Path) -> bool:
    parts = path.relative_to(ROOT).parts
    if parts and parts[0] not in INCLUDE_TOP:
        return False
    if any(p in EXCLUDE_DIRS for p in parts):
        return False
    if path.suffix.lower() in EXCLUDE_EXT:
        return False
    return True


def main() -> None:
    dist = ROOT / "frontend" / "dist" / "index.html"
    if not dist.exists():
        raise SystemExit("frontend/dist not built. Run: cd frontend && npm run build")

    count = 0
    if OUT.exists():
        OUT.unlink()
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for dirpath, dirnames, filenames in os.walk(ROOT):
            d = Path(dirpath)
            # prune excluded dirs in-place for speed
            dirnames[:] = [n for n in dirnames if n not in EXCLUDE_DIRS]
            rel0 = d.relative_to(ROOT).parts
            if rel0 and rel0[0] not in INCLUDE_TOP:
                continue
            for fn in filenames:
                fp = d / fn
                if not keep(fp):
                    continue
                arc = f"{PREFIX}/{fp.relative_to(ROOT).as_posix()}"
                z.write(fp, arc)
                count += 1
    size_mb = OUT.stat().st_size / 1024 / 1024
    print(f"wrote {OUT} : {count} files, {size_mb:.2f} MB")


if __name__ == "__main__":
    main()
