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
FORBIDDEN_EXACT_NAMES = {
    "initial_admin.txt", "id_rsa", "id_ed25519", ".npmrc", ".pypirc",
    "client-secret.md",
}
FORBIDDEN_DIR_NAMES = {".ssh", "secrets", "private"}
FORBIDDEN_DATABASE_MARKERS = (".db", ".sqlite", ".sqlite3")
FORBIDDEN_KEY_MARKERS = (".key", ".pem", ".p12", ".pfx")
CREDENTIAL_MARKERS = (
    "token", "credential", "secret", "api_key", "api-key", "private_key",
    "private-key", "service_account", "service-account",
)
CREDENTIAL_ARTIFACT_SUFFIXES = {
    "", ".bak", ".cfg", ".conf", ".csv", ".ini", ".json", ".toml", ".txt",
    ".yaml", ".yml", ".credential", ".credentials", ".token",
}
# Top-level entries to include (everything else at root is skipped).
INCLUDE_TOP = {
    "backend", "engine", "frontend", "packaging", "samples", "scripts",
    "START.bat", "README.md", "DESIGN.md", "REBUILD.md", "HANDOFF.md",
    "THIRD_PARTY_NOTICES.md", ".gitignore",
}
# Inside frontend we keep src/dist/public + config, but never node_modules (in EXCLUDE_DIRS).


def _has_artifact_marker(name: str, markers: tuple[str, ...]) -> bool:
    return any(
        name.endswith(marker) or f"{marker}-" in name or f"{marker}." in name
        for marker in markers
    )


def is_forbidden_source_path(path: Path) -> bool:
    """Reject local runtime data and credential artifacts from release sources."""
    parts = tuple(part.lower() for part in path.parts)
    if any(part == "data" or part.startswith(".venv") or part.startswith(".env")
           or part in FORBIDDEN_DIR_NAMES
           for part in parts):
        return True
    if not parts:
        return False
    name = parts[-1]
    if name in FORBIDDEN_EXACT_NAMES:
        return True
    if any(marker in name for marker in FORBIDDEN_DATABASE_MARKERS):
        return True
    if _has_artifact_marker(name, FORBIDDEN_KEY_MARKERS):
        return True
    return (
        Path(name).suffix.lower() in CREDENTIAL_ARTIFACT_SUFFIXES
        and any(marker in name for marker in CREDENTIAL_MARKERS)
    )


def keep(path: Path) -> bool:
    parts = path.relative_to(ROOT).parts
    if parts and parts[0] not in INCLUDE_TOP:
        return False
    if is_forbidden_source_path(Path(*parts)):
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
            dirnames[:] = [
                n for n in dirnames
                if n not in EXCLUDE_DIRS
                and not is_forbidden_source_path((d / n).relative_to(ROOT))
            ]
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
