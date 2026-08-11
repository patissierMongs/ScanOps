"""All-in-one (Python 포함) 에어갭 번들 생성 — 타깃에 아무 설치 없이 압축만 풀고 START.bat.

구성: Windows 임베디드 Python + 의존성 사전설치(runtime/site) + 앱 + 프론트 dist.
타깃 요건: Windows x64. (Python 불필요. 스캔 실행만 별도 nmap 필요, XML 가져오기는 불필요.)

ASCII 전용 스크립트.
Usage:
    python packaging/build_allinone.py                  # 3.12 (기본, ../ScanOps_allinone.zip)
    python packaging/build_allinone.py --python 3.13    # ../ScanOps_allinone_py313.zip
    python packaging/build_allinone.py --python 3.12 --out /path/to/custom.zip

wheelhouse 는 지원 버전별 win_amd64 휠을 모두 담고 있어야 한다(pure 휠은 공용, 바이너리
휠은 cp312/cp313 각각). 인자 없이 실행할 때의 산출물 이름/스테이지 경로는 기존 계약 그대로다
(scripts/package_runtime_smoke.py 가 그 이름을 기대한다).
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "packaging"
CACHE = PKG / "_cache"
WHEELHOUSE = PKG / "wheelhouse"

# 지원하는 임베디드 런타임: 마이너 버전 -> 배포 패치 버전.
PY_RELEASES = {"3.12": "3.12.8", "3.13": "3.13.9"}
DEFAULT_PYTHON = "3.12"

# 아래 4개는 --python 에 따라 configure() 가 다시 묶는다. 모듈 전역으로 두는 이유는
# 테스트가 monkeypatch 로 ROOT/OUT 을 갈아끼우기 때문이다.
PYTHON = DEFAULT_PYTHON
PYVER = PY_RELEASES[DEFAULT_PYTHON]
ABI = "cp312"
EMBED_URL = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
STAGE = ROOT.parent / "_allinone_stage"
OUT = ROOT.parent / "ScanOps_allinone.zip"
PREFIX = "ScanOps"

# Windows 조건부 의존성. pip 의 크로스 설치(--platform win_amd64)는 환경 마커를 '빌드 호스트'
# 기준으로 평가해서, 리눅스에서 만들면 'colorama; platform_system == "Windows"' 가 통째로
# 빠진다. click(=uvicorn CLI)이 Windows 에서 ANSI 출력을 감쌀 때 import 하는 필수 런타임
# 의존성이라, 여기서 명시적으로 채워 넣어야 완전 오프라인 타깃에서 죽지 않는다.
WINDOWS_EXTRA_PACKAGES = ["colorama"]

# 확장 모듈 파일명의 ABI 태그(_pydantic_core.cp312-win_amd64.pyd -> cp312).
_ABI_TAG_RE = re.compile(r"\.(cp\d+)-")


def configure(python: str = DEFAULT_PYTHON, out: Path | None = None) -> None:
    """선택한 마이너 버전에 맞춰 런타임/ABI/산출물 경로를 묶는다."""
    global PYTHON, PYVER, ABI, EMBED_URL, STAGE, OUT
    if python not in PY_RELEASES:
        raise SystemExit(f"지원하지 않는 Python 버전: {python} (가능: {', '.join(PY_RELEASES)})")
    PYTHON = python
    PYVER = PY_RELEASES[python]
    ABI = "cp" + python.replace(".", "")
    EMBED_URL = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
    # 기본(3.12)은 기존 이름을 그대로 써서 smoke/CI 계약을 깨지 않는다.
    suffix = "" if python == DEFAULT_PYTHON else f"_py{python.replace('.', '')}"
    STAGE = ROOT.parent / f"_allinone_stage{suffix}"
    OUT = Path(out) if out else ROOT.parent / f"ScanOps_allinone{suffix}.zip"

SKIP_DIR = {".venv", ".venv312", ".venv313", "__pycache__", ".pytest_cache", "tests", ".vite"}
SKIP_EXT = {".pyc", ".pyo", ".log"}
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


def _ignored_source_names(directory: str, names: list[str]) -> set[str]:
    base = Path(directory)
    return {
        name for name in names
        if is_forbidden_source_path((base / name).relative_to(ROOT))
    }


def log(msg: str) -> None:
    print(f"[allinone] {msg}", flush=True)


def download_embed() -> Path:
    CACHE.mkdir(exist_ok=True)
    dst = CACHE / f"python-{PYVER}-embed-amd64.zip"
    if dst.exists() and dst.stat().st_size > 1_000_000:
        log(f"embed cached: {dst.name}")
        return dst
    log(f"downloading {EMBED_URL}")
    urllib.request.urlretrieve(EMBED_URL, dst)
    log(f"downloaded {dst.stat().st_size//1024} KB")
    return dst


def copy_app(app: Path) -> None:
    # backend + vendored scan engine source (tests/venv/cache excluded)
    for top in ("backend", "engine"):
        for p in (ROOT / top).rglob("*"):
            if p.is_dir():
                continue
            rel = p.relative_to(ROOT)
            if (is_forbidden_source_path(rel)
                    or any(part in SKIP_DIR for part in rel.parts)
                    or p.suffix in SKIP_EXT):
                continue
            dst = app / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
    # 프론트 빌드 산출물
    dist = ROOT / "frontend" / "dist"
    if not (dist / "index.html").exists():
        sys.exit("frontend/dist not built. Run: cd frontend && npm run build")
    shutil.copytree(
        dist, app / "frontend" / "dist", ignore=_ignored_source_names,
    )
    # 문서
    for f in ("README.md", "DESIGN.md", "REBUILD.md", "HANDOFF.md", "THIRD_PARTY_NOTICES.md"):
        if (ROOT / f).exists():
            shutil.copy2(ROOT / f, app / f)
    # standalone 스캐너(에어갭 스캔 호스트용). CLI(scanops_scanner.py)는 stdlib 전용이라
    # 번들 임베디드 파이썬으로도 실행 가능. GUI 는 tkinter 필요(임베디드엔 없음 → 별도 풀파이썬).
    scanner_dst = app / "scanner"
    scanner_dst.mkdir(parents=True, exist_ok=True)
    for f in ("scanops_scanner.py", "scanops_scanner_gui.py", "run_gui.bat", "README.md"):
        src = ROOT / "scanner" / f
        if src.exists():
            shutil.copy2(src, scanner_dst / f)


def install_site(app: Path) -> None:
    site = app / "runtime" / "site"
    site.mkdir(parents=True)
    log(f"pip install --target runtime/site (offline, win_amd64 {ABI} wheels)")
    # 타깃 고정 설치: 빌드 호스트 OS/파이썬과 무관하게 Windows 휠로 설치(리눅스에서 크로스빌드 가능).
    # --only-binary=:all: 가 있어야 --platform/--abi/--python-version 가 허용된다(소스빌드 금지).
    cross = [
        "--platform", "win_amd64", "--python-version", PYTHON,
        "--abi", ABI, "--implementation", "cp", "--only-binary=:all:",
    ]
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "--no-index",
        "--find-links", str(WHEELHOUSE), "--target", str(site),
        *cross, "-r", str(ROOT / "backend" / "requirements.txt"),
    ])
    # Windows 전용 의존성 보강(위 WINDOWS_EXTRA_PACKAGES 주석 참고). --no-deps 로 붙여
    # requirements 해석 결과를 흔들지 않는다.
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "--no-index",
        "--find-links", str(WHEELHOUSE), "--target", str(site),
        *cross, "--no-deps", *WINDOWS_EXTRA_PACKAGES,
    ])
    # 용량/잡음 줄이기: 사전설치본의 캐시 제거
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)
    verify_site(site)


def verify_site(site: Path) -> None:
    """완전 오프라인 타깃에서 import 가능한 형태인지 빌드 시점에 확인한다."""
    missing = [
        name for name in ("fastapi", "uvicorn", "sqlalchemy", "pydantic",
                          "pydantic_core", "pydantic_settings", "starlette",
                          "openpyxl", "multipart", "click", "colorama", "greenlet")
        if not (site / name).exists() and not list(site.glob(f"{name}*"))
    ]
    if missing:
        raise SystemExit(f"runtime/site 에 빠진 패키지: {', '.join(missing)}")
    # 확장 모듈이 선택한 ABI 와 맞는지(엉뚱한 cp 태그가 섞이면 타깃에서 import 실패).
    # ABI 태그가 없는 .pyd 는 버전 무관이므로 통과시킨다.
    wrong = sorted({
        p.name for p in site.rglob("*.pyd")
        if (tag := _ABI_TAG_RE.search(p.name)) and tag.group(1) != ABI
    })
    if wrong:
        raise SystemExit(f"{ABI} 가 아닌 확장 모듈이 섞였습니다: {wrong[:5]}")
    log(f"verified runtime/site: {len(list(site.glob('*')))} entries, all {ABI}")


def place_python(app: Path, embed_zip: Path) -> None:
    pyd = app / "runtime" / "python"
    pyd.mkdir(parents=True)
    with zipfile.ZipFile(embed_zip) as z:
        z.extractall(pyd)
    # ._pth 에 site / backend 경로 추가(임베디드는 PYTHONPATH 무시 → ._pth 로 주입).
    pth = next(pyd.glob("python*._pth"))
    lines = pth.read_text(encoding="ascii").splitlines()
    for extra in ("..\\site", "..\\..\\backend", "..\\..\\engine"):
        if extra not in lines:
            lines.append(extra)
    pth.write_text("\n".join(lines) + "\n", encoding="ascii")
    log(f"patched {pth.name}: + site + backend + engine")


def write_launcher(app: Path) -> None:
    # -E -s: 시스템에 다른 Python 이 깔려 PYTHONHOME/PYTHONPATH 등 PYTHON* 환경변수가 설정돼 있어도
    # 임베디드 런타임이 그걸 무시하도록 완전 격리(절대경로 호출 + ._pth 와 함께 폐쇄망 안전).
    # SCANOPS_* 설정값은 PYTHON* 가 아니므로 그대로 읽힌다.
    (app / "START.bat").write_text(
        "@echo off\r\n"
        "title ScanOps\r\n"
        "cd /d \"%~dp0backend\"\r\n"
        "echo Starting ScanOps -- open http://<this-server-ip>:8770/ in a browser.\r\n"
        "\"%~dp0runtime\\python\\python.exe\" -E -s -m uvicorn scanops.main:app --host 0.0.0.0 --port 8770\r\n"
        "pause\r\n",
        encoding="ascii",
    )
    # standalone 스캐너를 번들 임베디드 파이썬으로 실행(nmap 은 호스트에 별도 설치 필요).
    # 예: SCAN.bat --workflow auto 10.0.0.0/24
    (app / "SCAN.bat").write_text(
        "@echo off\r\n"
        "\"%~dp0runtime\\python\\python.exe\" -E -s \"%~dp0scanner\\scanops_scanner.py\" %*\r\n",
        encoding="ascii",
    )


def zip_bundle(app: Path) -> int:
    if OUT.exists():
        OUT.unlink()
    count = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, f"{PREFIX}/{p.relative_to(app).as_posix()}")
                count += 1
    return count


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Build the all-in-one air-gapped bundle.")
    ap.add_argument("--python", default=DEFAULT_PYTHON, choices=sorted(PY_RELEASES),
                    help="Embedded CPython minor version to bundle.")
    ap.add_argument("--out", default=None, help="Output zip path (default: ../ScanOps_allinone[_pyXYZ].zip)")
    args = ap.parse_args(argv)
    configure(args.python, Path(args.out) if args.out else None)

    log(f"target: Windows x64 / embedded CPython {PYVER} ({ABI})")
    embed_zip = download_embed()
    if STAGE.exists():
        shutil.rmtree(STAGE)
    app = STAGE / PREFIX
    app.mkdir(parents=True)
    copy_app(app)
    place_python(app, embed_zip)
    install_site(app)
    write_launcher(app)
    n = zip_bundle(app)
    size_mb = OUT.stat().st_size / 1024 / 1024
    log(f"wrote {OUT} : {n} files, {size_mb:.1f} MB")


if __name__ == "__main__":
    main()
