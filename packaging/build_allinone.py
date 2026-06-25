"""All-in-one (Python 포함) 에어갭 번들 생성 — 타깃에 아무 설치 없이 압축만 풀고 START.bat.

구성: Windows 임베디드 Python 3.12 + 의존성 사전설치(runtime/site) + 앱 + 프론트 dist.
타깃 요건: Windows x64. (Python 불필요. 스캔 실행만 별도 nmap 필요, XML 가져오기는 불필요.)

ASCII 전용 스크립트. Usage: py -3.12 packaging/build_allinone.py
Output: ../ScanOps_allinone.zip
"""
from __future__ import annotations

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
PYVER = "3.12.8"
EMBED_URL = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
STAGE = ROOT.parent / "_allinone_stage"
OUT = ROOT.parent / "ScanOps_allinone.zip"
PREFIX = "ScanOps"

SKIP_DIR = {".venv", ".venv312", ".venv313", "__pycache__", ".pytest_cache", "tests", ".vite"}
SKIP_EXT = {".pyc", ".pyo", ".log"}


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
    # backend 소스(테스트/venv/캐시 제외)
    for p in (ROOT / "backend").rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIR for part in rel.parts) or p.suffix in SKIP_EXT:
            continue
        dst = app / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)
    # 프론트 빌드 산출물
    dist = ROOT / "frontend" / "dist"
    if not (dist / "index.html").exists():
        sys.exit("frontend/dist not built. Run: cd frontend && npm run build")
    shutil.copytree(dist, app / "frontend" / "dist")
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
    log("pip install --target runtime/site (offline, win_amd64 cp312 wheels)")
    # 타깃 고정 설치: 빌드 호스트 OS/파이썬과 무관하게 Windows cp312 휠로 설치(리눅스에서 크로스빌드 가능).
    # --only-binary=:all: 가 있어야 --platform/--abi/--python-version 가 허용된다(소스빌드 금지).
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "--no-index",
        "--find-links", str(WHEELHOUSE), "--target", str(site),
        "--platform", "win_amd64", "--python-version", "3.12",
        "--abi", "cp312", "--implementation", "cp", "--only-binary=:all:",
        "-r", str(ROOT / "backend" / "requirements.txt"),
    ])
    # 용량/잡음 줄이기: 사전설치본의 캐시 제거
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)


def place_python(app: Path, embed_zip: Path) -> None:
    pyd = app / "runtime" / "python"
    pyd.mkdir(parents=True)
    with zipfile.ZipFile(embed_zip) as z:
        z.extractall(pyd)
    # ._pth 에 site / backend 경로 추가(임베디드는 PYTHONPATH 무시 → ._pth 로 주입).
    pth = next(pyd.glob("python*._pth"))
    lines = pth.read_text(encoding="ascii").splitlines()
    for extra in ("..\\site", "..\\..\\backend"):
        if extra not in lines:
            lines.append(extra)
    pth.write_text("\n".join(lines) + "\n", encoding="ascii")
    log(f"patched {pth.name}: + ..\\site + ..\\..\\backend")


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


def main() -> None:
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
