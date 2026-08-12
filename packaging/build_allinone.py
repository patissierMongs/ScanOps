"""All-in-one (Python 포함) 에어갭 번들 생성 — 타깃에 아무 설치 없이 압축만 풀고 START.bat.

구성: Windows 임베디드 Python + 의존성 사전설치(runtime/site) + 앱 + 프론트 dist.
타깃 요건: Windows x64. (Python 불필요. 스캔 실행만 별도 nmap 필요, XML 가져오기는 불필요.)

ASCII 전용 스크립트.
Usage:
    python packaging/build_allinone.py                     # 3.13 (기본, ../ScanOps_allinone.zip)
    python packaging/build_allinone.py --python 3.12       # ../ScanOps_allinone_py312.zip
    python packaging/build_allinone.py --split-mb 10       # 10 MB 조각 + JOIN.bat (반출 한도용)
    python packaging/build_allinone.py --out /path/to/custom.zip

wheelhouse 는 지원 버전별 win_amd64 휠을 모두 담고 있어야 한다(pure 휠은 공용, 바이너리
휠은 cp312/cp313 각각). 인자 없이 실행할 때의 산출물 이름/스테이지 경로는 기존 계약 그대로다
(scripts/package_runtime_smoke.py 가 그 이름을 기대한다).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
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
DEFAULT_PYTHON = "3.13"

# 아래 4개는 --python 에 따라 configure() 가 다시 묶는다. 모듈 전역으로 두는 이유는
# 테스트가 monkeypatch 로 ROOT/OUT 을 갈아끼우기 때문이다.
PYTHON = DEFAULT_PYTHON
PYVER = PY_RELEASES[DEFAULT_PYTHON]
# 기본값에서 파생시킨다 — 손으로 적으면 DEFAULT_PYTHON 을 옮길 때 ABI 만 남아 어긋난다.
ABI = "cp" + DEFAULT_PYTHON.replace(".", "")
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


# ── 슬림화 ──────────────────────────────────────────────────────────────────
# 번들은 사람이 USB 로 들고 들어가는 물건이라 작을수록 좋다. 다만 여기서 지우는 것은
# 두 부류로 한정한다: (1) 서버 실행에 절대 쓰이지 않는 개발/대화형 도구, (2) 이 앱이
# 쓰지 않는 DB 드라이버. **기능을 없애는 절단은 하지 않는다** — 예를 들어 OpenSSL
# (libcrypto)은 로그인 해시(hashlib.pbkdf2_hmac)가 3.12+ 부터 순수 파이썬 대체 구현
# 없이 _hashlib 만 쓰므로, 크기를 위해 빼면 에어갭 현장에서 아무도 로그인하지 못한다.
# 지운 이름을 앱이나 의존성이 실제로 import 하면 verify_stdlib_drop 이 빌드를 세운다.
STDLIB_DROP_PACKAGES = {
    "pydoc_data", "unittest", "xmlrpc", "wsgiref", "idlelib", "turtledemo",
    "tkinter", "venv", "ensurepip", "curses", "dbm", "lib2to3", "distutils",
    "test", "_pyrepl",
}
# pdb/bdb/cmd/code/codeop 는 click.testing 이, colorsys 는 pydantic.color 가 import 한다
# (둘 다 우리가 부르지 않아도 모듈 최상단에서 걸린다) → 지우지 않는다.
STDLIB_DROP_MODULES = {
    "pydoc", "doctest", "pickletools", "mailbox", "imaplib", "smtplib",
    "poplib", "ftplib", "turtle", "antigravity", "this", "cProfile", "profile",
    "pstats", "timeit", "trace", "tabnanny", "symtable", "py_compile",
    "compileall", "pyclbr", "netrc", "nturl2path", "filecmp", "fileinput",
    "statistics", "optparse",
}
# 이 앱은 sqlite 만 쓴다(backend/scanops/db.py 의 create_engine). 나머지 방언은
# SQLAlchemy 가 등록기에서 지연 import 하므로 없어도 sqlite 경로는 그대로 동작한다.
SQLALCHEMY_DROP_DIALECTS = ("postgresql", "mysql", "oracle", "mssql")
# greenlet 은 SQLAlchemy asyncio 전용이고 util/concurrency.py 가 ImportError 를
# 정상 경로로 다룬다. 백엔드는 동기 엔진만 쓴다.
SITE_DROP_PACKAGES = ("greenlet",)


def log(msg: str) -> None:
    print(f"[allinone] {msg}", flush=True)


def _top_level_imports(source: str) -> set[str]:
    """모듈 소스에서 최상위 import 이름만 뽑는다(from x.y import z -> x)."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()          # 파이썬 2 잔재 등은 어차피 실행되지 않는다
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def verify_stdlib_drop(app: Path, dropped: set[str]) -> None:
    """지운 표준 라이브러리를 실제로 import 하는 코드가 번들에 있는지 확인한다.

    지움 목록은 사람이 적으므로 언젠가 틀린다. 틀렸을 때 실패해야 하는 지점은
    '에어갭 타깃의 첫 실행'이 아니라 '빌드'다. 앱·의존성 소스를 통째로 훑어
    교집합이 생기면 여기서 세운다."""
    used: set[str] = set()
    for py in app.rglob("*.py"):
        used |= _top_level_imports(py.read_text(encoding="utf-8", errors="ignore"))
    clash = sorted(used & dropped)
    if clash:
        raise SystemExit(
            "슬림화가 실제로 쓰이는 표준 라이브러리를 지웠습니다: "
            f"{', '.join(clash)} — STDLIB_DROP_* 에서 빼 주세요."
        )
    log(f"verified stdlib trim: {len(dropped)} names dropped, none imported")


def slim_python(app: Path) -> set[str]:
    """임베디드 런타임에서 실행에 쓰이지 않는 것만 덜어낸다. 지운 이름을 돌려준다."""
    pyd = app / "runtime" / "python"
    # python.cat: 배포본 서명 카탈로그. 런타임이 읽지 않는다.
    cat = pyd / "python.cat"
    if cat.exists():
        cat.unlink()
    stdlib_zip = next(pyd.glob("python*.zip"))
    dropped: set[str] = set()
    tmp = stdlib_zip.with_suffix(".zip.slim")
    with zipfile.ZipFile(stdlib_zip) as old:
        # 원본이 이미 deflate 라 그대로 다시 담으면 이득이 없다. 최대 압축으로 다시 쓴다.
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as new:
            for info in old.infolist():
                head = info.filename.split("/")[0]
                stem = Path(info.filename).stem
                if "/" in info.filename and head in STDLIB_DROP_PACKAGES:
                    dropped.add(head)
                    continue
                if "/" not in info.filename and stem in STDLIB_DROP_MODULES:
                    dropped.add(stem)
                    continue
                new.writestr(info, old.read(info.filename))
    before = stdlib_zip.stat().st_size
    stdlib_zip.unlink()
    tmp.rename(stdlib_zip)
    log(f"slim stdlib: {before//1024} KB -> {stdlib_zip.stat().st_size//1024} KB")
    return dropped


def slim_site(site: Path) -> None:
    """앱이 쓰지 않는 의존성 조각만 덜어낸다(기능 손실 없음)."""
    shutil.rmtree(site / "sqlalchemy" / "testing", ignore_errors=True)
    for dialect in SQLALCHEMY_DROP_DIALECTS:
        shutil.rmtree(site / "sqlalchemy" / "dialects" / dialect, ignore_errors=True)
    for name in SITE_DROP_PACKAGES:
        shutil.rmtree(site / name, ignore_errors=True)
        for meta in site.glob(f"{name}-*.dist-info"):
            shutil.rmtree(meta, ignore_errors=True)
    # 의존성이 함께 배포한 자기 테스트 코드. 서버는 부르지 않고, unittest 를 끌어와서
    # 표준 라이브러리 슬림화까지 막는다.
    for tests in list(site.glob("*/tests")):
        if tests.is_dir():
            shutil.rmtree(tests, ignore_errors=True)
    # 타입 스텁은 런타임이 읽지 않는다(.dist-info 의 라이선스 파일은 그대로 둔다).
    for stub in site.rglob("*.pyi"):
        stub.unlink()
    log("slim site: sqlalchemy testing/non-sqlite dialects, greenlet, vendored tests, *.pyi")


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
    # compresslevel=9: 산출물은 한 번 만들어 여러 번 옮기므로 빌드 시간보다 크기가 싸다.
    # 압축 방식은 deflate 로 고정한다 — LZMA 는 더 작지만 Windows 탐색기가 못 풀어서
    # '압축만 풀고 START.bat' 이라는 이 번들의 유일한 설치 절차가 깨진다.
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, f"{PREFIX}/{p.relative_to(app).as_posix()}")
                count += 1
    return count


def split_archive(archive: Path, limit_mb: float) -> list[Path]:
    """전송 한도(USB/메일/반출 심사) 때문에 산출물을 조각으로 나눈다.

    형식은 zip 의 분할 볼륨(.z01)이 아니라 **단순 바이트 분할**(.001, .002 …)이다.
    이유는 받는 쪽의 선택지를 넓히려는 것 하나다 — 반디집/7-Zip 은 .001 을 그대로 열고,
    그런 도구가 아예 없는 서버에서도 함께 넣은 JOIN.bat 이 Windows 기본 `copy /b` 로
    되붙인다. 분할 볼륨 zip 은 도구 없이는 손쓸 방법이 없고 파이썬 표준 라이브러리로
    만들 수도 없다.

    조각을 이어붙이면 원본과 바이트가 같아야 하므로, 합친 결과의 SHA-256 을 옆에 적어
    둔다(USB 복사가 중간에 잘리는 사고는 조용히 지나가면 안 된다)."""
    limit = int(limit_mb * 1024 * 1024)
    if limit <= 0:
        raise SystemExit("--split-mb 는 0 보다 커야 합니다.")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    parts: list[Path] = []
    with archive.open("rb") as src:
        while chunk := src.read(limit):
            part = archive.with_name(f"{archive.name}.{len(parts) + 1:03d}")
            part.write_bytes(chunk)
            parts.append(part)
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest} *{archive.name}\n", encoding="ascii",
    )
    write_join_script(archive, parts, digest)
    archive.unlink()          # 조각만 남긴다. 원본이 같이 있으면 어느 쪽을 옮길지 헷갈린다.
    for part in parts:
        log(f"part {part.name}: {part.stat().st_size / 1024 / 1024:.1f} MB")
    return parts


def write_join_script(archive: Path, parts: list[Path], digest: str) -> Path:
    """조각을 되붙이는 배치 파일. 반디집이 없는 서버를 위한 최후 수단이다."""
    joined = "+".join(f'"{p.name}"' for p in parts)
    script = archive.with_name("JOIN.bat")
    script.write_text(
        "@echo off\r\n"
        "setlocal\r\n"
        "cd /d \"%~dp0\"\r\n"
        f"echo Joining {len(parts)} parts into {archive.name} ...\r\n"
        f"copy /b {joined} \"{archive.name}\" >nul\r\n"
        "if errorlevel 1 goto :failed\r\n"
        "echo Verifying SHA-256 ...\r\n"
        "powershell -NoProfile -ExecutionPolicy Bypass -Command "
        f"\"if ((Get-FileHash -Algorithm SHA256 '{archive.name}').Hash -ne '{digest}')"
        " { exit 1 }\"\r\n"
        "if errorlevel 1 goto :corrupt\r\n"
        f"echo OK. Unzip {archive.name} and run START.bat\r\n"
        "pause\r\n"
        "exit /b 0\r\n"
        ":failed\r\n"
        "echo [ERROR] join failed -- are all parts in this folder?\r\n"
        "pause\r\n"
        "exit /b 1\r\n"
        ":corrupt\r\n"
        "echo [ERROR] checksum mismatch -- copy the parts again.\r\n"
        f"del \"{archive.name}\"\r\n"
        "pause\r\n"
        "exit /b 1\r\n",
        encoding="ascii",
    )
    return script


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Build the all-in-one air-gapped bundle.")
    ap.add_argument("--python", default=DEFAULT_PYTHON, choices=sorted(PY_RELEASES),
                    help="Embedded CPython minor version to bundle.")
    ap.add_argument("--out", default=None, help="Output zip path (default: ../ScanOps_allinone[_pyXYZ].zip)")
    ap.add_argument("--no-slim", action="store_true",
                    help="Keep the untrimmed runtime (debugging the bundle itself).")
    ap.add_argument("--max-mb", type=float, default=None,
                    help="Fail the build if the archive exceeds this size in MB.")
    ap.add_argument("--split-mb", type=float, default=None, metavar="MB",
                    help="Split the archive into .001/.002 parts of at most MB each "
                         "(Bandizip/7-Zip open the .001; JOIN.bat rejoins without them).")
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
    if not args.no_slim:
        slim_site(app / "runtime" / "site")
        dropped = slim_python(app)
        # 슬림화가 끝난 상태(앱+의존성 전체)를 대고 검사해야 의미가 있다.
        verify_stdlib_drop(app, dropped)
    n = zip_bundle(app)
    size_mb = OUT.stat().st_size / 1024 / 1024
    log(f"wrote {OUT} : {n} files, {size_mb:.1f} MB")
    # --max-mb 는 '한 조각의' 한도다. 분할하면 조각 크기로 판정한다.
    limit_target = size_mb if not args.split_mb else min(args.split_mb, size_mb)
    if args.max_mb and limit_target > args.max_mb:
        raise SystemExit(
            f"번들이 한도를 넘었습니다: {limit_target:.1f} MB > {args.max_mb} MB"
        )
    if args.split_mb:
        parts = split_archive(OUT, args.split_mb)
        log(f"split into {len(parts)} parts (+ JOIN.bat, {OUT.name}.sha256)")


if __name__ == "__main__":
    main()
