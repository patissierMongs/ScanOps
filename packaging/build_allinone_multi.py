"""Multi-version all-in-one 번들 생성 — Windows x64, Python 3.11/3.12/3.13/3.14 각각.

기존 build_allinone.py 의 검증된 로직(copy_app/place_python/write_launcher/시크릿 필터)을
재사용하되, 파이썬 버전·임베디드 패치·ABI·requirements 를 파라미터화했다. 리눅스에서
크로스빌드(--platform win_amd64 --abi cpXX --only-binary=:all:).

산출: <ROOT>/_allinone_out/ScanOps_allinone_py{XY}_win_amd64.zip

Usage: python packaging/build_allinone_multi.py [3.11 3.12 3.13 3.14]
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_allinone import ROOT, copy_app, place_python, write_launcher  # 재사용

CACHE = ROOT / "packaging" / "_cache"
OUTDIR = ROOT / "_allinone_out"
PREFIX = "ScanOps"

# (minor, 임베디드 패치, ABI, requirements 경로). 3.14 는 pydantic_core 2.27.2 의 cp314 휠이
# 없어 pydantic 을 최소 상향(>=2.12 → 2.13.x, core 2.46.x cp314)한 변형 requirements 를 쓴다.
BASE_REQS = ROOT / "backend" / "requirements.txt"
REQ314 = ROOT / "packaging" / "_cache" / "requirements-py314.txt"

TARGETS = {
    "3.11": {"patch": "3.11.9",  "abi": "cp311", "reqs": BASE_REQS},
    "3.12": {"patch": "3.12.10", "abi": "cp312", "reqs": BASE_REQS},
    "3.13": {"patch": "3.13.9",  "abi": "cp313", "reqs": BASE_REQS},
    "3.14": {"patch": "3.14.2",  "abi": "cp314", "reqs": REQ314},
}


def log(msg: str) -> None:
    print(f"[allinone-multi] {msg}", flush=True)


def prep_req314() -> None:
    """3.14 용 requirements: pydantic 핀만 완화(코어 cp314 휠 확보), 나머지 고정 유지."""
    CACHE.mkdir(parents=True, exist_ok=True)
    lines = []
    for line in BASE_REQS.read_text(encoding="utf-8").splitlines():
        if line.strip().lower().startswith("pydantic=="):
            lines.append("pydantic>=2.12,<3  # 3.14: pydantic_core cp314 휠 확보 위해 최소 상향")
        else:
            lines.append(line)
    REQ314.write_text("\n".join(lines) + "\n", encoding="utf-8")


def download_embed(patch: str) -> Path:
    CACHE.mkdir(parents=True, exist_ok=True)
    dst = CACHE / f"python-{patch}-embed-amd64.zip"
    if dst.exists() and dst.stat().st_size > 1_000_000:
        log(f"embed cached: {dst.name}")
        return dst
    url = f"https://www.python.org/ftp/python/{patch}/python-{patch}-embed-amd64.zip"
    log(f"downloading {url}")
    urllib.request.urlretrieve(url, dst)
    log(f"downloaded {dst.stat().st_size // 1024} KB")
    return dst


def build_wheelhouse(minor: str, abi: str, reqs: Path) -> Path:
    """해당 버전의 win_amd64 휠을 온라인으로 받아 전용 wheelhouse 구성(소스빌드 금지)."""
    wh = CACHE / f"wheelhouse_{abi}"
    if wh.exists():
        shutil.rmtree(wh)
    wh.mkdir(parents=True)
    log(f"pip download → {wh.name} (win_amd64 {abi})")
    subprocess.check_call([
        sys.executable, "-m", "pip", "download", "--only-binary=:all:",
        "--platform", "win_amd64", "--implementation", "cp",
        "--abi", abi, "--python-version", minor,
        "-d", str(wh), "-r", str(reqs),
    ])
    return wh


def install_site(app: Path, wh: Path, minor: str, abi: str, reqs: Path) -> None:
    site = app / "runtime" / "site"
    site.mkdir(parents=True)
    log(f"pip install --target runtime/site (offline {abi} win_amd64)")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "--no-index",
        "--find-links", str(wh), "--target", str(site),
        "--platform", "win_amd64", "--python-version", minor,
        "--abi", abi, "--implementation", "cp", "--only-binary=:all:",
        "-r", str(reqs),
    ])
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)


def zip_bundle(app: Path, out: Path) -> int:
    if out.exists():
        out.unlink()
    count = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, f"{PREFIX}/{p.relative_to(app).as_posix()}")
                count += 1
    return count


def build_one(minor: str) -> Path:
    spec = TARGETS[minor]
    tag = "py" + minor.replace(".", "")
    log(f"=== building {minor} (embed {spec['patch']}, {spec['abi']}) ===")
    embed = download_embed(spec["patch"])
    wh = build_wheelhouse(minor, spec["abi"], spec["reqs"])
    stage = CACHE / f"_stage_{tag}"
    if stage.exists():
        shutil.rmtree(stage)
    app = stage / PREFIX
    app.mkdir(parents=True)
    copy_app(app)
    place_python(app, embed)
    install_site(app, wh, minor, spec["abi"], spec["reqs"])
    write_launcher(app)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    out = OUTDIR / f"ScanOps_allinone_{tag}_win_amd64.zip"
    n = zip_bundle(app, out)
    size_mb = out.stat().st_size / 1024 / 1024
    log(f"wrote {out.name}: {n} files, {size_mb:.1f} MB")
    shutil.rmtree(stage, ignore_errors=True)
    return out


def main() -> None:
    versions = sys.argv[1:] or ["3.11", "3.12", "3.13", "3.14"]
    prep_req314()
    outs = [build_one(v) for v in versions]
    log("=== DONE ===")
    for o in outs:
        log(f"  {o}  ({o.stat().st_size / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    main()
