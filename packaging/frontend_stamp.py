"""커밋된 `frontend/dist` 가 지금 소스로 만든 것인지 확인하는 지문.

`frontend/dist` 는 에어갭 배포용으로 **커밋되는** 산출물이다(.gitignore 참고). 그래서
소스만 고치고 다시 빌드하지 않으면, 저장소와 올인원 번들이 코드와 다른 화면을 싣는다 -
테스트는 소스를 보고 통과하고 CI 는 러너에서 새로 빌드했다 버리므로 아무도 못 잡는다.
실제로 그렇게 한 번 나갔다.

빌드 결과물을 비교하지 않는 이유: vite/rollup 출력은 node 버전에 따라 달라질 수 있어
CI 와 로컬이 다른 파일을 만들 수 있다. 대신 **입력**(소스)을 해시해 dist 옆에 적어 둔다.
빌드 도구가 무엇을 뱉든, 입력이 달라졌는지는 확실히 안다.

    python packaging/frontend_stamp.py            # 확인만 (다르면 exit 1)
    python packaging/frontend_stamp.py --write    # npm run build 직후 갱신
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STAMP = ROOT / "frontend" / "dist" / ".srcstamp"

# 빌드 입력. 여기 없는 것을 고치면 지문이 안 변하니, 화면에 영향을 주는 것은 다 넣는다.
SOURCE_TREES = ("frontend/src", "frontend/public", "frontend/vendor")
SOURCE_FILES = (
    "frontend/index.html", "frontend/package.json",
    "frontend/package-lock.json", "frontend/vite.config.js",
)
SKIP_NAMES = {".DS_Store"}


def _inputs() -> list[Path]:
    found: list[Path] = []
    for rel in SOURCE_TREES:
        base = ROOT / rel
        if base.is_dir():
            found += [p for p in base.rglob("*")
                      if p.is_file() and p.name not in SKIP_NAMES]
    found += [ROOT / rel for rel in SOURCE_FILES if (ROOT / rel).is_file()]
    return sorted(found, key=lambda p: p.relative_to(ROOT).as_posix())


def compute() -> str:
    digest = hashlib.sha256()
    for path in _inputs():
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def stale() -> str:
    """일치하면 "", 아니면 사람이 읽을 이유."""
    if not (ROOT / "frontend" / "dist" / "index.html").is_file():
        return "frontend/dist 가 없습니다."
    if not STAMP.is_file():
        return "frontend/dist/.srcstamp 이 없습니다(빌드 후 지문을 안 남겼습니다)."
    if STAMP.read_text(encoding="utf-8").strip() != compute():
        return "frontend/dist 가 지금 소스보다 낡았습니다."
    return ""


REBUILD_HINT = (
    "  cd frontend && npm run build\n"
    "  python packaging/frontend_stamp.py --write\n"
    "  git add frontend/dist"
)


def main(argv: list[str]) -> int:
    if "--write" in argv:
        STAMP.parent.mkdir(parents=True, exist_ok=True)
        STAMP.write_text(compute() + "\n", encoding="utf-8")
        print(f"[stamp] {STAMP.relative_to(ROOT)} = {compute()[:12]}…")
        return 0
    reason = stale()
    if reason:
        print(f"[stamp] {reason}\n{REBUILD_HINT}", file=sys.stderr)
        return 1
    print("[stamp] frontend/dist 는 지금 소스로 만든 것입니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
