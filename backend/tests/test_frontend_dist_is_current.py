"""커밋된 화면 산출물이 커밋된 소스와 같은 것인지.

`frontend/dist` 는 에어갭 배포용으로 커밋된다. 그래서 소스만 고치고 빌드를 안 하면
저장소가 코드와 다른 화면을 들고 있게 되는데, 어떤 검사도 그걸 못 잡았다 - 프런트
테스트는 `src/` 를 읽고, CI 의 `npm run build` 는 러너에서 새로 만들었다 버린다.
실제로 배지 수정이 소스에만 들어간 채 번들로 나갈 뻔했다.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

import frontend_stamp  # noqa: E402


def test_the_committed_frontend_build_matches_the_committed_sources():
    reason = frontend_stamp.stale()
    assert not reason, f"{reason}\n{frontend_stamp.REBUILD_HINT}"


def test_the_stamp_actually_watches_the_files_the_screen_is_built_from():
    """지문이 무엇을 보는지 - 화면 소스를 고쳐도 안 변하면 위 검사는 빈 검사다."""
    watched = {p.relative_to(ROOT).as_posix() for p in frontend_stamp._inputs()}
    for must in ("frontend/src/views/Scans.jsx", "frontend/src/lib/scanStatus.js",
                 "frontend/index.html", "frontend/package.json"):
        assert must in watched, f"{must} 가 지문 대상에 없다"

    before = frontend_stamp.compute()
    target = ROOT / "frontend" / "src" / "lib" / "scanStatus.js"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n// stamp probe\n")
        assert frontend_stamp.compute() != before, "소스를 고쳐도 지문이 그대로다"
    finally:
        target.write_bytes(original)
    assert frontend_stamp.compute() == before, "원상복구했는데 지문이 다르다"
