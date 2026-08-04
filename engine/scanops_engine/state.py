"""run-state — 단계/호스트 재개 + 외부 중지 플래그. ScanOps 사이드카 패턴의 일반화.

중지: ScanOps(또는 사용자)가 run-state.json 의 stop=true 를 쓰면 엔진이 단계/배치/호스트
경계에서 감지하고 멈춘다(완료분 보존). 이어가기: 같은 out_dir 로 재실행하면 완료 단계·호스트를
건너뛴다. 청킹(chunker.py)의 '커서'를 '단계×호스트'로 확장한 것.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

_DEFAULT = {"stages_done": [], "open_map": {}, "live": None, "service_done": [], "stop": False}
_STOP_SENTINEL = "stop-requested"


class RunState:
    def __init__(self, path):
        self.path = Path(path)
        self.stop_path = self.path.parent / _STOP_SENTINEL
        # Lists/dicts are per-run state. A shallow copy leaks completed stages and hosts into
        # later Pipeline instances in the same process (notably tests and embedded callers).
        self.data = deepcopy(_DEFAULT)
        if self.path.exists():
            try:
                self.data.update(json.loads(self.path.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass

    def get(self, k, default=None):
        return self.data.get(k, default)

    def set(self, k, v):
        self.data[k] = v

    def done(self, stage) -> bool:
        return stage in self.data["stages_done"]

    def mark_done(self, stage):
        if stage not in self.data["stages_done"]:
            self.data["stages_done"].append(stage)

    def service_done(self, ip) -> bool:
        return ip in self.data["service_done"]

    def mark_service_done(self, ip):
        if ip not in self.data["service_done"]:
            self.data["service_done"].append(ip)

    def stopped(self) -> bool:
        """외부 중지 sentinel을 우선 감지하고 구형 JSON stop=true도 이어받는다."""
        if self.stop_path.exists():
            return True
        if self.path.exists():
            try:
                return bool(json.loads(self.path.read_text(encoding="utf-8")).get("stop"))
            except (OSError, ValueError):
                pass
        return bool(self.data.get("stop"))

    def save(self):
        # sentinel은 진행 state JSON과 분리되어 stale save가 중지 요청을 덮을 수 없다.
        if self.stopped():
            self.data["stop"] = True
        temp = self.path.with_name(f"{self.path.name}.tmp")
        temp.write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        temp.replace(self.path)
