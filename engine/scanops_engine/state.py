"""run-state — 단계/호스트 재개 + 외부 중지 플래그. ScanOps 사이드카 패턴의 일반화.

중지: ScanOps(또는 사용자)가 run-state.json 의 stop=true 를 쓰면 엔진이 단계/배치/호스트
경계에서 감지하고 멈춘다(완료분 보존). 이어가기: 같은 out_dir 로 재실행하면 완료 단계·호스트를
건너뛴다. 청킹(chunker.py)의 '커서'를 '단계×호스트'로 확장한 것.
"""
from __future__ import annotations

import json
from pathlib import Path

_DEFAULT = {"stages_done": [], "open_map": {}, "live": None, "service_done": [], "stop": False}


class RunState:
    def __init__(self, path):
        self.path = Path(path)
        self.data = dict(_DEFAULT)
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
        """외부가 파일에 stop=true 를 쓰면 감지 — 디스크 신선 읽기(메모리 캐시 우회)."""
        if self.path.exists():
            try:
                return bool(json.loads(self.path.read_text(encoding="utf-8")).get("stop"))
            except (OSError, ValueError):
                pass
        return bool(self.data.get("stop"))

    def save(self):
        self.path.write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
