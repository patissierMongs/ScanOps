"""run-state — 단계/호스트 재개 + 외부 중지 플래그. ScanOps 사이드카 패턴의 일반화.

중지: ScanOps(또는 사용자)가 run-state.json 의 stop=true 를 쓰면 엔진이 단계/배치/호스트
경계에서 감지하고 멈춘다(완료분 보존). 이어가기: 같은 out_dir 로 재실행하면 완료 단계·호스트를
건너뛴다. 청킹(chunker.py)의 '커서'를 '단계×호스트'로 확장한 것.
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

_DEFAULT = {"stages_done": [], "open_map": {}, "live": None, "service_done": [],
            # 배치 단위 재개 — 스캔은 배치마다 sweep → 식별까지 끝내고 다음 배치로 간다.
            # 단계 전체가 아니라 '어느 배치의 어느 일까지 끝났나'가 재개 단위다.
            "batches_done": [],
            # --host-timeout 으로 포기당한 호스트. 나중에 따로 다시 스캔할 대상이라
            # 실행이 끝나도 남겨야 한다. 진실은 프로토콜별로 들고(gave_up_by_proto),
            # gave_up 은 그 합집합이다 - 소비자가 읽기 쉽게 평면으로도 남긴다.
            "gave_up": [], "gave_up_by_proto": {},
            "stop": False}
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

    def batch_done(self, key) -> bool:
        return key in self.data["batches_done"]

    def mark_batch_done(self, key):
        if key not in self.data["batches_done"]:
            self.data["batches_done"].append(key)

    def record_gave_up(self, proto, covered, gave_up):
        """이 프로토콜의 sweep 결과를 반영한다 - **그 프로토콜의 몫만** 건드린다.

        한 목록으로 뭉치면 순서 의존 오류가 난다. 같은 배치에서 TCP 가 포기당하고 UDP 가
        정상이면, 뒤에 도는 UDP 의 성공이 앞의 TCP 포기를 지워 그 호스트가 재시도 대상에서
        조용히 사라진다. 순서를 뒤집으면 반대가 남는다 - 어느 쪽이든 틀린다.

        재시도로 끝까지 훑은 호스트는 그 프로토콜에서만 빠진다(한 번 걸렸다고 영구 낙인이
        아니다). 다른 프로토콜에서 아직 못 본 호스트는 합집합에 그대로 남는다.
        """
        by = dict(self.data.get("gave_up_by_proto") or {})
        known = set(by.get(proto) or [])
        known |= set(gave_up)
        known -= (set(covered) - set(gave_up))
        if known:
            by[proto] = sorted(known)
        else:
            by.pop(proto, None)
        self.data["gave_up_by_proto"] = by
        union: set = set()
        for hosts in by.values():
            union |= set(hosts)
        self.data["gave_up"] = sorted(union)

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
