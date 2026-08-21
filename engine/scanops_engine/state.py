"""run-state — 단계/호스트 재개 + 외부 중지 플래그. ScanOps 사이드카 패턴의 일반화.

중지: ScanOps(또는 사용자)가 run-state.json 의 stop=true 를 쓰면 엔진이 단계/배치/호스트
경계에서 감지하고 멈춘다(완료분 보존). 이어가기: 같은 out_dir 로 재실행하면 완료 단계·호스트를
건너뛴다. 청킹(chunker.py)의 '커서'를 '단계×호스트'로 확장한 것.
"""
from __future__ import annotations

import json
import os
import threading
import time
from copy import deepcopy
from pathlib import Path

_DEFAULT = {"stages_done": [], "open_map": {}, "live": None, "service_done": [],
            # 배치 단위 재개 — 스캔은 배치마다 sweep → 식별까지 끝내고 다음 배치로 간다.
            # 단계 전체가 아니라 '어느 배치의 어느 일까지 끝났나'가 재개 단위다.
            "batches_done": [],
            # --host-timeout 으로 포기당한 호스트. 나중에 따로 다시 스캔할 대상이라
            # 실행이 끝나도 남겨야 한다.
            "gave_up": [],
            # 프로토콜별 증거를 보존해야 TCP timeout 을 정상 UDP 결과가 지우지 않는다.
            "gave_up_by_stage": {},
            # 포트 재전송 상한에 걸린 호스트. host timeout과 원인은 다르지만 결과를 완전히
            # 신뢰할 수 없으므로 같은 후속 재스캔 흐름에서 별도 이유로 관리한다.
            "retransmission_cap_by_stage": {},
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

    def update_gave_up(self, stage, timed_out, completed):
        """단계별 timeout 을 갱신하고, 어느 단계든 남은 호스트의 합집합을 공개한다.

        같은 단계 재시도가 성공하면 그 단계 목록에서는 빠진다. 다른 단계의 timeout 증거는
        그대로 남으므로 TCP 에서 포기한 호스트를 정상 UDP 결과가 지울 수 없다.
        """
        by_stage = self.data.setdefault("gave_up_by_stage", {})
        known = list(by_stage.get(stage) or [])
        drop = set(completed)
        known = [host for host in known if host not in drop]
        for host in timed_out:
            if host not in known:
                known.append(host)
        by_stage[stage] = known

        merged = []
        for hosts in by_stage.values():
            for host in hosts:
                if host not in merged:
                    merged.append(host)
        self.data["gave_up"] = merged

    def add_retransmission_cap(self, stage, hosts):
        """한 번이라도 cap-hit이 난 호스트를 해당 실행이 끝날 때까지 보존한다."""
        by_stage = self.data.setdefault("retransmission_cap_by_stage", {})
        known = list(by_stage.get(stage) or [])
        for host in hosts:
            if host not in known:
                known.append(host)
        by_stage[stage] = known

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
        # Windows에서는 진행 API가 state를 읽는 아주 짧은 순간에도 os.replace가
        # WinError 5를 낼 수 있다. 식별 병렬 실행끼리 같은 ``.tmp`` 이름을 공유하는 것도
        # 피하고, 대상 파일의 일시적인 공유 잠금은 짧게 재시도한다.
        temp = self.path.with_name(
            f".{self.path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        temp.write_text(json.dumps(self.data, ensure_ascii=False), encoding="utf-8")
        try:
            for attempt in range(12):
                try:
                    os.replace(temp, self.path)
                    return
                except PermissionError:
                    if attempt == 11:
                        raise
                    time.sleep(min(0.01 * (attempt + 1), 0.1))
        finally:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
