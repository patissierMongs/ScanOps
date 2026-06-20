"""이벤트 싱크 — NDJSON 을 stdout + 파일에 동시 기록(스레드 안전). 가시화의 원천.

한 줄 = 한 이벤트(JSON). ScanOps 가 이 스트림을 tail 해 진행/단계/에러를 UI 로 흘린다.
event 종류: job_start, stage_start, stage_progress, hosts_up, ports_open,
            service, error, stage_done, job_done
"""
from __future__ import annotations

import json
import sys
import threading
import time


class EventSink:
    def __init__(self, path=None, stdout: bool = True):
        self._lock = threading.Lock()
        self._fh = open(path, "a", encoding="utf-8") if path else None
        self._stdout = stdout

    def emit(self, event: str, **fields) -> None:
        rec = {"event": event, "ts": round(time.time(), 3), **fields}
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            if self._stdout:
                sys.stdout.write(line + "\n")
                sys.stdout.flush()
            if self._fh:
                self._fh.write(line + "\n")
                self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
