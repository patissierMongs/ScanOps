from __future__ import annotations

import threading
import time

USER_MAX_FAILURES = 5
IP_MAX_FAILURES = 30
WINDOW_SECONDS = 15 * 60
LOCK_SECONDS = 5 * 60

_LOCK = threading.Lock()
_FAILURES: dict[str, list[float]] = {}
_LOCKED_UNTIL: dict[str, float] = {}


def _keys(username: str, client_ip: str) -> list[tuple[str, int]]:
    return [
        (f"user:{(username or '').strip().casefold()}", USER_MAX_FAILURES),
        (f"ip:{client_ip or ''}", IP_MAX_FAILURES),
    ]


def retry_after(username: str, client_ip: str, now: float | None = None) -> int:
    now = time.time() if now is None else now
    with _LOCK:
        remaining = 0
        for key, _limit in _keys(username, client_ip):
            until = _LOCKED_UNTIL.get(key, 0.0)
            if until > now:
                remaining = max(remaining, int(until - now) + 1)
        return remaining


MAX_TRACKED_KEYS = 10_000


def _prune(now: float) -> None:
    for key in [k for k, until in _LOCKED_UNTIL.items() if until <= now]:
        del _LOCKED_UNTIL[key]
    for key in [k for k, stamps in _FAILURES.items()
                if not stamps or now - stamps[-1] >= WINDOW_SECONDS]:
        del _FAILURES[key]


def record_failure(username: str, client_ip: str, now: float | None = None) -> int:
    now = time.time() if now is None else now
    locked = 0
    with _LOCK:
        if len(_FAILURES) + len(_LOCKED_UNTIL) > MAX_TRACKED_KEYS:
            _prune(now)
        for key, limit in _keys(username, client_ip):
            recent = [t for t in _FAILURES.get(key, []) if now - t < WINDOW_SECONDS]
            recent.append(now)
            _FAILURES[key] = recent
            if len(recent) >= limit:
                _LOCKED_UNTIL[key] = now + LOCK_SECONDS
                _FAILURES[key] = []
                locked = LOCK_SECONDS
    return locked


def record_success(username: str, client_ip: str) -> None:
    with _LOCK:
        key = _keys(username, client_ip)[0][0]
        _FAILURES.pop(key, None)
        _LOCKED_UNTIL.pop(key, None)


def reset() -> None:
    with _LOCK:
        _FAILURES.clear()
        _LOCKED_UNTIL.clear()
