"""인증 프리미티브 — 에어갭 위해 stdlib 만 사용(네이티브 의존 0).

- 비밀번호: PBKDF2-HMAC-SHA256 (반복 200k), 솔트 동봉 포맷.
- 토큰: HMAC 서명된 stateless 토큰 (uid.exp.sig).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode

_PBKDF2_ROUNDS = 200_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, dk_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, AttributeError):
        return False


def _b64e(b: bytes) -> str:
    return urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64d(s: str) -> bytes:
    return urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(user_id: int, secret: bytes, ttl_hours: int) -> str:
    exp = int(time.time()) + ttl_hours * 3600
    payload = f"{user_id}.{exp}"
    sig = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
    return f"{payload}.{_b64e(sig)}"


def verify_token(token: str, secret: bytes) -> int | None:
    """유효하면 user_id, 아니면 None."""
    try:
        uid_s, exp_s, sig_s = token.split(".")
        payload = f"{uid_s}.{exp_s}"
        expected = hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64d(sig_s)):
            return None
        if int(exp_s) < int(time.time()):
            return None
        return int(uid_s)
    except (ValueError, AttributeError):
        return None


def load_or_create_secret(path) -> bytes:
    """에어갭에서 안전한 서명 시크릿을 최초 1회 생성·보관."""
    from pathlib import Path

    p = Path(path)
    if p.exists():
        return p.read_bytes()
    secret = secrets.token_bytes(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(secret)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return secret
