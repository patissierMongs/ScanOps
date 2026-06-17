"""설정 — 환경변수 또는 기본값. 에어갭/사내서버 운영 가정."""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_data_dir() -> Path:
    # 운영 데이터(SQLite/스캔 산출물/시크릿)는 프로젝트 밖 data/ 에 모은다.
    env = os.environ.get("SCANOPS_DATA_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SCANOPS_", env_file=".env", extra="ignore")

    # 경로
    data_dir: Path = _default_data_dir()
    # 프론트 빌드 산출물(에어갭 배포 시 동봉). 없으면 정적 서빙 생략(API만).
    frontend_dist: Path = Path(__file__).resolve().parents[2] / "frontend" / "dist"

    # 서버
    host: str = "0.0.0.0"
    port: int = 8770

    # 인증
    # 시크릿은 최초 부팅 시 data_dir/secret.key 에 생성·보관(에어갭에서 안전한 난수).
    token_ttl_hours: int = 12

    # nmap
    # 비우면 표준 위치 자동 탐지(find_nmap_exe). 지정 시 그 경로 사용.
    nmap_path: str = ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scanops.db"

    @property
    def scans_dir(self) -> Path:
        return self.data_dir / "scans"

    @property
    def secret_file(self) -> Path:
        return self.data_dir / "secret.key"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.scans_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
