"""자산대장 라우터 — CRUD + xlsx 가져오기 + 발견 매칭(IP→부서)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Asset, Finding, User
from ..schemas import AssetIn, AssetOut
from .deps import current_user, require_role

router = APIRouter()

# xlsx 헤더 별칭 → 표준 필드
_ALIASES = {
    "ip": "ip", "아이피": "ip", "host_ip": "ip", "주소": "ip",
    "hostname": "hostname", "호스트명": "hostname", "호스트": "hostname",
    "dept": "dept", "부서": "dept", "담당부서": "dept",
    "owner": "owner", "담당자": "owner",
    "asset_no": "asset_no", "자산번호": "asset_no", "관리번호": "asset_no",
    "note": "note", "비고": "note",
}


def match_assets(db: Session) -> int:
    """자산대장 IP 로 finding.dept/contact/owner 채움(자산이 진실원천). 갱신 건수 리턴."""
    by_ip = {a.ip: a for a in db.query(Asset).all()}
    n = 0
    for f in db.query(Finding).all():
        a = by_ip.get(f.host_ip)
        if not a:
            continue
        changed = False
        if a.dept and f.dept != a.dept:
            f.dept = a.dept
            changed = True
        if a.contact and f.contact != a.contact:
            f.contact = a.contact
            changed = True
        if a.owner and f.owner != a.owner:   # 자산대장 담당자명 → 통보에 활용
            f.owner = a.owner
            changed = True
        if changed:
            n += 1
    db.commit()
    return n


@router.get("", response_model=list[AssetOut])
def list_assets(_: User = Depends(current_user), db: Session = Depends(get_db)):
    return db.query(Asset).order_by(Asset.ip).all()


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(body: AssetIn, _: User = Depends(require_role("auditor")), db: Session = Depends(get_db)):
    a = Asset(**body.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    match_assets(db)
    return a


@router.patch("/{aid}", response_model=AssetOut)
def update_asset(aid: int, body: AssetIn, _: User = Depends(require_role("auditor")), db: Session = Depends(get_db)):
    a = db.get(Asset, aid)
    if a is None:
        raise HTTPException(status_code=404, detail="자산을 찾을 수 없습니다.")
    for k, v in body.model_dump().items():
        setattr(a, k, v)
    db.commit()
    db.refresh(a)
    match_assets(db)
    return a


@router.delete("/{aid}", status_code=204)
def delete_asset(aid: int, _: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    a = db.get(Asset, aid)
    if a is None:
        raise HTTPException(status_code=404, detail="자산을 찾을 수 없습니다.")
    db.delete(a)
    db.commit()


@router.post("/bulk")
def bulk_import(
    body: list[AssetIn],
    _: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    """프론트(SheetJS)가 병합해제·헤더감지·매핑까지 끝낸 레코드를 IP 기준 업서트."""
    by_ip = {a.ip: a for a in db.query(Asset).all()}
    added = updated = 0
    for rec in body:
        ip = rec.ip.strip()
        if not ip:
            continue
        a = by_ip.get(ip)
        if a is None:
            a = Asset(**rec.model_dump())
            db.add(a)
            by_ip[ip] = a
            added += 1
        else:
            for k, v in rec.model_dump().items():
                if k != "ip" and v:
                    setattr(a, k, v)
            updated += 1
    db.commit()
    matched = match_assets(db)
    return {"added": added, "updated": updated, "findings_matched": matched}


@router.post("/import")
async def import_assets(
    file: UploadFile = File(...),
    _: User = Depends(require_role("auditor")),
    db: Session = Depends(get_db),
):
    import openpyxl

    wb = openpyxl.load_workbook(await _to_tmp(file), read_only=True)
    ws = wb.active
    rows = list(ws.iter_rows(values_only=True))
    if not rows:
        raise HTTPException(status_code=400, detail="빈 파일입니다.")
    header = [(_ALIASES.get(str(c).strip().lower()) if c else None) for c in rows[0]]
    if "ip" not in header:
        raise HTTPException(status_code=400, detail="IP 컬럼을 찾을 수 없습니다. (헤더: IP/아이피/주소)")

    by_ip = {a.ip: a for a in db.query(Asset).all()}
    added = updated = 0
    for row in rows[1:]:
        rec = {header[i]: (str(row[i]).strip() if row[i] is not None else "")
               for i in range(len(header)) if header[i]}
        ip = rec.get("ip", "")
        if not ip:
            continue
        a = by_ip.get(ip)
        if a is None:
            a = Asset(**{k: rec.get(k, "") for k in ("ip", "hostname", "dept", "owner", "asset_no", "note")})
            db.add(a)
            by_ip[ip] = a
            added += 1
        else:
            for k in ("hostname", "dept", "owner", "asset_no", "note"):
                if rec.get(k):
                    setattr(a, k, rec[k])
            updated += 1
    db.commit()
    matched = match_assets(db)
    return {"added": added, "updated": updated, "findings_matched": matched}


async def _to_tmp(file: UploadFile):
    import io
    return io.BytesIO(await file.read())
