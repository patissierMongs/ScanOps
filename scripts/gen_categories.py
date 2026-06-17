"""nmapParser categories.xlsx → ScanOps seed/categories.json 생성.

분류(category)는 그대로 가져오고, 위험등급/컴플라이언스 근거를 규칙으로 부여한다.
(데이터 유도는 이 스크립트에서 명시적으로 — 런타임 taxonomy 는 JSON 만 읽어 단순.)
"""
import json
from pathlib import Path

import openpyxl

SRC = Path(r"C:\Users\upica\claude\nmapParser1\categories.xlsx")
OUT = Path(__file__).resolve().parents[1] / "backend" / "scanops" / "seed" / "categories.json"

# 분류별 기본 위험등급
CATEGORY_RISK = {
    "원격접속": "high", "DBMS": "high", "파일공유": "high", "산업제어": "high",
    "디렉토리": "high", "인증": "high",
    "웹": "medium", "파일전송": "medium", "VPN": "medium", "VoIP": "medium",
    "RPC": "medium", "프록시": "medium", "컨테이너": "medium", "메시지큐": "medium",
    "메일": "medium", "네트워크검색": "medium", "정보조회": "medium", "관리": "medium",
}  # 그 외 분류는 'low'

# 평문/고노출 서비스는 분류와 무관하게 high 로 승격
FORCE_HIGH = {
    "telnet", "ftp", "tftp", "rlogin", "rsh", "rexec", "vnc", "snmp",
    "microsoft-ds", "smb", "netbios-ssn", "netbios-ns", "ms-wbt-server", "rdp",
    "x11", "rpcbind", "ldap",
}

# 컴플라이언스 근거 — 분류 기준(KISA: 기반시설 취약점 점검 항목 취지, NIS: 보안업무 지침 취지)
COMPLIANCE_BY_CATEGORY = {
    "원격접속": [{"std": "KISA", "ref": "평문 원격관리 프로토콜 사용 제한"},
              {"std": "NIS", "ref": "원격 접속 통제"}],
    "파일전송": [{"std": "KISA", "ref": "평문 파일전송(FTP/TFTP) 노출 점검"}],
    "파일공유": [{"std": "KISA", "ref": "불필요한 파일공유 서비스 차단"},
              {"std": "NIS", "ref": "공유 폴더 접근통제"}],
    "DBMS": [{"std": "KISA", "ref": "DB 서비스 외부 직접 노출 차단"},
             {"std": "NIS", "ref": "DB 접근통제"}],
    "산업제어": [{"std": "NIS", "ref": "제어시스템 망분리"}],
    "디렉토리": [{"std": "KISA", "ref": "LDAP 익명 바인드 점검"}],
    "정보조회": [{"std": "KISA", "ref": "SNMP 기본 community/정보노출 점검"}],
    "인증": [{"std": "NIS", "ref": "인증 서비스 접근통제"}],
}


def risk_for(service: str, category: str) -> str:
    if service in FORCE_HIGH:
        return "high"
    return CATEGORY_RISK.get(category, "low")


def main() -> None:
    wb = openpyxl.load_workbook(SRC)
    ws = wb.active
    out = []
    for row in list(ws.iter_rows(values_only=True))[1:]:
        if not row or not row[0]:
            continue
        service = str(row[0]).strip().lower()
        category = (str(row[1]).strip() if row[1] else "")
        usage = (str(row[2]).strip() if len(row) > 2 and row[2] else "")
        desc = (str(row[3]).strip() if len(row) > 3 and row[3] else "")
        out.append({
            "service_name": service,
            "category": category,
            "usage": usage,
            "risk_level": risk_for(service, category),
            "compliance": COMPLIANCE_BY_CATEGORY.get(category, []),
            "desc": desc,
        })
    OUT.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {len(out)} services -> {OUT}")
    hi = sum(1 for x in out if x["risk_level"] == "high")
    print(f"  high={hi}, with-compliance={sum(1 for x in out if x['compliance'])}")


if __name__ == "__main__":
    main()
