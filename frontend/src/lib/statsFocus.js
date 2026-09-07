// 통계 행에서 발견 목록으로 넘어갈 때의 조건.
//
// 통계는 활성 상태(open + open|filtered)를 세고 식별로 거르지 않는다. 그래서 발견 목록의
// 기본 접힘(미확정·tcpwrapped)을 그대로 두고 넘어가면 "22번 포트 12대" 를 눌렀는데 목록에는
// 8건만 나온다 - 통계가 틀린 것처럼 보인다. 접힘은 목록 화면의 표시 정책일 뿐이므로
// 이 이동에서는 푼다(matchFocus 가 규칙 건수에서 같은 판단을 하는 것과 같은 이유다).
//
// 다만 정상처리·허용은 **통계가 실제로 센 대로** 따라간다. 통계에서 뺐으면 목록에서도 빼야
// 두 수가 맞는다.
export function statsFocus(kind, row, filters = {}) {
  const applied = {};
  if (kind === "ports") {
    applied.port = String(row.port ?? "");
    if (row.proto) applied.proto = row.proto;
  } else if (kind === "services") {
    applied.service = row.service === "(미식별)" ? "" : row.service || "";
  } else {
    applied.product = row.product === "(미식별)" ? "" : row.product || "";
  }
  return {
    filters: applied,
    match: kind === "products" ? "contains" : "exact",
    hideNormal: !filters.include_resolved,
    hideAllowed: !filters.include_allowed,
    hideUnconfirmed: false,
    hideTcpwrapped: false,
  };
}
