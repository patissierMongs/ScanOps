// 규칙이 잡는 발견을 실제로 보러 갈 때의 조건.
//
// 서버의 _match_count 와 **같은 기준**이어야 건수와 목록이 어긋나지 않는다: 서비스·포트는
// 정확일치, 제품·CPE 는 부분일치이고, 건수는 상태(정상처리)나 허용 여부를 가리지 않으므로
// 그 접힘도 함께 푼다. 접힌 채로 이동하면 "3건" 을 눌렀는데 빈 목록이 나온다.
export function matchFocus(rule) {
  const filters = {};
  let match = "exact";
  if (rule.kind === "port_rule") {
    filters.port = String(rule.port ?? "");
    if (rule.service) filters.service = rule.service;
  } else if (rule.kind === "product_rule") {
    filters.product = rule.product || "";
    match = "contains";
  } else if (rule.kind === "cpe_rule") {
    filters.cpe = rule.cpe || "";
    match = "contains";
  } else {
    filters.service = rule.service || "";
  }
  return { filters, match, hideNormal: false, hideAllowed: false };
}
