// 컬럼 빌더 단일 진실원천 (백엔드 api/findings.py COLUMNS 와 key 집합 동일).
// 화면 테이블 = 내보내기(WYSIWYG): 같은 key 로 셀값을 해석한다.
import { RISK_LABEL } from "./format.js";

const fmtDate = (v) => (v ? String(v).slice(0, 10) : "");
const joinExposure = (list) =>
  (list || []).map((s) => s.detail || s.kind).filter(Boolean).join(" · ");
const joinCompliance = (list) =>
  (list || []).map((c) => `${c.std}:${c.ref}`).join("; ");

// Nmap 이 프로브로 확인하지 못하면 포트번호 관례표(nmap-services)의 이름을 그대로 내놓는다.
// 예: 8770 → "apple-iphoto". 실제로 도는 건 uvicorn 인데도 그렇다. 이 이름은 관측이 아니라
// '그 포트는 보통 이거였다'는 관례일 뿐이므로, 관측값과 같은 무게로 보여주면 안 된다.
export const isGuessedService = (finding) => finding?.identification === "추측";

// 같은 '열림'이라도 syn-ack(응답을 받아 확인)과 no-response(못 받고 추정)는 증거 강도가
// 다르다. UDP 는 응답 없는 포트가 예외가 아니라 다수라, 이 구분을 안 보여주면 추정을
// 관측처럼 읽게 된다. 판정은 서버(observation.py)가 하고 여기서는 표시만 정한다.
export const needsConfirmation = (finding) => Boolean(finding?.needs_confirmation);

/** 상태 + 근거를 한 줄로. 근거가 확인이면 굳이 덧붙이지 않는다(모든 행에 붙으면 신호가 죽는다). */
export function stateWithEvidence(finding) {
  const state = finding?.state || "";
  const evidence = finding?.state_evidence || "";
  if (!evidence || evidence === "응답 확인") return state;
  return `${state} (${evidence})`;
}

// 부재로 닫힌 행에는 열려 있던 시절의 reason 이 provenance 로 남아 있다. 그걸 현재 상태
// 옆에 그대로 보여 주면 'closed · syn-ack' 이 되어 읽는 사람이 둘을 잇는다.
const STALE_EVIDENCE = new Set(["부재로 판정", "미관측"]);

/** 현재 상태를 뒷받침하는 근거 원문만. 아니면 빈 문자열(서버 observation.current_reason 과 같은 규칙). */
export function currentReason(finding) {
  if (finding?.current_reason != null) return finding.current_reason;
  if (STALE_EVIDENCE.has(finding?.state_evidence || "")) return "";
  return finding?.reason || "";
}

export function observedIdentity(finding) {
  const productVersion = [finding?.product, finding?.version].filter(Boolean).join(" ");
  return finding?.server || productVersion || "";
}

export function primaryServiceIdentity(finding) {
  // 서버 identity.display_identity 가 표기의 단일 진실원천이다(추측 표시 포함).
  // 여기서 다시 계산하면 표와 내보내기가 서로 다른 문자열을 내게 된다.
  if (finding?.display_identity) return finding.display_identity;
  const observed = observedIdentity(finding);
  if (observed) return observed;
  const service = finding?.service;
  if (!service) return "—";
  return isGuessedService(finding) ? `${service} (포트 추측)` : service;
}

export function secondaryServiceIdentity(finding) {
  const primary = primaryServiceIdentity(finding);
  const service = finding?.service;
  const values = [
    [finding?.product, finding?.version].filter(Boolean).join(" "),
    // 관측값이 있는데 포트 관례 이름을 옆에 덧붙이면 'uvicorn apple-iphoto' 처럼 읽혀
    // 오히려 식별을 흐린다. 추측 이름은 주 식별이 관측값일 때 숨긴다.
    isGuessedService(finding) && observedIdentity(finding) ? "" : service,
  ].filter((value, index, all) => value && value !== primary && all.indexOf(value) === index);
  return values.join(" · ");
}

// fingerprint-strings 원시 응답을 사람이 읽기 좋게: probe 그룹별로 들여쓰기 정리 + 동일 응답 합치기.
// 백엔드 nmap_parse.pretty_fingerprint 와 동일 로직(표=내보내기 동일하게).
export function prettyFingerprint(raw) {
  if (!raw) return "";
  const blocks = [];
  let cur = null;
  for (const ln of String(raw).replace(/\r/g, "").split("\n")) {
    if (!ln.trim()) continue;
    const m = ln.match(/^\s{1,3}(\S.*?):\s*$/);   // probe 그룹 헤더(들여쓰기 + 콜론 끝)
    if (m) { cur = { probes: m[1], body: [] }; blocks.push(cur); }
    else if (cur) cur.body.push(ln.trim());
    else { cur = { probes: "", body: [ln.trim()] }; blocks.push(cur); }
  }
  const seen = new Set();
  const out = [];
  for (const b of blocks) {
    const key = b.body.join("\n");
    if (seen.has(key)) continue;                  // 동일 응답(여러 probe) 중복 제거
    seen.add(key);
    out.push((b.probes ? `[${b.probes}]\n` : "") + b.body.join("\n"));
  }
  return out.join("\n\n");
}

// key, label(=백엔드 헤더), get(finding)->표시문자열, display 기본형식
export const ALL_COLUMNS = [
  { key: "finding_key", label: "발견키", get: (f) => f.finding_key, mono: true },
  { key: "host_ip", label: "IP", get: (f) => f.host_ip, mono: true },
  { key: "hostname", label: "호스트명", get: (f) => f.hostname },
  { key: "port", label: "포트", get: (f) => f.port, mono: true, num: true },
  { key: "proto", label: "프로토콜", get: (f) => f.proto },
  { key: "state", label: "상태", get: (f) => f.state },
  { key: "state_evidence", label: "상태 근거", get: (f) => f.state_evidence || "" },
  { key: "reason", label: "근거 원문", get: (f) => f.current_reason ?? currentReason(f), mono: true },
  { key: "display_identity", label: "주 식별", get: (f) => primaryServiceIdentity(f) },
  { key: "server", label: "Server", get: (f) => f.server },
  { key: "service", label: "서비스", get: (f) => f.service },
  { key: "product", label: "제품", get: (f) => f.product },
  { key: "version", label: "버전", get: (f) => f.version },
  { key: "banner", label: "서비스 상세", get: (f) => f.banner, mono: true },
  { key: "cpe", label: "CPE", get: (f) => f.cpe, mono: true },
  { key: "fingerprint", label: "핑거프린트", get: (f) => prettyFingerprint(f.fingerprint), mono: true, pre: true },
  { key: "rtt", label: "RTT", get: (f) => f.rtt, mono: true },
  { key: "identification", label: "식별", get: (f) => f.identification },
  { key: "category", label: "분류", get: (f) => f.category },
  { key: "usage", label: "용도", get: (f) => f.usage },
  { key: "risk_level", label: "위험등급", get: (f) => RISK_LABEL[f.risk_level] || f.risk_level, badge: "risk" },
  { key: "remarks", label: "비고", get: (f) => f.remarks },
  // 관측된 노출 사실(익명 접근·평문·레거시·인증서 문제). 등급을 올린 근거이기도 하다.
  { key: "exposure", label: "노출 관측", get: (f) => joinExposure(f.exposure_json) },
  { key: "compliance", label: "컴플라이언스근거", get: (f) => joinCompliance(f.compliance_json) },
  { key: "status", label: "운영상태", get: (f) => f.status, badge: "status" },
  { key: "reopened", label: "재발", get: (f) => (f.reopened ? "재발" : "") },
  { key: "dept", label: "부서", get: (f) => f.dept },
  { key: "owner", label: "담당자(자산대장)", get: (f) => f.owner },
  // 배정 담당자 — '이 발견을 조치할 사람'. 자산대장 담당자(그 자산을 관리하는 사람)와
  // 다른 축이라 라벨도 컬럼도 나눈다.
  { key: "assignee", label: "배정 담당자", get: (f) => f.assignee_name },
  { key: "contact", label: "연락처", get: (f) => f.contact, mono: true },
  { key: "deadline", label: "마감", get: (f) => fmtDate(f.deadline), mono: true },
  { key: "first_seen", label: "등록 날짜", get: (f) => fmtDate(f.first_seen), mono: true },
  { key: "last_seen", label: "스캔 날짜", get: (f) => fmtDate(f.last_seen), mono: true },
  // 용도근거: 표에선 가용 필드로 근사 표시, 내보내기(CSV/XLSX)는 서버가 NSE 추출까지 포함한 전체를 채운다.
  { key: "purpose", label: "용도근거", get: (f) => [f.hostname, primaryServiceIdentity(f), secondaryServiceIdentity(f), f.usage].filter((v) => v && v !== "—").join(" · ") },
  { key: "manual_note", label: "메모", get: (f) => f.manual_note },
];

export const COLUMN_MAP = Object.fromEntries(ALL_COLUMNS.map((c) => [c.key, c]));

export const cellValue = (finding, key) => {
  const col = COLUMN_MAP[key];
  return col ? col.get(finding) ?? "" : "";
};

// 프리셋 5종 (백엔드 finding 실제 컬럼에 맞춤) + 직접구성(커스텀 저장).
export const PRESETS = [
  { id: "p_report", name: "표준 보고서", cols: ["host_ip", "hostname", "port", "proto", "display_identity", "service", "risk_level", "status", "dept", "first_seen", "last_seen"] },
  { id: "p_ports", name: "포트 인벤토리", cols: ["host_ip", "port", "proto", "state", "display_identity", "service"] },
  { id: "p_finger", name: "서비스 핑거프린트", cols: ["host_ip", "port", "display_identity", "server", "service", "product", "version", "banner", "cpe", "fingerprint"] },
  { id: "p_risk", name: "위험·컴플라이언스", cols: ["host_ip", "port", "display_identity", "service", "risk_level", "exposure", "category", "compliance", "status", "deadline"] },
  { id: "p_min", name: "최소 (CSV)", cols: ["host_ip", "port", "display_identity"] },
];

export const DEFAULT_PRESET_ID = "p_report";
