// 컬럼 빌더 단일 진실원천 (백엔드 api/findings.py COLUMNS 와 key 집합 동일).
// 화면 테이블 = 내보내기(WYSIWYG): 같은 key 로 셀값을 해석한다.
import { RISK_LABEL } from "./format.js";

const fmtDate = (v) => (v ? String(v).slice(0, 10) : "");
const joinCompliance = (list) =>
  (list || []).map((c) => `${c.std}:${c.ref}`).join("; ");

// key, label(=백엔드 헤더), get(finding)->표시문자열, display 기본형식
export const ALL_COLUMNS = [
  { key: "finding_key", label: "발견키", get: (f) => f.finding_key, mono: true },
  { key: "host_ip", label: "IP", get: (f) => f.host_ip, mono: true },
  { key: "hostname", label: "호스트명", get: (f) => f.hostname },
  { key: "port", label: "포트", get: (f) => f.port, mono: true, num: true },
  { key: "proto", label: "프로토콜", get: (f) => f.proto },
  { key: "state", label: "상태", get: (f) => f.state },
  { key: "service", label: "서비스", get: (f) => f.service },
  { key: "product", label: "제품", get: (f) => f.product },
  { key: "version", label: "버전", get: (f) => f.version },
  { key: "banner", label: "배너", get: (f) => f.banner, mono: true },
  { key: "cpe", label: "CPE", get: (f) => f.cpe, mono: true },
  { key: "fingerprint", label: "핑거프린트", get: (f) => f.fingerprint, mono: true },
  { key: "rtt", label: "RTT", get: (f) => f.rtt, mono: true },
  { key: "identification", label: "식별", get: (f) => f.identification },
  { key: "category", label: "분류", get: (f) => f.category },
  { key: "usage", label: "용도", get: (f) => f.usage },
  { key: "risk_level", label: "위험등급", get: (f) => RISK_LABEL[f.risk_level] || f.risk_level, badge: "risk" },
  { key: "remarks", label: "비고", get: (f) => f.remarks },
  { key: "compliance", label: "컴플라이언스근거", get: (f) => joinCompliance(f.compliance_json) },
  { key: "status", label: "운영상태", get: (f) => f.status, badge: "status" },
  { key: "reopened", label: "재발", get: (f) => (f.reopened ? "재발" : "") },
  { key: "dept", label: "부서", get: (f) => f.dept },
  { key: "owner", label: "담당자", get: (f) => f.owner },
  { key: "contact", label: "연락처", get: (f) => f.contact, mono: true },
  { key: "deadline", label: "마감", get: (f) => fmtDate(f.deadline), mono: true },
  { key: "first_seen", label: "등록 날짜", get: (f) => fmtDate(f.first_seen), mono: true },
  { key: "last_seen", label: "스캔 날짜", get: (f) => fmtDate(f.last_seen), mono: true },
  // 용도근거: 표에선 가용 필드로 근사 표시, 내보내기(CSV/XLSX)는 서버가 NSE 추출까지 포함한 전체를 채운다.
  { key: "purpose", label: "용도근거", get: (f) => [f.hostname, [f.service, f.product, f.version].filter(Boolean).join(" "), f.usage].filter(Boolean).join(" · ") },
  { key: "manual_note", label: "메모", get: (f) => f.manual_note },
];

export const COLUMN_MAP = Object.fromEntries(ALL_COLUMNS.map((c) => [c.key, c]));

export const cellValue = (finding, key) => {
  const col = COLUMN_MAP[key];
  return col ? col.get(finding) ?? "" : "";
};

// 프리셋 5종 (백엔드 finding 실제 컬럼에 맞춤) + 직접구성(커스텀 저장).
export const PRESETS = [
  { id: "p_report", name: "표준 보고서", cols: ["host_ip", "hostname", "port", "proto", "service", "version", "risk_level", "status", "dept", "first_seen", "last_seen"] },
  { id: "p_ports", name: "포트 인벤토리", cols: ["host_ip", "port", "proto", "state", "service"] },
  { id: "p_finger", name: "서비스 핑거프린트", cols: ["host_ip", "port", "service", "product", "version", "banner", "cpe", "fingerprint"] },
  { id: "p_risk", name: "위험·컴플라이언스", cols: ["host_ip", "port", "service", "risk_level", "category", "compliance", "status", "deadline"] },
  { id: "p_min", name: "최소 (CSV)", cols: ["host_ip", "port", "service"] },
];

export const DEFAULT_PRESET_ID = "p_report";
