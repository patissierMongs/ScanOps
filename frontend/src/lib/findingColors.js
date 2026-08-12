// 발견 관리 색상 인디케이터 — 표에서 눈에 먼저 들어와야 하는 값에만 파스텔 배경을 준다.
// 무엇을 강조할지는 사람마다 다르므로(위험도만 보는 사람 / 마감만 보는 사람) 요소별로 켜고 끈다.
// 규칙을 뷰가 아니라 여기에 두는 이유: 색은 '표시 규칙'이라 테스트로 고정할 수 있어야 한다.
import { dday } from "./format.js";
import { isGuessedService } from "./columns.js";

export const COLOR_KEY = "scanops.findings.colors";
export const COLOR_DEFAULTS = { risk: true, deadline: true, status: true, guess: true };
export const COLOR_ELEMENTS = [
  { key: "risk", label: "위험도" },
  { key: "deadline", label: "마감" },
  { key: "status", label: "상태" },
  { key: "guess", label: "포트 추측" },
];

/** 셀 하나에 붙일 파스텔 톤 클래스. 꺼진 요소는 색을 내지 않는다. */
export function cellTone(finding, key, flags) {
  if (!finding || !flags) return "";
  if (flags.risk && key === "risk_level") {
    if (finding.risk_level === "banned" || finding.risk_level === "high") return "tone-high";
    return finding.risk_level === "medium" ? "tone-medium" : "";
  }
  if (flags.status && key === "status") {
    if (finding.status === "처리중") return "tone-medium";
    return finding.status === "정상처리" ? "tone-low" : "";
  }
  if (flags.deadline && key === "deadline") {
    const info = dday(finding.deadline);
    return info.over ? "tone-high" : info.cls === "near" ? "tone-medium" : "";
  }
  // 관측이 아니라 포트 번호 관례로 짐작한 식별 — 확실한 값과 같은 무게로 읽히면 안 된다.
  if (flags.guess && (key === "display_identity" || key === "service")) {
    return isGuessedService(finding) ? "tone-guess" : "";
  }
  return "";
}

/** 저장된 선택을 읽는다(없거나 깨졌으면 기본값). */
export function loadColorFlags(storage) {
  try {
    return { ...COLOR_DEFAULTS, ...JSON.parse(storage?.getItem(COLOR_KEY) || "{}") };
  } catch {
    return { ...COLOR_DEFAULTS };
  }
}
