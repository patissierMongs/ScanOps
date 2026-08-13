export const SCAN_STATUS = {
  running: { label: "실행 중", cls: "info" },
  canceling: { label: "중지 중", cls: "medium" },
  canceled: { label: "중지됨", cls: "medium" },
  interrupted: { label: "중단됨(서버 재시작)", cls: "high" },
  failed: { label: "실패", cls: "high" },
  // 결과는 쓸 수 있지만 nmap 이 끝까지 정상 종료하지 못한 실행 — 닫힘 판정에서 제외된다.
  partial: { label: "부분 완료", cls: "medium" },
  done: { label: "완료", cls: "low" },
};

export function scanStatus(status) {
  return SCAN_STATUS[status] || { label: status || "알 수 없음", cls: "info" };
}

// 완료된 스캔에도 남는 참고 코드 — '실패'가 아니라 '부가 증거가 덜 찼다'는 뜻이다.
// 포트 관측은 온전하므로 실패와 같은 자리에 같은 말로 그리면 방금 분리한 의미가 도로 합쳐진다.
const NOTICE_CODES = {
  nse_degraded: "참고 — 부가 정보 불완전",
};

export function scanNotice(source = {}) {
  const message = source.failure_message;
  if (!message) return null;
  const code = source.failure_code || "";
  const title = NOTICE_CODES[code];
  return title
    ? { tone: "notice", title, message, code }
    : { tone: "failure", title: "실패 원인", message, code };
}

export function scanKind(scan = {}) {
  if (scan.kind === "staged") return { key: "staged", label: "단계 엔진" };
  const name = String(scan.name || "");
  const command = String(scan.command || "");
  if (name.startsWith("가져오기:")) return { key: "import", label: "XML 가져오기" };
  if (command.includes("단계스캔(엔진)") || command.includes("타겟 재스캔(엔진)")) {
    return { key: "staged", label: "단계 엔진" };
  }
  return { key: "legacy", label: "레거시/직접" };
}

export function shouldLoadStages(scan = {}) {
  const active = scan.status === "running" || scan.status === "canceling";
  return active || (scanKind(scan).key === "staged" && !scan.stages_json?.length);
}
