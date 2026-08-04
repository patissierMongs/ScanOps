export const SCAN_STATUS = {
  running: { label: "실행 중", cls: "info" },
  canceling: { label: "중지 중", cls: "medium" },
  canceled: { label: "중지됨", cls: "medium" },
  interrupted: { label: "중단됨(서버 재시작)", cls: "high" },
  failed: { label: "실패", cls: "high" },
  done: { label: "완료", cls: "low" },
};

export function scanStatus(status) {
  return SCAN_STATUS[status] || { label: status || "알 수 없음", cls: "info" };
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
