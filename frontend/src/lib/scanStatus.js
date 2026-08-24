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
// observation_incomplete 는 같은 '완료된 참고'지만 뜻이 훨씬 무겁다 — 부가 정보가 아니라
// 포트 자체를 못 본 호스트가 있었다는 말이다. 그래서 라벨을 nse_degraded 와 나눠 둔다.
// 여기서 빠뜨리면 '실패 원인'으로 그려져, 결과를 정상적으로 인입한 실행이 실패로 읽힌다.
const NOTICE_CODES = {
  nse_degraded: "참고 — 부가 정보 불완전",
  observation_incomplete: "참고 — 일부 호스트 미관측",
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
  // 이미 영속된 타임라인이 있으면 목록 응답만으로 그릴 수 있다(withPersistedStages).
  // 가져온 실행도 타임라인을 남기므로, 단계 스캔만 받아오던 조건을 종류가 아니라
  // '타임라인이 있는가'로 바꾼다 - 웹에서 돌린 것과 가져온 것을 다르게 그릴 이유가 없다.
  if (scan.stages_json?.length) return false;
  return active || scanKind(scan).key === "staged";
}

// 이력 표의 '품질' 배지 — 몇 건을 어떤 말로 띄울지.
//
// 재스캔 배지(`재스캔 필요 · N대`)와 같은 줄에 선다. 재스캔은 host_timeout·재전송 상한·
// 서비스 저하처럼 **다시 돌리면 메워지는** 이슈만 대상으로 하는데, 예전에는 그 배지가
// 뜨면 품질 배지를 통째로 감췄다. 그래서 artifact_missing·command_error 처럼 재시도로
// 사라지지 않는 이슈가 섞여 있으면 화면에는 '재스캔 필요' 만 남아, 재스캔 한 번이면
// 전부 해결된다는 거짓 안내가 됐다. 이제 그 경우 **재시도로 못 메우는 나머지**만 센다.
// (severe 로 세는 세 종류는 모두 재시도 대상 밖이라 언제나 이 나머지에 들어온다.)
export function qualityBadge(scan = {}) {
  const total = scan.unresolved_issue_count || 0;
  if (!total) return null;
  const count = scan.retry_status === "required"
    ? (scan.unresolved_other_count || 0)
    : total;
  if (!count) return null;
  return { count, label: scan.quality_status === "error" ? "품질 오류" : "확인 필요" };
}
