// 날짜/등급 표시 헬퍼. 마감 비교는 ISO(YYYY-MM-DD) 문자열 비교로 충분.

export const today = () => new Date().toISOString().slice(0, 10);

export const asDate = (v) => (v ? String(v).slice(0, 10) : "");

// 마감 D-day 정보: over(초과)/near(임박 3일)/ok/none
export function dday(deadline) {
  const d = asDate(deadline);
  if (!d) return { text: "—", cls: "none", over: false };
  const t = today();
  const diff = Math.round((new Date(d) - new Date(t)) / 86400000);
  if (diff < 0) return { text: `${-diff}일 초과`, cls: "over", over: true };
  if (diff === 0) return { text: "오늘", cls: "near", over: false };
  if (diff <= 3) return { text: `D-${diff}`, cls: "near", over: false };
  return { text: `D-${diff}`, cls: "ok", over: false };
}

export const RISK_LABEL = { banned: "금지", high: "상", medium: "중", low: "하", info: "정보" };
export const riskClass = (r) => (["banned", "high", "medium", "low", "info"].includes(r) ? r : "info");

export const STATUS_CLASS = {
  미조치: "high",
  처리중: "medium",
  정상처리: "low",
  재발: "high",
};
