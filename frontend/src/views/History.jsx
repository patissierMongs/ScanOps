import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";

// 이벤트 타입 표시 메타 (백엔드 FindingEvent.type 과 일치)
const TYPE_META = {
  NEW_OPEN: { label: "신규 열림", cls: "low" },
  CLOSED: { label: "닫힘", cls: "high" },
  REOPENED: { label: "재발", cls: "high" },
  SERVICE_CHANGED: { label: "서비스 변경", cls: "medium" },
  VERSION_CHANGED: { label: "버전 변경", cls: "medium" },
  STATUS_CHANGE: { label: "상태 변경", cls: "info" },
  ASSIGN: { label: "담당 배정", cls: "info" },
  DEADLINE: { label: "마감 설정", cls: "info" },
  NOTE: { label: "메모", cls: "info" },
  EXCEPTION: { label: "예외", cls: "info" },
};
// 필터 가능한 타입 — 타임라인에 나타나는 모든 이벤트 타입(백엔드가 임의 타입 필터 지원)
const FILTERS = [
  "NEW_OPEN", "CLOSED", "REOPENED", "SERVICE_CHANGED", "VERSION_CHANGED",
  "STATUS_CHANGE", "ASSIGN", "DEADLINE", "NOTE",
];
const PAGE = 100;

export default function History() {
  const [feed, setFeed] = useState({ total: 0, items: [] });
  const [type, setType] = useState("");
  const [host, setHost] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [offset, setOffset] = useState(0);
  const toast = useToast();

  // type/offset 은 즉시 반영, host/기간은 [적용] 으로 커밋된 값(applied)만 질의에 쓴다.
  const [applied, setApplied] = useState({ host: "", since: "", until: "" });

  function load() {
    const qs = new URLSearchParams();
    if (type) qs.set("type", type);
    if (applied.host.trim()) qs.set("host", applied.host.trim());
    if (applied.since) qs.set("since", applied.since);
    if (applied.until) qs.set("until", applied.until + "T23:59:59");   // 그날 끝까지 포함
    qs.set("limit", String(PAGE));
    qs.set("offset", String(offset));
    api(`/events?${qs.toString()}`)
      .then(setFeed)
      .catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, [type, offset, applied]);

  function applyFilters() {
    setOffset(0);
    setApplied({ host, since, until });   // load 는 applied 변경으로 트리거
  }
  function changeType(v) { setOffset(0); setType(v); }

  const from = feed.total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE, feed.total);
  const hasPrev = offset > 0;
  const hasNext = offset + PAGE < feed.total;

  return (
    <div className="content">
      <div className="panel">
        <div className="row">
          <select value={type} onChange={(e) => changeType(e.target.value)}>
            <option value="">전체 타입</option>
            {FILTERS.map((t) => <option key={t} value={t}>{TYPE_META[t]?.label || t}</option>)}
          </select>
          <input placeholder="호스트 IP 필터" value={host} onChange={(e) => setHost(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && applyFilters()} />
          <label className="muted" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            기간
            <input type="date" value={since} max={until || undefined}
                   onChange={(e) => setSince(e.target.value)} />
            ~
            <input type="date" value={until} min={since || undefined}
                   onChange={(e) => setUntil(e.target.value)} />
          </label>
          <button onClick={applyFilters}>적용</button>
          {(applied.host || applied.since || applied.until) && (
            <button className="sm" onClick={() => {
              setHost(""); setSince(""); setUntil(""); setOffset(0);
              setApplied({ host: "", since: "", until: "" });
            }}>초기화</button>
          )}
          <span className="muted" style={{ marginLeft: "auto" }}>
            {feed.total > 0 ? `${from}–${to} / 총 ${feed.total}건` : "총 0건"}
          </span>
        </div>
      </div>

      <div className="panel">
        <div className="timeline">
          {feed.items.length === 0 ? (
            <div className="muted">이력 없음</div>
          ) : feed.items.map((ev) => {
            const m = TYPE_META[ev.type] || { label: ev.type, cls: "info" };
            return (
              <div className="ev" key={ev.id}>
                <div className="t">
                  <span className={"pill " + m.cls} style={{ marginRight: 8 }}>{m.label}</span>
                  <span className="mono">{ev.host_ip}:{ev.port}</span>
                  {ev.service && <span className="muted"> · {ev.service}</span>}
                </div>
                <div className="d">{ev.detail}</div>
                <div className="when">{String(ev.created_at).slice(0, 19).replace("T", " ")}</div>
              </div>
            );
          })}
        </div>
        {(hasPrev || hasNext) && (
          <div className="row" style={{ marginTop: 12, justifyContent: "center", gap: 12 }}>
            <button className="sm" disabled={!hasPrev} onClick={() => setOffset(Math.max(0, offset - PAGE))}>← 이전</button>
            <span className="muted">{Math.floor(offset / PAGE) + 1} / {Math.max(1, Math.ceil(feed.total / PAGE))}</span>
            <button className="sm" disabled={!hasNext} onClick={() => setOffset(offset + PAGE)}>다음 →</button>
          </div>
        )}
      </div>
    </div>
  );
}
