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
const FILTERS = ["", "NEW_OPEN", "CLOSED", "REOPENED", "SERVICE_CHANGED", "VERSION_CHANGED", "STATUS_CHANGE"];

export default function History() {
  const [feed, setFeed] = useState({ total: 0, items: [] });
  const [type, setType] = useState("");
  const [host, setHost] = useState("");
  const toast = useToast();

  function load() {
    const qs = new URLSearchParams();
    if (type) qs.set("type", type);
    if (host.trim()) qs.set("host", host.trim());
    qs.set("limit", "200");
    api(`/events?${qs.toString()}`)
      .then(setFeed)
      .catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, [type]);

  return (
    <div className="content">
      <div className="panel">
        <div className="row">
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="">전체 타입</option>
            {FILTERS.filter(Boolean).map((t) => <option key={t} value={t}>{TYPE_META[t]?.label || t}</option>)}
          </select>
          <input placeholder="호스트 IP 필터" value={host} onChange={(e) => setHost(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && load()} />
          <button onClick={load}>적용</button>
          <span className="muted" style={{ marginLeft: "auto" }}>총 {feed.total}건</span>
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
      </div>
    </div>
  );
}
