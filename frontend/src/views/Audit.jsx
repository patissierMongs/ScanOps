import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";

export default function Audit() {
  const [rows, setRows] = useState([]);
  const [action, setAction] = useState("");
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  function load() {
    setLoading(true);
    const qs = new URLSearchParams({ limit: "500" });
    if (action.trim()) qs.set("action", action.trim());
    api(`/audit?${qs.toString()}`)
      .then(setRows)
      .catch((error) => toast(error.message, { type: "err" }))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, []);

  return (
    <div className="content">
      <div className="panel">
        <div className="row">
          <input value={action} onChange={(event) => setAction(event.target.value)}
                 placeholder="작업 코드 필터 (예: SCAN_RUN)"
                 onKeyDown={(event) => {
                   if (event.nativeEvent.isComposing || event.keyCode === 229) return;
                   if (event.key === "Enter") load();
                 }} />
          <button onClick={load}>조회</button>
          <span className="muted" style={{ marginLeft: "auto" }}>최근 {rows.length}건</span>
        </div>
      </div>
      <div className="panel">
        <div className="table-wrap">
          <table className="tbl audit-table">
            <thead>
              <tr><th>시각</th><th>행위자</th><th>작업</th><th>대상</th><th>결과</th><th>상세</th></tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td className="empty" colSpan={6}>불러오는 중…</td></tr>
              ) : rows.length === 0 ? (
                <tr><td className="empty" colSpan={6}>감사 이력 없음</td></tr>
              ) : rows.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{String(row.created_at).slice(0, 19).replace("T", " ")}</td>
                  <td>{row.actor_name || "시스템"}</td>
                  <td><span className="tag mono">{row.action}</span></td>
                  <td className="audit-long-cell">{row.target || "—"}</td>
                  <td><span className={`pill ${row.ok ? "low" : "high"}`}>{row.ok ? "성공" : "실패"}</span></td>
                  <td className="audit-long-cell">{row.detail || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
