import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";

// 감사 액션 표시 메타 (백엔드 record() 액션과 일치)
const ACTION_META = {
  LOGIN: "로그인",
  SCAN_RUN: "스캔 실행",
  SCAN_STOP: "스캔 중지",
  SCAN_RESUME: "스캔 이어가기",
  SCAN_IMPORT: "XML 가져오기",
  SCAN_IMPORT_BUNDLE: "XML 묶음 가져오기",
  RULE_CREATE: "규칙 추가",
  RULE_UPDATE: "규칙 수정",
  RULE_DELETE: "규칙 삭제",
};
const ACTIONS = Object.keys(ACTION_META);
const LIMITS = [100, 200, 500, 1000];

export default function Audit() {
  const [rows, setRows] = useState([]);
  const [action, setAction] = useState("");
  const [limit, setLimit] = useState(200);
  const toast = useToast();

  function load() {
    const qs = new URLSearchParams();
    if (action) qs.set("action", action);
    qs.set("limit", String(limit));
    api(`/audit?${qs.toString()}`)
      .then(setRows)
      .catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, [action, limit]);

  return (
    <div className="content">
      <div className="panel">
        <div className="row">
          <select value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">전체 액션</option>
            {ACTIONS.map((a) => <option key={a} value={a}>{ACTION_META[a]}</option>)}
          </select>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {LIMITS.map((n) => <option key={n} value={n}>최근 {n}건</option>)}
          </select>
          <button onClick={load}>새로고침</button>
          <span className="muted" style={{ marginLeft: "auto" }}>{rows.length}건</span>
        </div>
      </div>

      <div className="panel">
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr><th>시간</th><th>사용자</th><th>액션</th><th>대상</th><th>상세</th><th>결과</th></tr>
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr><td className="empty" colSpan={6}>감사 로그 없음</td></tr>
              ) : rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ whiteSpace: "nowrap" }}>
                    {String(r.created_at).slice(0, 19).replace("T", " ")}
                  </td>
                  <td>{r.actor_name || <span className="muted">—</span>}</td>
                  <td>{ACTION_META[r.action] || r.action}</td>
                  <td className="mono" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis" }}>{r.target}</td>
                  <td className="muted">{r.detail}</td>
                  <td>
                    <span className={"pill " + (r.ok ? "low" : "high")}>{r.ok ? "성공" : "실패"}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
