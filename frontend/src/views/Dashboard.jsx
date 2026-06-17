import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { downloadFile } from "../lib/download.js";
import { useToast } from "../ui/Toast.jsx";
import { RISK_LABEL } from "../lib/format.js";

const RISK_ORDER = ["banned", "high", "medium", "low", "info"];

export default function Dashboard({ onNav }) {
  const [d, setD] = useState(null);
  const [err, setErr] = useState("");
  const toast = useToast();

  useEffect(() => {
    let live = true;
    api("/dashboard")
      .then((r) => { if (live) setD(r); })
      .catch((e) => setErr(e.message));
    return () => { live = false; };
  }, []);

  if (err) return <div className="content"><p className="err">{err}</p></div>;
  if (!d) return <div className="content muted">불러오는 중…</div>;

  function exportAudit() {
    downloadFile("/reports/audit")
      .then(() => toast("감사 리포트 내보냄"))
      .catch((e) => toast(e.message, { type: "err" }));
  }

  return (
    <div className="content">
      <div className="stats">
        <div className="stat"><div className="n">{d.open_total}</div><div className="l">열린 발견</div></div>
        <div className="stat">
          <div className="n" style={{ color: d.overdue ? "var(--high)" : "var(--ink)" }}>{d.overdue}</div>
          <div className="l">마감 초과</div>
        </div>
        <div className="stat">
          <div className="n" style={{ color: d.by_risk.banned ? "oklch(0.48 0.21 18)" : "var(--ink)" }}>
            {(d.by_risk.banned || 0) + (d.by_risk.high || 0)}
          </div>
          <div className="l">금지·상 {d.by_risk.banned ? `(금지 ${d.by_risk.banned})` : ""}</div>
        </div>
        <div className="stat"><div className="n">{d.by_status["미조치"] || 0}</div><div className="l">미조치</div></div>
      </div>

      <div className="panel">
        <h3>위험등급 분포</h3>
        <div className="row">
          {RISK_ORDER.map((r) => (
            <span key={r} className={"pill " + r} style={{ fontSize: 12 }}>
              {RISK_LABEL[r]} {d.by_risk[r] || 0}
            </span>
          ))}
        </div>
      </div>

      <div className="panel">
        <h3>부서별 미조치</h3>
        {d.by_dept.length === 0 ? (
          <div className="muted">데이터 없음</div>
        ) : (
          <table className="tbl">
            <thead><tr><th>부서</th><th>건수</th></tr></thead>
            <tbody>
              {d.by_dept.map((x) => (
                <tr key={x.dept}><td>{x.dept}</td><td className="mono">{x.count}</td></tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="panel">
        <h3>최근 스캔</h3>
        {d.recent_scans.length === 0 ? (
          <div className="muted">스캔 이력 없음 — <a className="linkbtn" onClick={() => onNav("scans")}>스캔 실행/가져오기</a></div>
        ) : (
          <table className="tbl">
            <thead><tr><th>이름</th><th>상태</th><th>호스트</th><th>포트</th></tr></thead>
            <tbody>
              {d.recent_scans.map((s) => (
                <tr key={s.id}>
                  <td>{s.name}</td><td>{s.status}</td>
                  <td className="mono">{s.host_count}</td><td className="mono">{s.port_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <button onClick={exportAudit}>감사 리포트(xlsx) 내보내기</button>
    </div>
  );
}
