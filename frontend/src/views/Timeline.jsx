import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";

// 4-state 히트맵 색 — 신규열림=빨강 / 지속열림=파랑 / 신규닫힘=보라 / 지속닫힘·부재=연회색
const CELL = {
  new_open:      { bg: "oklch(0.62 0.2 25)",  fg: "#fff", t: "open" },
  persist_open:  { bg: "oklch(0.58 0.13 255)", fg: "#fff", t: "open" },
  new_closed:    { bg: "oklch(0.55 0.16 300)", fg: "#fff", t: "closed" },
  persist_closed:{ bg: "oklch(0.92 0.01 262)", fg: "var(--muted)", t: "—" },
  none:          { bg: "transparent", fg: "var(--line)", t: "" },
};

export default function Timeline() {
  const [data, setData] = useState(null);
  const [limit, setLimit] = useState(8);
  const toast = useToast();

  useEffect(() => {
    api(`/reports/timeline?limit=${limit}`).then(setData).catch((e) => toast(e.message, { type: "err" }));
  }, [limit]);

  if (!data) return <div className="content"><div className="panel">불러오는 중…</div></div>;
  const { scans = [], rows = [], summary = {} } = data;

  return (
    <div className="content">
      <div className="panel">
        <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ margin: 0 }}>시간축 히트맵 — 포트 상태 추이</h3>
          <label className="row" style={{ gap: 6, fontSize: 13 }}>
            최근 스캔
            <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
              {[4, 6, 8, 12, 20].map((n) => <option key={n} value={n}>{n}개</option>)}
            </select>
          </label>
        </div>
        <p className="muted" style={{ fontSize: 12.5, margin: "6px 0 0" }}>
          여러 스캔 시점을 IP·포트별로 한 장에 — 언제 열리고 닫혔는지 4색으로. 셀에 마우스를 올리면 시점을 봅니다.
        </p>
      </div>

      <div className="panel">
        <div className="row" style={{ gap: 10, marginBottom: 4 }}>
          <span className="pill high">현재 열림 {summary.open_now || 0}</span>
          <span className="pill info">신규 열림 {summary.new_open || 0}</span>
          <span className="pill low">최근 닫힘 {summary.closed_recent || 0}</span>
          <span className="pill" style={{ background: "var(--high-bg)", color: "var(--high)" }}>금지 노출 {summary.banned_open || 0}</span>
        </div>
      </div>

      <div className="panel">
        {rows.length === 0 ? (
          <div className="empty">표시할 이력이 없습니다 — 스캔을 2회 이상 돌리면 추이가 쌓입니다.</div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "separate", borderSpacing: 3, fontSize: 12 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: "left", padding: "2px 8px", fontSize: 11, color: "var(--muted)" }}>IP : 포트 / 서비스</th>
                  {scans.map((s) => (
                    <th key={s.id} title={s.name} style={{ padding: "2px 4px", fontSize: 11, color: "var(--muted)", whiteSpace: "nowrap" }}>{s.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.key}>
                    <td className="mono" style={{ whiteSpace: "nowrap", padding: "2px 10px 2px 0", color: "var(--ink-soft)" }}>
                      {r.host} : {r.port}/{r.proto} {r.service && <span className="muted">{r.service}</span>} {r.banned && "🚫"}
                    </td>
                    {r.cells.map((c, i) => {
                      const cs = CELL[c] || CELL.none;
                      return (
                        <td key={i} title={`${scans[i]?.label || ""} · ${c}`}
                            style={{ width: 56, height: 22, borderRadius: 4, textAlign: "center",
                                     background: cs.bg, color: cs.fg, fontFamily: "var(--mono)", fontSize: 10.5 }}>
                          {cs.t}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="row" style={{ gap: 14, marginTop: 12, fontSize: 12, flexWrap: "wrap" }}>
          {[["new_open", "신규 열림"], ["persist_open", "지속 열림"], ["new_closed", "신규 닫힘"], ["persist_closed", "지속 닫힘/부재"]].map(([k, label]) => (
            <span key={k}><i style={{ display: "inline-block", width: 13, height: 13, borderRadius: 3, background: CELL[k].bg, border: "1px solid var(--line)", marginRight: 5, verticalAlign: -2 }} />{label}</span>
          ))}
          <span className="muted">🚫 = 금지 서비스</span>
        </div>
      </div>
    </div>
  );
}
