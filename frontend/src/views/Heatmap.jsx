import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { downloadFile } from "../lib/download.js";
import { RISK_LABEL, riskClass } from "../lib/format.js";
import { useToast } from "../ui/Toast.jsx";

const STATE_OPTIONS = ["", "신규열림", "기존열림", "신규닫힘", "기존닫힘", "대상 외"];
const OPEN_STATES = new Set(["신규열림", "기존열림"]);
const STATE_CLASS = {
  신규열림: "new-open",
  기존열림: "keep-open",
  신규닫힘: "new-closed",
  기존닫힘: "keep-closed",
  "대상 외": "out",
};

export default function Heatmap() {
  const [data, setData] = useState({ summary: {}, phases: [], rows: [], current_ports: [] });
  const [tab, setTab] = useState("heatmap");
  const [query, setQuery] = useState("");
  const [state, setState] = useState("");
  const [openOnly, setOpenOnly] = useState(false);
  const [loading, setLoading] = useState(false);
  const toast = useToast();

  function load() {
    setLoading(true);
    api("/heatmap")
      .then(setData)
      .catch((e) => toast(e.message, { type: "err" }))
      .finally(() => setLoading(false));
  }

  useEffect(() => { load(); }, []);

  const filteredRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data.rows || []).filter((row) => {
      if (state && row.current_state !== state && !row.cells.some((c) => c.state === state)) return false;
      if (openOnly && !OPEN_STATES.has(row.current_state)) return false;
      if (!q) return true;
      return [row.host_ip, row.hostname, row.port, row.proto, row.service, row.version, row.risk_label, row.status, row.dept]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q));
    });
  }, [data.rows, query, state, openOnly]);

  const currentRows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data.current_ports || []).filter((row) => {
      if (state && row.current_state !== state) return false;
      if (!q) return true;
      return [row.host_ip, row.hostname, row.port, row.proto, row.service, row.version, row.risk_label, row.status, row.dept]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q));
    });
  }, [data.current_ports, query, state]);

  const summary = data.summary || {};

  return (
    <div className="content">
      <div className="stats">
        <div className="stat"><div className="n">{summary.scan_count || 0}</div><div className="l">스캔 XML</div></div>
        <div className="stat"><div className="n">{summary.phase_count || 0}</div><div className="l">시간축 phase</div></div>
        <div className="stat"><div className="n">{summary.current_open_count || 0}</div><div className="l">현재 열린 포트</div></div>
        <div className="stat"><div className="n">{summary.row_count || 0}</div><div className="l">히트맵 행</div></div>
      </div>

      <div className="panel">
        <div className="row">
          <button className={tab === "heatmap" ? "primary sm" : "sm"} onClick={() => setTab("heatmap")}>시간축 히트맵</button>
          <button className={tab === "current" ? "primary sm" : "sm"} onClick={() => setTab("current")}>현재 포트</button>
          <input
            style={{ flex: 1, minWidth: 180 }}
            placeholder="IP, 포트, 서비스, 부서 검색"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">상태 전체</option>
            {STATE_OPTIONS.filter(Boolean).map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="row heat-check">
            <input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} disabled={tab === "current"} />
            열린 포트만
          </label>
          <button className="sm" onClick={load} disabled={loading}>{loading ? "갱신 중" : "갱신"}</button>
          <button
            className="sm"
            onClick={() => downloadFile("/heatmap/report").then(() => toast("히트맵 보고서를 내보냈습니다.")).catch((e) => toast(e.message, { type: "err" }))}
          >
            XLSX
          </button>
        </div>
        <div className="heat-legend">
          {STATE_OPTIONS.filter(Boolean).map((s) => (
            <span key={s} className={"heat-token " + stateClass(s)}>{s}</span>
          ))}
        </div>
      </div>

      {tab === "heatmap" ? (
        <HeatmapTable phases={data.phases || []} rows={filteredRows} />
      ) : (
        <CurrentTable rows={currentRows} />
      )}
    </div>
  );
}

function HeatmapTable({ phases, rows }) {
  return (
    <div className="panel heat-panel">
      <div className="heat-table-wrap">
        <table className="tbl heat-table">
          <thead>
            <tr>
              <th className="sticky-col">IP</th>
              <th>포트</th>
              <th>서비스</th>
              <th>위험</th>
              <th>현재</th>
              <th>마지막</th>
              {phases.map((p) => (
                <th key={p.index} className="phase" title={p.label}>
                  <span>{p.index + 1}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td className="empty" colSpan={6 + phases.length}>히트맵 데이터 없음</td></tr>
            ) : rows.map((row) => (
              <tr key={row.key}>
                <td className="sticky-col mono">{row.host_ip}</td>
                <td className="mono">{row.port}/{row.proto}</td>
                <td>
                  <div>{row.service || "—"}</div>
                  {row.version ? <div className="muted">{row.version}</div> : null}
                </td>
                <td>{row.risk_level ? <span className={"pill " + riskClass(row.risk_level)}>{RISK_LABEL[row.risk_level] || row.risk_label}</span> : <span className="muted">—</span>}</td>
                <td><span className={"heat-token " + stateClass(row.current_state)}>{row.current_state || "—"}</span></td>
                <td className="muted heat-last">{row.last_scan_label || "—"}</td>
                {row.cells.map((cell) => (
                  <td key={cell.phase} className={"heat-cell " + stateClass(cell.state)} title={cell.state}>
                    {shortState(cell.state)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {phases.length > 0 && (
        <div className="phase-strip">
          {phases.map((p) => (
            <div key={p.index}>
              <span className="mono">#{p.index + 1}</span>
              <span>{p.label}</span>
              <span className="muted">{p.open_count}/{p.scope_count}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CurrentTable({ rows }) {
  return (
    <div className="panel">
      <div style={{ overflowX: "auto" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>IP</th><th>포트</th><th>서비스</th><th>위험</th><th>현재</th><th>운영상태</th><th>부서</th><th>마지막</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td className="empty" colSpan={8}>현재 열린 포트 없음</td></tr>
            ) : rows.map((row) => (
              <tr key={row.key}>
                <td className="mono">{row.host_ip}</td>
                <td className="mono">{row.port}/{row.proto}</td>
                <td>
                  <div>{row.service || "—"}</div>
                  {row.version ? <div className="muted">{row.version}</div> : null}
                </td>
                <td>{row.risk_level ? <span className={"pill " + riskClass(row.risk_level)}>{RISK_LABEL[row.risk_level] || row.risk_label}</span> : <span className="muted">—</span>}</td>
                <td><span className={"heat-token " + stateClass(row.current_state)}>{row.current_state || "—"}</span></td>
                <td>{row.status || <span className="muted">—</span>}</td>
                <td>{row.dept || <span className="muted">—</span>}</td>
                <td className="muted heat-last">{row.last_scan_label || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function stateClass(state) {
  return STATE_CLASS[state] || "none";
}

function shortState(state) {
  if (state === "신규열림") return "열림+";
  if (state === "기존열림") return "열림";
  if (state === "신규닫힘") return "닫힘+";
  if (state === "기존닫힘") return "닫힘";
  if (state === "대상 외") return "외";
  return "";
}
