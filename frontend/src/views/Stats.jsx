import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { downloadFile } from "../lib/download.js";
import { statsFocus } from "../lib/statsFocus.js";
import { RISK_LABEL } from "../lib/format.js";
import { useToast } from "../ui/Toast.jsx";

const RISK_ORDER = ["banned", "high", "medium", "low", "info"];
const PERIODS = [
  { v: 0, label: "전체 기간" },
  { v: 7, label: "최근 7일" },
  { v: 30, label: "최근 30일" },
  { v: 90, label: "최근 90일" },
  { v: 365, label: "최근 1년" },
];

// 세 축이 같은 모양이라 표도 한 컴포넌트로 그린다 - 축마다 다르게 그리면 같은 수를
// 다르게 읽게 된다.
const AXES = [
  {
    id: "ports", title: "포트", unit: "포트",
    head: "포트",
    key: (r) => `${r.port}/${r.proto}`,
    cell: (r) => (
      <>
        <b className="mono">{r.port}</b>
        <span className="stat-proto">{(r.proto || "").toUpperCase()}</span>
      </>
    ),
  },
  {
    id: "services", title: "서비스", unit: "서비스",
    head: "서비스",
    key: (r) => r.service,
    cell: (r) => <span className="mono">{r.service}</span>,
  },
  {
    id: "products", title: "제품", unit: "제품",
    head: "제품",
    key: (r) => r.product,
    cell: (r) => <span>{r.product}</span>,
  },
];

export default function Stats({ onShowFindings }) {
  const [dept, setDept] = useState("");
  const [risk, setRisk] = useState("");
  const [proto, setProto] = useState("");
  const [days, setDays] = useState(0);
  const [includeResolved, setIncludeResolved] = useState(false);
  const [includeAllowed, setIncludeAllowed] = useState(false);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const qs = useMemo(() => {
    const p = new URLSearchParams();
    if (dept) p.set("dept", dept);
    if (risk) p.set("risk", risk);
    if (proto) p.set("proto", proto);
    if (days) p.set("days", String(days));
    if (includeResolved) p.set("include_resolved", "true");
    if (includeAllowed) p.set("include_allowed", "true");
    return p.toString();
  }, [dept, risk, proto, days, includeResolved, includeAllowed]);

  const load = useCallback(() => {
    setBusy(true);
    api(`/stats${qs ? `?${qs}` : ""}`)
      .then((r) => { setData(r); setErr(""); })
      .catch((e) => setErr(e.message))
      .finally(() => setBusy(false));
  }, [qs]);

  useEffect(() => { load(); }, [load]);

  function exportAxis(axis) {
    const sep = qs ? "&" : "";
    downloadFile(`/stats/export?axis=${axis}${sep}${qs}`)
      .then(() => toast("CSV 내보냄"))
      .catch((e) => toast(e.message, { type: "err" }));
  }

  if (err) return <div className="content"><p className="err">{err}</p></div>;
  if (!data) return <div className="content muted">불러오는 중…</div>;

  const t = data.totals;
  const filtered = Boolean(dept || risk || proto || days);

  return (
    <div className="content">
      <div className="panel stat-filters">
        <div className="row">
          <label>
            부서
            <select value={dept} onChange={(e) => setDept(e.target.value)}>
              <option value="">전체</option>
              {(data.dept_options || []).map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </label>
          <label>
            위험등급
            <select value={risk} onChange={(e) => setRisk(e.target.value)}>
              <option value="">전체</option>
              {RISK_ORDER.map((r) => <option key={r} value={r}>{RISK_LABEL[r]}</option>)}
            </select>
          </label>
          <label>
            프로토콜
            <select value={proto} onChange={(e) => setProto(e.target.value)}>
              <option value="">전체</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
          <label>
            기간
            <select value={days} onChange={(e) => setDays(Number(e.target.value))}>
              {PERIODS.map((p) => <option key={p.v} value={p.v}>{p.label}</option>)}
            </select>
          </label>
          <label className="chk">
            <input type="checkbox" checked={includeResolved}
                   onChange={(e) => setIncludeResolved(e.target.checked)} />
            정상처리 포함
          </label>
          <label className="chk">
            <input type="checkbox" checked={includeAllowed}
                   onChange={(e) => setIncludeAllowed(e.target.checked)} />
            허용 포함
          </label>
          {busy && <span className="muted">집계 중…</span>}
        </div>
        {days > 0 && (
          <div className="muted stat-note">
            마지막으로 관측한 시각 기준입니다 — 그 기간에 실제로 본 것만 셉니다.
          </div>
        )}
      </div>

      <div className="stats">
        <div className="stat"><div className="n">{t.findings}</div><div className="l">활성 발견</div></div>
        <div className="stat"><div className="n">{t.hosts}</div><div className="l">호스트</div></div>
        <div className="stat">
          <div className="n">{t.confirmed}</div>
          <div className="l">응답 확인</div>
        </div>
        <div className="stat">
          <div className="n" style={{ color: t.inferred ? "var(--medium)" : "var(--ink)" }}>
            {t.inferred}
          </div>
          <div className="l">무응답 추정</div>
        </div>
      </div>

      {t.inferred > 0 && (
        <div className="panel stat-hint">
          <b>무응답 추정 {t.inferred}건</b>은 응답이 없어 열렸다고 <em>추정</em>한 것입니다
          (대부분 UDP). 아래 표는 <b>응답 확인</b> 기준으로 정렬하며, 두 수를 합치지 않습니다 —
          합치면 아무도 응답하지 않은 포트가 상위를 차지합니다.
        </div>
      )}

      {AXES.map((axis) => (
        <AxisPanel
          key={axis.id} axis={axis} rows={data[axis.id] || []}
          truncated={data.truncated?.[axis.id]}
          filtered={filtered}
          onExport={() => exportAxis(axis.id)}
          onPick={onShowFindings
            ? (row) => onShowFindings(statsFocus(axis.id, row, data.filters || {}))
            : null}
        />
      ))}
    </div>
  );
}

function AxisPanel({ axis, rows, truncated, filtered, onExport, onPick }) {
  // 막대 기준은 **그 표의 1위**다. 전체 합계로 나누면 상위가 고만고만할 때 전부 납작해져
  // 아무것도 안 보인다.
  const peak = Math.max(1, ...rows.map((r) => r.confirmed + r.inferred));
  return (
    <div className="panel">
      <div className="panel-head">
        <h3>{axis.title}별 빈출{filtered ? " (필터 적용)" : ""}</h3>
        <button type="button" className="sm" onClick={onExport}>CSV</button>
      </div>
      {rows.length === 0 ? (
        <div className="muted">데이터 없음</div>
      ) : (
        <>
          <table className="tbl stat-tbl">
            <thead>
              <tr>
                <th>{axis.head}</th>
                <th className="num">호스트</th>
                <th className="num">응답 확인</th>
                <th className="num">무응답 추정</th>
                <th className="stat-bar-col">분포</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={axis.key(r)}>
                  <td>
                    {onPick ? (
                      <button type="button" className="linkbtn" onClick={() => onPick(r)}
                              title="이 발견들을 목록에서 보기">
                        {axis.cell(r)}
                      </button>
                    ) : axis.cell(r)}
                  </td>
                  <td className="num mono">{r.hosts}</td>
                  <td className="num mono">{r.confirmed}</td>
                  <td className="num mono stat-inferred">{r.inferred || ""}</td>
                  <td className="stat-bar-col">
                    <span className="stat-bar" aria-hidden="true">
                      <i className="is-confirmed" style={{ width: `${(r.confirmed / peak) * 100}%` }} />
                      <i className="is-inferred" style={{ width: `${(r.inferred / peak) * 100}%` }} />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {truncated && (
            <div className="muted stat-note">
              상위 {rows.length}개만 표시합니다. 전체는 CSV 로 내보내세요.
            </div>
          )}
        </>
      )}
    </div>
  );
}
