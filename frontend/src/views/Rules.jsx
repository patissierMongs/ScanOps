import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import { RISK_LABEL } from "../lib/format.js";

// 기본포트 사용 금지 규칙은 금지(banned)까지 지정 가능.
const RISK = ["banned", "high", "medium", "low"];

export default function Rules({ user }) {
  const [rules, setRules] = useState([]);
  const [kind, setKind] = useState("banned_service");
  const [service, setService] = useState("");
  const [port, setPort] = useState("");
  const [risk, setRisk] = useState("high");
  const [note, setNote] = useState("");
  const toast = useToast();
  const canEdit = user.role === "admin" || user.role === "auditor";

  function load() {
    api("/rules").then(setRules).catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, []);

  function add(e) {
    e.preventDefault();
    const body = { kind, risk_level: kind === "banned_service" ? "banned" : risk, note };
    if (kind === "banned_service") {
      body.service = service.trim();
    } else {
      body.service = service.trim();      // 기본포트 사용 금지 = 서비스 + 포트 조합
      body.port = parseInt(port, 10);
    }
    api("/rules", { method: "POST", json: body })
      .then((r) => { toast(`규칙 추가 · 매칭 ${r.match_count}건`); setService(""); setPort(""); setNote(""); load(); })
      .catch((e2) => toast(e2.message, { type: "err" }));
  }

  const kindLabel = (k) => (k === "banned_service" ? "금지 서비스" : "기본포트 사용 금지");

  function remove(id) {
    api(`/rules/${id}`, { method: "DELETE" })
      .then(() => { toast("규칙 삭제됨"); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  const totalHits = rules.reduce((s, r) => s + (r.match_count || 0), 0);

  return (
    <div className="content">
      {canEdit && (
        <div className="panel">
          <h3>위험 규칙 추가</h3>
          <form className="row" onSubmit={add}>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="banned_service">금지 서비스</option>
              <option value="port_rule">기본포트 사용 금지</option>
            </select>
            {kind === "banned_service" ? (
              <input placeholder="서비스명 (예: telnet)" value={service} onChange={(e) => setService(e.target.value)} />
            ) : (
              <>
                <input style={{ width: 130 }} placeholder="서비스 (예: ssh)" value={service} onChange={(e) => setService(e.target.value)} />
                <span className="muted" style={{ alignSelf: "center" }}>/</span>
                <input style={{ width: 90 }} type="number" placeholder="포트 (예: 22)" value={port} onChange={(e) => setPort(e.target.value)} />
              </>
            )}
            {kind === "banned_service" ? (
              <span className="pill banned" style={{ alignSelf: "center" }} title="금지 서비스는 최고 등급 '금지'로 자동 분류">금지</span>
            ) : (
              <select value={risk} onChange={(e) => setRisk(e.target.value)}>
                {RISK.map((r) => <option key={r} value={r}>{RISK_LABEL[r]}</option>)}
              </select>
            )}
            <input style={{ flex: 1, minWidth: 140 }} placeholder="비고(근거)" value={note} onChange={(e) => setNote(e.target.value)} />
            <button className="primary" disabled={kind === "banned_service" ? !service.trim() : (!service.trim() || !port)}>추가</button>
          </form>
        </div>
      )}

      <div className="panel">
        <h3>규칙 목록 · 총 매칭 {totalHits}건</h3>
        <table className="tbl">
          <thead>
            <tr><th>종류</th><th>대상</th><th>위험등급</th><th>매칭 발견</th><th>비고</th>{canEdit && <th></th>}</tr>
          </thead>
          <tbody>
            {rules.length === 0 ? (
              <tr><td className="empty" colSpan={canEdit ? 6 : 5}>규칙 없음</td></tr>
            ) : rules.map((r) => (
              <tr key={r.id}>
                <td>{kindLabel(r.kind)}</td>
                <td className="mono">
                  {r.kind === "banned_service" ? r.service : (r.service ? `${r.service} / ${r.port}` : r.port)}
                </td>
                <td><span className={"pill " + r.risk_level}>{RISK_LABEL[r.risk_level]}</span></td>
                <td>
                  <span className="mono" style={{ color: r.match_count ? "var(--high)" : "var(--muted)" }}>
                    {r.match_count}
                  </span>
                </td>
                <td className="muted">{r.note}</td>
                {canEdit && <td><button className="sm" onClick={() => remove(r.id)}>삭제</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
