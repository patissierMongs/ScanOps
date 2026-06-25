import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import { RISK_LABEL } from "../lib/format.js";

const RISK = ["banned", "high", "medium", "low", "info"];
const EMPTY_FORM = { kind: "service_rule", service: "", port: "", risk_level: "high", note: "" };

const kindLabel = (k) => {
  if (k === "banned_service") return "금지 서비스";
  if (k === "service_rule") return "서비스 규칙";
  return "서비스/포트 규칙";
};

const riskLabel = (r) => (r === "info" ? "허용/정보" : RISK_LABEL[r] || r);

function KindSelect({ value, onChange }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="service_rule">서비스 규칙</option>
      <option value="port_rule">서비스/포트 규칙</option>
      <option value="banned_service">금지 서비스</option>
    </select>
  );
}

function TargetInputs({ form, setForm }) {
  if (form.kind === "port_rule") {
    return (
      <>
        <input
          style={{ width: 130 }}
          placeholder="서비스(선택)"
          value={form.service}
          onChange={(e) => setForm({ ...form, service: e.target.value })}
        />
        <span className="muted" style={{ alignSelf: "center" }}>/</span>
        <input
          style={{ width: 90 }}
          type="number"
          placeholder="포트"
          value={form.port}
          onChange={(e) => setForm({ ...form, port: e.target.value })}
        />
      </>
    );
  }
  return (
    <input
      placeholder="서비스명 (예: telnet)"
      value={form.service}
      onChange={(e) => setForm({ ...form, service: e.target.value })}
    />
  );
}

export default function Rules({ user }) {
  const [rules, setRules] = useState([]);
  const [form, setForm] = useState(EMPTY_FORM);
  const [editing, setEditing] = useState(null);
  const toast = useToast();
  const canEdit = user.role === "admin" || user.role === "auditor";

  function load() {
    api("/rules").then(setRules).catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, []);

  function valid(f) {
    return f.kind === "port_rule" ? !!f.port : !!f.service.trim();
  }

  function toBody(f) {
    const body = {
      kind: f.kind,
      service: f.service.trim(),
      port: null,
      risk_level: f.kind === "banned_service" ? "banned" : f.risk_level,
      note: f.note,
    };
    if (f.kind === "port_rule") body.port = parseInt(f.port, 10);
    return body;
  }

  function add(e) {
    e.preventDefault();
    api("/rules", { method: "POST", json: toBody(form) })
      .then((r) => { toast(`규칙 추가 · 매칭 ${r.match_count}건`); setForm(EMPTY_FORM); load(); })
      .catch((e2) => toast(e2.message, { type: "err" }));
  }

  function remove(id) {
    api(`/rules/${id}`, { method: "DELETE" })
      .then(() => { toast("규칙 삭제됨"); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function startEdit(r) {
    setEditing({
      id: r.id,
      kind: r.kind,
      service: r.service || "",
      port: r.port == null ? "" : String(r.port),
      risk_level: r.risk_level || "high",
      note: r.note || "",
    });
  }

  function saveEdit() {
    api(`/rules/${editing.id}`, { method: "PUT", json: toBody(editing) })
      .then((r) => { toast(`규칙 수정 · 매칭 ${r.match_count}건`); setEditing(null); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  const totalHits = rules.reduce((s, r) => s + (r.match_count || 0), 0);

  return (
    <div className="content">
      {canEdit && (
        <div className="panel">
          <h3>규칙 추가</h3>
          <form className="row" onSubmit={add}>
            <KindSelect value={form.kind} onChange={(kind) => setForm({ ...form, kind })} />
            <TargetInputs form={form} setForm={setForm} />
            <select
              value={form.kind === "banned_service" ? "banned" : form.risk_level}
              onChange={(e) => setForm({ ...form, risk_level: e.target.value })}
              disabled={form.kind === "banned_service"}
            >
              {RISK.map((r) => <option key={r} value={r}>{riskLabel(r)}</option>)}
            </select>
            <input
              style={{ flex: 1, minWidth: 140 }}
              placeholder="비고(근거)"
              value={form.note}
              onChange={(e) => setForm({ ...form, note: e.target.value })}
            />
            <button className="primary" disabled={!valid(form)}>추가</button>
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
                {editing?.id === r.id ? (
                  <>
                    <td><KindSelect value={editing.kind} onChange={(kind) => setEditing({ ...editing, kind })} /></td>
                    <td className="mono">
                      <div className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
                        <TargetInputs form={editing} setForm={setEditing} />
                      </div>
                    </td>
                    <td>
                      <select
                        value={editing.kind === "banned_service" ? "banned" : editing.risk_level}
                        onChange={(e) => setEditing({ ...editing, risk_level: e.target.value })}
                        disabled={editing.kind === "banned_service"}
                      >
                        {RISK.map((risk) => <option key={risk} value={risk}>{riskLabel(risk)}</option>)}
                      </select>
                    </td>
                  </>
                ) : (
                  <>
                    <td>{kindLabel(r.kind)}</td>
                    <td className="mono">
                      {r.kind === "port_rule" ? (r.service ? `${r.service} / ${r.port}` : r.port) : r.service}
                    </td>
                    <td><span className={"pill " + r.risk_level}>{riskLabel(r.risk_level)}</span></td>
                  </>
                )}
                <td>
                  <span className="mono" style={{ color: r.match_count ? "var(--high)" : "var(--muted)" }}>
                    {r.match_count}
                  </span>
                </td>
                {editing?.id === r.id ? (
                  <>
                    <td><input value={editing.note} onChange={(e) => setEditing({ ...editing, note: e.target.value })} /></td>
                    {canEdit && (
                      <td>
                        <button className="sm" onClick={saveEdit} disabled={!valid(editing)}>저장</button>
                        <button className="sm" onClick={() => setEditing(null)}>취소</button>
                      </td>
                    )}
                  </>
                ) : (
                  <>
                    <td className="muted">{r.note}</td>
                    {canEdit && (
                      <td>
                        <button className="sm" onClick={() => startEdit(r)}>수정</button>
                        <button className="sm" onClick={() => remove(r.id)}>삭제</button>
                      </td>
                    )}
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
