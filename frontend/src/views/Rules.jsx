import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import { RISK_LABEL } from "../lib/format.js";

const RISK = ["banned", "high", "medium", "low", "info"];
const EMPTY_FORM = { kind: "service_rule", service: "", product: "", cpe: "", port: "", risk_level: "high", note: "" };

const kindLabel = (k) => {
  if (k === "banned_service") return "금지 서비스";
  if (k === "service_rule") return "서비스 규칙";
  if (k === "product_rule") return "제품 규칙";
  if (k === "cpe_rule") return "CPE 규칙";
  return "서비스/포트 규칙";
};

const riskLabel = (r) => (r === "info" ? "허용/정보" : RISK_LABEL[r] || r);

// 목록의 '대상' 칸 — 규칙 종류마다 실제로 매칭에 쓰이는 값을 보여준다.
const ruleTarget = (r) => {
  if (r.kind === "port_rule") return r.service ? `${r.service} / ${r.port}` : r.port;
  if (r.kind === "product_rule") return r.product;
  if (r.kind === "cpe_rule") return r.cpe;
  return r.service;
};

function KindSelect({ value, onChange }) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="service_rule">서비스 규칙</option>
      <option value="port_rule">서비스/포트 규칙</option>
      <option value="banned_service">금지 서비스</option>
      <option value="product_rule">제품 규칙</option>
      <option value="cpe_rule">CPE 규칙</option>
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
  // nmap 의 service 는 저신뢰 추측일 때가 많다(uniconv 등). 그런 포트도 제품/CPE 로는 잡힌다.
  // 둘 다 부분일치라 'Samba smbd' 같은 서술 접미사나 여러 개 이어진 CPE 에도 걸린다.
  if (form.kind === "product_rule") {
    return (
      <input
        placeholder="제품명 부분일치 (예: vsftpd, OpenSSH)"
        value={form.product}
        onChange={(e) => setForm({ ...form, product: e.target.value })}
      />
    );
  }
  if (form.kind === "cpe_rule") {
    return (
      <input
        style={{ minWidth: 260 }}
        placeholder="CPE 부분일치 (예: openbsd:openssh)"
        value={form.cpe}
        onChange={(e) => setForm({ ...form, cpe: e.target.value })}
      />
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
    if (f.kind === "port_rule") return !!f.port;
    if (f.kind === "product_rule") return !!f.product.trim();
    if (f.kind === "cpe_rule") return !!f.cpe.trim();
    return !!f.service.trim();
  }

  function toBody(f) {
    const body = {
      kind: f.kind,
      service: f.service.trim(),
      product: f.product.trim(),
      cpe: f.cpe.trim(),
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
      product: r.product || "",
      cpe: r.cpe || "",
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
                      {ruleTarget(r)}
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
