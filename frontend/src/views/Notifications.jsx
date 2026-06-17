import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { downloadText } from "../lib/download.js";
import { useToast } from "../ui/Toast.jsx";
import { asDate, dday, today } from "../lib/format.js";

const STATUSES = ["미조치", "처리중", "정상처리"];
const TPL_KEY = "scanops_notify_templates";
const loadTpls = () => { try { return JSON.parse(localStorage.getItem(TPL_KEY)) || []; } catch { return []; } };

const DEFAULT_TPL = `[{dept}] 네트워크 노출 점검 통보
미조치 발견 {count}건 · 담당자 {owner} · 담당 연락처 {contact}
작성일 {date}

{list}

조치 후 회신 바랍니다.`;

function daysLeft(f) {
  if (!f.deadline) return null;
  return Math.round((new Date(asDate(f.deadline)) - new Date(today())) / 86400000);
}

function render(tpl, dept, findings) {
  const contact = findings.find((f) => f.contact)?.contact || "-";
  const owner = [...new Set(findings.map((f) => f.owner).filter(Boolean))].join(", ") || "-";
  const list = findings.map((f) => {
    const dl = f.deadline ? ` · 마감 ${asDate(f.deadline)}(${dday(f.deadline).text})` : "";
    const who = f.owner ? ` (${f.owner})` : "";
    return `- ${f.host_ip}:${f.port}/${f.proto} ${f.service}${who} ${f.status}${dl}`;
  }).join("\n");
  return tpl
    .replaceAll("{dept}", dept || "")
    .replaceAll("{count}", String(findings.length))
    .replaceAll("{contact}", contact)
    .replaceAll("{owner}", owner)
    .replaceAll("{date}", today())
    .replaceAll("{list}", list || "(해당 발견 없음)");
}

export default function Notifications({ user }) {
  const [depts, setDepts] = useState([]);
  const [dept, setDept] = useState("");
  const [findings, setFindings] = useState([]);
  const [statusSel, setStatusSel] = useState(() => new Set(["미조치", "처리중"]));
  const [deadlineMode, setDeadlineMode] = useState("all");
  const [tpl, setTpl] = useState(DEFAULT_TPL);
  const [tpls, setTpls] = useState(loadTpls);
  const [tplId, setTplId] = useState("");
  const [history, setHistory] = useState([]);
  const toast = useToast();
  const canSend = user.role === "admin" || user.role === "auditor";

  function loadHistory() { api("/notifications").then(setHistory).catch(() => {}); }
  useEffect(() => {
    let live = true;
    api("/dashboard").then((d) => { if (live) setDepts(d.by_dept.map((x) => x.dept)); }).catch(() => {});
    loadHistory();
    return () => { live = false; };
  }, []);

  useEffect(() => {
    if (!dept) { setFindings([]); return; }
    let live = true;
    api(`/findings?state=open&dept=${encodeURIComponent(dept)}`)
      .then((r) => { if (live) setFindings(r); })
      .catch((e) => toast(e.message, { type: "err" }));
    return () => { live = false; };
  }, [dept]);

  const filtered = useMemo(() => findings.filter((f) => {
    if (!statusSel.has(f.status)) return false;
    const dl = daysLeft(f);
    if (deadlineMode === "over") return dl != null && dl < 0;
    if (deadlineMode === "near") return dl != null && dl >= 0 && dl <= 7;
    if (deadlineMode === "set") return dl != null;
    if (deadlineMode === "none") return dl == null;
    return true;
  }), [findings, statusSel, deadlineMode]);

  const body = useMemo(() => render(tpl, dept, filtered), [tpl, dept, filtered]);

  function toggleStatus(s) {
    setStatusSel((cur) => { const n = new Set(cur); n.has(s) ? n.delete(s) : n.add(s); return n; });
  }

  // 템플릿 프리셋
  function applyTpl(id) {
    setTplId(id);
    const p = tpls.find((x) => x.id === id);
    if (p) setTpl(p.body);
  }
  function saveTpl() {
    const name = prompt("문구 프리셋 이름", "기본 통보문");
    if (!name || !name.trim()) return;
    const next = [...tpls, { id: "nt_" + Date.now(), name: name.trim(), body: tpl }];
    setTpls(next); localStorage.setItem(TPL_KEY, JSON.stringify(next)); setTplId(next[next.length - 1].id);
    toast(`문구 프리셋 저장 · ${name.trim()}`);
  }
  function delTpl() {
    const next = tpls.filter((p) => p.id !== tplId);
    setTpls(next); localStorage.setItem(TPL_KEY, JSON.stringify(next)); setTplId("");
  }

  function copyBody() { navigator.clipboard?.writeText(body).then(() => toast("통보문 복사됨")); }
  function saveBody() { downloadText(body, `통보_${dept || "전체"}.txt`); }
  function record() {
    api("/notifications", { method: "POST", json: { dept, body, finding_ids: filtered.map((f) => f.id) } })
      .then(() => { toast(`${dept} 통보 기록됨`); loadHistory(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  return (
    <div className="content">
      <div className="panel">
        <h3>부서 · 대상 선택</h3>
        <div className="row" style={{ marginBottom: 10 }}>
          <select value={dept} onChange={(e) => setDept(e.target.value)}>
            <option value="">부서 선택…</option>
            {depts.map((d) => <option key={d} value={d}>{d}</option>)}
          </select>
          <select value={deadlineMode} onChange={(e) => setDeadlineMode(e.target.value)}>
            <option value="all">마감 전체</option>
            <option value="over">마감 초과</option>
            <option value="near">마감 임박(7일)</option>
            <option value="set">마감 설정됨</option>
            <option value="none">마감 없음</option>
          </select>
          <span className="muted" style={{ marginLeft: "auto" }}>대상 {filtered.length} / 부서 발견 {findings.length}건</span>
        </div>
        <div className="cb-label">상태 필터</div>
        <div className="row" style={{ gap: 14, flexWrap: "wrap" }}>
          {STATUSES.map((s) => (
            <label key={s} className="row" style={{ gap: 5, fontSize: 12.5 }}>
              <input type="checkbox" checked={statusSel.has(s)} onChange={() => toggleStatus(s)} />{s}
            </label>
          ))}
        </div>
      </div>

      <div className="panel">
        <div className="row" style={{ marginBottom: 8 }}>
          <h3 style={{ margin: 0 }}>통보 문구 (템플릿)</h3>
          <div className="row" style={{ marginLeft: "auto", gap: 6 }}>
            <select value={tplId} onChange={(e) => applyTpl(e.target.value)}>
              <option value="">문구 프리셋…</option>
              {tpls.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <button className="sm" onClick={saveTpl}>현재 문구 저장</button>
            {tplId && <button className="sm" onClick={delTpl}>삭제</button>}
          </div>
        </div>
        <textarea value={tpl} onChange={(e) => { setTpl(e.target.value); setTplId(""); }}
                  style={{ width: "100%", minHeight: 120, font: "inherit", fontSize: 13, padding: 10,
                           border: "1px solid var(--line)", borderRadius: 8, resize: "vertical",
                           background: "var(--surface)", color: "var(--ink)" }} />
        <div className="muted" style={{ fontSize: 11.5, marginTop: 4 }}>
          치환 토큰: {"{dept}"} {"{count}"} {"{owner}"}(담당자) {"{contact}"} {"{date}"} {"{list}"}(발견 목록)
        </div>
      </div>

      <div className="panel">
        <h3>미리보기</h3>
        <div className="pre">{body}</div>
        <div className="row" style={{ marginTop: 12 }}>
          <button onClick={copyBody} disabled={!dept}>복사</button>
          <button onClick={saveBody} disabled={!dept}>.txt 저장(BOM)</button>
          {canSend && <button className="primary" onClick={record} disabled={!dept}>통보 기록</button>}
        </div>
      </div>

      <div className="panel">
        <h3>통보 이력</h3>
        <table className="tbl">
          <thead><tr><th>부서</th><th>채널</th><th>시각</th></tr></thead>
          <tbody>
            {history.length === 0 ? (
              <tr><td className="empty" colSpan={3}>이력 없음</td></tr>
            ) : history.map((h) => (
              <tr key={h.id}>
                <td>{h.dept}</td><td>{h.channel}</td>
                <td className="mono">{String(h.sent_at).slice(0, 16).replace("T", " ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
