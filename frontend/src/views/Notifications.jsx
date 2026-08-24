import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { downloadText } from "../lib/download.js";
import { useToast } from "../ui/Toast.jsx";
import { asDate, dday, RISK_LABEL, today } from "../lib/format.js";
import { primaryServiceIdentity } from "../lib/columns.js";

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

export function renderNotification(tpl, dept, findings) {
  const contact = findings.find((f) => f.contact)?.contact || "-";
  const owner = [...new Set(findings.map((f) => f.owner).filter(Boolean))].join(", ") || "-";
  const list = findings.map((f) => {
    const dl = f.deadline ? ` · 마감 ${asDate(f.deadline)}(${dday(f.deadline).text})` : "";
    const who = f.owner ? ` (${f.owner})` : "";
    const identity = primaryServiceIdentity(f);
    const service = f.service && f.service !== identity ? ` (서비스: ${f.service})` : "";
    const risk = RISK_LABEL[f.risk_level] || f.risk_level || "정보";
    const confirmation = f.needs_confirmation ? " · 재확인 필요" : "";
    const exposure = (f.exposure_json || []).map((item) => item.detail || item.kind).filter(Boolean).join(" · ");
    const exposureText = exposure ? ` · ${exposure}` : "";
    return `- ${f.host_ip}:${f.port}/${f.proto} ${identity}${service}${who} [${risk}] ${f.status}${confirmation}${exposureText}${dl}`;
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
    // 두 축을 **명시적으로 펼친다.** /findings 의 기본값은 발견 목록 화면의 표시 정책이고,
    // 통보는 다른 일이다 - 서버의 /notifications/preview 는 _open_findings_for_dept 로
    // 이 둘을 계속 포함하므로, 여기서 기본값을 물려받으면 화면이 서버 preview 와 어긋난다.
    // 특히 tcpwrapped 는 포트 열림이 확인된 건이라, 조치 통보에서 빠지면 거짓 음성이다.
    api(`/findings?state=open&dept=${encodeURIComponent(dept)}`
        + "&hide_unconfirmed=false&hide_tcpwrapped=false")
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

  const body = useMemo(() => renderNotification(tpl, dept, filtered), [tpl, dept, filtered]);

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
          {canSend && <button className="primary" onClick={record} disabled={!dept || !filtered.length}>통보 기록</button>}
        </div>
      </div>

      <div className="panel">
        <h3>통보 이력</h3>
        <table className="tbl">
          <thead><tr><th>부서</th><th>기록자</th><th>대상</th><th>채널</th><th>시각</th><th>기록 내용</th></tr></thead>
          <tbody>
            {history.length === 0 ? (
              <tr><td className="empty" colSpan={6}>이력 없음</td></tr>
            ) : history.map((h) => (
              <tr key={h.id}>
                <td>{h.dept}</td>
                <td>{h.sent_by_name || (h.sent_by ? `사용자 #${h.sent_by}` : "—")}</td>
                <td className="mono">{h.finding_count ?? h.finding_ids?.length ?? 0}건</td>
                <td>{h.channel}</td>
                <td className="mono">{String(h.sent_at).slice(0, 16).replace("T", " ")}</td>
                <td>
                  <details className="notification-history-detail">
                    <summary>본문 보기</summary>
                    <div className="pre">{h.body || "(저장된 본문 없음)"}</div>
                    {!!h.finding_ids?.length && (
                      <div className="muted mono">발견 ID · {h.finding_ids.join(", ")}</div>
                    )}
                  </details>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
