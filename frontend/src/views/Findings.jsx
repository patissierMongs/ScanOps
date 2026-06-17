import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";
import { downloadFile } from "../lib/download.js";
import { useToast } from "../ui/Toast.jsx";
import ColumnBuilder from "../ui/ColumnBuilder.jsx";
import ScanOptions from "../ui/ScanOptions.jsx";
import { COLUMN_MAP, PRESETS, DEFAULT_PRESET_ID, cellValue } from "../lib/columns.js";
import { dday, STATUS_CLASS, RISK_LABEL } from "../lib/format.js";

const COLS_KEY = "scanops_cols";
const CUSTOM_KEY = "scanops_custom_presets";
const loadJSON = (k, fb) => { try { return JSON.parse(localStorage.getItem(k)) ?? fb; } catch { return fb; } };

export default function Findings({ user }) {
  const initial = PRESETS.find((p) => p.id === DEFAULT_PRESET_ID).cols;
  const [cols, setCols] = useState(() => loadJSON(COLS_KEY, initial));
  const [displayModes, setDisplayModes] = useState(() => loadJSON("scanops_colmodes", {}));
  const [presetId, setPresetId] = useState(DEFAULT_PRESET_ID);
  const [customPresets, setCustomPresets] = useState(() => loadJSON(CUSTOM_KEY, []));

  const [findings, setFindings] = useState([]);
  const [q, setQ] = useState("");
  const [risk, setRisk] = useState("");
  const [status, setStatus] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [hideNormal, setHideNormal] = useState(true);
  const [selected, setSelected] = useState(() => new Set());
  const [confirmId, setConfirmId] = useState(null);
  const [showRescan, setShowRescan] = useState(false);
  const [rescanOpt, setRescanOpt] = useState({ options: [], ports: "" });
  const [rescanBusy, setRescanBusy] = useState(false);
  const [drawer, setDrawer] = useState(null);
  const toast = useToast();
  const canEdit = user.role === "admin" || user.role === "auditor";

  function persistCols(next) { setCols(next); localStorage.setItem(COLS_KEY, JSON.stringify(next)); setPresetId(""); }

  function load() {
    const qs = new URLSearchParams({ state: "open" });
    if (risk) qs.set("risk", risk);
    if (status) qs.set("status", status);
    if (q.trim()) qs.set("q", q.trim());
    api(`/findings?${qs.toString()}`)
      .then(setFindings)
      .catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, [risk, status]);

  const view = useMemo(() => {
    let v = findings;
    if (hideNormal) v = v.filter((f) => f.status !== "정상처리");
    if (overdueOnly) v = v.filter((f) => dday(f.deadline).over);
    return v;
  }, [findings, overdueOnly, hideNormal]);

  // ---- 컬럼 빌더 ----
  function applyPreset(id) {
    const p = [...PRESETS, ...customPresets].find((x) => x.id === id);
    if (p) { setCols(p.cols); localStorage.setItem(COLS_KEY, JSON.stringify(p.cols)); }
    setPresetId(id);
  }
  function saveCustom(name) {
    const id = "c_" + Date.now();
    const next = [...customPresets, { id, name, cols }];
    setCustomPresets(next);
    localStorage.setItem(CUSTOM_KEY, JSON.stringify(next));
    setPresetId(id);
    toast(`프리셋 저장 · ${name}`);
  }
  function toggleDisplay(key) {
    const col = COLUMN_MAP[key];
    const cur = displayModes[key] || (col?.badge ? "badge" : "text");
    const next = { ...displayModes, [key]: cur === "badge" ? "text" : "badge" };
    setDisplayModes(next);
    localStorage.setItem("scanops_colmodes", JSON.stringify(next));
  }
  function exportCols(fmt) {
    const qs = new URLSearchParams({ cols: cols.join(","), fmt, state: "open" });
    if (risk) qs.set("risk", risk);
    if (status) qs.set("status", status);
    if (q.trim()) qs.set("q", q.trim());
    downloadFile(`/findings/export?${qs.toString()}`)
      .then(() => toast(`${fmt.toUpperCase()} 내보냄 · ${cols.length}컬럼`))
      .catch((e) => toast(e.message, { type: "err" }));
  }

  // ---- 선택 / 재스캔 명령 ----
  function toggleSel(id) {
    setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  }
  function selectAll() {
    setSelected((s) => (s.size === view.length ? new Set() : new Set(view.map((f) => f.id))));
  }
  const selFindings = findings.filter((f) => selected.has(f.id));
  const selHosts = [...new Set(selFindings.map((f) => f.host_ip))].sort();
  const portsAuto = [...new Set(selFindings.map((f) => f.port))].sort((a, b) => a - b).join(",");

  function runRescan() {
    const ids = [...selected];
    if (!ids.length) { toast("발견을 선택하세요", { type: "err" }); return; }
    setRescanBusy(true);
    api("/findings/rescan", { method: "POST", json: { finding_ids: ids, options: rescanOpt.options, ports: rescanOpt.ports } })
      .then((r) => {
        const c = r.counts;
        toast(`재스캔 완료 · 닫힘 ${c.closed || 0} / 재발 ${c.reopened || 0} / 변경 ${(c.service_changed || 0) + (c.version_changed || 0)}`);
        setShowRescan(false);
        setSelected(new Set());
        load();
      })
      .catch((e) => toast(e.message, { type: "err" }))
      .finally(() => setRescanBusy(false));
  }

  // ---- 2단계 정상처리 + undo ----
  function markNormal(f) {
    if (confirmId !== f.id) {
      setConfirmId(f.id);
      setTimeout(() => setConfirmId((c) => (c === f.id ? null : c)), 4000);
      return;
    }
    setConfirmId(null);
    const prev = f.status;
    api(`/findings/${f.id}`, { method: "PATCH", json: { status: "정상처리" } })
      .then(() => {
        load();
        toast("정상처리 완료", {
          action: {
            label: "되돌리기",
            onClick: () =>
              api(`/findings/${f.id}`, { method: "PATCH", json: { status: prev } })
                .then(() => { load(); toast("되돌림"); })
                .catch((e) => toast(e.message, { type: "err" })),
          },
        });
      })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function openDrawer(f) {
    api(`/findings/${f.id}/events`)
      .then((events) => setDrawer({ finding: f, events }))
      .catch((e) => toast(e.message, { type: "err" }));
  }

  return (
    <div className="content">
      <ColumnBuilder
        selected={cols} onChange={persistCols}
        displayModes={displayModes} onToggleDisplay={toggleDisplay}
        presetId={presetId} onApplyPreset={applyPreset}
        customPresets={customPresets} onSaveCustom={saveCustom}
        onExport={exportCols}
      />

      <div className="panel">
        <div className="row" style={{ marginBottom: 12 }}>
          <input style={{ flex: 1, minWidth: 180 }} placeholder="검색 (서비스/호스트명)" value={q}
                 onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
          <select value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="">위험 전체</option>
            <option value="banned">금지</option>
            <option value="high">상</option><option value="medium">중</option>
            <option value="low">하</option><option value="info">정보</option>
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">상태 전체</option>
            {["미조치", "처리중", "정상처리", "재발"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="row" style={{ gap: 5 }}>
            <input type="checkbox" checked={hideNormal} onChange={(e) => setHideNormal(e.target.checked)} />
            정상처리 제외
          </label>
          <label className="row" style={{ gap: 5 }}>
            <input type="checkbox" checked={overdueOnly} onChange={(e) => setOverdueOnly(e.target.checked)} />
            마감초과만
          </label>
          {canEdit && (
            <button className="sm" disabled={selected.size === 0}
                    onClick={() => setShowRescan((v) => !v)}>
              선택 재스캔 ({selected.size})
            </button>
          )}
        </div>

        {canEdit && showRescan && selected.size > 0 && (
          <div className="panel" style={{ background: "var(--surface-2)", marginBottom: 12 }}>
            <h3>타겟 재스캔 — {selHosts.length}호스트 · 포트 {portsAuto || "(자동)"} · {selected.size}건</h3>
            <ScanOptions targets={selHosts} portsAuto={portsAuto} onState={setRescanOpt} />
            <div className="row" style={{ marginTop: 12 }}>
              <button className="primary" disabled={rescanBusy} onClick={runRescan}>
                {rescanBusy ? "재스캔 실행 중…" : "재스캔 실행 (조치 검증)"}
              </button>
              <button onClick={() => setShowRescan(false)}>닫기</button>
              <span className="muted" style={{ fontSize: 11.5 }}>선택한 포트만 검증 — 닫혔으면 자동 정상처리</span>
            </div>
          </div>
        )}

        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th><input type="checkbox" checked={view.length > 0 && selected.size === view.length} onChange={selectAll} /></th>
                {cols.map((k) => <th key={k}>{COLUMN_MAP[k]?.label || k}</th>)}
                <th>마감</th>
                {canEdit && <th></th>}
              </tr>
            </thead>
            <tbody>
              {view.length === 0 ? (
                <tr><td className="empty" colSpan={cols.length + 3}>발견 없음</td></tr>
              ) : view.map((f) => {
                const dl = dday(f.deadline);
                // 금지/마감초과 → 연한 빨강, 처리중 → 연한 노랑(빨강 우선).
                const bg = (f.risk_level === "banned" || dl.over) ? "var(--high-bg)"
                         : f.status === "처리중" ? "var(--medium-bg)" : null;
                return (
                  <tr key={f.id} className="click" style={bg ? { background: bg } : null}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggleSel(f.id)} />
                    </td>
                    {cols.map((k) => <td key={k} onClick={() => openDrawer(f)}>{renderCell(f, k, displayModes)}</td>)}
                    <td onClick={() => openDrawer(f)}>
                      <span className={"dday " + dl.cls} style={{ color: dl.over ? "var(--high)" : undefined }}>{dl.text}</span>
                    </td>
                    {canEdit && (
                      <td onClick={(e) => e.stopPropagation()}>
                        <button className={"sm" + (confirmId === f.id ? " primary" : "")} onClick={() => markNormal(f)}>
                          {confirmId === f.id ? "확인?" : "정상처리"}
                        </button>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {drawer && (
        <Drawer data={drawer} canEdit={canEdit} onClose={() => setDrawer(null)}
                onSaved={() => { load(); setDrawer(null); }} toast={toast} />
      )}
    </div>
  );
}

function renderCell(finding, key, displayModes) {
  const col = COLUMN_MAP[key];
  const val = cellValue(finding, key);
  if (!col?.badge) return <span className={col?.mono ? "mono" : undefined}>{val}</span>;
  const mode = displayModes[key] || "badge";
  if (mode === "text") return <span>{val}</span>;
  if (col.badge === "risk") return <span className={"pill " + (finding.risk_level || "info")}>{RISK_LABEL[finding.risk_level] || val}</span>;
  if (col.badge === "status") return <span className={"pill " + (STATUS_CLASS[finding.status] || "info")}>{val}</span>;
  return <span>{val}</span>;
}

function Drawer({ data, canEdit, onClose, onSaved, toast }) {
  const { finding, events } = data;
  const [status, setStatus] = useState(finding.status);
  const [deadline, setDeadline] = useState(finding.deadline ? String(finding.deadline).slice(0, 10) : "");
  const [note, setNote] = useState(finding.manual_note || "");

  function save() {
    const body = { status };
    if (deadline) body.deadline = deadline + "T00:00:00";
    body.manual_note = note;
    api(`/findings/${finding.id}`, { method: "PATCH", json: body })
      .then(() => { toast("저장됨"); onSaved(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer">
        <h3>{finding.host_ip}:{finding.port}/{finding.proto}</h3>
        <div className="muted" style={{ marginBottom: 10 }}>{finding.service} {finding.version}</div>
        <div className="row" style={{ marginBottom: 8 }}>
          <span className={"pill " + (finding.risk_level || "info")}>{RISK_LABEL[finding.risk_level]}</span>
          <span className="tag">{finding.category || "미분류"}</span>
          <span className="tag">{finding.identification}</span>
          {finding.dept && <span className="tag">{finding.dept}</span>}
        </div>

        {canEdit && (
          <div className="panel" style={{ boxShadow: "none" }}>
            <div className="row">
              <label className="field">상태
                <select value={status} onChange={(e) => setStatus(e.target.value)}>
                  {["미조치", "처리중", "정상처리", "재발"].map((s) => <option key={s}>{s}</option>)}
                </select>
              </label>
              <label className="field">마감
                <input type="date" value={deadline} onChange={(e) => setDeadline(e.target.value)} />
              </label>
            </div>
            <label className="field" style={{ marginTop: 8 }}>메모
              <input value={note} onChange={(e) => setNote(e.target.value)} />
            </label>
            <button className="primary sm" style={{ marginTop: 10 }} onClick={save}>저장</button>
          </div>
        )}

        <h3 style={{ fontSize: 14, margin: "16px 0 8px" }}>변경 이력</h3>
        <div className="timeline">
          {events.length === 0 ? <div className="muted">이력 없음</div> : events.map((ev) => (
            <div className="ev" key={ev.id}>
              <div className="t">{ev.type}</div>
              <div className="d">{ev.detail}</div>
              <div className="when">{String(ev.created_at).slice(0, 19).replace("T", " ")}</div>
            </div>
          ))}
        </div>
        <button style={{ marginTop: 16 }} onClick={onClose}>닫기</button>
      </div>
    </>
  );
}
