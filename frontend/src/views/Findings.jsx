import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api.js";
import { downloadFile } from "../lib/download.js";
import { useToast } from "../ui/Toast.jsx";
import ColumnBuilder from "../ui/ColumnBuilder.jsx";
import ScanOptions from "../ui/ScanOptions.jsx";
import {
  COLUMN_MAP, PRESETS, DEFAULT_PRESET_ID, cellValue,
  primaryServiceIdentity, secondaryServiceIdentity,
  currentReason, needsConfirmation, stateWithEvidence,
} from "../lib/columns.js";
import { deadlinePatchValue } from "../lib/findingPatch.js";
import {
  COLOR_ELEMENTS, COLOR_KEY, cellTone, loadColorFlags,
} from "../lib/findingColors.js";
import { dday, STATUS_CLASS, RISK_LABEL } from "../lib/format.js";

const COLS_KEY = "scanops_cols";
const CUSTOM_KEY = "scanops_custom_presets";
// 한 번에 그리는 행 수. 발견이 수천 건이어도 DOM 이 그만큼 커지지 않게 서버 페이지로 끊는다.
const PAGE_SIZE = 200;
// 브라우저 로컬 날짜(YYYY-MM-DD) — 마감초과 판정 기준을 서버 UTC 가 아니라 사용자 기준으로 맞춘다.
const localToday = () => {
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};
const loadJSON = (k, fb) => { try { return JSON.parse(localStorage.getItem(k)) ?? fb; } catch { return fb; } };

export default function Findings({ user }) {
  const initial = PRESETS.find((p) => p.id === DEFAULT_PRESET_ID).cols;
  const [cols, setCols] = useState(() => loadJSON(COLS_KEY, initial));
  const [displayModes, setDisplayModes] = useState(() => loadJSON("scanops_colmodes", {}));
  const [presetId, setPresetId] = useState(DEFAULT_PRESET_ID);
  const [customPresets, setCustomPresets] = useState(() => loadJSON(CUSTOM_KEY, []));

  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [match, setMatch] = useState("contains");   // contains(일부 포함) | exact(정확히)
  const [colFilters, setColFilters] = useState({});  // {컬럼키: 검색어}
  const [sort, setSort] = useState({ key: "", dir: "asc" });
  const [page, setPage] = useState(0);
  // 한글 IME 조합 중인지 — 조합 단계마다 질의가 나가지 않게 막는 플래그.
  const composing = useRef(false);
  const [imeTick, setImeTick] = useState(0);   // 조합 종료 시점에 질의를 한 번 깨우는 용도
  const [risk, setRisk] = useState("");
  // 색상 인디케이터 — 무엇을 색으로 알릴지 사람마다 다르다. 요소별로 켜고 끄고, 선택은 남긴다.
  const [colorFlags, setColorFlags] = useState(() => loadColorFlags(localStorage));
  useEffect(() => {
    try { localStorage.setItem(COLOR_KEY, JSON.stringify(colorFlags)); } catch { /* 저장 실패는 무시 */ }
  }, [colorFlags]);
  const toggleColor = (key) => setColorFlags((prev) => ({ ...prev, [key]: !prev[key] }));
  const [status, setStatus] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [hideNormal, setHideNormal] = useState(true);
  const [selected, setSelected] = useState(() => new Set());
  const [confirmId, setConfirmId] = useState(null);
  const [rescanDrawer, setRescanDrawer] = useState(null);
  const [rescanBusy, setRescanBusy] = useState(false);
  const [drawer, setDrawer] = useState(null);
  const toast = useToast();
  const canEdit = user.role === "admin" || user.role === "auditor";

  function persistCols(next) { setCols(next); localStorage.setItem(COLS_KEY, JSON.stringify(next)); setPresetId(""); }

  // 검색·필터·정렬·페이지는 모두 서버가 처리한다. 화면이 보는 값과 내보내기가 어긋나지 않게
  // 서버가 '표시값' 기준으로 판정하며, 큰 원문(fingerprint)은 그 컬럼을 켰을 때만 실어 보낸다.
  const queryString = useMemo(() => {
    const qs = new URLSearchParams({ state: "open", match, cols: cols.join(",") });
    if (risk) qs.set("risk", risk);
    if (status) qs.set("status", status);
    if (q.trim()) qs.set("q", q.trim());
    const active = Object.fromEntries(Object.entries(colFilters).filter(([, v]) => v.trim()));
    if (Object.keys(active).length) qs.set("filters", JSON.stringify(active));
    if (sort.key) { qs.set("sort", sort.key); qs.set("dir", sort.dir); }
    // 이 두 토글도 서버가 걸러야 한다. 페이지를 자른 뒤 화면에서 걸러내면 조건에 맞는 행이
    // 뒷 페이지에 남아 첫 페이지가 빈 것처럼 보이고, 건수·내보내기도 화면과 어긋난다.
    if (hideNormal) qs.set("hide_normal", "true");
    if (overdueOnly) qs.set("overdue_only", "true");
    // 마감초과 판정은 사용자 로컬 날짜 기준이어야 화면의 'N일 초과' 표시와 일치한다.
    if (overdueOnly) qs.set("today", localToday());
    return qs;
  }, [match, cols, risk, status, q, colFilters, sort, hideNormal, overdueOnly]);

  function load(targetPage = page) {
    const qs = new URLSearchParams(queryString);
    qs.set("limit", String(PAGE_SIZE));
    qs.set("offset", String(targetPage * PAGE_SIZE));
    setLoading(true);
    api(`/findings?${qs.toString()}`, { raw: true })
      .then(({ body, total: count }) => { setFindings(body); setTotal(count); })
      .catch((e) => toast(e.message, { type: "err" }))
      .finally(() => setLoading(false));
  }

  // 입력 중 매 글자마다 서버를 때리지 않도록 살짝 늦춘다(검색어·컬럼 필터).
  // 한글 조합 중에는 아예 보내지 않는다 — 'ㄴ', '나', '남'… 조합 단계마다 질의하면
  // 엉뚱한 결과가 스쳐 지나가고 서버도 헛돈다. 조합이 끝나면 그때 한 번 나간다.
  useEffect(() => {
    if (composing.current) return;
    const timer = setTimeout(() => { setPage(0); load(0); }, 250);
    return () => clearTimeout(timer);
  }, [queryString.toString(), imeTick]);
  useEffect(() => { load(page); }, [page]);

  // 필터는 전부 서버가 페이지를 자르기 전에 적용한다 — 여기서 다시 거르면 페이지와 어긋난다.
  const view = findings;

  const filterCount = Object.values(colFilters).filter((v) => v.trim()).length
    + (q.trim() ? 1 : 0) + (risk ? 1 : 0) + (status ? 1 : 0) + (overdueOnly ? 1 : 0);

  function clearFilters() {
    setQ("");
    setColFilters({});
    setRisk("");
    setStatus("");
    setOverdueOnly(false);
    setSort({ key: "", dir: "asc" });
    setPage(0);
  }

  function toggleSort(key) {
    // 오름차순 → 내림차순 → 정렬 없음 순환. '정렬 없음'이 있어야 원래 순서로 돌아올 수 있다.
    setSort((s) => (s.key !== key ? { key, dir: "asc" }
      : s.dir === "asc" ? { key, dir: "desc" } : { key: "", dir: "asc" }));
    setPage(0);
  }

  function setColFilter(key, value) {
    setColFilters((f) => ({ ...f, [key]: value }));
  }

  // 한글 조합(IME) 안전 입력 핸들러 — 조합 중에는 질의를 막고, 끝나면 한 번만 깨운다.
  const imeProps = {
    onCompositionStart: () => { composing.current = true; },
    onCompositionEnd: () => { composing.current = false; setImeTick((n) => n + 1); },
  };

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
    // 화면에서 걸러 본 그대로 내보낸다 — 같은 파라미터를 같은 서버 뷰에 넘긴다.
    const qs = new URLSearchParams(queryString);
    qs.set("cols", cols.join(","));
    qs.set("fmt", fmt);
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

  function runRescanDue() {
    setRescanBusy(true);
    // 마감 지났거나 처리중인 '열린' 발견을 서버가 모아 일괄 재검증(라이프사이클 구동).
    api("/findings/rescan-due", { method: "POST", json: {} })
      .then((r) => {
        toast(`마감·처리중 일괄 재검증 시작 · #${r.scan_id} (${r.hosts.length}호스트 — 닫혔으면 자동 정상처리)`);
        setSelected(new Set());
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
    // 이벤트 + 용도 근거를 함께 받아 상세에 표시(근거 실패해도 상세는 열림).
    Promise.all([
      api(`/findings/${f.id}/events`),
      api(`/findings/${f.id}/evidence`).then((r) => r.evidence).catch(() => []),
    ])
      .then(([events, evidence]) => setDrawer({ finding: f, events, evidence }))
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
          <input style={{ flex: 1, minWidth: 180 }} placeholder="모든 컬럼 검색" value={q}
                 {...imeProps} onChange={(e) => setQ(e.target.value)} />
          <div className="seg" title="일부 포함: 검색어가 들어간 값 / 정확히: 값 전체가 검색어와 같음">
            <button type="button" className={match === "contains" ? "on" : ""}
                    onClick={() => setMatch("contains")}>일부 포함</button>
            <button type="button" className={match === "exact" ? "on" : ""}
                    onClick={() => setMatch("exact")}>정확히</button>
          </div>
          <select value={risk} onChange={(e) => setRisk(e.target.value)}>
            <option value="">위험 전체</option>
            <option value="banned">금지</option>
            <option value="high">상</option><option value="medium">중</option>
            <option value="low">하</option><option value="info">정보</option>
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">상태 전체</option>
            {["미조치", "처리중", "정상처리"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <label className="row" style={{ gap: 5 }}>
            <input type="checkbox" checked={hideNormal} onChange={(e) => setHideNormal(e.target.checked)} />
            정상처리 제외
          </label>
          <label className="row" style={{ gap: 5 }}>
            <input type="checkbox" checked={overdueOnly} onChange={(e) => setOverdueOnly(e.target.checked)} />
            마감초과만
          </label>
          <div className="color-toggles" role="group" aria-label="색상 표시">
            <span className="muted">색상</span>
            {COLOR_ELEMENTS.map((el) => (
              <label key={el.key} className="row" style={{ gap: 4 }}>
                <input type="checkbox" checked={!!colorFlags[el.key]}
                       onChange={() => toggleColor(el.key)} />
                {el.label}
              </label>
            ))}
          </div>
          <button className="sm" onClick={clearFilters} disabled={!filterCount && !sort.key}
                  title="검색어·컬럼 필터·위험/상태·정렬을 모두 초기화">
            필터 제거{filterCount ? ` (${filterCount})` : ""}
          </button>
          {canEdit && (
            <button className="sm" disabled={selected.size === 0}
                    onClick={() => setRescanDrawer({ targets: selFindings })}>
              선택 재스캔 ({selected.size})
            </button>
          )}
          {canEdit && (
            <button className="sm" disabled={rescanBusy} onClick={runRescanDue}
                    title="마감 지났거나 처리중인 열린 발견을 일괄 재검증">
              마감·처리중 재검증
            </button>
          )}
        </div>

        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th><input type="checkbox" checked={view.length > 0 && selected.size === view.length} onChange={selectAll} /></th>
                {cols.map((k) => (
                  <th key={k} className="sortable" onClick={() => toggleSort(k)}
                      title="클릭: 오름차순 → 내림차순 → 정렬 해제">
                    {COLUMN_MAP[k]?.label || k}
                    <span className="sort-mark">{sort.key === k ? (sort.dir === "asc" ? "▲" : "▼") : "↕"}</span>
                  </th>
                ))}
                <th className="sortable" onClick={() => toggleSort("deadline")} title="클릭: 오름차순 → 내림차순 → 정렬 해제">
                  마감<span className="sort-mark">{sort.key === "deadline" ? (sort.dir === "asc" ? "▲" : "▼") : "↕"}</span>
                </th>
                {canEdit && <th></th>}
              </tr>
              {/* 컬럼별 필터 — 각 컬럼 바로 아래에서 그 컬럼만 좁힌다. 위 검색창은 모든 컬럼 대상. */}
              <tr className="filter-row">
                <th></th>
                {cols.map((k) => (
                  <th key={k}>
                    <input value={colFilters[k] || ""} placeholder="필터"
                           aria-label={`${COLUMN_MAP[k]?.label || k} 필터`} {...imeProps}
                           onChange={(e) => setColFilter(k, e.target.value)} />
                  </th>
                ))}
                <th>
                  <input value={colFilters.deadline || ""} placeholder="필터" aria-label="마감 필터"
                         {...imeProps} onChange={(e) => setColFilter("deadline", e.target.value)} />
                </th>
                {canEdit && <th></th>}
              </tr>
            </thead>
            <tbody>
              {view.length === 0 ? (
                <tr><td className="empty" colSpan={cols.length + 3}>
                  {loading ? "불러오는 중…" : filterCount ? "조건에 맞는 발견 없음 — [필터 제거]로 초기화" : "발견 없음"}
                </td></tr>
              ) : view.map((f) => {
                const dl = dday(f.deadline);
                // 금지/마감초과 → 연한 빨강, 처리중 → 연한 노랑(빨강 우선). 각 요소는 토글로 끌 수 있다.
                const bg = (colorFlags.risk && f.risk_level === "banned") || (colorFlags.deadline && dl.over)
                  ? "var(--high-bg)"
                  : (colorFlags.status && f.status === "처리중") ? "var(--medium-bg)" : null;
                return (
                  <tr key={f.id} className="click" style={bg ? { background: bg } : null}>
                    <td onClick={(e) => e.stopPropagation()}>
                      <input type="checkbox" checked={selected.has(f.id)} onChange={() => toggleSel(f.id)} />
                    </td>
                    {cols.map((k) => (
                      <td key={k} className={cellTone(f, k, colorFlags)} onClick={() => openDrawer(f)}>
                        {renderCell(f, k, displayModes)}
                      </td>
                    ))}
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

        <div className="row" style={{ marginTop: 10, alignItems: "center" }}>
          <span className="muted" style={{ fontSize: 12 }}>
            {total === 0 ? "0건" : `${total.toLocaleString()}건 중 ${(page * PAGE_SIZE + 1).toLocaleString()}–${Math.min((page + 1) * PAGE_SIZE, total).toLocaleString()}`}
            {loading ? " · 불러오는 중…" : ""}
          </span>
          <div style={{ flex: 1 }} />
          <button className="sm" disabled={page === 0 || loading} onClick={() => setPage((p) => Math.max(0, p - 1))}>이전</button>
          <button className="sm" disabled={(page + 1) * PAGE_SIZE >= total || loading} onClick={() => setPage((p) => p + 1)}>다음</button>
        </div>
      </div>

      {drawer && (
        <Drawer data={drawer} canEdit={canEdit} onClose={() => setDrawer(null)}
                onSaved={() => { load(); setDrawer(null); }} toast={toast} />
      )}

      {rescanDrawer && (
        <RescanDrawer targets={rescanDrawer.targets}
                      onClose={() => setRescanDrawer(null)}
                      onDone={() => { load(); setSelected(new Set()); }}
                      toast={toast} />
      )}
    </div>
  );
}

// 선택 발견을 IP:포트별 개별 명령으로 재스캔 — 우측 서랍에 명령(복사)·진행·타겟별 결과를 모은다.
function RescanDrawer({ targets, onClose, onDone, toast }) {
  const ids = targets.map((f) => f.id);
  const hosts = [...new Set(targets.map((f) => f.host_ip))].sort();
  const portsAuto = [...new Set(targets.map((f) => f.port))].sort((a, b) => a - b).join(",");
  const [opt, setOpt] = useState({ options: [], ports: "" });
  const [commands, setCommands] = useState([]);
  const [phase, setPhase] = useState("idle");   // idle | running | done | failed
  const [scanId, setScanId] = useState(null);
  const [results, setResults] = useState(null);  // [{prev, cur}]

  useEffect(() => {
    api("/findings/rescan-command", { method: "POST", json: { finding_ids: ids } })
      .then((r) => setCommands(r.commands || []))
      .catch(() => setCommands([]));
  }, []);

  function copyAll() {
    const text = commands.join("\n");
    (navigator.clipboard?.writeText(text) || Promise.reject())
      .then(() => toast(`명령 ${commands.length}개 복사됨`))
      .catch(() => toast("복사 실패 — 직접 선택하세요", { type: "err" }));
  }

  function poll(id) {
    api(`/scans/${id}`)
      .then((s) => {
        if (s.status === "running" || s.status === "canceling") {
          setTimeout(() => poll(id), 2000);
          return;
        }
        // 완료 → 각 타겟의 현재 상태 조회(닫힘이면 정상처리됨)
        Promise.all(targets.map((t) =>
          api(`/findings/${t.id}`).then((cur) => ({ prev: t, cur })).catch(() => ({ prev: t, cur: null }))
        )).then((rows) => {
          setResults(rows);
          setPhase(s.status === "done" ? "done" : "failed");
          onDone && onDone();
        });
      })
      .catch(() => setPhase("failed"));
  }

  function start() {
    setPhase("running");
    api("/findings/rescan", { method: "POST", json: { finding_ids: ids, options: opt.options, nse: opt.nse } })
      .then((r) => { setScanId(r.scan_id); poll(r.scan_id); })
      .catch((e) => { toast(e.message, { type: "err" }); setPhase("failed"); });
  }

  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer">
        <h3>타겟 재스캔 — {targets.length}건 (IP:포트별 개별)</h3>
        <div className="muted" style={{ marginBottom: 10 }}>{hosts.length}호스트 · 포트 {portsAuto || "(자동)"}</div>

        {/* 개별 nmap 명령 — 망분리 시 스캔 호스트에 붙여 실행 후 XML 가져오기 */}
        <div className="panel" style={{ boxShadow: "none", background: "var(--surface-2)", marginBottom: 12 }}>
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <div className="cb-label" style={{ marginTop: 0 }}>개별 nmap 명령 ({commands.length}) — 그 IP·그 포트만</div>
            <button className="sm" onClick={copyAll} disabled={!commands.length}>전체 복사</button>
          </div>
          <pre className="mono" style={{ fontSize: 11.5, whiteSpace: "pre-wrap", maxHeight: 150, overflow: "auto", margin: "6px 0 4px" }}>
            {commands.join("\n") || "…"}
          </pre>
          <div className="muted" style={{ fontSize: 11 }}>망분리면 이 명령을 스캔 호스트에서 실행 → 결과 XML 가져오기.</div>
        </div>

        {/* 옵션 + 백그라운드 실행(콘솔이 대상망에 직접 닿을 때) */}
        {phase !== "done" && (
          <>
            <ScanOptions targets={hosts} portsAuto={portsAuto} fixedTargetPorts onState={setOpt} />
            <div className="row" style={{ marginTop: 10 }}>
              <button className="primary" disabled={phase === "running"} onClick={start}>
                {phase === "running" ? "재스캔 중…" : "백그라운드 재스캔 시작 (조치 검증)"}
              </button>
              <span className="muted" style={{ fontSize: 11.5 }}>발견·찾기 생략 → 선택 포트만 2-pass 정밀 확인 — 닫혔으면 자동 정상처리</span>
            </div>
          </>
        )}

        {phase === "running" && !results && (
          <div className="muted" style={{ marginTop: 12 }}>재스캔 진행 중… 완료되면 타겟별 결과가 여기에 표시됩니다.</div>
        )}

        {/* 타겟별 결과 */}
        {results && (
          <>
            <h3 style={{ fontSize: 14, margin: "16px 0 8px" }}>결과{scanId ? ` · #${scanId}` : ""}</h3>
            <table className="tbl">
              <thead><tr><th>대상</th><th>이전</th><th>현재</th><th>서비스</th></tr></thead>
              <tbody>
                {results.map(({ prev, cur }, i) => {
                  const closed = !cur || cur.state === "closed";
                  return (
                    <tr key={i}>
                      <td className="mono">{prev.host_ip}:{prev.port}/{prev.proto}</td>
                      <td className="muted">{prev.status}</td>
                      <td>
                        {closed
                          ? <span className="pill low">닫힘 · 정상처리</span>
                          : <span className="pill high">여전히 열림{cur.reopened ? " · 재발" : ""}</span>}
                      </td>
                      <td>
                        {cur ? <ServiceIdentity finding={cur} /> : <span className="muted">—</span>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </>
        )}

        <button style={{ marginTop: 16 }} onClick={onClose}>닫기</button>
      </div>
    </>
  );
}

function renderCell(finding, key, displayModes) {
  const col = COLUMN_MAP[key];
  const val = cellValue(finding, key);
  // 여러 줄 값(핑거프린트 등): 줄바꿈 보존 + 높이 제한 스크롤 박스로 깔끔하게.
  if (col?.pre) return (
    <pre className="mono" style={{
      margin: 0, whiteSpace: "pre-wrap", wordBreak: "break-all",
      maxHeight: 160, overflow: "auto", fontSize: 11, lineHeight: 1.4,
      maxWidth: 460, background: "var(--line-soft, rgba(127,127,127,.08))", borderRadius: 6, padding: val ? "6px 8px" : 0,
    }}>{val}</pre>
  );
  if (!col?.badge) return <span className={col?.mono ? "mono" : undefined}>{val}</span>;
  const mode = displayModes[key] || "badge";
  if (mode === "text") return <span>{val}</span>;
  if (col.badge === "risk") return <span className={"pill " + (finding.risk_level || "info")}>{RISK_LABEL[finding.risk_level] || val}</span>;
  if (col.badge === "status") return (
    <span>
      <span className={"pill " + (STATUS_CLASS[finding.status] || "info")}>{val}</span>
      {finding.reopened ? <span className="tag" style={{ marginLeft: 4, color: "var(--high)" }}>재발</span> : null}
    </span>
  );
  return <span>{val}</span>;
}

function ServiceIdentity({ finding }) {
  const secondary = secondaryServiceIdentity(finding);
  return (
    <span>
      <span>{primaryServiceIdentity(finding)}</span>
      {secondary && <span className="muted" style={{ marginLeft: 5 }}>({secondary})</span>}
    </span>
  );
}

function Drawer({ data, canEdit, onClose, onSaved, toast }) {
  const { finding, events, evidence = [] } = data;
  const [status, setStatus] = useState(finding.status);
  const [deadline, setDeadline] = useState(finding.deadline ? String(finding.deadline).slice(0, 10) : "");
  const [note, setNote] = useState(finding.manual_note || "");

  function save() {
    const body = { status, deadline: deadlinePatchValue(deadline) };
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
        <div style={{ marginBottom: 10 }}><ServiceIdentity finding={finding} /></div>
        <div className="row" style={{ marginBottom: 8 }}>
          <span className={"pill " + (finding.risk_level || "info")}>{RISK_LABEL[finding.risk_level]}</span>
          {finding.reopened ? <span className="tag" style={{ color: "var(--high)" }}>재발</span> : null}
          <span className="tag">{finding.category || "미분류"}</span>
          <span className="tag">{finding.identification}</span>
          {/* 열려 있다고 확인한 게 아니라 무응답으로 추정한 건이면 그 사실을 먼저 보여 준다. */}
          {needsConfirmation(finding)
            ? <span className="tag" style={{ color: "var(--medium)" }}>재확인 필요</span> : null}
          {finding.dept && <span className="tag">{finding.dept}</span>}
        </div>

        {/* 관측 근거 — '이 포트가 열려 있다고 어떻게 판단했나'. 용도 근거(무엇인가)와 다른 축이다. */}
        <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>
          관측 근거: {stateWithEvidence(finding)}
          {currentReason(finding) ? <span className="mono"> · {currentReason(finding)}</span> : null}
        </div>

        {/* 용도 근거 — '왜 열렸나/무엇인가' 추정 근거(역DNS·서비스·NSE 추출 등). 관리자 통보의 핵심. */}
        <div className="panel" style={{ boxShadow: "none", marginBottom: 12, background: "var(--accent-bg)" }}>
          <div className="cb-label" style={{ marginTop: 0 }}>용도 근거 (이 포트가 무엇이고 왜 열렸나)</div>
          {evidence.length ? (
            <ul style={{ margin: "4px 0 0", paddingLeft: 18, fontSize: 12.5, lineHeight: 1.6 }}>
              {evidence.map((e, i) => <li key={i}>{e}</li>)}
            </ul>
          ) : (
            <div className="muted" style={{ fontSize: 12 }}>
              수집된 근거가 부족합니다 — -sV/NSE(인증서·SMB·HTTP 등)나 역DNS를 켜고 재스캔하면 채워집니다.
            </div>
          )}
          {finding.owner && <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>담당(자산대장): {finding.owner}{finding.contact ? ` · ${finding.contact}` : ""}</div>}
        </div>

        {canEdit && (
          <div className="panel" style={{ boxShadow: "none" }}>
            <div className="row">
              <label className="field">상태
                <select value={status} onChange={(e) => setStatus(e.target.value)}>
                  {["미조치", "처리중", "정상처리"].map((s) => <option key={s}>{s}</option>)}
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
