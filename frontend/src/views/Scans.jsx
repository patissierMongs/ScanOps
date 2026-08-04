import React, { useEffect, useRef, useState } from "react";
import { api, uploadMany } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import ScanOptions from "../ui/ScanOptions.jsx";
import { scanKind, scanStatus, shouldLoadStages } from "../lib/scanStatus.js";

const isActive = (s) => s === "running" || s === "canceling";
// 중단됨(interrupted): 서버 재시작으로 워커가 사라진 실행 — 자동 복구는 안 하고 수동 이어하기만.
const canResume = (s) => s === "canceled" || s === "failed" || s === "interrupted";

// 초 → 사람 읽기 좋은 시간 문자열
function fmtDur(sec) {
  if (sec == null) return "—";
  sec = Math.round(sec);
  if (sec < 60) return `${sec}초`;
  const m = Math.round(sec / 60);
  if (m < 60) return `${m}분`;
  const h = Math.floor(m / 60), mm = m % 60;
  return mm ? `${h}시간 ${mm}분` : `${h}시간`;
}

function withPersistedStages(previous, scans) {
  const next = { ...previous };
  scans.forEach((scan) => {
    if (!scan.stages_json?.length) return;
    next[scan.id] = {
      ...(next[scan.id] || {}),
      stages: scan.stages_json,
      overall: { status: scan.status, percent: isActive(scan.status) ? null : 100 },
    };
  });
  return next;
}

export default function Scans({ user }) {
  const [scans, setScans] = useState([]);
  const [progress, setProgress] = useState({});   // { [scanId]: { percent, etc, remaining, elapsed, hosts_up } }
  const [targets, setTargets] = useState("");
  const [name, setName] = useState("");
  const [opt, setOpt] = useState({ workflow: "auto", options: [], ports: "", nse: [], command: "" });
  const [batchSize, setBatchSize] = useState(256);
  const [staged, setStaged] = useState(true);      // 단계 분리 엔진 스캔(발견→포트→서비스) — 기본 ON
  const [discovery, setDiscovery] = useState("sn");
  const [stages, setStages] = useState({});        // { [scanId]: { stages, overall } } — 단계 타임라인
  const [rawMode, setRawMode] = useState(false);   // 직접 명령 입력 모드
  const [rawCmd, setRawCmd] = useState("");
  const [rawEdited, setRawEdited] = useState(false);
  const [est, setEst] = useState(null);
  const [busy, setBusy] = useState(false);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const fileButtonRef = useRef(null);
  const folderButtonRef = useRef(null);
  const importRestoreFocusRef = useRef(null);
  const [expanded, setExpanded] = useState(() => new Set());
  const toast = useToast();
  const canRun = user.role === "admin" || user.role === "auditor";

  function load() {
    api("/scans").then(async (list) => {
      setScans(list);
      setStages((prev) => withPersistedStages(prev, list));
      const stageEntries = await Promise.all(
        list.filter(shouldLoadStages)
          .map((scan) => api(`/scans/${scan.id}/stages`).then((detail) => [scan.id, detail]).catch(() => null))
      );
      setStages((prev) => {
        const next = { ...prev };
        stageEntries.filter(Boolean).forEach(([id, detail]) => { next[id] = detail; });
        return next;
      });
    }).catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, []);

  // 폴더 선택 속성은 React 가 prop 으로 안정적으로 안 넘기므로 DOM 에 직접 설정.
  // webkitdirectory 면 선택 폴더의 하위까지 재귀로 파일이 들어오고, .xml 만 importFiles 에서 거른다.
  useEffect(() => {
    if (folderInputRef.current) {
      folderInputRef.current.setAttribute("webkitdirectory", "");
      folderInputRef.current.setAttribute("directory", "");
    }
  }, []);

  // 실행 중인 스캔이 있는 동안만 폴링 — 진행률(percent/ETC/경과)을 주기적으로 갱신.
  // 활성 스캔 집합이 바뀔 때만 인터벌 재설정(매 틱 churn 방지).
  const activeKey = scans.filter((s) => isActive(s.status)).map((s) => s.id).join(",");
  useEffect(() => {
    if (!activeKey) return;
    let alive = true;
    const tick = async () => {
      try {
        const list = await api("/scans");
        if (!alive) return;
        setScans(list);
        setStages((prev) => withPersistedStages(prev, list));
        const act = list.filter((s) => isActive(s.status));
        const entries = await Promise.all(
          act.map((s) => api(`/scans/${s.id}/progress`).then((p) => [s.id, p]).catch(() => null))
        );
        if (!alive) return;
        setProgress((prev) => {
          const m = { ...prev };
          entries.filter(Boolean).forEach(([id, p]) => { m[id] = p; });
          return m;
        });
        // 단계 엔진 스캔이면 단계 타임라인도 폴링(없는 스캔은 빈 stages → 무시).
        const stageEntries = await Promise.all(
          act.map((s) => api(`/scans/${s.id}/stages`).then((st) => [s.id, st]).catch(() => null))
        );
        if (!alive) return;
        setStages((prev) => {
          const m = { ...prev };
          stageEntries.filter(Boolean).forEach(([id, st]) => { m[id] = st; });
          return m;
        });
      } catch { /* 일시 오류는 다음 틱에 회복 */ }
    };
    const h = setInterval(tick, 3000);
    tick();
    return () => { alive = false; clearInterval(h); };
  }, [activeKey]);

  const targetList = targets.split(/[\s,]+/).filter(Boolean);

  // 실행 전 예상 — 타겟/옵션/포트/배치크기가 바뀌면 디바운스로 /estimate 호출.
  const estKey = JSON.stringify({ t: targetList, w: opt.workflow, o: opt.options, p: opt.ports, b: batchSize });
  useEffect(() => {
    if (!canRun || !targetList.length) { setEst(null); return; }
    let alive = true;
    const id = setTimeout(() => {
      api("/scans/estimate", { method: "POST", json: { targets: targetList, workflow: opt.workflow, options: opt.options, ports: opt.ports, batch_size: batchSize } })
        .then((e) => { if (alive) setEst(e); })
        .catch(() => { if (alive) setEst(null); });
    }, 400);
    return () => { alive = false; clearTimeout(id); };
  }, [estKey]);

  // 여러 .xml 또는 폴더째 가져오기 — 자동 스캔 단계 파일은 서버에서 한 실행 결과로 묶어 인입한다.
  async function importFiles(fileList, restoreFocusTo = null) {
    const xmls = [...fileList]
      .filter((f) => f.name.toLowerCase().endsWith(".xml"))
      .sort((a, b) => (a.webkitRelativePath || a.name).localeCompare(b.webkitRelativePath || b.name));
    if (!xmls.length) { toast("가져올 .xml 파일이 없습니다", { type: "err" }); return; }
    setBusy(true);
    try {
      const r = await uploadMany("/scans/import-bundle", xmls.map((f) => ({ file: f, name: f.webkitRelativePath || f.name })));
      const c = r.counts || {};
      toast(`가져옴 · 결과 ${r.imported}건 / 파일 ${r.file_count}개${r.failed ? ` (실패 ${r.failed})` : ""} · 신규 ${c.new || 0} / 닫힘 ${c.closed || 0}`,
            r.failed ? { type: "err" } : undefined);
      load();
    } catch (e) {
      toast(e.message, { type: "err" });
    } finally {
      setBusy(false);
      window.setTimeout(() => {
        if (restoreFocusTo?.isConnected && !restoreFocusTo.disabled) restoreFocusTo.focus();
      }, 0);
    }
  }

  function restoreImportFocus() {
    const restore = importRestoreFocusRef.current;
    importRestoreFocusRef.current = null;
    if (restore?.isConnected) restore.focus();
    // 네이티브 선택기가 이벤트 종료 뒤 포커스를 다시 가져가는 브라우저도 있어 한 번 더 복구한다.
    if (restore?.isConnected) window.setTimeout(() => {
      if (restore.isConnected && !restore.disabled) restore.focus();
    }, 0);
    return restore;
  }

  function onImport(e) {
    // value 를 비우면 라이브 FileList 가 같이 비므로, 먼저 배열로 스냅샷한 뒤 리셋한다.
    const files = e.target.files ? [...e.target.files] : [];
    e.target.value = "";
    const restore = restoreImportFocus();
    if (files.length) importFiles(files, restore);
  }

  function openImport(inputRef, buttonRef) {
    importRestoreFocusRef.current = buttonRef.current;
    inputRef.current?.click();
  }

  function toggleDetails(scan) {
    const opening = !expanded.has(scan.id);
    setExpanded((current) => {
      const next = new Set(current);
      if (opening) next.add(scan.id);
      else next.delete(scan.id);
      return next;
    });
    if (!opening) return;
    api(`/scans/${scan.id}/stages`)
      .then((detail) => setStages((current) => ({ ...current, [scan.id]: detail })))
      .catch((e) => toast(e.message, { type: "err" }));
  }

  // 직접 명령 모드 진입 시(또는 옵션 변경 시) 사용자가 손대기 전까진 조립된 명령을 따라간다.
  useEffect(() => {
    if (rawMode && !rawEdited) setRawCmd(opt.workflow === "manual" ? (opt.command || "") : "");
  }, [rawMode, rawEdited, opt.command, opt.workflow]);

  function runScan() {
    if (rawMode) {
      if (!rawCmd.trim()) { toast("명령을 입력하세요", { type: "err" }); return; }
      setBusy(true);
      api("/scans/run-command", { method: "POST", json: { name, command: rawCmd } })
        .then((s) => { toast(`직접 명령 스캔 시작됨 · #${s.id} (단발 실행 — 이어가기 미지원)`); load(); })
        .catch((e2) => toast(e2.message, { type: "err" }))
        .finally(() => setBusy(false));
      return;
    }
    if (!targetList.length) { toast("타겟을 입력하세요", { type: "err" }); return; }
    setBusy(true);
    const endpoint = staged ? "/scans/run-staged" : "/scans/run";
    const body = staged
      ? { name, options: opt.options, ports: opt.ports, nse: opt.nse, targets: targetList, batch_size: batchSize, discovery }
      : { name, workflow: opt.workflow, options: opt.options, ports: opt.ports, nse: opt.nse, targets: targetList, batch_size: batchSize };
    api(endpoint, { method: "POST", json: body })
      .then((s) => { toast(`${staged ? "단계 " : ""}스캔 시작됨 · #${s.id} (백그라운드 — 진행은 아래 표)`); setTargets(""); setName(""); load(); })
      .catch((e2) => toast(e2.message, { type: "err" }))
      .finally(() => setBusy(false));
  }

  function stopScan(id) {
    api(`/scans/${id}/stop`, { method: "POST" })
      .then(() => { toast(`#${id} 중지 요청 — 다음날 [이어하기]로 재개 가능`); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function resumeScan(id) {
    api(`/scans/${id}/resume`, { method: "POST" })
      .then(() => { toast(`#${id} 이어가기 시작됨`); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  return (
    <div className="content">
      {canRun && (
        <div className="panel">
          <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ margin: 0 }}>스캔 실행</h3>
            <div className="row" style={{ gap: 14 }}>
              <label className="row" style={{ gap: 6, fontSize: 13, cursor: "pointer" }}
                     title="켜면 발견→TCP→UDP→서비스 단계를 한 번에 몰아 돌리지 않고, 단계로 나눠 분산 순차 실행합니다(앞 단계 결과를 다음 단계 입력으로). 아래 '실행될 명령어'에 단계별 명령이 표시됩니다.">
                <input type="checkbox" checked={staged} disabled={rawMode}
                       onChange={(e) => setStaged(e.target.checked)} />
                단계 분리 (발견→포트→서비스 · 분산 실행)
              </label>
              <label className="row" style={{ gap: 6, fontSize: 13, cursor: "pointer" }}>
                <input type="checkbox" checked={rawMode}
                       onChange={(e) => { setRawMode(e.target.checked); setRawEdited(false); }} />
                명령 직접 입력 (고급)
              </label>
            </div>
          </div>
          <div className="row" style={{ marginBottom: 12, marginTop: 10 }}>
            <input placeholder="이름(선택)" value={name} onChange={(e) => setName(e.target.value)} />
            {!rawMode && (
              <input style={{ flex: 1, minWidth: 240 }} placeholder="타겟 (예: 10.0.12.0/24 10.0.13.5)"
                     value={targets} onChange={(e) => setTargets(e.target.value)} />
            )}
          </div>

          {rawMode && (
            <div style={{ marginBottom: 12 }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="cb-label">nmap 명령 — 직접 편집 (출력 플래그는 서버가 -oA 로 강제 교체)</span>
                <button type="button" className="sm" onClick={() => { setRawCmd(opt.workflow === "manual" ? (opt.command || "") : ""); setRawEdited(false); }}>
                  단일 실행 명령으로 채우기
                </button>
              </div>
              <textarea className="mono" rows={3} value={rawCmd}
                        onChange={(e) => { setRawCmd(e.target.value); setRawEdited(true); }}
                        placeholder="nmap -sV -p 22,80,443 10.0.12.0/24"
                        style={{ width: "100%", resize: "vertical", fontSize: 12.5 }} />
              <div className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
                직접 명령은 단발 실행입니다 — 배치 청킹/이어가기는 미지원(중지만 가능). 셸 메타문자(; | &amp; $ ` 등)는 차단되고,
                허용 대역(scope)이 설정돼 있으면 그 밖의 IP 는 거절됩니다.
              </div>
            </div>
          )}

          {/* 옵션 빌더는 raw 모드에서도 마운트 유지(숨김만) — opt.command 가 최신이라 '채우기'가 정확하게 동작 */}
          <div style={{ display: rawMode ? "none" : "block" }}>
            <ScanOptions targets={targetList} staged={staged} onState={setOpt} />

            <div style={{ marginTop: 12 }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <span className="cb-label">배치 크기 — 중지·이어가기 단위 (넓은 대역을 이만큼씩 쪼개 스캔)</span>
                <span className="mono">{batchSize} 호스트 / 배치</span>
              </div>
              <input type="range" min={16} max={1024} step={16} value={batchSize}
                     onChange={(e) => setBatchSize(Number(e.target.value))} style={{ width: "100%" }} />
              <div className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
                {est
                  ? `${est.host_count} 호스트 / ${est.batch_count} 배치` +
                    (est.basis === "history" && est.est_seconds != null
                      ? ` · 예상 ~${fmtDur(est.est_seconds)} (과거 동일설정 ${est.sample_count}건 기준·근사)`
                      : " · 예상시간: 동일설정 이력 없음 → 실행 후 배치 기준으로 정밀 추정")
                  : (targetList.length ? "예상 계산 중…" : "타겟을 입력하면 호스트·배치 수와 예상시간을 보여줍니다")}
              </div>
            </div>

            {staged && (
              <div className="row" style={{ marginTop: 12, alignItems: "center", gap: 8 }}>
                <span className="cb-label">발견 단계</span>
                <select value={discovery} onChange={(e) => setDiscovery(e.target.value)}>
                  <option value="sn">핑 스윕 (-sn)</option>
                  <option value="pn">생략 (-Pn · ICMP 차단망)</option>
                </select>
                <span className="mono" style={{ fontSize: 11.5, color: "var(--muted)" }}>
                  내부적으로 발견→TCP 찾기→(UDP)→열린 포트에만 서비스 probe. 진행은 단계 타임라인으로.
                </span>
              </div>
            )}
          </div>

          <div className="row" style={{ marginTop: 14 }}>
            <button className="primary" disabled={busy || (rawMode ? !rawCmd.trim() : !targetList.length)} onClick={runScan}>
              {busy ? "시작 중…" : "스캔 실행"}
            </button>
            <button ref={fileButtonRef} type="button" className="linkbtn inline-action" disabled={busy}
                    onClick={() => openImport(fileInputRef, fileButtonRef)}>
              XML 가져오기(여러 개)
            </button>
            <button ref={folderButtonRef} type="button" className="linkbtn inline-action" disabled={busy}
                    onClick={() => openImport(folderInputRef, folderButtonRef)}>
              폴더째 가져오기(.xml만)
            </button>
            <input ref={fileInputRef} type="file" accept=".xml" multiple hidden tabIndex={-1}
                   disabled={busy} onChange={onImport} onCancel={restoreImportFocus} />
            <input ref={folderInputRef} type="file" hidden tabIndex={-1}
                   disabled={busy} onChange={onImport} onCancel={restoreImportFocus} />
            <span className="muted" style={{ fontSize: 12 }}>
              자동 스캔은 발견·식별·UDP 확인을 배치 안에서 순서대로 실행합니다. 실행 중엔 [중지], 중단분은 [이어하기]로 재개합니다.
            </span>
          </div>
        </div>
      )}

      <div className="panel">
        <h3>스캔 이력</h3>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead><tr>
              <th>ID</th><th>이름</th><th>명령</th><th>상태</th>
              <th style={{ minWidth: 220 }}>진행</th><th>호스트</th><th>포트</th><th>작업</th>
            </tr></thead>
            <tbody>
              {scans.length === 0 ? (
                <tr><td className="empty" colSpan={8}>스캔 이력 없음</td></tr>
              ) : scans.map((s) => {
                const st = scanStatus(s.status);
                const kind = scanKind({ ...s, kind: stages[s.id]?.kind || s.kind });
                const p = progress[s.id];
                return (
                  <React.Fragment key={s.id}>
                  <tr>
                    <td className="mono">{s.id}</td>
                    <td>{s.name}<div><span className="tag">{kind.label}</span></div></td>
                    <td className="mono" style={{ fontSize: 11, maxWidth: 300, whiteSpace: "normal", color: "var(--muted)" }}>{s.command}</td>
                    <td style={{ whiteSpace: "normal", minWidth: 150 }}>
                      <span className={`pill ${st.cls}`}>{st.label}</span>
                      {s.failure_message && <div className="scan-failure">{s.failure_message}</div>}
                    </td>
                    <td>{stages[s.id]?.stages?.length
                      ? <StageTimeline s={stages[s.id]} />
                      : isActive(s.status) ? <Progress p={p} /> : <span className="muted">—</span>}</td>
                    <td className="mono">{s.host_count}</td>
                    <td className="mono">{s.port_count}</td>
                    <td>
                      {canRun && isActive(s.status) && (
                        <button className="sm" onClick={() => stopScan(s.id)} disabled={s.status === "canceling"}>중지</button>
                      )}
                      {canRun && canResume(s.status) && (
                        <button className="sm" onClick={() => resumeScan(s.id)}>이어하기</button>
                      )}
                      <button className="sm" aria-expanded={expanded.has(s.id)}
                              aria-controls={`scan-detail-${s.id}`} onClick={() => toggleDetails(s)}>
                        {expanded.has(s.id) ? "상세 닫기" : "상세"}
                      </button>
                    </td>
                  </tr>
                  {expanded.has(s.id) && (
                    <tr id={`scan-detail-${s.id}`}>
                      <td colSpan={8}><ScanDetails scan={s} detail={stages[s.id]} /></td>
                    </tr>
                  )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// 진행률 막대 — 전체 진행(배치 누적)을 막대로, 배치 카운트 + 현재 배치 ETC/경과를 보조로.
function Progress({ p }) {
  if (!p) return <span className="muted">…</span>;
  const overall = p.overall_percent != null ? p.overall_percent : null;
  const total = p.batches_total || 1;
  const known = overall != null;
  return (
    <div style={{ minWidth: 200 }}>
      <div role="progressbar" aria-label="스캔 진행률" aria-valuemin="0" aria-valuemax="100"
           aria-valuenow={known ? Math.round(overall) : undefined}
           style={{ height: 6, borderRadius: 4, background: "var(--line)", overflow: "hidden" }}>
        <div style={{
          width: known ? `${Math.min(overall, 100)}%` : "12%",
          height: "100%", background: "var(--accent)",
          transition: "width .4s", opacity: known ? 1 : 0.45,
        }} />
      </div>
      <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 3 }}>
        {known ? `${overall}%` : "준비 중"}
        {total > 1 ? ` · 배치 ${p.batches_done}/${total}` : ""}
        {p.eta_seconds != null ? ` · ~남음 ${fmtDur(p.eta_seconds)}` : (p.remaining ? ` · 남음 ${p.remaining}` : "")}
        {p.elapsed ? ` · 경과 ${p.elapsed}` : ""}
      </div>
    </div>
  );
}

// 단계 타임라인 — 단계분리 엔진 스캔의 발견/TCP/UDP/서비스 진행을 색 칩으로(이벤트 기반).
const STAGE_LABEL = { discovery: "발견", tcp: "TCP", udp: "UDP", service: "서비스" };
const STAGE_CLS = { pending: "info", running: "info", done: "low", stopped: "medium", error: "high" };

function stageLabel(stage) {
  const key = stage.stage || stage.name;
  return STAGE_LABEL[key] || key || "단계";
}

function StageTimeline({ s }) {
  const list = s?.stages || [];
  if (!list.length) return <span className="muted">…</span>;
  const overall = s.overall?.percent;
  const known = overall != null;
  return (
    <div style={{ minWidth: 220 }}>
      <div role="progressbar" aria-label="단계 스캔 진행률" aria-valuemin="0" aria-valuemax="100"
           aria-valuenow={known ? Math.round(overall) : undefined}
           style={{ height: 6, borderRadius: 4, background: "var(--line)", overflow: "hidden" }}>
        <div style={{
          width: known ? `${Math.min(overall, 100)}%` : "12%",
          height: "100%", background: "var(--accent)", transition: "width .4s", opacity: known ? 1 : 0.45,
        }} />
      </div>
      <div className="row" style={{ gap: 4, marginTop: 4, flexWrap: "wrap" }}>
        {list.map((st, index) => {
          const c = st.counts || {};
          const extra = st.status === "running" && st.percent != null ? ` ${Math.round(st.percent)}%`
            : c.live != null ? ` ${c.live}대`
            : c.open_ports != null ? ` ${c.open_ports}p`
            : c.services != null ? ` ${c.services}svc` : "";
          return (
            <span key={`${st.stage || st.name || "stage"}-${index}`}
                  className={`pill ${STAGE_CLS[st.status] || "info"}`}
                  title={st.error || ""} style={{ fontSize: 10.5 }}>
              {stageLabel(st)}{extra}{st.status === "error" ? " ⚠" : ""}
            </span>
          );
        })}
      </div>
      {list.filter((stage) => stage.error).map((stage, index) => (
        <div key={`${stage.stage || stage.name || "stage"}-error-${index}`} className="scan-failure">
          {stageLabel(stage)}: {stage.error}
        </div>
      ))}
    </div>
  );
}

function ScanDetails({ scan, detail }) {
  const kind = detail?.kind === "staged" ? "단계 엔진" : scanKind(scan).label;
  const failureMessage = detail?.failure_message || scan.failure_message;
  const failureCode = detail?.failure_code || scan.failure_code;
  return (
    <div className="scan-detail">
      <div className="row">
        <b>실행 유형</b><span>{kind}</span>
        <b>상태</b><span>{scanStatus(detail?.status || scan.status).label}</span>
      </div>
      {detail?.stages?.length
        ? <StageTimeline s={detail} />
        : <div className="muted">{detail?.timeline_available === false ? "저장된 단계 이벤트가 없습니다." : "단계 정보를 불러오는 중…"}</div>}
      {failureMessage && (
        <div className="scan-failure-detail">
          <b>실패 원인</b> {failureMessage}
          {failureCode && <code>{failureCode}</code>}
        </div>
      )}
    </div>
  );
}
