import React, { useEffect, useRef, useState } from "react";
import { api, uploadMany } from "../api.js";
import { formatImportSummary, prepareImportGroups, runImportGroups } from "../lib/scanImports.js";
import { splitScanTokens } from "../lib/scanTargets.js";
import { formatScanPortScope } from "../lib/scanScope.js";
import { useToast } from "../ui/Toast.jsx";
import ScanOptions from "../ui/ScanOptions.jsx";
import { scanKind, scanNotice, scanStatus, shouldLoadStages } from "../lib/scanStatus.js";
import ScanTrace from "../ui/ScanTrace.jsx";

const isActive = (s) => s === "running" || s === "canceling";

// 실행 방식 3종 — 무엇을 고르는 것인지가 카드 본문으로 읽히게 한다.
const SCAN_MODES = [
  {
    id: "staged", title: "단계별 정밀 (권장)",
    desc: "살아있는 호스트 → 열린 포트 → 그 포트의 서비스 순으로 좁혀 갑니다. 넓은 대역에 가장 빠르고 정확합니다.",
    on: (staged, rawMode) => staged && !rawMode,
    pick: ({ setStaged, setRawMode }) => { setRawMode(false); setStaged(true); },
  },
  {
    id: "single", title: "한 번에 실행",
    desc: "옵션을 직접 조합해 nmap 을 한 번만 돌립니다. 대상이 적고 무엇을 볼지 이미 아는 경우에.",
    on: (staged, rawMode) => !staged && !rawMode,
    pick: ({ setStaged, setRawMode }) => { setRawMode(false); setStaged(false); },
  },
  {
    id: "raw", title: "명령 직접 입력 (고급)",
    desc: "nmap 명령을 그대로 씁니다. 단발 실행이라 이어하기는 안 됩니다.",
    on: (_staged, rawMode) => rawMode,
    pick: ({ setRawMode, setRawEdited }) => { setRawMode(true); setRawEdited(false); },
  },
];
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

function fmtElapsed(sec) {
  if (sec == null || !Number.isFinite(sec)) return "계산 중";
  sec = Math.max(0, Math.floor(sec));
  const s = sec % 60;
  const totalMinutes = Math.floor(sec / 60);
  if (!totalMinutes) return `${s}초`;
  const m = totalMinutes % 60;
  const h = Math.floor(totalMinutes / 60);
  if (!h) return `${m}분 ${s}초`;
  return `${h}시간 ${m}분 ${s}초`;
}

function scanDuration(scan, liveProgress) {
  if (liveProgress?.elapsed_seconds != null) return liveProgress.elapsed_seconds;
  if (!scan?.started_at || !scan?.finished_at) return null;
  // 가져온 스캔도 소요시간을 보여 준다. `finished_at` 은 인입 시각이 아니라 **XML 이 스스로
  // 밝힌 종료 시각**(runstats/finished)으로 저장하므로(_xml_finished_at), 빼면 실제 실행
  // 시간이 나온다. 예전에는 인입 시각을 써서 한 달 전 XML 이 한 달짜리 스캔으로 보였는데,
  // 그렇다고 값을 지우면 어느 단계가 시간을 썼는지 볼 방법이 함께 사라진다.
  const seconds = (new Date(scan.finished_at).getTime() - new Date(scan.started_at).getTime()) / 1000;
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}

function formatArgv(argv) {
  return (argv || []).map((arg) => (/\s|"/.test(arg) ? `"${arg.replaceAll('"', '\\"')}"` : arg)).join(" ");
}

function procedurePercent(stages) {
  if (!stages?.length) return null;
  const total = stages.reduce((sum, stage) => {
    if (["done", "warning"].includes(stage.status)) return sum + 100;
    return sum + Math.max(0, Math.min(100, Number(stage.percent) || 0));
  }, 0);
  return Math.round((total / stages.length) * 10) / 10;
}

function withPersistedStages(previous, scans) {
  const next = { ...previous };
  scans.forEach((scan) => {
    if (!scan.stages_json?.length) return;
    next[scan.id] = {
      ...(next[scan.id] || {}),
      stages: scan.stages_json,
      overall: { status: scan.status, percent: procedurePercent(scan.stages_json) },
    };
  });
  return next;
}

export default function Scans({ user }) {
  const [scans, setScans] = useState([]);
  const [progress, setProgress] = useState({});   // { [scanId]: { percent, etc, remaining, elapsed, hosts_up } }
  const [targets, setTargets] = useState("");
  const [exclude, setExclude] = useState("");
  const [excludePorts, setExcludePorts] = useState("");
  const [name, setName] = useState("");
  const [opt, setOpt] = useState({ workflow: "auto", options: [], ports: "", nse: [], command: "" });
  const [batchSize, setBatchSize] = useState(256);
  // nmap 프로세스당 상한(분). 0 = 끔이 기본이다 — 정상적인 전 포트 스캔이 몇 시간 걸리는
  // 망이 실제로 있어서, 섣부른 값은 '느린 망'을 '실패'로 바꾼다.
  const [watchdogMin, setWatchdogMin] = useState(0);
  const [staged, setStaged] = useState(true);      // 단계 분리 엔진 스캔(발견→포트→서비스) — 기본 ON
  const [discovery, setDiscovery] = useState("sn");
  const [stages, setStages] = useState({});        // { [scanId]: { stages, overall } } — 단계 타임라인
  const [rawMode, setRawMode] = useState(false);   // 직접 명령 입력 모드
  const [rawCmd, setRawCmd] = useState("");
  const [rawEdited, setRawEdited] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);   // 세부 설정 — 기본은 접힘
  const [est, setEst] = useState(null);
  const [busy, setBusy] = useState(false);
  const [retryingId, setRetryingId] = useState(null);
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);
  const fileButtonRef = useRef(null);
  const folderButtonRef = useRef(null);
  const importRestoreFocusRef = useRef(null);
  const [expanded, setExpanded] = useState(() => new Set());
  const toast = useToast();
  const canRun = user.role === "admin" || user.role === "auditor";
  // 삭제는 발견(다른 사람이 달아 둔 상태·담당자·메모 포함)까지 지우므로 admin 만.
  const canDelete = user.role === "admin";

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
  // webkitdirectory 면 하위까지 재귀로 들어오고, XML/standalone manifest만 importFiles에서 고른다.
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

  const targetList = splitScanTokens(targets);
  const excludeList = splitScanTokens(exclude);
  const previewExcludes = est?.exclude ?? excludeList;

  // "지금 실행 버튼을 누르면 무슨 일이 일어나는가"를 한 줄로. nmap 플래그가 아니라 사람 말로 쓴다 —
  // 세부 설정을 펼치지 않아도 무엇을 하려는지 확인하고 실행할 수 있어야 한다.
  const planSummary = (() => {
    if (rawMode) {
      return rawCmd.trim()
        ? { headline: "입력한 nmap 명령을 그대로 1회 실행", detail: "이어하기는 지원되지 않습니다." }
        : { headline: "실행할 명령을 입력하세요", detail: "" };
    }
    if (!targetList.length) {
      return { headline: "스캔할 대상을 입력하세요", detail: "IP 하나, 대역(10.0.12.0/24), 범위(10.0.12.1-30) 모두 됩니다." };
    }
    const how = staged ? "단계별 정밀 스캔" : "한 번에 실행";
    const hosts = est ? `${est.host_count.toLocaleString()}개 호스트` : `대상 ${targetList.length}개`;
    const eta = est?.basis === "history" && est?.est_seconds != null
      ? ` · 예상 ~${fmtDur(est.est_seconds)}`
      : (est ? " · 예상시간은 첫 배치가 끝나면 나옵니다" : "");
    const skipped = previewExcludes.length ? ` · 제외 ${previewExcludes.length}개` : "";
    return {
      headline: `${hosts} · ${how}${eta}`,
      detail: `${est ? `${est.batch_count}개 배치로 나눠 실행` : "계산 중"}${skipped} — 중간에 멈춰도 이어할 수 있습니다.`,
    };
  })();

  // 실행 전 예상 — 타겟/제외/옵션/포트/배치크기가 바뀌면 디바운스로 /estimate 호출.
  const estKey = JSON.stringify({ t: targetList, x: excludeList, xp: excludePorts, w: opt.workflow, o: opt.options, p: opt.ports, b: batchSize, s: staged });
  useEffect(() => {
    if (!canRun || !targetList.length) { setEst(null); return; }
    setEst(null);
    let alive = true;
    const id = setTimeout(() => {
      api("/scans/estimate", { method: "POST", json: { targets: targetList, exclude: excludeList, exclude_ports: excludePorts, workflow: opt.workflow, options: opt.options, ports: opt.ports, batch_size: batchSize, staged } })
        .then((e) => { if (alive) setEst(e); })
        .catch(() => { if (alive) setEst(null); });
    }, 400);
    return () => { alive = false; clearTimeout(id); };
  }, [estKey]);

  // 여러 XML 또는 폴더째 가져오기. standalone manifest가 함께 있으면 제외/미관측 범위도 검증한다.
  async function importFiles(fileList, restoreFocusTo = null) {
    setBusy(true);
    try {
      const plan = await prepareImportGroups(fileList);
      const summary = await runImportGroups(plan, async (group) => (
        uploadMany("/scans/import-bundle", group.files)
      ));
      // 검증에 걸린 파일이 있으면 성공 토스트로 흘려보내지 않는다 - 눈에 남아야 한다.
      const flagged = (summary.reviews || []).length > 0;
      toast(formatImportSummary(summary),
            summary.hasFailures || flagged ? { type: "err" } : undefined);
      if (summary.succeededGroups) load();
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
      // 제외 대상도 함께 보낸다. 예전에는 직접 명령 모드에서만 제외가 조용히 버려져,
      // 폼에 제외를 입력한 뒤 모드를 바꾸면 제외 없이 스캔이 나갔다. 서버가 명령 안의
      // --exclude 와 합쳐 하나의 옵션으로 만든다.
      api("/scans/run-command", { method: "POST", json: { name, command: rawCmd, exclude: excludeList } })
        .then((s) => { toast(`직접 명령 스캔 시작됨 · #${s.id} (단발 실행 — 이어가기 미지원)`); load(); })
        .catch((e2) => toast(e2.message, { type: "err" }))
        .finally(() => setBusy(false));
      return;
    }
    if (!targetList.length) { toast("타겟을 입력하세요", { type: "err" }); return; }
    setBusy(true);
    const endpoint = staged ? "/scans/run-staged" : "/scans/run";
    // 실행 상한은 두 경로 모두에 있다. staged 분기에만 실으면 단계 스캔을 끈 사용자는
    // 화면에서 값을 정해 놓고도 그 값이 서버에 닿지 않는다.
    const watchdogSeconds = Math.max(0, Math.round(watchdogMin * 60));
    const body = staged
      ? { name, options: opt.options, ports: opt.ports, nse: opt.nse, targets: targetList, exclude: excludeList, exclude_ports: excludePorts, batch_size: batchSize, discovery, watchdog_seconds: watchdogSeconds }
      : { name, workflow: opt.workflow, options: opt.options, ports: opt.ports, nse: opt.nse, targets: targetList, exclude: excludeList, exclude_ports: excludePorts, batch_size: batchSize, watchdog_seconds: watchdogSeconds };
    api(endpoint, { method: "POST", json: body })
      .then((s) => { toast(`${staged ? "단계 " : ""}스캔 시작됨 · #${s.id} (백그라운드 — 진행은 아래 표)`); setTargets(""); setExclude(""); setName(""); load(); })
      .catch((e2) => toast(e2.message, { type: "err" }))
      .finally(() => setBusy(false));
  }

  function stopScan(id) {
    api(`/scans/${id}/stop`, { method: "POST" })
      .then(() => { toast(`#${id} 중지 요청 — 다음날 [이어하기]로 재개 가능`); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function deleteScan(scan) {
    // 되돌릴 수 없는 삭제라 무엇이 함께 지워지는지 먼저 말한다.
    const ok = window.confirm(
      `스캔 #${scan.id} "${scan.name || "이름 없음"}" 을 삭제할까요?\n\n`
      + "이 스캔에서만 발견된 항목은 발견 관리에서 함께 삭제됩니다.\n"
      + "다른 스캔에서도 관측된 발견은 남습니다. 되돌릴 수 없습니다.",
    );
    if (!ok) return;
    api(`/scans/${scan.id}`, { method: "DELETE" })
      .then((r) => {
        toast(`#${scan.id} 삭제됨 — 발견 ${r.findings_deleted}건 함께 삭제`);
        setExpanded((prev) => { const next = new Set(prev); next.delete(scan.id); return next; });
        load();
      })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function resumeScan(id) {
    api(`/scans/${id}/resume`, { method: "POST" })
      .then(() => { toast(`#${id} 이어가기 시작됨`); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  function retryTimeouts(scan) {
    setRetryingId(scan.id);
    api(`/scans/${scan.id}/retry-timeouts`, { method: "POST" })
      .then((next) => {
        toast(`#${scan.id} 확인 필요 ${scan.retry_count}대 재스캔 시작 · 새 스캔 #${next.id}`);
        load();
      })
      .catch((e) => toast(e.message, { type: "err" }))
      .finally(() => setRetryingId(null));
  }

  return (
    <div className="content">
      {canRun && (
        <div className="panel">
          {/* 화면을 열었을 때 보이는 것은 '대상 + 실행' 뿐이다. 나머지(실행 방식·제외·옵션·배치)는
              기본값으로 잘 도는 값이라 접어 두고, 바꾸고 싶을 때만 펼친다. 예전에는 체크박스 80여 개와
              명령 미리보기가 실행 버튼 앞을 가로막아 무엇을 해야 하는지 읽히지 않았다. */}
          <div className="scan-head">
            <h3 style={{ margin: 0 }}>스캔 실행</h3>
            <span className="muted">열린 포트를 찾아 무엇이 돌고 있는지 확인하고, 결과를 발견 관리로 넘깁니다.</span>
          </div>

          {!rawMode && (
            <label className="scan-target-field">
              <span className="cb-label">어디를 스캔할까요?</span>
              <textarea rows={2} value={targets} onChange={(e) => setTargets(e.target.value)}
                        placeholder="예: 10.0.12.0/24   10.0.13.5   10.0.14.1-30"
                        style={{ width: "100%", resize: "vertical" }} />
              <span className="muted scan-hint">IP·대역을 공백이나 줄바꿈으로 나열합니다.</span>
            </label>
          )}

          {rawMode && (
            <div className="scan-target-field">
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
              <span className="muted scan-hint">
                단발 실행입니다 — 이어하기는 안 됩니다. 셸 메타문자는 차단되고, 허용 대역(scope) 밖 IP 는 거절됩니다.
              </span>
            </div>
          )}

          {/* 지금 누르면 무슨 일이 일어나는지 한 줄로. nmap 플래그가 아니라 사람 말로 쓴다. */}
          <div className="scan-summary">
            <b>{planSummary.headline}</b>
            <span className="muted">{planSummary.detail}</span>
          </div>

          <div className="scan-run-row">
            <button className="primary scan-run"
                    disabled={busy || (rawMode ? !rawCmd.trim() : !targetList.length)}
                    onClick={runScan}
                    title={rawMode ? "명령을 입력하면 실행할 수 있습니다" : "대상을 입력하면 실행할 수 있습니다"}>
              {busy ? "시작 중…" : "스캔 실행"}
            </button>
            <button type="button" className="sm" aria-expanded={showAdvanced}
                    onClick={() => setShowAdvanced((v) => !v)}>
              {showAdvanced ? "세부 설정 접기" : "세부 설정"}
            </button>
            <span className="muted" style={{ fontSize: 12 }}>
              백그라운드로 돕니다. 진행은 아래 [스캔 이력]에서 보고, 중지·이어하기 할 수 있습니다.
            </span>
          </div>

          {/* ── 세부 설정 (기본 접힘) ── */}
          <div className="scan-advanced" style={{ display: showAdvanced ? "block" : "none" }}>
            <section className="scan-step">
              <div className="cb-label">실행 방식</div>
              <div className="scan-mode-cards">
                {SCAN_MODES.map((mode) => (
                  <button key={mode.id} type="button" aria-pressed={mode.on(staged, rawMode)}
                          onClick={() => mode.pick({ setStaged, setRawMode, setRawEdited })}
                          className={"scan-mode-card" + (mode.on(staged, rawMode) ? " on" : "")}>
                    <b>{mode.title}</b>
                    <small>{mode.desc}</small>
                  </button>
                ))}
              </div>
            </section>

            <section className="scan-step">
              <label className="cb-label" htmlFor="scan-name">이름 (선택)</label>
              <input id="scan-name" placeholder="이력에서 알아보기 쉽게" value={name}
                     onChange={(e) => setName(e.target.value)} style={{ width: "100%" }} />
            </section>

            <section className="scan-step">
              <label className="cb-label" htmlFor="scan-exclude">제외할 IPv4/CIDR/범위 (선택)</label>
              <textarea id="scan-exclude" aria-describedby="scan-exclude-help" rows={2}
                        style={{ width: "100%", resize: "vertical" }}
                        placeholder="예: 10.0.12.1, 10.0.13.0/28, 10.0.12.20-30"
                        value={exclude} onChange={(e) => setExclude(e.target.value)} />
              <div id="scan-exclude-help" className="muted scan-hint">
                공백·쉼표·줄바꿈으로 구분합니다. 제외 대상은 스캔과 닫힘 판정 범위에서 빠집니다.
                {rawMode && " 직접 명령의 --exclude 와 합쳐 하나의 옵션으로 전달됩니다."}
              </div>

              <label className="cb-label" htmlFor="scan-exclude-ports" style={{ marginTop: 12 }}>
                제외할 포트 (선택)
              </label>
              <input id="scan-exclude-ports" aria-describedby="scan-exclude-ports-help"
                     style={{ width: "100%" }} placeholder="예: 9100, 515, 631"
                     value={excludePorts} onChange={(e) => setExcludePorts(e.target.value)} />
              <div id="scan-exclude-ports-help" className="muted scan-hint">
                포트 지정과 같은 문법입니다(<code>9100</code>, <code>1-1024</code>,
                {" "}<code>U:53</code>). 프린터 같은 장비가 스캔에 반응해 문제를 일으키는 포트를 뺄 때
                씁니다.{" "}
                실행되는 모든 nmap 명령에서 빠집니다 — 단계별 정밀 스캔도 발견·TCP·UDP·서비스
                네 단계 전부에 적용됩니다.
              </div>
            </section>

            {/* 옵션 빌더는 raw 모드에서도 마운트 유지(숨김만) — opt.command 가 최신이라 '채우기'가 정확하게 동작 */}
            <div style={{ display: rawMode ? "none" : "block" }}>
              <ScanOptions targets={targetList} excludes={previewExcludes} excludePorts={excludePorts} staged={staged}
                           discovery={discovery} onState={setOpt} />

              <section className="scan-step" style={{ marginTop: 14 }}>
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <span className="cb-label">배치 크기 — 중지·이어가기 단위</span>
                  <span className="mono">{batchSize} 호스트 / 배치</span>
                </div>
                <input type="range" min={16} max={1024} step={16} value={batchSize}
                       onChange={(e) => setBatchSize(Number(e.target.value))} style={{ width: "100%" }} />
                <div className="muted scan-hint">넓은 대역을 이만큼씩 쪼개 스캔합니다.</div>
              </section>

              {/* 실행 상한은 단계 스캔과 한 번에 실행 양쪽에 모두 적용된다 — staged 안에
                  넣어 두면 단계 스캔을 끈 사용자가 값을 정할 방법이 없다. */}
              <section className="scan-step">
                <div className="row" style={{ justifyContent: "space-between" }}>
                  <span className="cb-label">실행 상한 — nmap 프로세스 하나당</span>
                  <span className="mono">{watchdogMin ? `${watchdogMin}분` : "없음"}</span>
                </div>
                <input type="range" min={0} max={240} step={10} value={watchdogMin}
                       onChange={(e) => setWatchdogMin(Number(e.target.value))} style={{ width: "100%" }} />
                <div className="muted scan-hint">
                  기본은 <b>없음</b>입니다. 전 포트 스캔이 정상적으로 몇 시간 걸리는 망도 있어서,
                  섣부른 값은 느린 망을 실패로 바꿉니다.
                </div>
                {/* 화면이 약속하는 것과 실제로 일어나는 일이 어긋나면 안 된다. 두 가지가
                    각각 다르다 — (1) 산출물 파일에 관측이 보존되는 것과 그 관측이 ScanOps 에
                    인입되는 것, (2) 파일이 존재하는 것과 이 화면을 보는 사람이 그 파일에
                    닿을 수 있는 것. 산출물은 **스캔 서버의 파일시스템**에 있고 웹에는
                    내려받는 경로가 없으므로, 원격 접속한 사용자는 [가져오기]로 그 폴더를
                    고를 수 없다. 실행할 수 없는 절차를 안내하지 않는다. */}
                {watchdogMin > 0 && (
                  <div className="muted scan-hint">
                    <b>주의:</b> 상한에 걸린 실행은 <b>실패로 마감</b>되고, <b>발견으로 인입되지
                    않습니다</b>. 그때까지 끝난 호스트의 관측은 스캔 서버에 XML 로만 남습니다
                    (닫힘 판정 권한은 얻지 못합니다). 웹에서 내려받는 경로는 없으므로
                    {" "}<b>스캔 서버에 직접 접근할 수 있는 관리자만</b> 그 파일을 꺼낼 수 있습니다.
                    {/* 두 실행 방식은 산출물을 **다른 모양**으로 남긴다. 단계 엔진만
                        out_dir = scans_dir/scan_<id> 를 mkdir 하고 그 안에 넣는다. 레거시는
                        같은 문자열을 **파일 접두사**로 써서(_basename + ".b0" + ".<stage>")
                        data/scans/ 바로 아래에 흩어 놓는다. 한쪽 규칙을 공통이라고 적으면
                        나머지 한쪽은 없는 폴더를 열게 된다. */}
                    {staged ? (
                      <> 결과 폴더는 <code>data/scans/scan_&lt;스캔번호&gt;/</code> 이고,
                      절대경로는 [상세] → [실제 실행 명령]의 <code>-oA</code> 인자에도 있습니다.</>
                    ) : (
                      <> 파일은 <code>data/scans/</code> 바로 아래에
                      {" "}<code>scan_&lt;스캔번호&gt;.b&lt;배치&gt;.&lt;단계&gt;.xml</code> 이름으로
                      흩어져 있습니다(한 번에 실행은 스캔별 폴더를 만들지 않습니다).</>
                    )}
                    {" "}켜기 전에 [중지] 버튼으로 충분한지 먼저 검토하시기 바랍니다.
                  </div>
                )}
              </section>

              {staged && (
                <section className="scan-step">
                  <span className="cb-label">발견 단계</span>
                  <select value={discovery} onChange={(e) => setDiscovery(e.target.value)}>
                    <option value="sn">핑 스윕 (-sn)</option>
                    <option value="pn">생략 (-Pn · ICMP 차단망)</option>
                  </select>
                  <div className="muted scan-hint">
                    ICMP 를 막는 망이면 '생략'을 고릅니다. 대신 죽은 IP 도 전부 스캔해 느려집니다.
                  </div>
                </section>
              )}
            </div>
          </div>

          {/* 가져오기는 '스캔한다'와 다른 작업이다 — 실행 버튼 옆이 아니라 따로 둔다. */}
          <div className="scan-import-row">
            <span className="muted">이미 스캔한 결과가 있나요?</span>
            <button ref={fileButtonRef} type="button" className="sm" disabled={busy}
                    onClick={() => openImport(fileInputRef, fileButtonRef)}>
              XML 가져오기
            </button>
            <button ref={folderButtonRef} type="button" className="sm" disabled={busy}
                    onClick={() => openImport(folderInputRef, folderButtonRef)}>
              폴더째 가져오기
            </button>
            <input ref={fileInputRef} type="file" accept=".xml,.manifest.json" multiple hidden tabIndex={-1}
                   disabled={busy} onChange={onImport} onCancel={restoreImportFocus} />
            <input ref={folderInputRef} type="file" hidden tabIndex={-1}
                   disabled={busy} onChange={onImport} onCancel={restoreImportFocus} />
            <span className="muted" style={{ fontSize: 11.5 }}>
              단독 스캐너 결과 폴더를 그대로 고르면 manifest 까지 함께 읽습니다.
            </span>
          </div>
        </div>
      )}

      <div className="panel">
        <h3>스캔 이력</h3>
        <div className="scan-history-scroll">
          <table className="tbl scan-history-table">
            <colgroup>
              <col className="scan-history-col-id" />
              <col className="scan-history-col-name" />
              <col className="scan-history-col-scope" />
              <col className="scan-history-col-status" />
              <col className="scan-history-col-progress" />
              <col className="scan-history-col-count" />
              <col className="scan-history-col-count" />
              <col className="scan-history-col-actions" />
            </colgroup>
            <thead><tr>
              <th>ID</th><th>이름</th><th>스캔 범위</th><th>상태</th>
              <th>진행</th><th>호스트</th><th>포트</th><th>작업</th>
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
                    <td className="scan-history-name">{s.name}<div><span className="tag">{kind.label}</span></div>
                      <div className="muted scan-created-by">실행자 · {s.created_by_name || (s.created_by ? `사용자 #${s.created_by}` : "—")}</div>
                    </td>
                    <td><ScanScope summary={s.summary} /></td>
                    <td>
                      <span className={`pill ${st.cls}`}>{st.label}</span>
                      <RetryBadge scan={s} />
                      <QualityBadge scan={s} />
                      {s.failure_message && <div className="scan-failure">{s.failure_message}</div>}
                    </td>
                    <td>
                      {stages[s.id]?.stages?.length
                        ? <StageTimeline s={stages[s.id]} />
                        : isActive(s.status) ? <Progress p={p} /> : null}
                      {/* StageTimeline 은 단계 칩·전체 % 막대만 그린다 — 배치 x/y·경과는 Progress 에만
                          있어 진행 중 단계 스캔에서 사라졌다. /progress 는 엔진 스캔에도 배치·경과를
                          채워 주므로(배치는 swept_batches) 그걸 StageTimeline 아래에 되살린다. */}
                      {stages[s.id]?.stages?.length && isActive(s.status)
                        ? <StagedRunMeta p={p} /> : null}
                      {/* 배치 구성은 끝난 뒤에도 '이 스캔이 어떻게 돌았는지'를 말해 준다. */}
                      <BatchNote scan={s} progress={isActive(s.status) ? p : null} />
                      <div className="scan-total-time mono">
                        총 {fmtDur(scanDuration(s, isActive(s.status) ? p : null))}
                      </div>
                      {!stages[s.id]?.stages?.length && !isActive(s.status) && !s.batch_total
                        ? <span className="muted">—</span> : null}
                    </td>
                    <td className="mono">{s.host_count}</td>
                    <td className="mono">{s.port_count}</td>
                    <td className="scan-history-actions-cell">
                      <div className="scan-history-actions">
                      {canRun && isActive(s.status) && (
                        <button className="sm" onClick={() => stopScan(s.id)} disabled={s.status === "canceling"}>중지</button>
                      )}
                      {canRun && canResume(s.status) && (
                        <button className="sm" onClick={() => resumeScan(s.id)}>이어하기</button>
                      )}
                      {canRun && s.retry_required && !isActive(s.status) && (
                        <button className="sm retry" onClick={() => retryTimeouts(s)}
                                disabled={retryingId === s.id}>
                          {retryingId === s.id ? "재스캔 준비 중" : `${s.retry_count}대 재스캔`}
                        </button>
                      )}
                      <button className="sm" aria-expanded={expanded.has(s.id)}
                              aria-controls={`scan-detail-${s.id}`} onClick={() => toggleDetails(s)}>
                        {expanded.has(s.id) ? "상세 닫기" : "상세"}
                      </button>
                      {canDelete && !isActive(s.status) && (
                        <button className="sm danger" onClick={() => deleteScan(s)}>삭제</button>
                      )}
                      </div>
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

function RetryBadge({ scan }) {
  const status = scan.retry_status;
  if (status === "required") {
    return <span className="pill retry-required">재스캔 필요 · {scan.retry_count}대</span>;
  }
  if (status === "running") {
    return <span className="pill retry-running">재스캔 진행 중 · #{scan.retry_scan_id}</span>;
  }
  if (status === "resolved") {
    return <span className="pill retry-resolved">재스캔 완료 · #{scan.retry_scan_id}</span>;
  }
  if (status === "failed") {
    return <span className="pill retry-required">재스캔 실패 · 다시 확인</span>;
  }
  return null;
}

function QualityBadge({ scan }) {
  const count = scan.unresolved_issue_count || 0;
  if (!count || scan.retry_status === "required") return null;
  const label = scan.quality_status === "error" ? "품질 오류" : "확인 필요";
  return <span className="pill retry-required">{label} · {count}건</span>;
}

// 이력 표의 '스캔 범위' — 명령줄 대신 어디를·어떤 포트를·무슨 프로토콜로 봤는지만.
// 원문 명령은 [상세]에 그대로 남는다(필요한 사람은 거기서 본다).
function ScanScope({ summary }) {
  if (!summary) return <span className="muted">—</span>;
  // 프로토콜을 모르면 뱃지를 달지 않는다. 예전에는 명령 표기가 argv 가 아니면 무조건
  // 'TCP · 기본 1000개' 로 그려서, 전 포트 TCP+UDP 단계 스캔이 상위 1000개 TCP 스캔으로
  // 보였다 - 스캔하지 않은 범위를 봤다고 말하고 실제 범위는 감추는 이중 오류였다.
  const unknown = !(summary.protocols || []).length;
  const excludedPorts = Boolean(summary.excluded_ports);
  return (
    <div className="scan-scope">
      <div className="scan-scope-target">{summary.targets}</div>
      <div className="scan-scope-line">
        <span className={`scan-scope-ports${excludedPorts ? " is-partial" : ""}${unknown ? " is-unknown" : ""}`}
              title={unknown ? "이 실행의 명령 표기에 스캔 범위가 남아 있지 않습니다 (이 기능 이전에 실행된 스캔)" : undefined}>
          {formatScanPortScope(summary)}
        </span>
      </div>
      {summary.excluded_hosts && (
        <div className="scan-scope-excluded">
          대상 제외 <code>{summary.excluded_hosts}</code>
        </div>
      )}
    </div>
  );
}

// 진행률 막대 — 전체 진행(배치 누적)을 막대로, 배치 카운트 + 현재 배치 ETC/경과를 보조로.
// 배치 구성 한 줄 — 실행 중이면 Progress 가 x/y 를 이미 그리므로 크기만, 끝난 뒤에는 둘 다.
function BatchNote({ scan, progress }) {
  if (!scan.batch_total || scan.batch_total <= 1) return null;
  if (progress) {
    return progress.batch_size ? null : (
      <div className="mono muted" style={{ fontSize: 11 }}>{scan.batch_size}대씩</div>
    );
  }
  return (
    <div className="mono muted" style={{ fontSize: 11, marginTop: 2 }}>
      배치 {scan.batch_total}/{scan.batch_total} · {scan.batch_size}대씩
    </div>
  );
}

// 단계 스캔 보조줄 — StageTimeline 은 단계 칩만 그리므로, /progress 가 엔진 스캔에도 채워 주는
// 배치 x/y·크기·경과를 여기서 되살린다. ETA·대상수는 엔진 스캔에서 백엔드가 아직 비워 주므로
// (sidecar 의존) 지어내지 않는다 — 있는 값만 정직하게 보여준다.
function StagedRunMeta({ p }) {
  if (!p) return null;
  const total = p.batches_total || 1;
  const parts = [];
  // done+1 을 '현재 배치'로 쓰면 없는 배치를 진행 중이라고 말한다 - sweep 이 다 끝나고 서비스
  // 단계가 도는 중에도 다음 배치를 가리키고, 프로토콜별 최솟값이라 TCP 만 도는 동안에는 0 이다.
  // 센 것만 정직하게 적는다: 끝난 배치 수.
  if (total > 1) parts.push(`배치 ${Math.min(p.batches_done, total)}/${total} 완료`);
  if (total > 1 && p.batch_size) parts.push(`${p.batch_size}대씩`);
  if (p.elapsed_seconds != null) parts.push(`경과 ${fmtDur(p.elapsed_seconds)}`);
  if (!parts.length) return null;
  return (
    <div className="mono" style={{ fontSize: 11, color: "var(--muted)", marginTop: 3 }}>
      {parts.join(" · ")}
    </div>
  );
}

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
        {total > 1 ? ` · 배치 ${Math.min(p.batches_done + 1, total)}/${total}` : ""}
        {total > 1 && p.batch_size ? ` (${p.batch_size}대씩)` : ""}
        {p.eta_seconds != null ? ` · ~남음 ${fmtDur(p.eta_seconds)}` : (p.remaining ? ` · 남음 ${p.remaining}` : "")}
        {p.elapsed_seconds != null ? ` · 경과 ${fmtDur(p.elapsed_seconds)}` : (p.elapsed ? ` · 경과 ${p.elapsed}` : "")}
      </div>
      {/* 퍼센트 하나만 보이면 몇 분째 같은 숫자를 보면서 진행 중인지 멈춘 것인지 알 수 없다.
          지금 어느 대역의 어느 단계를 보고 있는지가 그 답이다. */}
      {(p.stage || p.batch_label) && (
        <div style={{ fontSize: 11, marginTop: 3, display: "flex", gap: 5, flexWrap: "wrap", alignItems: "center" }}>
          {p.stage && <span className="pill info" style={{ fontSize: 10.5 }}>{STAGE_LABEL[p.stage] || p.stage}</span>}
          {p.batch_label && <span className="mono muted">{p.batch_label}</span>}
          {p.stage_hosts ? <span className="muted">· 대상 {p.stage_hosts}대</span> : null}
          {p.hosts_up != null ? <span className="muted">· 응답 {p.hosts_up}대</span> : null}
        </div>
      )}
    </div>
  );
}

// 단계 타임라인 — 단계분리 엔진 스캔의 발견/TCP/UDP/서비스 진행을 색 칩으로(이벤트 기반).
// 엔진 단계(discovery/tcp/udp/service)와 자동 스캔·가져오기 단계(tcp_discovery/…)를 한 표에서
// 함께 그린다. 가져온 결과라고 해서 이름을 다르게 부를 이유가 없다.
const STAGE_LABEL = {
  discovery: "호스트 발견",
  tcp: "TCP 포트 발견", tcp_service: "TCP 서비스 프로브",
  udp: "UDP 포트 발견", udp_service: "UDP 서비스 프로브",
  service: "서비스 프로브",
  tcp_discovery: "TCP 포트 발견", tcp_identify: "TCP 서비스 프로브",
  udp_identify: "UDP 서비스 프로브",
};
const STAGE_CLS = {
  pending: "stage-pending", running: "stage-running", done: "stage-done",
  warning: "stage-warning", stopped: "stage-stopped", error: "stage-warning",
};

function stageLabel(stage) {
  const key = stage.stage || stage.name;
  return STAGE_LABEL[key] || key || "단계";
}

function currentHosts(current) {
  const hosts = current?.hosts || [];
  if (!hosts.length) return "";
  const shown = hosts.slice(0, 3);
  const total = Math.max(current.current_host_count || hosts.length, hosts.length);
  const rest = total - shown.length;
  return `${shown.join(", ")}${rest > 0 ? ` 외 ${rest}대` : ""}`;
}

function StageTimeline({ s }) {
  const list = s?.stages || [];
  if (!list.length) return <span className="muted">…</span>;
  const overall = s.overall?.percent;
  const current = s.current || {};
  const known = overall != null;
  return (
    <div className="stage-timeline">
      <div role="progressbar" aria-label="전체 절차 완료율" aria-valuemin="0" aria-valuemax="100"
           aria-valuenow={known ? Math.round(overall) : undefined} className="scan-procedure-progress">
        <div className="scan-procedure-progress-fill"
             style={{ width: known ? `${Math.min(overall, 100)}%` : "12%", opacity: known ? 1 : 0.45 }} />
        <span>{known ? `절차 ${Math.round(overall)}%` : "절차 준비 중"}</span>
      </div>
      <div className="stage-status-list">
        {list.map((st, index) => {
          // 응답한 호스트가 없어 돌 것이 없던 단계다. '완료' 로 부르면 훑고 온 단계와
          // 구분되지 않는다 - 돈 것과 돌 것이 없던 것은 다른 사실이다.
          const extra = st.counts?.skipped ? " 생략"
            : st.status === "running" ? ` ${Math.round(st.percent || 0)}%`
            : st.status === "done" ? " 완료"
            : st.status === "warning" ? " 확인 필요"
            : st.status === "stopped" ? " 중지"
            : st.status === "error" ? " 오류" : " 대기";
          const issueText = (st.issues || []).map((issue) => issue.message).join(" ");
          const serviceResults = st.counts?.result_endpoints ?? st.counts?.services;
          return (
            <span key={`${st.stage || st.name || "stage"}-${index}`}
                  className={`stage-status ${STAGE_CLS[st.status] || "stage-pending"}`}
                  title={issueText || st.error || ""}>
              <span>{stageLabel(st)}{extra}</span>
              {serviceResults != null && <small>프로브 결과 {serviceResults}개 endpoint</small>}
              {st.seconds != null && <small>{fmtDur(st.seconds)}</small>}
            </span>
          );
        })}
      </div>
      {current.stage && (
        <div style={{ fontSize: 11, marginTop: 5, lineHeight: 1.55, whiteSpace: "normal" }}>
          <span className="pill info" style={{ fontSize: 10.5 }}>진행 중</span>{" "}
          <b>{STAGE_LABEL[current.stage] || current.stage}</b>
          {current.batch_total ? <span className="mono muted"> · 배치 {current.batch}/{current.batch_total}</span> : null}
          {currentHosts(current) ? <div className="mono">현재 대상 · {currentHosts(current)}</div> : null}
          {current.total_hosts != null ? (
            <div className="muted">이 배치의 서비스 프로브 · {current.completed_hosts || 0}/{current.total_hosts}대 완료</div>
          ) : null}
        </div>
      )}
      {list.filter((stage) => stage.error || stage.issues?.length).map((stage, index) => (
        <div key={`${stage.stage || stage.name || "stage"}-error-${index}`} className="stage-problem-hint">
          {stageLabel(stage)} · 상세에서 원인 확인
        </div>
      ))}
    </div>
  );
}

function ScanDetails({ scan, detail }) {
  const kind = detail?.kind === "staged" ? "단계 엔진" : scanKind(scan).label;
  const executions = detail?.executions || [];
  const legacyIssues = (detail?.stages || []).flatMap((stage) =>
    (stage.issues || []).map((issue) => ({ ...issue, stage: issue.stage || stage.stage || stage.name })));
  const issues = detail?.issues?.length ? detail.issues : legacyIssues;
  const recoveries = detail?.recoveries || (detail?.stages || []).flatMap((stage) => stage.recoveries || []);
  const totalSeconds = detail?.overall?.seconds ?? scanDuration(scan, null);
  const notice = scanNotice({
    failure_message: detail?.failure_message || scan.failure_message,
    failure_code: detail?.failure_code || scan.failure_code,
  });
  return (
    <div className="scan-detail">
      <div className="scan-detail-overview">
        <div><small>실행 유형</small><b>{kind}</b></div>
        <div><small>상태</small><b>{scanStatus(detail?.status || scan.status).label}</b></div>
        <div><small>실행자</small><b>{scan.created_by_name || (scan.created_by ? `사용자 #${scan.created_by}` : "—")}</b></div>
        <div><small>총 소요시간</small><b className="mono">{fmtDur(totalSeconds)}</b></div>
        <div><small>문제 기록</small><b className="mono">{issues.length}건</b></div>
        <div><small>Nmap 실행</small><b className="mono">{executions.length}회</b></div>
      </div>
      {detail?.stages?.length
        ? <StageTimeline s={detail} />
        : <div className="muted">{detail?.timeline_available === false ? "저장된 단계 이벤트가 없습니다." : "단계 정보를 불러오는 중…"}</div>}
      {notice && (
        <div className={`scan-failure-detail ${notice.tone}`}>
          <b>{notice.title}</b> {notice.message}
          {notice.code && <code>{notice.code}</code>}
        </div>
      )}
      {!!detail?.gave_up?.length && (
        <RetryQueue retry={detail.retry} />
      )}
      <StageRecoveries recoveries={recoveries} />
      <StageIssueDetails issues={issues} />
      {scan.command && (
        <div className="scan-detail-command">
          <b>실행 계획</b>
          <code className="mono">{scan.command}</code>
        </div>
      )}
      {/* 지연 진단은 평소에 접어 둔다 — 필요할 때만 펼쳐 보는 정보다. */}
      <ScanTrace trace={detail?.trace} />
      <ExecutionGroups executions={executions} />
    </div>
  );
}

function RetryQueue({ retry }) {
  const byStage = retry?.by_stage || {};
  const reasons = retry?.reasons_by_stage || {};
  const reasonLabel = (reason) => reason === "host_timeout" ? "호스트 시간 초과"
    : reason === "retransmission_cap" ? "포트 재전송 한도 도달" : reason;
  return (
    <div className="scan-failure-detail retry-queue">
      <div className="retry-queue-head">
        <b>재스캔 대기열</b>
        <span className="pill retry-required">{retry?.count || 0}대</span>
      </div>
      <p>완료된 결과와 섞지 않고 보존했습니다. 이력의 <b>재스캔</b> 버튼은 이 대상만 새 스캔으로 실행합니다.</p>
      {Object.entries(byStage).map(([stage, hosts]) => (
        <details key={stage}>
          <summary>{STAGE_LABEL[stage.replace("service:", "") + (stage.startsWith("service:") ? "_service" : "")] || STAGE_LABEL[stage] || stage} · {hosts.length}대</summary>
          {hosts.map((host) => (
            <div className="retry-host" key={host}>
              <code className="mono">{host}</code>
              <span>{(reasons?.[stage]?.[host] || []).map(reasonLabel).join(" · ")}</span>
            </div>
          ))}
        </details>
      ))}
    </div>
  );
}

function issueLabel(type) {
  if (type === "host_timeout") return "호스트 시간 초과";
  if (type === "retransmission_cap") return "포트 재전송 한도 도달";
  if (type === "service_degraded") return "서비스 프로브 결과 저하";
  return "Nmap 실행 오류";
}

function StageRecoveries({ recoveries }) {
  if (!recoveries.length) return null;
  return (
    <section className="scan-detail-section">
      <h4>복구 시도</h4>
      <p className="muted">실패 범위를 줄이기 위해 대체 엔진 재시도 또는 개별 격리를 수행한 기록입니다. 미해결 문제와는 구분됩니다.</p>
      {/* 서버(engine_runner.parse_events)가 `type: "split" | "retry"` 와 `hosts` 배열로
          정규화해 준다. 옛 이벤트 이름(`service_split`)이나 단수 `host` 를 보면 포트 분할
          복구가 전부 '대체 엔진 재시도' 로 표기되고, 어느 호스트에서 무엇이 돌았는지가
          증거에서 통째로 빠진다. */}
      {recoveries.map((recovery, index) => {
        const hosts = recovery.hosts?.length
          ? recovery.hosts
          : [recovery.host || recovery.ip].filter(Boolean);
        return (
          <div className="stage-recovery" key={`${recovery.type || "recovery"}-${hosts[0] || index}-${index}`}>
            <b>{recovery.type === "split" ? "개별·격리 실행" : "대체 엔진 재시도"}</b>
            <span>{STAGE_LABEL[recovery.stage] || recovery.stage || "서비스 프로브"}</span>
            <code className="mono">
              {[hosts.join(", "), recovery.proto,
                recovery.port_spec || recovery.ports?.join(",")].filter(Boolean).join(" · ")}
            </code>
          </div>
        );
      })}
    </section>
  );
}

function StageIssueDetails({ issues }) {
  if (!issues.length) return null;
  return (
    <section className="scan-detail-section">
      <h4>단계별 문제</h4>
      {issues.map((issue, index) => {
        const resolved = issue.status === "resolved";
        const hosts = issue.hosts?.length ? issue.hosts : issue.host ? [issue.host] : [];
        return (
          <div className={`stage-issue-card${resolved ? " issue-resolved" : ""}`} key={issue.issue_key || `${issue.type}-${index}`}>
            <div>
              <b>{STAGE_LABEL[issue.stage] || issue.stage || "스캔"}</b>
              <span>{resolved ? `재스캔으로 해결${issue.resolved_by_scan_id ? ` · #${issue.resolved_by_scan_id}` : ""}` : "일부 결과 확인 필요"}</span>
            </div>
            <div className="stage-issue">
              <b>{issueLabel(issue.type)}</b>
              <span>{issue.message}</span>
              {!!hosts.length && <code className="mono">{hosts.join(", ")}</code>}
              {(issue.proto || issue.port_spec) && (
                <code className="mono">{[issue.proto, issue.port_spec].filter(Boolean).join(" · ")}</code>
              )}
            </div>
          </div>
        );
      })}
    </section>
  );
}

function ExecutionGroups({ executions }) {
  const hasRunning = executions.some((execution) => execution.status === "running");
  const snapshotAt = useRef(Date.now());
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const receivedAt = Date.now();
    snapshotAt.current = receivedAt;
    setNow(receivedAt);
  }, [executions]);
  useEffect(() => {
    if (!hasRunning) return undefined;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [hasRunning]);
  if (!executions.length) return (
    <div className="scan-detail-section muted">이 기능 적용 이전 실행이라 개별 Nmap 명령 기록이 없습니다.</div>
  );
  const groups = [
    ["common", "공통·배치 실행", "같은 포트나 배치 범위를 공유해 Nmap 자체 병렬 처리를 사용한 명령입니다."],
    ["individual", "개별·격리 실행", "실패 범위를 격리하거나 특정 호스트·포트만 다시 확인한 명령입니다."],
  ];
  return (
    <section className="scan-detail-section command-evidence">
      <h4>실제 실행 명령</h4>
      {groups.map(([key, title, description]) => {
        const items = executions.filter((execution) => execution.group === key);
        if (!items.length) return null;
        return (
          <details key={key} className="command-group" open={key === "common"}>
            <summary><b>{title}</b><span>{items.length}회</span></summary>
            <p>{description}</p>
            <div className="command-list">
              {items.map((execution, index) => {
                const liveSeconds = execution.status === "running" && Number.isFinite(execution.seconds)
                  ? execution.seconds + Math.max(0, now - snapshotAt.current) / 1000
                  : null;
                return <div className={`command-record command-${execution.status}`} key={execution.id || index}>
                  <div className="command-record-head">
                    <b>{STAGE_LABEL[execution.stage] || execution.stage}</b>
                    <span className="mono">{execution.status === "running"
                      ? `경과 ${fmtElapsed(liveSeconds)}` : fmtDur(execution.seconds)}</span>
                    <span>{execution.interrupted ? "기록 없이 종료"
                      : execution.status === "running" ? "실행 중"
                      /* 워치독은 우리가 프로세스 상한으로 끊은 것이다. nmap 이 죽은 것과
                         구분해야 사용자가 할 일이 갈린다 — 상한을 늘릴지, 대상을 줄일지. */
                      : execution.status === "watchdog"
                        ? `실행 상한 초과 (${fmtDur(execution.watchdog_seconds)})`
                      : execution.status === "timeout" ? `시간 초과 ${execution.timeout_count}대`
                      : execution.retransmission_cap_count ? `재전송 한도 ${execution.retransmission_cap_count}대`
                      : execution.status === "error" ? `오류 · rc ${execution.rc}`
                      : execution.status === "stopped" ? "중지됨" : "완료"}</span>
                  </div>
                  <p>{execution.reason}</p>
                  <code className="mono">{formatArgv(execution.argv)}</code>
                  {!!execution.timed_out?.length && <small className="mono">시간 초과: {execution.timed_out.join(", ")}</small>}
                  {!!execution.retransmission_cap_hosts?.length && (
                    <small className="mono">재전송 한도 도달: {execution.retransmission_cap_hosts.join(", ")}</small>
                  )}
                </div>;
              })}
            </div>
          </details>
        );
      })}
    </section>
  );
}
