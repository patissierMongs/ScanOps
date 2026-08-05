import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

const PRESET_KEY = "scanops_scan_presets";
const RESCAN_OPTION_KEYS = new Set(["version_all", "version_light"]);
const loadPresets = () => { try { return JSON.parse(localStorage.getItem(PRESET_KEY)) || []; } catch { return []; } };

const PRECISION_OPTS = ["noping", "dns_no", "syn", "fast", "version", "version_all",
  "max_retries", "open_only", "reason", "defeat_rst", "min_hostgroup", "max_parallel", "udp"];

const TIMING_KEYS = [
  ["t0", "-T0"], ["t1", "-T1"], ["t2", "-T2"], ["t3", "-T3"],
  ["fast", "-T4"], ["t5", "-T5"],
];

function normalizeSelections(keys) {
  const next = new Set(keys || []);
  if (next.has("connect")) {
    next.delete("syn");
    next.delete("udp");
    next.delete("defeat_rst");
  } else {
    // 단계 엔진은 TCP 방식 미지정도 SYN으로 해석하므로 UI도 같은 상태를 보여준다.
    next.add("syn");
  }
  const selectedTiming = TIMING_KEYS.find(([key]) => next.has(key))?.[0];
  TIMING_KEYS.forEach(([key]) => next.delete(key));
  if (selectedTiming) next.add(selectedTiming);
  return next;
}

function protocolPorts(spec, proto) {
  let current = "";
  const out = [];
  (spec || "").replace(/\s+/g, "").split(",").forEach((raw) => {
    if (!raw) return;
    let item = raw;
    const parts = raw.split(":");
    if (parts.length === 2 && ["T", "U"].includes(parts[0].toUpperCase())) {
      current = parts[0].toUpperCase();
      item = parts[1];
    }
    if (!item) return;
    if (!current && proto === "T") out.push(item);
    if (current === proto) out.push(item);
  });
  return out.join(",");
}

function autoPortSpecs(ports, udpPorts) {
  const spec = (ports || "").trim();
  if (!spec) return { tcp: "T:1-65535", udp: udpPorts ? `U:${udpPorts}` : "" };
  const tcp = protocolPorts(spec, "T");
  const udp = protocolPorts(spec, "U");
  return { tcp, udp: udp ? `U:${udp}` : "" };
}

function tcpOnlyPortSpec(spec) {
  const tcp = protocolPorts(spec, "T");
  return `T:${tcp || "1-65535"}`;
}

function hasExplicitUdpPorts(spec) {
  return Boolean(protocolPorts(spec, "U"));
}

function commandText(parts) {
  return parts.filter(Boolean).join(" ");
}

// 발견 단계 host-discovery probe — 백엔드 nmap_runner.DISCOVERY_PS/PA 와 동일하게 유지(미리보기 정확도).
const DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080";
const DISCOVERY_PA = "-PA80,443,3389";

export default function ScanOptions({
  targets = [], excludes = [], portsAuto = "", staged = false, discovery = "sn", fixedTargetPorts = false, onState,
}) {
  const [workflow, setWorkflow] = useState("auto");
  const [registry, setRegistry] = useState([]);
  const [sel, setSel] = useState(() => new Set());
  const [ports, setPorts] = useState("");
  const [nseReg, setNseReg] = useState([]);
  const [nseSel, setNseSel] = useState(() => new Set());
  const [nseDefault, setNseDefault] = useState([]);
  const [udpPorts, setUdpPorts] = useState("");
  const [showManualOptions, setShowManualOptions] = useState(false);
  const [showNse, setShowNse] = useState(false);
  const [presets, setPresets] = useState(loadPresets);
  const [presetId, setPresetId] = useState("");
  const [touchedPorts, setTouchedPorts] = useState(false);

  useEffect(() => {
    let live = true;
    api("/scans/options")
      .then((r) => {
        if (!live) return;
        setRegistry(r.options || []);
        setSel(normalizeSelections(r.default || []));
        setNseReg(r.nse || []);
        setNseDefault(r.nse_default || []);
        setNseSel(new Set(r.nse_default || []));
        setUdpPorts(r.udp_default_ports || "");
        if (!touchedPorts) setPorts(r.default_ports || "");
      })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const selectedScripts = useMemo(
    () => nseReg.filter((s) => nseSel.has(s.key)).map((s) => s.key),
    [nseReg, nseSel]
  );
  // Nmap 7.99는 반복 --exclude를 누적하지 않으므로 항상 단일 comma-list로 표시한다.
  const excludeArgs = useMemo(
    () => excludes.length ? ["--exclude", excludes.join(",")] : [],
    [excludes]
  );

  // 단계 분리(staged) 또는 자동 스캔이면 한 번에 안 돌고 단계별로 나눠 순차 실행된다.
  const stepped = staged || workflow === "auto";

  // 분산 실행되는 각 단계 명령 — staged 엔진과 legacy 자동 워크플로를 각각 그대로 설명한다.
  const steps = useMemo(() => {
    const p = (ports || portsAuto).trim();
    const { tcp, udp } = autoPortSpecs(p, udpPorts);
    const scriptsFor = (proto) => nseReg
      .filter((script) => nseSel.has(script.key) && [proto, "both"].includes(script.proto || "both"))
      .map((script) => script.key)
      .join(",");
    const tcpScripts = scriptsFor("tcp");
    const udpScripts = scriptsFor("udp");
    const stagedScripts = selectedScripts.join(",");
    const out = [];

    if (staged) {
      const scanFlag = sel.has("connect") ? "-sT" : "-sS";
      const defeatRst = scanFlag === "-sS" ? "--defeat-rst-ratelimit" : "";
      const timing = TIMING_KEYS.find(([key]) => sel.has(key))?.[1] || "-T4";
      const versionFlag = sel.has("version_light")
        ? "--version-light"
        : sel.has("version_all") ? "--version-all" : "";
      const sweepTargets = discovery === "pn" ? targets : ["<발견된 호스트>"];

      if (discovery !== "pn") {
        out.push({
          title: "호스트 발견",
          desc: "포트 스캔 전에 ICMP Echo와 TCP SYN/ACK probe로 응답 호스트만 추립니다.",
          cmd: commandText(["nmap", "--stats-every", "5s", "-sn", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n",
            timing, "--reason", "--max-retries", "2", "--min-hostgroup", "64", "--max-parallelism", "100",
            ...excludeArgs, "-oA", "scan_<id>.discovery", ...targets]),
        });
      }
      if (tcp) {
        out.push({
          title: "TCP 포트 탐색",
          desc: "발견된 호스트를 배치로 나눠 열린 TCP 포트를 찾습니다.",
          cmd: commandText(["nmap", "--stats-every", "5s", scanFlag, "-Pn", "-n", "--open", timing,
            "--reason", "--max-retries", "2", "--min-hostgroup", "64", defeatRst,
            "--max-parallelism", "100", "-p", tcp, ...excludeArgs,
            "-oA", "scan_<id>.tcp_<batch>", ...sweepTargets]),
        });
        out.push({
          title: "TCP 서비스 식별",
          desc: "호스트별 열린 TCP에만 서비스·제품·버전·NSE 단서를 확인합니다.",
          cmd: commandText(["nmap", "--stats-every", "5s", scanFlag, "-Pn", "-sV", versionFlag, "--open",
            "--reason", timing, "--max-retries", "2", "-p", "T:<TCP 탐색에서 열린 포트>",
            stagedScripts && "--script", stagedScripts, stagedScripts && "--script-timeout", stagedScripts && "10s", ...excludeArgs,
            "-oA", "scan_<id>.tcp_service_<host>", "<호스트 1대>"]),
        });
      }
      if (sel.has("udp") && udp) {
        out.push({
          title: "UDP 포트 탐색",
          desc: "발견된 호스트의 주요/지정 UDP 포트에서 응답 후보를 찾습니다.",
          cmd: commandText(["nmap", "--stats-every", "5s", "-sU", "-Pn", "-n", "--open", timing,
            "--reason", "--max-retries", "2", "-p", udp, ...excludeArgs,
            "-oA", "scan_<id>.udp_<batch>", ...sweepTargets]),
        });
        out.push({
          title: "UDP 서비스 식별",
          desc: "호스트별 열린 UDP에 -sV와 UDP용 NSE 단서를 적용합니다(--version-all 제외).",
          cmd: commandText(["nmap", "--stats-every", "5s", "-sU", "-Pn", "-n", "-sV",
            versionFlag === "--version-light" && versionFlag, "--open", "--reason", timing, "--max-retries", "2",
            "-p", "U:<UDP 탐색에서 열린 포트>", stagedScripts && "--script", stagedScripts,
            stagedScripts && "--script-timeout", stagedScripts && "10s", ...excludeArgs,
            "-oA", "scan_<id>.udp_service_<host>", "<호스트 1대>"]),
        });
      }
      return out;
    }

    if (tcp) {
      out.push({
        title: "TCP 발견",
        desc: "전체/지정 TCP에서 지금 열려 있는 포트만 먼저 추려냅니다.",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sS", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", "-T4",
          "--reason", "--min-hostgroup", "64", "--max-retries", "2", "--defeat-rst-ratelimit",
          "--max-parallelism", "100", "-p", tcp, ...excludeArgs,
          "-oA", "scan_<id>.tcp_discovery", ...targets]),
      });
      out.push({
        title: "TCP 식별",
        desc: "앞 단계에서 살아있던 호스트의 열린 TCP에만 서비스·제품·버전·NSE 단서를 확인합니다.",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason",
          "-T4", "--max-retries", "2", tcpScripts && "--script", tcpScripts, "--script-timeout", "10s",
          "-p", "T:<1단계에서 발견된 TCP 포트>", ...excludeArgs,
          "-oA", "scan_<id>.tcp_identify", ...targets]),
      });
    }
    if (udp) {
      out.push({
        title: "UDP 식별",
        desc: "주요/지정 UDP에서 DNS·SNMP·NTP 같은 용도 단서를 확인합니다(강도 7 -sV — UDP는 version-all 미적용).",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sU", "-Pn", "-n", "-sV", "--open",
          "--reason", "-T4", "--max-retries", "2", udpScripts && "--script", udpScripts, "--script-timeout", "10s",
          "-p", udp, ...excludeArgs, "-oA", "scan_<id>.udp_identify", ...targets]),
      });
    }
    return out;
  }, [ports, portsAuto, udpPorts, targets, staged, discovery, sel, nseReg, nseSel, selectedScripts, excludeArgs]);

  // 단일 실행(manual) 명령 — raw 모드 '채우기' 및 하위호환용.
  const singleCommand = useMemo(() => {
    const p = (ports || portsAuto).trim();
    const flags = registry.filter((o) => sel.has(o.key)).flatMap((o) => o.flags);
    const parts = ["nmap", ...flags];
    if (p) parts.push("-p", p);
    if (selectedScripts.length) parts.push("--script", selectedScripts.join(","));
    parts.push(...excludeArgs);
    parts.push("-oA", "scan_<id>");
    if (targets.length) parts.push(...targets);
    return parts.join(" ");
  }, [sel, ports, portsAuto, targets, registry, selectedScripts, excludeArgs]);

  // onState.command: manual 은 항상 단일 명령(raw 모드 '채우기'용), 그 외엔 분산 단계 명령.
  const command = workflow === "manual" ? singleCommand : steps.map((s) => s.cmd).join("\n");

  useEffect(() => {
    onState && onState({
      workflow,
      options: fixedTargetPorts
        ? [...sel].filter((key) => RESCAN_OPTION_KEYS.has(key))
        : staged || workflow === "manual" ? [...sel] : [],
      ports,
      nse: [...nseSel],
      command,
    });
  }, [workflow, sel, ports, nseSel, command]);

  const groups = useMemo(() => {
    const g = {};
    registry
      .filter((option) => !fixedTargetPorts || RESCAN_OPTION_KEYS.has(option.key))
      .forEach((o) => { (g[o.group] ||= []).push(o); });
    return g;
  }, [registry, fixedTargetPorts]);

  const nseGroups = useMemo(() => {
    const g = {};
    nseReg.forEach((s) => { (g[s.group] ||= []).push(s); });
    return g;
  }, [nseReg]);

  function toggle(k) {
    if (k === "connect" || (k === "udp" && sel.has("udp"))) {
      setPorts((current) => tcpOnlyPortSpec(current));
    }
    setSel((s) => {
      const n = new Set(s);
      if (k === "syn") {
        n.add("syn");
        n.delete("connect");
      } else if (k === "connect") {
        n.add("connect");
        n.delete("syn");
        n.delete("udp");
        n.delete("defeat_rst");
      } else if (k === "udp" && !n.has("udp")) {
        n.add("udp");
        n.add("syn");
        n.delete("connect");
      } else if (TIMING_KEYS.some(([key]) => key === k)) {
        TIMING_KEYS.forEach(([key]) => n.delete(key));
        n.add(k);
      } else {
        n.has(k) ? n.delete(k) : n.add(k);
      }
      return n;
    });
    setPresetId("");
  }
  function toggleNse(k) {
    setNseSel((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
    setPresetId("");
  }
  const setNseAll = (keys) => { setNseSel(new Set(keys)); setPresetId(""); };
  const setPortPreset = (spec) => {
    setPorts(spec);
    if (hasExplicitUdpPorts(spec)) {
      setSel((s) => {
        const n = new Set(s);
        n.add("syn");
        n.add("udp");
        n.delete("connect");
        return n;
      });
    }
    setPresetId("");
  };

  function applyPrecision() {
    setWorkflow("manual");
    setSel(new Set(PRECISION_OPTS.filter((k) => registry.some((o) => o.key === k))));
    setPorts(udpPorts ? `T:1-65535,U:${udpPorts}` : "T:1-65535");
    setNseSel(new Set(nseDefault));
    setShowManualOptions(true);
    setShowNse(true);
    setPresetId("");
  }

  function applyPreset(id) {
    const p = presets.find((x) => x.id === id);
    if (p) {
      const nextSel = normalizeSelections(p.keys || []);
      let nextPorts = p.ports || "";
      if (nextSel.has("connect")) {
        nextPorts = tcpOnlyPortSpec(nextPorts);
      } else if (hasExplicitUdpPorts(nextPorts)) {
        nextSel.add("udp");
      }
      setWorkflow(p.workflow || "manual");
      setSel(nextSel);
      setPorts(nextPorts);
      setNseSel(new Set(p.nse || []));
    }
    setPresetId(id);
  }

  function savePreset() {
    const name = prompt("스캔 프리셋 이름", workflow === "auto" ? "자동 스캔" : "단일 실행");
    if (!name || !name.trim()) return;
    const next = [...presets, {
      id: "sp_" + Date.now(),
      name: name.trim(),
      workflow,
      keys: [...sel],
      ports,
      nse: [...nseSel],
    }];
    setPresets(next);
    localStorage.setItem(PRESET_KEY, JSON.stringify(next));
    setPresetId(next[next.length - 1].id);
  }

  function delPreset() {
    const next = presets.filter((p) => p.id !== presetId);
    setPresets(next);
    localStorage.setItem(PRESET_KEY, JSON.stringify(next));
    setPresetId("");
  }

  const { tcp, udp } = autoPortSpecs((ports || portsAuto).trim(), udpPorts);
  const udpActive = staged ? sel.has("udp") && Boolean(udp) : Boolean(udp);

  return (
    <div className="scan-builder">
      {!fixedTargetPorts && <div className="scan-modebar">
        <div className="seg">
          <button type="button" className={workflow === "auto" ? "on" : ""} onClick={() => setWorkflow("auto")}>자동 스캔</button>
          <button type="button" className={workflow === "manual" ? "on" : ""} onClick={() => setWorkflow("manual")}>단일 실행</button>
        </div>
        <select value={presetId} onChange={(e) => applyPreset(e.target.value)} aria-label="프리셋 선택">
          <option value="">프리셋 선택…</option>
          {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button type="button" className="sm" onClick={savePreset}>현재 구성 저장</button>
        {presetId && <button type="button" className="sm" onClick={delPreset}>삭제</button>}
      </div>}

      {fixedTargetPorts ? (
        <div className="scan-result-note">
          재스캔 대상은 선택한 발견의 IP:포트로 고정됩니다. 서비스·버전·NSE 단서만 2-pass로 다시 확인합니다.
        </div>
      ) : workflow === "auto" ? (
        <div className="scan-auto">
          <div className="scan-flow">
            {staged ? (
              <>
                <div className={discovery === "pn" ? "muted-step" : ""}>
                  <b>{discovery === "pn" ? "호스트 발견 생략" : "호스트 발견"}</b>
                  <span>{discovery === "pn" ? "입력 대상을 바로 포트 탐색에 넘깁니다." : "ICMP·TCP probe로 응답 호스트만 추립니다."}</span>
                </div>
                <div className={tcp ? "" : "muted-step"}><b>TCP 포트 탐색</b><span>응답 호스트의 열린 TCP를 찾습니다.</span></div>
                <div className={tcp ? "" : "muted-step"}><b>TCP 서비스 식별</b><span>열린 TCP만 제품·버전·NSE로 확인합니다.</span></div>
                <div className={udpActive ? "" : "muted-step"}><b>UDP 포트 탐색</b><span>주요/지정 UDP의 응답 후보를 찾습니다.</span></div>
                <div className={udpActive ? "" : "muted-step"}><b>UDP 서비스 식별</b><span>열린 UDP만 용도 단서로 확인합니다.</span></div>
              </>
            ) : (
              <>
                <div className={tcp ? "" : "muted-step"}><b>TCP 발견</b><span>전체 또는 지정 TCP에서 현재 열린 포트를 먼저 줄입니다.</span></div>
                <div className={tcp ? "" : "muted-step"}><b>TCP 식별</b><span>발견된 TCP만 서비스·제품·버전·NSE 단서로 다시 확인합니다.</span></div>
                <div className={udpActive ? "" : "muted-step"}><b>UDP 식별</b><span>주요 또는 지정 UDP에서 DNS·SNMP·NTP 같은 용도 단서를 확인합니다.</span></div>
              </>
            )}
          </div>
          <div className="scan-result-note">
            결과에는 열린 포트, 서비스명, 제품/버전, 웹 제목, 서버 헤더, TLS 인증서, SSH 키, NetBIOS/RDP/NTP/RPC 단서가 남습니다.
            TCP 발견 결과는 내부 과정으로 쓰고, 운영 데이터에는 식별 결과를 우선 반영합니다.
          </div>
        </div>
      ) : (
        <div className="scan-result-note">
          옵션을 직접 조합해 nmap 한 번으로 실행합니다. 자동 스캔처럼 발견된 TCP만 좁혀 2차 식별하지는 않습니다.
        </div>
      )}

      {!fixedTargetPorts && <div className="scan-actions">
        <button type="button" className="sm" onClick={() => setPortPreset("")}>자동 기본 포트</button>
        <button type="button" className="sm" onClick={() => setPortPreset("T:1-65535")}>TCP 전체</button>
        {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`U:${udpPorts}`)}>UDP 주요만</button>}
        {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`T:1-65535,U:${udpPorts}`)}>TCP+UDP</button>}
        <button type="button" className="sm" onClick={applyPrecision}>단일 정밀 구성</button>
      </div>}

      <div className="scan-collapsible">
        <button type="button" className="sm" onClick={() => setShowManualOptions((v) => !v)}>
          {showManualOptions ? "접기" : "펼치기"} 상세 옵션
        </button>
        <button type="button" className="sm" onClick={() => setShowNse((v) => !v)}>
          {showNse ? "접기" : "펼치기"} NSE <span className="pill info">{nseSel.size}</span>
        </button>
      </div>

      {fixedTargetPorts ? (
        <div className="field scan-ports">
          포트 <span className="mono">{portsAuto || "선택한 IP:포트"}</span>
          <small className="muted">선택한 발견의 포트만 재검증하므로 변경할 수 없습니다.</small>
        </div>
      ) : (
        <label className="field scan-ports">
          포트 {portsAuto && <span className="muted">(비우면 {portsAuto})</span>}
          <input placeholder={workflow === "auto" ? "비우면 TCP 전체 + 주요 UDP, 예: 22,443 또는 U:53" : "예: 22,80,443 또는 1-1024"}
                 value={ports} onChange={(e) => setPortPreset(e.target.value)} />
        </label>
      )}

      {showManualOptions && (
        <div className="scan-option-groups">
          {Object.entries(groups).map(([grp, opts]) => (
            <div key={grp} className="scan-option-group">
              <div className="cb-label">{grp}</div>
              <div className="scan-option-grid">
                {opts.map((o) => {
                  const on = sel.has(o.key);
                  return (
                    <label key={o.key} title={o.desc || ""} className={`scan-toggle ${on ? "on" : ""}`}>
                      <input type="checkbox" checked={on} onChange={() => toggle(o.key)} />
                      <span>
                        <b>{o.label}</b>
                        {o.note && <em>{o.note}</em>}
                        {o.desc && <small>{o.desc}</small>}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {showNse && (
        <div className="scan-nse">
          <div className="scan-actions">
            <button type="button" className="sm" onClick={() => setNseAll(nseDefault)}>기본 단서</button>
            <button type="button" className="sm" onClick={() => setNseAll(nseReg.map((s) => s.key))}>전체</button>
            <button type="button" className="sm" onClick={() => setNseAll([])}>끄기</button>
          </div>
          {Object.entries(nseGroups).map(([grp, scripts]) => (
            <div key={grp} className="scan-option-group">
              <div className="cb-label">{grp}</div>
              <div className="scan-nse-grid">
                {scripts.map((s) => {
                  const on = nseSel.has(s.key);
                  return (
                    <label key={s.key} title={s.desc || ""} className={`scan-toggle compact ${on ? "on" : ""}`}>
                      <input type="checkbox" checked={on} onChange={() => toggleNse(s.key)} />
                      <span>
                        <b className="mono">{s.key}</b>
                        {s.nmap_default === false && <em>주의</em>}
                        {s.desc && <small>{s.desc}</small>}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {fixedTargetPorts ? (
        <div className="scan-result-note" style={{ marginTop: 12 }}>
          실행 명령은 위에 표시된 발견별 IP:포트 개별 명령을 기준으로 합니다.
        </div>
      ) : (
        <>
          <div className="cb-label" style={{ marginTop: 12 }}>실행될 명령어</div>
          {stepped ? (
            <>
              <div className="scan-result-note" style={{ marginBottom: 8 }}>
                {staged ? (
                  <>
                    아래 {steps.length}개는 <b>단계별 명령 템플릿</b>입니다. 발견은 한 번, TCP·UDP 탐색은 배치별,
                    서비스 식별은 호스트·프로토콜별로 반복 실행됩니다. 앞 단계에서 찾은 호스트와 열린 포트만 다음 단계로 넘기며,
                    각 실행은 별도 산출물(<span className="mono">-oA</span>)로 남습니다.
                  </>
                ) : (
                  <>
                    아래 {steps.length}개 명령은 <b>한 번에 실행되지 않습니다.</b> 자동 스캔이 각 단계를
                    <b> 나눠서 순차 실행</b>하며 TCP 발견에서 열린 포트만 골라 식별 단계로 넘깁니다.
                    각 단계는 별도 산출물(<span className="mono">-oA</span>)로 남습니다.
                  </>
                )}
              </div>
              {steps.map((s, i) => (
                <div key={i} style={{ marginTop: i ? 10 : 0 }}>
                  <div className="cb-label" style={{ fontSize: 12, marginBottom: 4 }}>
                    {i + 1}단계 · {s.title} <span className="muted" style={{ fontWeight: 400 }}>— {s.desc}</span>
                  </div>
                  <div className="pre scan-command">{s.cmd}</div>
                </div>
              ))}
            </>
          ) : (
            <div className="pre scan-command">{command}</div>
          )}
        </>
      )}
    </div>
  );
}
