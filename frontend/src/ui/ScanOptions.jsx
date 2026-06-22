import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

const PRESET_KEY = "scanops_scan_presets";
const loadPresets = () => { try { return JSON.parse(localStorage.getItem(PRESET_KEY)) || []; } catch { return []; } };

const PRECISION_OPTS = ["noping", "dns_no", "syn", "fast", "version", "version_all",
  "max_retries", "open_only", "reason", "defeat_rst", "min_hostgroup", "max_parallel", "udp"];

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

function commandText(parts) {
  return parts.filter(Boolean).join(" ");
}

export default function ScanOptions({ targets = [], portsAuto = "", onState }) {
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
        setSel(new Set(r.default || []));
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

  const command = useMemo(() => {
    const p = (ports || portsAuto).trim();
    if (workflow === "auto") {
      const { tcp, udp } = autoPortSpecs(p, udpPorts);
      const scripts = selectedScripts.length ? selectedScripts.join(",") : "";
      const lines = [];
      if (tcp) {
        lines.push(commandText(["nmap", "--stats-every", "10s", "-sS", "-Pn", "-n", "-T4", "--open", "--reason",
          "--min-hostgroup", "64", "--max-retries", "1", "--defeat-rst-ratelimit", "--max-parallelism", "100",
          "--max-scan-delay", "5ms", "-p", tcp, "-oA", "scan_<id>.tcp_discovery", ...targets]));
        lines.push(commandText(["nmap", "--stats-every", "10s", "-sS", "-Pn", "-n", "-sV", "--version-all", "--open",
          "--reason", "-T4", "--max-retries", "2", scripts && "--script", scripts, "--script-timeout", "10s",
          "-p", "T:<발견된 TCP 포트>", "-oA", "scan_<id>.tcp_identify", ...targets]));
      }
      if (udp) {
        lines.push(commandText(["nmap", "--stats-every", "10s", "-sU", "-Pn", "-n", "-sV", "--version-all", "--open",
          "--reason", "-T4", "--max-retries", "1", "--max-scan-delay", "5ms", scripts && "--script", scripts,
          "--script-timeout", "10s", "-p", udp, "-oA", "scan_<id>.udp_identify", ...targets]));
      }
      return lines.join("\n");
    }

    const flags = registry.filter((o) => sel.has(o.key)).flatMap((o) => o.flags);
    const parts = ["nmap", ...flags];
    if (p) parts.push("-p", p);
    if (selectedScripts.length) parts.push("--script", selectedScripts.join(","));
    parts.push("-oA", "scan_<id>");
    if (targets.length) parts.push(...targets);
    return parts.join(" ");
  }, [workflow, sel, ports, portsAuto, targets, registry, selectedScripts, udpPorts]);

  useEffect(() => {
    onState && onState({
      workflow,
      options: workflow === "manual" ? [...sel] : [],
      ports,
      nse: [...nseSel],
      command,
    });
  }, [workflow, sel, ports, nseSel, command]);

  const groups = useMemo(() => {
    const g = {};
    registry.forEach((o) => { (g[o.group] ||= []).push(o); });
    return g;
  }, [registry]);

  const nseGroups = useMemo(() => {
    const g = {};
    nseReg.forEach((s) => { (g[s.group] ||= []).push(s); });
    return g;
  }, [nseReg]);

  function toggle(k) {
    setSel((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
    setPresetId("");
  }
  function toggleNse(k) {
    setNseSel((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
    setPresetId("");
  }
  const setNseAll = (keys) => { setNseSel(new Set(keys)); setPresetId(""); };
  const setPortPreset = (spec) => { setPorts(spec); setPresetId(""); };

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
      setWorkflow(p.workflow || "manual");
      setSel(new Set(p.keys || []));
      setPorts(p.ports || "");
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

  return (
    <div className="scan-builder">
      <div className="scan-modebar">
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
      </div>

      {workflow === "auto" ? (
        <div className="scan-auto">
          <div className="scan-flow">
            <div className={tcp ? "" : "muted-step"}><b>TCP 발견</b><span>전체 또는 지정 TCP에서 현재 열린 포트를 먼저 줄입니다.</span></div>
            <div className={tcp ? "" : "muted-step"}><b>TCP 식별</b><span>발견된 TCP만 서비스·제품·버전·NSE 단서로 다시 확인합니다.</span></div>
            <div className={udp ? "" : "muted-step"}><b>UDP 식별</b><span>주요 또는 지정 UDP에서 DNS·SNMP·NTP 같은 용도 단서를 확인합니다.</span></div>
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

      <div className="scan-actions">
        <button type="button" className="sm" onClick={() => setPortPreset("")}>자동 기본 포트</button>
        <button type="button" className="sm" onClick={() => setPortPreset("T:1-65535")}>TCP 전체</button>
        {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`U:${udpPorts}`)}>UDP 주요만</button>}
        {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`T:1-65535,U:${udpPorts}`)}>TCP+UDP</button>}
        <button type="button" className="sm" onClick={applyPrecision}>단일 정밀 구성</button>
      </div>

      <div className="scan-collapsible">
        <button type="button" className="sm" onClick={() => setShowManualOptions((v) => !v)}>
          {showManualOptions ? "접기" : "펼치기"} 상세 옵션
        </button>
        <button type="button" className="sm" onClick={() => setShowNse((v) => !v)}>
          {showNse ? "접기" : "펼치기"} NSE <span className="pill info">{nseSel.size}</span>
        </button>
      </div>

      <label className="field scan-ports">
        포트 {portsAuto && <span className="muted">(비우면 {portsAuto})</span>}
        <input placeholder={workflow === "auto" ? "비우면 TCP 전체 + 주요 UDP, 예: 22,443 또는 U:53" : "예: 22,80,443 또는 1-1024"}
               value={ports} onChange={(e) => setPortPreset(e.target.value)} />
      </label>

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

      <div className="cb-label" style={{ marginTop: 12 }}>실시간 명령</div>
      <div className="pre scan-command">{command}</div>
    </div>
  );
}
