import React, { useEffect, useMemo, useRef, useState } from "react";
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

// 발견 단계 host-discovery probe — 백엔드 nmap_runner.DISCOVERY_PS/PA 와 동일하게 유지(미리보기 정확도).
const DISCOVERY_PS = "-PS21,22,23,25,80,110,135,139,143,443,445,993,1433,1521,3306,3389,5432,8080";
const DISCOVERY_PA = "-PA80,443,3389";

export default function ScanOptions({
  targets = [], targetsText = "", setTargetsText,
  exclude = "", setExclude, staged = false, portsAuto = "", onState,
}) {
  const [workflow, setWorkflow] = useState("auto");
  const [registry, setRegistry] = useState([]);
  const [defaultOpts, setDefaultOpts] = useState([]);
  const [sel, setSel] = useState(() => new Set());
  const [ports, setPorts] = useState("");
  const [nseReg, setNseReg] = useState([]);
  const [nseSel, setNseSel] = useState(() => new Set());
  const [nseDefault, setNseDefault] = useState([]);
  const [udpPorts, setUdpPorts] = useState("");
  const [precision, setPrecision] = useState(false);   // 정밀 옵션(단일 실행 상세) 토글 — 켜고 끌 수 있음
  const [showNse, setShowNse] = useState(false);
  const [showPreview, setShowPreview] = useState(false);  // 실행될 명령어 — 기본 접힘
  const [presets, setPresets] = useState(loadPresets);
  const [touchedPorts, setTouchedPorts] = useState(false);
  const targetsFileRef = useRef(null);
  const portsFileRef = useRef(null);

  useEffect(() => {
    let live = true;
    api("/scans/options")
      .then((r) => {
        if (!live) return;
        setRegistry(r.options || []);
        setDefaultOpts(r.default || []);
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

  // 단계 분리(staged) 또는 자동 스캔이면 한 번에 안 돌고 단계별로 나눠 순차 실행된다.
  const stepped = staged || workflow === "auto";

  // 분산 실행되는 각 단계 명령 — 백엔드 nmap_runner.build_auto_command 의 플래그와 동기화.
  const steps = useMemo(() => {
    const p = (ports || portsAuto).trim();
    const { tcp, udp } = autoPortSpecs(p, udpPorts);
    const scripts = selectedScripts.length ? selectedScripts.join(",") : "";
    const out = [];
    if (tcp) {
      out.push({
        title: "TCP 발견",
        desc: "전체/지정 TCP에서 지금 열려 있는 포트만 먼저 추려냅니다.",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sS", "-PE", DISCOVERY_PS, DISCOVERY_PA, "-n", "-T4",
          "--reason", "--min-hostgroup", "64", "--max-retries", "2", "--defeat-rst-ratelimit",
          "--max-parallelism", "100", "-p", tcp, "-oA", "scan_<id>.tcp_discovery", ...targets]),
      });
      out.push({
        title: "TCP 식별",
        desc: "앞 단계에서 살아있던 호스트의 열린 TCP에만 서비스·제품·버전·NSE 단서를 확인합니다.",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sS", "-Pn", "-sV", "--version-all", "--open", "--reason",
          "-T4", "--max-retries", "2", scripts && "--script", scripts, "--script-timeout", "10s",
          "-p", "T:<1단계에서 발견된 TCP 포트>", "-oA", "scan_<id>.tcp_identify", ...targets]),
      });
    }
    if (udp) {
      out.push({
        title: "UDP 식별",
        desc: "주요/지정 UDP에서 DNS·SNMP·NTP 같은 용도 단서를 확인합니다(강도 7 -sV — UDP는 version-all 미적용).",
        cmd: commandText(["nmap", "--stats-every", "10s", "-sU", "-Pn", "-n", "-sV", "--open",
          "--reason", "-T4", "--max-retries", "2", scripts && "--script", scripts, "--script-timeout", "10s",
          "-p", udp, "-oA", "scan_<id>.udp_identify", ...targets]),
      });
    }
    return out;
  }, [ports, portsAuto, udpPorts, targets, selectedScripts]);

  // 단일 실행(manual) 명령 — raw 모드 '채우기' 및 하위호환용.
  const singleCommand = useMemo(() => {
    const p = (ports || portsAuto).trim();
    const flags = registry.filter((o) => sel.has(o.key)).flatMap((o) => o.flags);
    const parts = ["nmap", ...flags];
    if (p) parts.push("-p", p);
    if (selectedScripts.length) parts.push("--script", selectedScripts.join(","));
    parts.push("-oA", "scan_<id>");
    if (targets.length) parts.push(...targets);
    return parts.join(" ");
  }, [sel, ports, portsAuto, targets, registry, selectedScripts]);

  const command = workflow === "manual" ? singleCommand : steps.map((s) => s.cmd).join("\n");

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
  }
  function toggleNse(k) {
    setNseSel((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
  }
  const setNseAll = (keys) => setNseSel(new Set(keys));
  const setPortPreset = (spec) => { setPorts(spec); setTouchedPorts(true); };

  // 모드 전환 — '자동 스캔'으로 가면 정밀 옵션은 끈다(단일 실행 전용 개념).
  function chooseAuto() { setWorkflow("auto"); setPrecision(false); }
  function chooseManual() { setWorkflow("manual"); }

  // 정밀 옵션 토글 — 켜면 단일 실행 + 정밀 프리셋 로드, 끄면 기본 구성으로 되돌린다(닫을 수 있음).
  function togglePrecision(on) {
    setPrecision(on);
    if (on) {
      setWorkflow("manual");
      setSel(new Set(PRECISION_OPTS.filter((k) => registry.some((o) => o.key === k))));
      setPorts(udpPorts ? `T:1-65535,U:${udpPorts}` : "T:1-65535");
      setTouchedPorts(true);
      setNseSel(new Set(nseDefault));
      setShowNse(true);
    } else {
      setSel(new Set(defaultOpts));
      setNseSel(new Set(nseDefault));
      setShowNse(false);
      setWorkflow("auto");
    }
  }

  function applyPreset(p) {
    if (!p) return;
    setWorkflow(p.workflow || "manual");
    setPrecision(!!p.precision);
    setSel(new Set(p.keys || []));
    setPorts(p.ports || "");
    setTouchedPorts(true);
    setNseSel(new Set(p.nse || []));
    if (setTargetsText && p.targets != null) setTargetsText(p.targets);   // IP 텍스트 즉시 반영
    if (setExclude && p.exclude != null) setExclude(p.exclude);
    if ((p.keys || []).length || p.precision) setShowNse(true);
  }

  function savePreset() {
    const name = prompt("이 구성을 프리셋으로 저장 — 이름", workflow === "auto" ? "자동 스캔" : "단일 실행");
    if (!name || !name.trim()) return;
    const next = [...presets, {
      id: "sp_" + Date.now(),
      name: name.trim(),
      workflow, precision,
      keys: [...sel], ports, nse: [...nseSel],
      targets: targetsText, exclude,   // IP·제외까지 저장 → 적용 시 그대로 복원
    }];
    setPresets(next);
    localStorage.setItem(PRESET_KEY, JSON.stringify(next));
  }

  function delPreset(id) {
    const next = presets.filter((p) => p.id !== id);
    setPresets(next);
    localStorage.setItem(PRESET_KEY, JSON.stringify(next));
  }

  function readTokensFromFile(file, cb) {
    file.text().then((txt) => {
      const toks = txt.split(/[\s,]+/).map((t) => t.trim()).filter((t) => t && !t.startsWith("#"));
      cb(toks);
    }).catch(() => {});
  }
  function onTargetsFile(e) {
    const f = e.target.files?.[0]; e.target.value = "";
    if (f && setTargetsText) readTokensFromFile(f, (toks) => setTargetsText(toks.join("\n")));
  }
  function onPortsFile(e) {
    const f = e.target.files?.[0]; e.target.value = "";
    if (f) readTokensFromFile(f, (toks) => setPortPreset(toks.join(",")));
  }

  const { tcp, udp } = autoPortSpecs((ports || portsAuto).trim(), udpPorts);
  const portActive = (spec) => (ports || "").trim() === spec;

  return (
    <div className="scan-builder">
      {/* 모드 + 프리셋(버튼) */}
      <div className="scan-modebar">
        <div className="seg">
          <button type="button" className={workflow === "auto" ? "on" : ""} onClick={chooseAuto}>자동 스캔</button>
          <button type="button" className={workflow === "manual" ? "on" : ""} onClick={chooseManual}>단일 실행</button>
        </div>
        <div className="scan-presetbar">
          <span className="scan-mini-label">구성 프리셋</span>
          {presets.length === 0 && <span className="muted" style={{ fontSize: 12 }}>저장된 구성 없음</span>}
          {presets.map((p) => (
            <span key={p.id} className="preset-chip">
              <button type="button" className="preset-apply" onClick={() => applyPreset(p)} title="이 구성 적용(IP·포트·옵션 복원)">{p.name}</button>
              <button type="button" className="preset-del" onClick={() => delPreset(p.id)} title="삭제">×</button>
            </span>
          ))}
          <button type="button" className="sm" onClick={savePreset}>+ 현재 구성 저장</button>
        </div>
      </div>

      {/* ① 대상 IP 패널 */}
      <section className="scan-panel scan-panel-ip">
        <div className="scan-panel-head">
          <span className="scan-panel-title"><span className="scan-panel-kbd">IP</span> 대상</span>
          <label className="linkbtn">
            파일 불러오기(.txt)
            <input ref={targetsFileRef} type="file" accept=".txt,.csv,text/plain" style={{ display: "none" }} onChange={onTargetsFile} />
          </label>
        </div>
        <textarea
          className="scan-target-input"
          rows={3}
          placeholder="예: 10.10.20.0/24  10.10.30.5  10.10.40.1-50  (공백·줄바꿈·콤마 구분)"
          value={targetsText}
          onChange={(e) => setTargetsText && setTargetsText(e.target.value)}
        />
        <div className="scan-subfield">
          <label className="scan-mini-label">제외 대역 (선택)</label>
          <input
            className="scan-exclude-input"
            placeholder="스캔에서 뺄 IP·CIDR — 예: 10.10.20.19, 10.10.30.0/24"
            value={exclude}
            onChange={(e) => setExclude && setExclude(e.target.value)}
          />
        </div>
        <div className="scan-hint">IP·CIDR·범위(10.0.0.1-50)를 자유롭게. 제외 대역은 대상 확장 후 걸러냅니다(자동/단일/단계 모두 적용).</div>
      </section>

      {/* ② 포트 패널 (강조) */}
      <section className="scan-panel scan-panel-port">
        <div className="scan-panel-head">
          <span className="scan-panel-title"><span className="scan-panel-kbd">PORT</span> 포트</span>
          <label className="linkbtn">
            파일 불러오기(.txt)
            <input ref={portsFileRef} type="file" accept=".txt,.csv,text/plain" style={{ display: "none" }} onChange={onPortsFile} />
          </label>
        </div>
        <div className="scan-preset-row">
          <button type="button" className={`portpreset ${portActive("") ? "on" : ""}`} onClick={() => setPortPreset("")}>최적화된 포트</button>
          <button type="button" className={`portpreset ${portActive("T:1-65535") ? "on" : ""}`} onClick={() => setPortPreset("T:1-65535")}>TCP 전체</button>
          {udpPorts && <button type="button" className={`portpreset ${portActive(`U:${udpPorts}`) ? "on" : ""}`} onClick={() => setPortPreset(`U:${udpPorts}`)}>UDP 주요만</button>}
          {udpPorts && <button type="button" className={`portpreset ${portActive(`T:1-65535,U:${udpPorts}`) ? "on" : ""}`} onClick={() => setPortPreset(`T:1-65535,U:${udpPorts}`)}>TCP + UDP</button>}
        </div>
        <input
          className="scan-port-input"
          placeholder={workflow === "auto" ? "비우면 TCP 전체 + 주요 UDP · 예: 22,443 또는 U:53" : "예: 22,80,443 또는 1-1024"}
          value={ports}
          onChange={(e) => setPortPreset(e.target.value)}
        />
        <div className="scan-hint">
          위 버튼을 누르면 아래 칸에 <b>즉시 반영</b>됩니다(직접 편집도 가능).
          {" "}현재: TCP <b className="mono">{tcp || "없음"}</b>{udp ? <> · UDP <b className="mono">{udp}</b></> : null}
          {!ports ? "  ·  최적화된 포트 = 자동 발견 프로파일(권장)" : ""}
        </div>
      </section>

      {/* 스캔 흐름 설명(자동) / 참고(단일) */}
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

      {/* 정밀 옵션 — 포트 프리셋과 분리된 별도 토글(켜고 끌 수 있음) */}
      <section className="scan-panel scan-panel-precision">
        <label className="scan-precision-toggle">
          <input type="checkbox" checked={precision} onChange={(e) => togglePrecision(e.target.checked)} />
          <span>
            <b>정밀 옵션 (단일 실행 상세 구성)</b>
            <small>개별 nmap 스캔 옵션·NSE 스크립트를 직접 켜고 끕니다. 끄면 기본 구성으로 되돌아갑니다.</small>
          </span>
        </label>

        {precision && (
          <div className="scan-precision-body">
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

            <div className="scan-collapsible" style={{ marginTop: 12 }}>
              <button type="button" className="sm" onClick={() => setShowNse((v) => !v)}>
                {showNse ? "접기" : "펼치기"} NSE 스크립트 <span className="pill info">{nseSel.size}</span>
              </button>
            </div>
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
          </div>
        )}
      </section>

      {/* 실행될 명령어 — 기본 접힘 */}
      <div className="scan-preview">
        <button type="button" className="scan-preview-toggle" onClick={() => setShowPreview((v) => !v)}>
          <span className="scan-caret">{showPreview ? "▾" : "▸"}</span> 실행될 명령어 미리보기
          <span className="pill info">{stepped ? `${steps.length}단계` : "1개"}</span>
        </button>
        {showPreview && (
          stepped ? (
            <div className="scan-preview-body">
              <div className="scan-result-note" style={{ marginBottom: 8 }}>
                아래 {steps.length}개 명령은 <b>한 번에 실행되지 않습니다.</b> {staged ? "단계 분리 엔진이 " : "자동 스캔이 "}
                각 단계를 <b>나눠서(분산) 순차 실행</b>하며, 앞 단계의 결과가 다음 단계의 입력이 됩니다
                (예: TCP 발견에서 열린 포트만 골라 식별 단계로 넘김). 각 단계는 별도 명령·별도 산출물(<span className="mono">-oA</span>)로 남습니다.
              </div>
              {steps.map((s, i) => (
                <div key={i} style={{ marginTop: i ? 10 : 0 }}>
                  <div className="cb-label" style={{ fontSize: 12, marginBottom: 4 }}>
                    {i + 1}단계 · {s.title} <span className="muted" style={{ fontWeight: 400 }}>— {s.desc}</span>
                  </div>
                  <div className="pre scan-command">{s.cmd}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="scan-preview-body"><div className="pre scan-command">{command}</div></div>
          )
        )}
      </div>
    </div>
  );
}
