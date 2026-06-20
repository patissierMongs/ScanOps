import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

// 스캔 옵션 빌더 — 서버 화이트리스트(/scans/options)를 받아 토글을 그리고,
// nmap 명령을 실시간 조립해 보여준다. 커스텀 프리셋 저장(localStorage).
// onState({options, ports, nse, command}) 로 현재 선택을 부모에 알린다.
const PRESET_KEY = "scanops_scan_presets";
const loadPresets = () => { try { return JSON.parse(localStorage.getItem(PRESET_KEY)) || []; } catch { return []; } };

// nmapParser phase1 기본 활성 옵션(ScanOps 키) — '정밀 프리셋'이 참조. -A/-O 는 OFF.
const PHASE1_OPTS = ["noping", "dns_no", "syn", "fast", "version", "version_all",
  "max_retries", "open_only", "reason", "defeat_rst", "min_hostgroup", "max_parallel", "udp"];

export default function ScanOptions({ targets = [], portsAuto = "", onState }) {
  const [registry, setRegistry] = useState([]);
  const [sel, setSel] = useState(() => new Set());
  const [ports, setPorts] = useState("");
  const [nseReg, setNseReg] = useState([]);
  const [nseSel, setNseSel] = useState(() => new Set());
  const [nseDefault, setNseDefault] = useState([]);
  const [udpPorts, setUdpPorts] = useState("");
  const [showOpts, setShowOpts] = useState(false);   // 스캔 옵션 빌더 — 기본 접힘
  const [showNse, setShowNse] = useState(false);     // NSE 패널 — 기본 접힘
  const [presets, setPresets] = useState(loadPresets);
  const [presetId, setPresetId] = useState("");
  const [touchedPorts, setTouchedPorts] = useState(false);

  useEffect(() => {
    let live = true;
    api("/scans/options")
      .then((r) => {
        if (!live) return;
        // '정밀 식별' 기본 프로파일: 추천 옵션 + 전체 TCP·주요 UDP 포트 + 정체 식별형 NSE 21종.
        setRegistry(r.options); setSel(new Set(r.default));
        setNseReg(r.nse || []); setNseDefault(r.nse_default || []);
        setNseSel(new Set(r.nse_default || []));
        setUdpPorts(r.udp_default_ports || "");
        if (!touchedPorts) setPorts(r.default_ports || "");
      })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const command = useMemo(() => {
    const flags = registry.filter((o) => sel.has(o.key)).flatMap((o) => o.flags);
    const p = (ports || portsAuto).trim();
    const parts = ["nmap", ...flags];
    if (p) parts.push("-p", p);
    const scripts = nseReg.filter((s) => nseSel.has(s.key)).map((s) => s.key);
    if (scripts.length) parts.push("--script", scripts.join(","));
    parts.push("-oA", "scan_<id>");
    if (targets.length) parts.push(...targets);
    return parts.join(" ");
  }, [sel, ports, portsAuto, targets, registry, nseReg, nseSel]);

  // 부모(Scans)가 직접 명령 편집을 prefill 할 수 있도록 조립된 명령도 함께 올린다.
  useEffect(() => { onState && onState({ options: [...sel], ports, nse: [...nseSel], command }); }, [sel, ports, nseSel, command]);

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

  // 포트 프리셋 — 입력란을 채워줄 뿐(직접 수정 가능). T:/U: 스펙은 서버가 그대로 -p 로 전달.
  const tcpAll = "T:1-65535";
  function setPortPreset(spec) { setPorts(spec); setPresetId(""); }

  // nmapParser 정밀(phase1) — 옵션·포트·NSE 를 한 번에 그 기본값으로.
  function applyPhase1() {
    setSel(new Set(PHASE1_OPTS.filter((k) => registry.some((o) => o.key === k))));
    setPorts(udpPorts ? `${tcpAll},U:${udpPorts}` : tcpAll);
    setNseSel(new Set(nseDefault));
    setShowNse(true);
    setPresetId("");
  }

  function applyPreset(id) {
    const p = presets.find((x) => x.id === id);
    if (p) { setSel(new Set(p.keys)); setPorts(p.ports || ""); setNseSel(new Set(p.nse || [])); }
    setPresetId(id);
  }
  function savePreset() {
    const name = prompt("스캔 프리셋 이름", "내 스캔");
    if (!name || !name.trim()) return;
    const next = [...presets, { id: "sp_" + Date.now(), name: name.trim(), keys: [...sel], ports, nse: [...nseSel] }];
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

  const SUMMARY_BG = { background: "var(--bg)", border: "1px solid var(--line)", borderRadius: 9, padding: "8px 12px", width: "100%", textAlign: "left", cursor: "pointer", fontSize: 12.5 };

  return (
    <div>
      {/* ── 스캔 옵션 빌더 (기본 접힘) ── */}
      <button type="button" style={SUMMARY_BG} onClick={() => setShowOpts((v) => !v)}>
        {showOpts ? "▾" : "▸"} 스캔 옵션 — 정밀 식별 기본값{" "}
        <span className="muted">· 선택 {sel.size}개 · 포트 {ports ? (ports.length > 24 ? "지정됨" : ports) : "기본"}</span>
      </button>

      {showOpts && (
        <div style={{ marginTop: 10 }}>
          <div className="row" style={{ marginBottom: 10 }}>
            <select value={presetId} onChange={(e) => applyPreset(e.target.value)}>
              <option value="">프리셋 선택…</option>
              {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
            <button type="button" className="sm" onClick={savePreset}>현재 구성 저장</button>
            {presetId && <button type="button" className="sm" onClick={delPreset}>삭제</button>}
            <button type="button" className="sm" onClick={applyPhase1} title="nmapParser 기본 정밀 스캔 구성을 한 번에 적용">⚡ 정밀(phase1)</button>
          </div>

          {Object.entries(groups).map(([grp, opts]) => (
            <div key={grp} style={{ marginBottom: 12 }}>
              <div className="cb-label">{grp}</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(290px, 1fr))", gap: 8 }}>
                {opts.map((o) => {
                  const on = sel.has(o.key);
                  return (
                    <label key={o.key} title={o.desc || ""}
                           style={{
                             display: "flex", gap: 8, padding: "8px 10px", cursor: "pointer",
                             border: "1px solid var(--line)", borderRadius: 9,
                             background: on ? "var(--accent-bg)" : "var(--surface)",
                             borderColor: on ? "var(--accent)" : "var(--line)",
                           }}>
                      <input type="checkbox" checked={on} onChange={() => toggle(o.key)} style={{ marginTop: 2 }} />
                      <span style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        <span style={{ fontSize: 12.5, fontWeight: 600 }}>
                          {o.label}
                          {o.note && <span className="pill medium" style={{ marginLeft: 6, fontSize: 10, padding: "0 6px" }}>{o.note}</span>}
                        </span>
                        {o.desc && <span className="muted" style={{ fontSize: 11.5, lineHeight: 1.45 }}>{o.desc}</span>}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>
          ))}

          <label className="field" style={{ marginTop: 6 }}>
            포트 {portsAuto && <span className="muted">(비우면 {portsAuto})</span>}
            <input placeholder={portsAuto || "예: 22,80,443 또는 1-1024 (비우면 nmap 기본)"}
                   value={ports} onChange={(e) => { setTouchedPorts(true); setPorts(e.target.value); }} />
          </label>
          <div className="row" style={{ gap: 6, marginTop: 6 }}>
            <span className="muted" style={{ fontSize: 11.5 }}>포트 프리셋:</span>
            <button type="button" className="sm" onClick={() => setPortPreset(tcpAll)}>TCP 전체(1-65535)</button>
            {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`U:${udpPorts}`)}>UDP 주요(26)</button>}
            {udpPorts && <button type="button" className="sm" onClick={() => setPortPreset(`${tcpAll},U:${udpPorts}`)}>TCP+UDP</button>}
            {ports && <button type="button" className="sm" onClick={() => setPortPreset("")}>지우기</button>}
          </div>
        </div>
      )}

      {/* ── NSE 스크립트 패널 (기본 접힘) — 선택 시 --script 로 조립 ── */}
      <div style={{ marginTop: 10 }}>
        <button type="button" style={SUMMARY_BG} onClick={() => setShowNse((v) => !v)}>
          {showNse ? "▾" : "▸"} NSE 스크립트 — 정체 식별형 기본값{" "}
          <span className="muted">· 선택 {nseSel.size}개</span>
        </button>
        {showNse && (
          <div className="row" style={{ gap: 6, margin: "8px 0", justifyContent: "flex-end" }}>
            <button type="button" className="sm" onClick={() => setNseAll(nseReg.map((s) => s.key))}>전체</button>
            <button type="button" className="sm" onClick={() => setNseAll(nseDefault)}>기본({nseDefault.length})</button>
            <button type="button" className="sm" onClick={() => setNseAll([])}>해제</button>
          </div>
        )}
        {showNse && Object.entries(nseGroups).map(([grp, scripts]) => (
          <div key={grp} style={{ marginTop: 8 }}>
            <div className="cb-label">{grp}</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(260px, 1fr))", gap: 6 }}>
              {scripts.map((s) => {
                const on = nseSel.has(s.key);
                return (
                  <label key={s.key} title={s.desc || ""}
                         style={{
                           display: "flex", gap: 7, padding: "6px 9px", cursor: "pointer", fontSize: 12,
                           border: "1px solid var(--line)", borderRadius: 8,
                           background: on ? "var(--accent-bg)" : "var(--surface)",
                           borderColor: on ? "var(--accent)" : "var(--line)",
                         }}>
                    <input type="checkbox" checked={on} onChange={() => toggleNse(s.key)} style={{ marginTop: 1 }} />
                    <span style={{ display: "flex", flexDirection: "column", gap: 1 }}>
                      <span className="mono" style={{ fontSize: 11.5, fontWeight: 600 }}>
                        {s.key}
                        {s.nmap_default === false && <span className="muted" style={{ marginLeft: 5, fontSize: 10 }}>· 기본 제외</span>}
                      </span>
                      {s.desc && <span className="muted" style={{ fontSize: 11, lineHeight: 1.4 }}>{s.desc}</span>}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <div className="cb-label" style={{ marginTop: 12 }}>실시간 명령</div>
      <div className="pre" style={{ marginTop: 0 }}>{command}</div>
    </div>
  );
}
