import React, { useEffect, useMemo, useState } from "react";
import { api } from "../api.js";

// 스캔 옵션 빌더 — 서버 화이트리스트(/scans/options)를 받아 토글을 그리고,
// nmap 명령을 실시간 조립해 보여준다. 커스텀 프리셋 저장(localStorage).
// onState({options, ports}) 로 현재 선택을 부모에 알린다.
const PRESET_KEY = "scanops_scan_presets";
const loadPresets = () => { try { return JSON.parse(localStorage.getItem(PRESET_KEY)) || []; } catch { return []; } };

export default function ScanOptions({ targets = [], portsAuto = "", onState }) {
  const [registry, setRegistry] = useState([]);
  const [sel, setSel] = useState(() => new Set());
  const [ports, setPorts] = useState("");
  const [presets, setPresets] = useState(loadPresets);
  const [presetId, setPresetId] = useState("");

  useEffect(() => {
    let live = true;
    api("/scans/options")
      .then((r) => { if (live) { setRegistry(r.options); setSel(new Set(r.default)); } })
      .catch(() => {});
    return () => { live = false; };
  }, []);

  const command = useMemo(() => {
    const flags = registry.filter((o) => sel.has(o.key)).flatMap((o) => o.flags);
    const p = (ports || portsAuto).trim();
    const parts = ["nmap", ...flags];
    if (p) parts.push("-p", p);
    parts.push("-oA", "scan_<id>");
    if (targets.length) parts.push(...targets);
    return parts.join(" ");
  }, [sel, ports, portsAuto, targets, registry]);

  // 부모(Scans)가 직접 명령 편집을 prefill 할 수 있도록 조립된 명령도 함께 올린다.
  useEffect(() => { onState && onState({ options: [...sel], ports, command }); }, [sel, ports, command]);

  const groups = useMemo(() => {
    const g = {};
    registry.forEach((o) => { (g[o.group] ||= []).push(o); });
    return g;
  }, [registry]);

  function toggle(k) {
    setSel((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });
    setPresetId("");
  }
  function applyPreset(id) {
    const p = presets.find((x) => x.id === id);
    if (p) { setSel(new Set(p.keys)); setPorts(p.ports || ""); }
    setPresetId(id);
  }
  function savePreset() {
    const name = prompt("스캔 프리셋 이름", "내 스캔");
    if (!name || !name.trim()) return;
    const next = [...presets, { id: "sp_" + Date.now(), name: name.trim(), keys: [...sel], ports }];
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

  return (
    <div>
      <div className="row" style={{ marginBottom: 10 }}>
        <select value={presetId} onChange={(e) => applyPreset(e.target.value)}>
          <option value="">프리셋 선택…</option>
          {presets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button type="button" className="sm" onClick={savePreset}>현재 구성 저장</button>
        {presetId && <button type="button" className="sm" onClick={delPreset}>삭제</button>}
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
               value={ports} onChange={(e) => setPorts(e.target.value)} />
      </label>

      <div className="cb-label" style={{ marginTop: 10 }}>실시간 명령</div>
      <div className="pre" style={{ marginTop: 0 }}>{command}</div>
    </div>
  );
}
