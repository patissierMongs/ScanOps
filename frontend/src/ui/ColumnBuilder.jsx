import React, { useState } from "react";
import { ALL_COLUMNS, COLUMN_MAP, PRESETS } from "../lib/columns.js";

// 컬럼 빌더 — 드래그&드롭으로 표시/내보낼 컬럼 구성, 프리셋 전환·저장, 표시형식, 내보내기.
// selected: 선택된 컬럼 key 배열(순서 = 표시순서).
export default function ColumnBuilder({
  selected, onChange, displayModes, onToggleDisplay,
  presetId, onApplyPreset, customPresets, onSaveCustom, onExport,
}) {
  const [dragIdx, setDragIdx] = useState(null);
  const [overIdx, setOverIdx] = useState(null);
  const selectedSet = new Set(selected);
  const palette = ALL_COLUMNS.filter((c) => !selectedSet.has(c.key));

  function add(key) {
    if (!selectedSet.has(key)) onChange([...selected, key]);
  }
  function remove(key) {
    onChange(selected.filter((k) => k !== key));
  }
  function onDrop(targetIdx) {
    if (dragIdx == null || dragIdx === targetIdx) { setDragIdx(null); setOverIdx(null); return; }
    const next = [...selected];
    const [moved] = next.splice(dragIdx, 1);
    next.splice(targetIdx, 0, moved);
    onChange(next);
    setDragIdx(null);
    setOverIdx(null);
  }

  function saveCustom() {
    const name = prompt("프리셋 이름", "내 구성");
    if (name && name.trim()) onSaveCustom(name.trim());
  }

  const allPresets = [...PRESETS, ...customPresets];

  return (
    <div className="panel" data-testid="column-builder">
      <h3>컬럼 빌더</h3>
      <div className="row" style={{ marginBottom: 12 }}>
        <select value={presetId} onChange={(e) => onApplyPreset(e.target.value)} data-testid="preset-select">
          <option value="">프리셋 선택…</option>
          {allPresets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <button className="sm" onClick={saveCustom}>현재 구성 저장</button>
        <div style={{ marginLeft: "auto" }} className="row">
          <button className="sm" onClick={() => onExport("csv")} data-testid="export-csv">CSV 내보내기</button>
          <button className="sm" onClick={() => onExport("xlsx")} data-testid="export-xlsx">XLSX 내보내기</button>
        </div>
      </div>

      <div className="cb-grid">
        <div>
          <div className="cb-label">선택된 컬럼 · 드래그로 순서변경</div>
          <div className="cb-selected" data-testid="cb-selected">
            {selected.length === 0 && <div className="muted" style={{ padding: 8 }}>컬럼을 추가하세요</div>}
            {selected.map((key, idx) => {
              const col = COLUMN_MAP[key];
              const badgeable = col?.badge;
              const mode = displayModes[key] || (badgeable ? "badge" : "text");
              return (
                <div
                  key={key}
                  className={"cb-chip" + (overIdx === idx ? " over" : "") + (dragIdx === idx ? " dragging" : "")}
                  draggable
                  onDragStart={() => setDragIdx(idx)}
                  onDragOver={(e) => { e.preventDefault(); setOverIdx(idx); }}
                  onDragLeave={() => setOverIdx((o) => (o === idx ? null : o))}
                  onDrop={() => onDrop(idx)}
                  onDragEnd={() => { setDragIdx(null); setOverIdx(null); }}
                >
                  <span className="cb-handle">⋮⋮</span>
                  <span className="cb-name">{col?.label || key}</span>
                  {badgeable && (
                    <button className="cb-mini" title="표시형식" onClick={() => onToggleDisplay(key)}>
                      {mode === "badge" ? "뱃지" : "텍스트"}
                    </button>
                  )}
                  <button className="cb-x" onClick={() => remove(key)}>✕</button>
                </div>
              );
            })}
          </div>
        </div>
        <div>
          <div className="cb-label">추가 가능한 필드</div>
          <div className="cb-palette" data-testid="cb-palette">
            {palette.map((c) => (
              <button key={c.key} className="cb-add" onClick={() => add(c.key)}>+ {c.label}</button>
            ))}
            {palette.length === 0 && <div className="muted" style={{ padding: 8 }}>모든 필드 추가됨</div>}
          </div>
        </div>
      </div>
    </div>
  );
}
