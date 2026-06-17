import React, { useEffect, useRef, useState } from "react";
import { api } from "../api.js";
import { useToast } from "../ui/Toast.jsx";
import {
  readWorkbook, unmergeFillWs, detectHeaderRow, assetColumnsFrom,
  computeAutoMap, buildAssetRecords, normalizeSpec, normHeader, ASSET_MAP_FIELDS,
} from "../lib/assetImport.js";

const MAP_PRESET_KEY = "scanops_asset_map_presets";
const loadPresets = () => { try { return JSON.parse(localStorage.getItem(MAP_PRESET_KEY)) || []; } catch { return []; } };

export default function Assets({ user }) {
  const [assets, setAssets] = useState([]);
  const [search, setSearch] = useState("");
  const [imp, setImp] = useState(null);
  const [mapPresets, setMapPresets] = useState(loadPresets);
  const [presetId, setPresetId] = useState("");
  const fileRef = useRef(null);
  const toast = useToast();
  const canEdit = user.role === "admin" || user.role === "auditor";

  function load() {
    api("/assets").then(setAssets).catch((e) => toast(e.message, { type: "err" }));
  }
  useEffect(() => { load(); }, []);

  function selectSheet(wb, sheetNames, sheet) {
    const { aoa, mergeCount } = unmergeFillWs(wb.Sheets[sheet]);
    const headerRow = detectHeaderRow(aoa);
    const cols = assetColumnsFrom(aoa, headerRow);
    setImp({ wb, sheetNames, sheet, aoa, headerRow, mergeCount, cols, mapping: computeAutoMap(cols), extraCols: [] });
    setPresetId("");
    const dataN = cols.length ? cols[0].values.length : 0;
    toast(`불러옴 · 헤더 ${headerRow + 1}행 · 데이터 ${dataN}행` + (mergeCount ? ` · 병합 ${mergeCount}개 해제` : ""));
  }

  function onFile(e) {
    const file = e.target.files && e.target.files[0];
    e.target.value = "";
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const { wb, sheetNames } = readWorkbook(reader.result);
        selectSheet(wb, sheetNames, sheetNames[0]);
      } catch {
        toast("엑셀 파싱 실패 — .xlsx/.xls/.csv 확인", { type: "err" });
      }
    };
    reader.onerror = () => toast("파일을 읽지 못했습니다", { type: "err" });
    reader.readAsArrayBuffer(file);
  }

  function setHeaderRow(idx) {
    const headerRow = Math.max(0, Math.min(idx, imp.aoa.length - 1));
    const cols = assetColumnsFrom(imp.aoa, headerRow);
    setImp({ ...imp, headerRow, cols, mapping: computeAutoMap(cols), extraCols: [] });
  }

  function updateSpec(key, patch) {
    const cur = normalizeSpec(imp.mapping[key]) || { col: null, sep: "", part: null };
    const next = { ...cur, ...patch };
    const m = { ...imp.mapping };
    if (next.col == null || next.col === "") delete m[key];
    else if (next.sep || next.part != null) m[key] = { col: next.col, sep: next.sep || "", part: next.part ?? null };
    else m[key] = next.col;
    setImp({ ...imp, mapping: m });
    setPresetId("");
  }
  const onCol = (key, v) => updateSpec(key, v === "" ? { col: null } : { col: Number(v), part: null });
  const onSep = (key, v) => updateSpec(key, { sep: v });
  const onPart = (key, v) => updateSpec(key, { part: v === "" ? null : Number(v) });

  function toggleExtra(idx) {
    const has = imp.extraCols.includes(idx);
    setImp({ ...imp, extraCols: has ? imp.extraCols.filter((x) => x !== idx) : [...imp.extraCols, idx] });
  }

  // ---- 매핑 프리셋 (헤더명 기준 — 컬럼 순서가 바뀌어도 재적용) ----
  const colByHeader = (header) => {
    let c = imp.cols.find((x) => x.header === header);
    if (!c) c = imp.cols.find((x) => normHeader(x.header) === normHeader(header));
    return c ? c.index : null;
  };
  function saveMapPreset() {
    const name = prompt("매핑 프리셋 이름 (반복 양식 재사용)", "월간 자산대장");
    if (!name || !name.trim()) return;
    const fields = {};
    ASSET_MAP_FIELDS.forEach((f) => {
      const ns = normalizeSpec(imp.mapping[f.key]);
      if (ns) fields[f.key] = { header: imp.cols[ns.col]?.header || "", sep: ns.sep, part: ns.part };
    });
    const extraHeaders = imp.extraCols.map((i) => imp.cols[i]?.header).filter(Boolean);
    const next = [...mapPresets, { id: "mp_" + Date.now(), name: name.trim(), fields, extraHeaders }];
    setMapPresets(next);
    localStorage.setItem(MAP_PRESET_KEY, JSON.stringify(next));
    setPresetId(next[next.length - 1].id);
    toast(`매핑 프리셋 저장 · ${name.trim()}`);
  }
  function applyMapPreset(id) {
    setPresetId(id);
    const p = mapPresets.find((x) => x.id === id);
    if (!p) return;
    const mapping = {};
    let miss = 0;
    Object.entries(p.fields).forEach(([field, spec]) => {
      const idx = colByHeader(spec.header);
      if (idx == null) { miss++; return; }
      mapping[field] = (spec.sep || spec.part != null) ? { col: idx, sep: spec.sep || "", part: spec.part ?? null } : idx;
    });
    const extraCols = (p.extraHeaders || []).map(colByHeader).filter((x) => x != null);
    setImp({ ...imp, mapping, extraCols });
    toast(miss ? `프리셋 적용 · ${miss}개 컬럼은 헤더 불일치로 누락` : "매핑 프리셋 적용");
  }
  function delMapPreset() {
    const next = mapPresets.filter((p) => p.id !== presetId);
    setMapPresets(next);
    localStorage.setItem(MAP_PRESET_KEY, JSON.stringify(next));
    setPresetId("");
  }

  function doImport() {
    const recs = buildAssetRecords(imp.cols, imp.mapping, imp.extraCols);
    if (!recs.length) { toast("IP 컬럼을 매핑하세요", { type: "err" }); return; }
    api("/assets/bulk", { method: "POST", json: recs })
      .then((r) => { toast(`자산 가져옴 · 신규 ${r.added} / 갱신 ${r.updated} · 발견매칭 ${r.findings_matched}`); setImp(null); load(); })
      .catch((e) => toast(e.message, { type: "err" }));
  }

  const partsOf = (colIdx, sep) => {
    if (!sep) return 0;
    const col = imp.cols[colIdx];
    const sample = (col?.values || []).find((v) => v && v.includes(sep)) || col?.values[0] || "";
    return String(sample).split(sep).length;
  };

  const usedCols = new Set();
  if (imp) ASSET_MAP_FIELDS.forEach((f) => { const ns = normalizeSpec(imp.mapping[f.key]); if (ns) usedCols.add(ns.col); });
  const candidateExtra = imp ? imp.cols.filter((c) => !usedCols.has(c.index)) : [];
  const records = imp ? buildAssetRecords(imp.cols, imp.mapping, imp.extraCols) : [];
  const preview = records[0] || null;
  const dataRows = imp ? (imp.cols[0]?.values.length || 0) : 0;
  const skipped = imp ? Math.max(0, dataRows - records.length) : 0;

  const q = search.trim().toLowerCase();
  const filtered = !q ? assets : assets.filter((a) =>
    [a.ip, a.hostname, a.dept, a.owner, a.contact, a.asset_no].some((v) => (v || "").toLowerCase().includes(q)) ||
    Object.values(a.extra || {}).some((v) => String(v).toLowerCase().includes(q)));

  return (
    <div className="content">
      {canEdit && (
        <div className="panel">
          <h3>엑셀 가져오기 — 병합해제 · 헤더감지 · 자동매핑 · 결합셀 분리 · 커스텀 필드 · 매핑 프리셋</h3>
          <div className="row">
            <button onClick={() => fileRef.current?.click()}>파일 선택 (.xlsx/.xls/.csv)</button>
            <input ref={fileRef} type="file" accept=".xlsx,.xls,.csv" style={{ display: "none" }} onChange={onFile} />
            {imp && imp.sheetNames.length > 1 && (
              <select value={imp.sheet} onChange={(e) => selectSheet(imp.wb, imp.sheetNames, e.target.value)}>
                {imp.sheetNames.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            )}
          </div>

          {imp && (
            <div style={{ marginTop: 14 }}>
              <div className="row" style={{ marginBottom: 12 }}>
                <label className="field">헤더 행
                  <input type="number" min={1} value={imp.headerRow + 1} style={{ width: 76 }}
                         onChange={(e) => setHeaderRow((parseInt(e.target.value, 10) || 1) - 1)} />
                </label>
                <span className="muted">병합 {imp.mergeCount}개 해제 · {imp.cols.length}컬럼 · 데이터 {dataRows}행</span>
                <div className="row" style={{ marginLeft: "auto", gap: 6 }}>
                  <select value={presetId} onChange={(e) => applyMapPreset(e.target.value)}>
                    <option value="">매핑 프리셋…</option>
                    {mapPresets.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                  </select>
                  <button className="sm" onClick={saveMapPreset}>현재 매핑 저장</button>
                  {presetId && <button className="sm" onClick={delMapPreset}>삭제</button>}
                </div>
              </div>

              <div className="cb-label">핵심 필드 매핑 — 한 컬럼을 구분자로 나눠 여러 필드에 배정 가능</div>
              <div className="map-grid">
                {ASSET_MAP_FIELDS.map((fld) => {
                  const ns = normalizeSpec(imp.mapping[fld.key]);
                  const col = ns ? ns.col : "";
                  const sep = ns ? ns.sep : "";
                  const np = partsOf(col, sep);
                  return (
                    <div key={fld.key} className="map-row">
                      <span className="map-key">{fld.label}{fld.req && <b className="err"> *</b>}</span>
                      <select value={col} onChange={(e) => onCol(fld.key, e.target.value)}>
                        <option value="">—</option>
                        {imp.cols.map((c) => <option key={c.index} value={c.index}>{c.letter}: {c.header}</option>)}
                      </select>
                      {ns && (
                        <>
                          <input className="map-sep" placeholder="구분자" value={sep}
                                 onChange={(e) => onSep(fld.key, e.target.value)} title="결합셀 분리 구분자 (예: , )" />
                          <select className="map-part" value={ns.part == null ? "" : ns.part}
                                  onChange={(e) => onPart(fld.key, e.target.value)} disabled={!sep}>
                            <option value="">전체</option>
                            {Array.from({ length: np }, (_, k) => <option key={k} value={k}>부분 {k + 1}</option>)}
                          </select>
                        </>
                      )}
                    </div>
                  );
                })}
              </div>

              {candidateExtra.length > 0 && (
                <>
                  <div className="cb-label" style={{ marginTop: 14 }}>
                    커스텀 필드로 보존 — 핵심 외 컬럼을 그대로 자산에 저장
                    <a className="linkbtn" style={{ marginLeft: 10 }}
                       onClick={() => setImp({ ...imp, extraCols: imp.extraCols.length === candidateExtra.length ? [] : candidateExtra.map((c) => c.index) })}>
                      {imp.extraCols.length === candidateExtra.length ? "모두 해제" : "모두 선택"}
                    </a>
                  </div>
                  <div className="row" style={{ gap: 12, flexWrap: "wrap" }}>
                    {candidateExtra.map((c) => (
                      <label key={c.index} className="row" style={{ gap: 5, fontSize: 12.5 }}>
                        <input type="checkbox" checked={imp.extraCols.includes(c.index)} onChange={() => toggleExtra(c.index)} />
                        {c.header}
                      </label>
                    ))}
                  </div>
                </>
              )}

              {preview && (
                <div className="pre" style={{ marginTop: 14 }}>
                  {`ip       : ${preview.ip}
dept     : ${preview.dept || "—"}
owner    : ${preview.owner || "—"}
contact  : ${preview.contact || "—"}
asset_no : ${preview.asset_no || "—"}
extra    : ${Object.keys(preview.extra).length ? JSON.stringify(preview.extra, null, 0) : "{}"}`}
                </div>
              )}
              <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>
                가져올 행 {records.length}건{skipped > 0 && <span className="err"> · IP 없어 제외 {skipped}행</span>}
              </div>

              <div style={{ overflowX: "auto", border: "1px solid var(--line)", borderRadius: 8, marginTop: 12 }}>
                <table className="tbl">
                  <thead><tr>{imp.cols.map((c) => <th key={c.index}>{c.letter}: {c.header}</th>)}</tr></thead>
                  <tbody>
                    {(imp.cols[0]?.values || []).slice(0, 5).map((_, i) => (
                      <tr key={i}>{imp.cols.map((c) => <td key={c.index}>{c.values[i]}</td>)}</tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="row" style={{ marginTop: 12 }}>
                <button className="primary" disabled={imp.mapping.ip == null} onClick={doImport}>가져오기 ({records.length}건)</button>
                <button onClick={() => setImp(null)}>취소</button>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="panel">
        <div className="row" style={{ marginBottom: 12 }}>
          <h3 style={{ margin: 0 }}>자산 목록 · {filtered.length}{q && `/${assets.length}`}건</h3>
          <input style={{ marginLeft: "auto", minWidth: 220 }} placeholder="검색 (IP/부서/담당/연락처/커스텀)"
                 value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead><tr><th>IP</th><th>호스트명</th><th>부서</th><th>담당자</th><th>연락처</th><th>자산번호</th><th>커스텀</th></tr></thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td className="empty" colSpan={7}>{assets.length ? "검색 결과 없음" : "자산 없음"}</td></tr>
              ) : filtered.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.ip}</td><td>{a.hostname}</td>
                  <td>{a.dept}</td><td>{a.owner}</td>
                  <td className="mono">{a.contact}</td><td className="mono">{a.asset_no}</td>
                  <td className="muted" style={{ fontSize: 11.5 }}>
                    {a.extra && Object.keys(a.extra).length
                      ? Object.entries(a.extra).map(([k, v]) => `${k}:${v}`).join(" · ") : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
