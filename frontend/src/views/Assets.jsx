import React, { useEffect, useMemo, useRef, useState } from "react";
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

  // ---- 커밋 전 변경 미리보기(diff) — 현재 대장과 비교(신규/수정/동일/대장에만). 업서트 의미와 동일하게
  //      '비어있지 않고 값이 다른' 입력만 변경으로 센다. 기존 가져오기 동작은 그대로(여기선 표시만). ----
  const CMP = [["hostname", "호스트명"], ["dept", "부서"], ["owner", "담당자"], ["contact", "연락처"], ["asset_no", "자산번호"], ["note", "비고"]];
  const existingByIp = useMemo(() => { const m = {}; assets.forEach((a) => { m[a.ip] = a; }); return m; }, [assets]);
  const diff = useMemo(() => {
    const res = { neu: [], changed: [], same: 0, missing: 0 };
    const seen = new Set();
    records.forEach((r) => {
      const ip = (r.ip || "").trim();
      if (!ip) return;
      seen.add(ip);
      const cur = existingByIp[ip];
      if (!cur) { res.neu.push(r); return; }
      const changes = [];
      CMP.forEach(([f, label]) => {
        const nv = (r[f] ?? "").toString().trim();
        if (nv && nv !== (cur[f] ?? "").toString()) changes.push({ label, old: cur[f] || "", neu: nv });
      });
      Object.entries(r.extra || {}).forEach(([k, v]) => {
        const ov = cur.extra ? (cur.extra[k] ?? "") : "";
        if (String(v).trim() && String(v) !== String(ov)) changes.push({ label: k, old: ov, neu: v });
      });
      if (changes.length) res.changed.push({ ip: r.ip, changes }); else res.same += 1;
    });
    res.missing = assets.filter((a) => !seen.has(a.ip)).length;
    return res;
  }, [records, existingByIp, assets]);
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

              {imp.mapping.ip != null && records.length > 0 && (
                <div style={{ marginTop: 12, border: "1px solid var(--line)", borderRadius: 8, padding: "12px 14px" }}>
                  <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
                    <span className="cb-label" style={{ margin: 0 }}>변경 미리보기 — 현재 대장과 비교 (커밋 전, DB 미반영)</span>
                    <span className="row" style={{ gap: 6, fontSize: 12 }}>
                      <span className="pill low">신규 {diff.neu.length}</span>
                      <span className="pill medium">수정 {diff.changed.length}</span>
                      <span className="pill info">동일 {diff.same}</span>
                      {diff.missing > 0 && <span className="pill" title="시트에 없는 기존 자산 — 삭제하지 않고 유지">대장에만 {diff.missing}</span>}
                    </span>
                  </div>
                  {(diff.neu.length === 0 && diff.changed.length === 0) ? (
                    <div className="muted" style={{ fontSize: 12 }}>변경 없음 — 모두 기존과 동일합니다.</div>
                  ) : (
                    <div style={{ maxHeight: 220, overflow: "auto", fontSize: 12 }}>
                      {diff.changed.slice(0, 100).map((c) => (
                        <div key={"c" + c.ip} style={{ padding: "4px 0", borderBottom: "1px solid var(--line-soft)" }}>
                          <span className="pill medium" style={{ fontSize: 10 }}>수정</span>{" "}
                          <span className="mono">{c.ip}</span>{" — "}
                          {c.changes.map((ch, i) => (
                            <span key={i} style={{ marginRight: 8 }}>
                              {ch.label}: <span style={{ color: "var(--high)", textDecoration: "line-through", opacity: 0.7 }}>{ch.old || "—"}</span>
                              {" → "}<span style={{ color: "var(--low)", fontWeight: 600 }}>{ch.neu}</span>
                            </span>
                          ))}
                        </div>
                      ))}
                      {diff.neu.slice(0, 100).map((r) => (
                        <div key={"n" + r.ip} style={{ padding: "4px 0", borderBottom: "1px solid var(--line-soft)" }}>
                          <span className="pill low" style={{ fontSize: 10 }}>신규</span>{" "}
                          <span className="mono">{r.ip}</span>
                          <span className="muted">{"  "}{[r.hostname, r.dept, r.owner].filter(Boolean).join(" · ")}</span>
                        </div>
                      ))}
                      {(diff.changed.length > 100 || diff.neu.length > 100) && (
                        <div className="muted" style={{ paddingTop: 6 }}>…목록 일부만 표시 (요약 칩이 전체 건수)</div>
                      )}
                    </div>
                  )}
                  {diff.missing > 0 && (
                    <div className="muted" style={{ fontSize: 11.5, marginTop: 8 }}>
                      ※ 시트에 없는 기존 자산 {diff.missing}건은 <b>삭제하지 않고 그대로 유지</b>됩니다(가져오기는 업서트).
                    </div>
                  )}
                </div>
              )}

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
