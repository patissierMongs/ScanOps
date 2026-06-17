// 자산대장 엑셀 고급 임포트 — TSnmap 의 검증된 순수 로직을 그대로 포트.
//  · 병합 셀 해제: !merges 를 앵커값으로 채움(세로 forward-fill / 가로 헤더 전파)
//  · 헤더 행 자동 감지: 별칭 매칭 수 최다 행(제목/단일값 행 제외), 동점이면 위쪽
//  · 컬럼 자동 매핑: 정규화 후 별칭 부분일치
// (원본: TSnmap "Column Builder A.dc.html" unmergeFillWs/detectHeaderRow/computeAutoMap)
import * as XLSX from "xlsx";

// 컬럼명 자동 매핑 별칭 (정규화 후 부분일치)
export const ASSET_ALIASES = {
  ip: ["ip", "아이피", "ipaddress", "ipaddr", "ip주소"],
  asset_no: ["자산", "자산번호", "자산코드", "관리번호", "코드", "번호", "asset", "assetid"],
  dept: ["부서", "부서명", "관리부서", "소속", "조직", "팀"],
  owner: ["담당", "담당자", "관리자", "책임", "관리담당", "관리책임", "소유자"],
  contact: ["연락처", "전화", "전화번호", "휴대폰", "휴대전화", "핸드폰", "phone", "mobile", "tel", "contact"],
  hostname: ["호스트", "호스트명", "hostname", "host", "서버명", "장비명"],
};

// 매핑 우선순위 — 백엔드 Asset 필드명과 일치
const MAP_ORDER = ["ip", "asset_no", "dept", "owner", "contact", "hostname"];

// 누락/placeholder 토큰 — 정규화 후 빈값으로 처리
const BLANK_TOKENS = new Set(["", "-", "--", ".", "n/a", "na", "없음", "미지정", "해당없음", "null"]);
export const cleanVal = (v) => {
  const s = String(v == null ? "" : v).trim();
  return BLANK_TOKENS.has(s.toLowerCase()) ? "" : s;
};

export const normHeader = (s) =>
  String(s == null ? "" : s).toLowerCase().replace(/[\s_\-./()]/g, "");

const colLetter = (n) => {
  let s = "";
  n = n + 1;
  while (n > 0) {
    const r = (n - 1) % 26;
    s = String.fromCharCode(65 + r) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
};

// 워크북 시트 → 병합 해제된 AoA. raw:false 로 표시문자열, defval 로 빈칸 채움.
export function unmergeFillWs(ws) {
  const aoa = XLSX.utils.sheet_to_json(ws, { header: 1, raw: false, defval: "" });
  const width = aoa.reduce((m, r) => Math.max(m, (r || []).length), 0);
  aoa.forEach((r) => {
    while (r.length < width) r.push("");
  });
  const merges = ws["!merges"] || [];
  merges.forEach((rng) => {
    const v = (aoa[rng.s.r] || [])[rng.s.c];
    for (let r = rng.s.r; r <= rng.e.r; r++)
      for (let c = rng.s.c; c <= rng.e.c; c++)
        if (aoa[r] !== undefined) aoa[r][c] = v;
  });
  return { aoa, mergeCount: merges.length };
}

// 헤더 행 자동 감지: 별칭 매칭 최다 행(고유값<2 인 제목/병합 행 제외).
export function detectHeaderRow(aoa) {
  aoa = aoa || [];
  let best = 0,
    bestScore = -1;
  const lim = Math.min(aoa.length, 25);
  for (let r = 0; r < lim; r++) {
    const vals = (aoa[r] || []).map((c) => String(c == null ? "" : c).trim()).filter(Boolean);
    const distinct = new Set(vals);
    if (distinct.size < 2) continue;
    let matched = 0;
    distinct.forEach((v) => {
      const t = normHeader(v);
      for (const k in ASSET_ALIASES) {
        if (ASSET_ALIASES[k].some((a) => t.includes(a))) {
          matched++;
          break;
        }
      }
    });
    const score = matched * 10 + distinct.size;
    if (score > bestScore) {
      bestScore = score;
      best = r;
    } // 동점이면 위쪽 행 유지
  }
  return best;
}

// AoA + 헤더행 인덱스 → 컬럼 모델 [{index, letter, header, values[]}]
export function assetColumnsFrom(aoa, headerRow) {
  aoa = aoa || [];
  if (!aoa.length) return [];
  const hr = Math.max(0, Math.min(headerRow | 0, aoa.length - 1));
  const header = aoa[hr] || [];
  const width = aoa.reduce((m, r) => Math.max(m, (r || []).length), 0);
  const dataRows = aoa
    .slice(hr + 1)
    .filter((r) => (r || []).some((c) => String(c == null ? "" : c).trim() !== ""));
  const cols = [];
  for (let c = 0; c < width; c++) {
    cols.push({
      index: c,
      letter: colLetter(c),
      header: String(header[c] == null ? "" : header[c]).trim() || `(빈 컬럼 ${colLetter(c)})`,
      values: dataRows.map((r) => String((r || [])[c] == null ? "" : (r || [])[c]).trim()),
    });
  }
  return cols;
}

// 헤더 텍스트 별칭 매칭으로 컬럼→시스템 필드 추천 매핑(첫 매칭 우선, 중복 배정 금지)
export function computeAutoMap(cols) {
  const m = {};
  cols.forEach((col) => {
    const t = normHeader(col.header);
    if (!t) return;
    for (const k of MAP_ORDER) {
      if (m[k] != null) continue;
      if (ASSET_ALIASES[k].some((a) => t.includes(a))) {
        m[k] = col.index;
        break;
      }
    }
  });
  return m;
}

// 파일 ArrayBuffer → {wb, sheetNames}
export function readWorkbook(buf) {
  const wb = XLSX.read(new Uint8Array(buf), { type: "array", cellDates: true });
  if (!wb.SheetNames || !wb.SheetNames.length) throw new Error("시트를 찾지 못했습니다");
  return { wb, sheetNames: wb.SheetNames.slice() };
}

// 매핑 스펙: 숫자(컬럼 전체) 또는 {col, sep, part}(구분자로 나눈 part 번째).
export function normalizeSpec(spec) {
  if (spec == null) return null;
  if (typeof spec === "number") return { col: spec, sep: "", part: null };
  return { col: spec.col, sep: spec.sep || "", part: spec.part ?? null };
}

// 한 셀 해석 — 결합셀이면 구분자로 나눠 part 번째, 그리고 누락값 정리.
export function resolveCell(cols, spec, i) {
  const s = normalizeSpec(spec);
  if (!s || !cols[s.col]) return "";
  let val = cols[s.col].values[i] ?? "";
  if (s.sep && s.part != null) {
    const parts = String(val).split(s.sep);
    val = parts[s.part] != null ? parts[s.part] : "";
  }
  return cleanVal(val);
}

const CORE_FIELDS = ["asset_no", "dept", "owner", "contact", "hostname"];

// 매핑 + (선택) 커스텀 컬럼 → 백엔드 Asset 임포트용 레코드 배열(ip 필수).
// mapping[field] = 컬럼번호 또는 {col,sep,part}. extraCols = 보존할 컬럼 index 배열.
export function buildAssetRecords(cols, mapping, extraCols = []) {
  const ipSpec = normalizeSpec(mapping.ip);
  if (!ipSpec || !cols[ipSpec.col]) return [];
  const n = cols[ipSpec.col].values.length;
  const out = [];
  for (let i = 0; i < n; i++) {
    const ip = resolveCell(cols, mapping.ip, i);
    if (!ip) continue;
    const rec = { ip, asset_no: "", dept: "", owner: "", contact: "", hostname: "", extra: {} };
    for (const k of CORE_FIELDS) {
      if (mapping[k] != null) rec[k] = resolveCell(cols, mapping[k], i);
    }
    for (const idx of extraCols) {
      const col = cols[idx];
      if (!col) continue;
      const v = cleanVal(col.values[i]);
      if (v) rec.extra[col.header] = v;
    }
    out.push(rec);
  }
  return out;
}

export const ASSET_MAP_FIELDS = [
  { key: "ip", label: "IP 주소", req: true },
  { key: "asset_no", label: "자산번호", req: false },
  { key: "hostname", label: "호스트명", req: false },
  { key: "dept", label: "부서", req: false },
  { key: "owner", label: "담당자", req: false },
  { key: "contact", label: "연락처", req: false },
];
