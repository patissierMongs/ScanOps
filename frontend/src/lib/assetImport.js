// 자산대장 엑셀 고급 임포트 — TSnmap 의 검증된 순수 로직을 그대로 포트.
//  · 병합 셀 해제: !merges 를 앵커값으로 채움(세로 forward-fill / 가로 헤더 전파)
//  · 헤더 행 자동 감지: 별칭 매칭 수 최다 행(제목/단일값 행 제외), 동점이면 위쪽
//  · 컬럼 자동 매핑: 정규화 후 별칭 부분일치
// (원본: TSnmap "Column Builder A.dc.html" unmergeFillWs/detectHeaderRow/computeAutoMap)
import * as XLSX from "xlsx";

const MAX_SHEET_ROWS = 100000;
const MAX_SHEET_COLS = 512;
const MAX_SHEET_CELLS = 2_000_000;
const MAX_WORKBOOK_BYTES = 25 * 1024 * 1024;
const MAX_WORKBOOK_EXPANDED_BYTES = 100 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 10_000;

const sheetLimitError = () =>
  new Error("시트가 처리 한도(100,000행, 512열, 2,000,000셀)를 초과했습니다");

const validateGrid = (rows, cols) => {
  if (!Number.isSafeInteger(rows) || !Number.isSafeInteger(cols) || rows < 0 || cols < 0 ||
      rows > MAX_SHEET_ROWS || cols > MAX_SHEET_COLS || rows * cols > MAX_SHEET_CELLS) {
    throw sheetLimitError();
  }
};

const asBytes = (buf) => {
  if (buf instanceof Uint8Array) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (ArrayBuffer.isView(buf)) return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  return new Uint8Array(buf);
};

// XLSX는 ZIP이므로 SheetJS가 압축을 풀기 전에 중앙 디렉터리의 총 해제 크기를 제한한다.
// XLS/CSV는 ZIP이 아니므로 파일 크기를 먼저 제한한다.
export function validateWorkbookArchive(buf, maxExpandedBytes = MAX_WORKBOOK_EXPANDED_BYTES) {
  const bytes = asBytes(buf);
  if (bytes.byteLength > MAX_WORKBOOK_BYTES) {
    throw new Error("자산 파일은 25MB 이하만 가져올 수 있습니다");
  }
  const startsWithLocalHeader = bytes.byteLength >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b &&
    bytes[2] === 0x03 && bytes[3] === 0x04;
  if (bytes.byteLength < 22) {
    if (startsWithLocalHeader) throw new Error("손상된 XLSX ZIP 구조입니다");
    return bytes;
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const minEocd = Math.max(0, bytes.byteLength - 22 - 0xffff);
  let eocd = -1;
  for (let pos = bytes.byteLength - 22; pos >= minEocd; pos--) {
    if (view.getUint32(pos, true) === 0x06054b50 &&
        pos + 22 + view.getUint16(pos + 20, true) === bytes.byteLength) {
      eocd = pos;
      break;
    }
  }
  if (eocd < 0) {
    if (startsWithLocalHeader) throw new Error("손상된 XLSX ZIP 구조입니다");
    return bytes;
  }
  // ZIP은 실행파일 등 임의 prefix를 허용하지만 SheetJS도 이를 열 수 있다. 그런 파일을 XLS/CSV로
  // 오인해 압축 해제 사전검사를 우회하지 않도록 EOCD가 있으면 정규 XLSX 시작 시그니처를 강제한다.
  if (!startsWithLocalHeader) {
    throw new Error("XLSX ZIP 앞에 허용되지 않는 데이터가 있습니다");
  }

  const diskNumber = view.getUint16(eocd + 4, true);
  const centralDisk = view.getUint16(eocd + 6, true);
  const diskEntryCount = view.getUint16(eocd + 8, true);
  const entryCount = view.getUint16(eocd + 10, true);
  const centralSize = view.getUint32(eocd + 12, true);
  const centralOffset = view.getUint32(eocd + 16, true);
  if (diskNumber !== 0 || centralDisk !== 0 || diskEntryCount !== entryCount ||
      entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff ||
      entryCount > MAX_ZIP_ENTRIES || centralOffset + centralSize > eocd) {
    throw new Error("지원하지 않거나 손상된 XLSX ZIP 구조입니다");
  }

  let expanded = 0;
  let pos = centralOffset;
  const centralEnd = centralOffset + centralSize;
  for (let i = 0; i < entryCount; i++) {
    if (pos + 46 > centralEnd || view.getUint32(pos, true) !== 0x02014b50) {
      throw new Error("손상된 XLSX ZIP 중앙 디렉터리입니다");
    }
    expanded += view.getUint32(pos + 24, true);
    if (expanded > maxExpandedBytes) {
      throw new Error(`XLSX 압축 해제 크기가 처리 한도(${maxExpandedBytes} bytes)를 초과했습니다`);
    }
    const nameLength = view.getUint16(pos + 28, true);
    const extraLength = view.getUint16(pos + 30, true);
    const commentLength = view.getUint16(pos + 32, true);
    pos += 46 + nameLength + extraLength + commentLength;
  }
  if (pos !== centralEnd) throw new Error("손상된 XLSX ZIP 중앙 디렉터리입니다");
  return bytes;
}

const startsWith = (bytes, signature) =>
  bytes.byteLength >= signature.length && signature.every((value, index) => bytes[index] === value);

function textEncoding(bytes) {
  if (startsWith(bytes, [0xff, 0xfe])) {
    return { offset: 2, stride: 2, littleEndian: true };
  }
  if (startsWith(bytes, [0xfe, 0xff])) {
    return { offset: 2, stride: 2, littleEndian: false };
  }
  return {
    offset: startsWith(bytes, [0xef, 0xbb, 0xbf]) ? 3 : 0,
    stride: 1,
    littleEndian: true,
  };
}

function scanDelimitedGrid(bytes, separator, encoding, {
  enforce = false,
  maxBytes = Number.POSITIVE_INFINITY,
} = {}) {
  const { offset, stride, littleEndian } = encoding;
  const codeUnitAt = (index) => {
    if (stride === 1) return bytes[index];
    if (index + 1 >= bytes.byteLength) return -1;
    return littleEndian
      ? bytes[index] | (bytes[index + 1] << 8)
      : (bytes[index] << 8) | bytes[index + 1];
  };

  let rows = 0;
  let columns = 1;
  let maxColumns = 0;
  let firstDelimitedRow = null;
  let firstDelimitedColumns = 1;
  let rowStarted = false;
  let fieldStart = true;
  let quoted = false;

  const finishRow = () => {
    if (firstDelimitedRow == null && columns > 1) {
      firstDelimitedRow = rows;
      firstDelimitedColumns = columns;
    }
    rows += 1;
    maxColumns = Math.max(maxColumns, columns);
    if (enforce) validateGrid(rows, maxColumns);
    columns = 1;
    rowStarted = false;
    fieldStart = true;
  };

  const end = Math.min(bytes.byteLength, offset + maxBytes);
  for (let index = offset; index < end; index += stride) {
    const code = codeUnitAt(index);
    if (quoted) {
      rowStarted = true;
      if (code === 0x22) {
        if (codeUnitAt(index + stride) === 0x22) index += stride;
        else quoted = false;
      }
      continue;
    }
    if (code === 0x22 && fieldStart) {
      quoted = true;
      rowStarted = true;
      fieldStart = false;
      continue;
    }
    if (code === 0x0a || code === 0x0d) {
      finishRow();
      if (code === 0x0d && codeUnitAt(index + stride) === 0x0a) index += stride;
      continue;
    }
    rowStarted = true;
    if (code === separator) {
      columns += 1;
      fieldStart = true;
      if (enforce && columns > MAX_SHEET_COLS) throw sheetLimitError();
    } else {
      fieldStart = false;
    }
  }
  if (rowStarted) finishRow();
  else if (enforce) validateGrid(rows, maxColumns);
  return { firstDelimitedRow, firstDelimitedColumns, maxColumns };
}

function validateDelimitedWorkbookGrid(bytes) {
  // ZIP XLSX and OLE/CFB XLS have their own structural checks. Text workbooks need a grid
  // bound before SheetJS materializes cells; the post-parse !ref check is too late for a
  // permitted 25 MB CSV with millions of columns.
  if (startsWith(bytes, [0x50, 0x4b, 0x03, 0x04]) ||
      startsWith(bytes, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) return;

  const encoding = textEncoding(bytes);
  // Pick the separator from the earliest delimited record, then force SheetJS to use that
  // exact separator. This avoids treating punctuation inside a later data cell as a second
  // delimiter while keeping the preflight and parser on the same grid contract.
  const separators = [0x2c, 0x09, 0x3b, 0x7c]; // comma, tab, semicolon, pipe
  const detectionBytes = 1024 * 1024;
  let selected = separators[0];
  let selectedStats = null;
  for (const separator of separators) {
    const stats = scanDelimitedGrid(bytes, separator, encoding, { maxBytes: detectionBytes });
    if (stats.firstDelimitedRow == null) continue;
    if (
      selectedStats == null
      || stats.firstDelimitedRow < selectedStats.firstDelimitedRow
      || (stats.firstDelimitedRow === selectedStats.firstDelimitedRow
        && stats.firstDelimitedColumns > selectedStats.firstDelimitedColumns)
    ) {
      selected = separator;
      selectedStats = stats;
    }
  }
  scanDelimitedGrid(bytes, selected, encoding, { enforce: true });
  return String.fromCharCode(selected);
}

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
  const merges = ws?.["!merges"] || [];
  if (ws?.["!ref"]) {
    const range = XLSX.utils.decode_range(ws["!ref"]);
    validateGrid(range.e.r + 1, range.e.c + 1);
  }
  let mergedCells = 0;
  merges.forEach((rng) => {
    if (!rng?.s || !rng?.e || rng.s.r < 0 || rng.s.c < 0 ||
        rng.e.r < rng.s.r || rng.e.c < rng.s.c) throw sheetLimitError();
    validateGrid(rng.e.r + 1, rng.e.c + 1);
    mergedCells += (rng.e.r - rng.s.r + 1) * (rng.e.c - rng.s.c + 1);
    if (mergedCells > MAX_SHEET_CELLS) throw sheetLimitError();
  });
  const aoa = XLSX.utils.sheet_to_json(ws, { header: 1, raw: false, defval: "" });
  const width = aoa.reduce((m, r) => Math.max(m, (r || []).length), 0);
  aoa.forEach((r) => {
    while (r.length < width) r.push("");
  });
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
  const bytes = validateWorkbookArchive(buf);
  const separator = validateDelimitedWorkbookGrid(bytes);
  const wb = XLSX.read(bytes, {
    type: "array",
    cellDates: true,
    ...(separator ? { FS: separator } : {}),
  });
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

// 알려진 핵심 필드(백엔드 Asset 컬럼) — IP 외에는 가져오기 화면에서 자유롭게 넣고 뺄 수 있다.
export const ASSET_KNOWN_FIELDS = [
  { key: "asset_no", label: "자산번호" },
  { key: "hostname", label: "호스트명" },
  { key: "dept", label: "부서" },
  { key: "owner", label: "담당자" },
  { key: "contact", label: "연락처" },
  { key: "note", label: "비고" },
];
const KNOWN_KEYS = new Set(ASSET_KNOWN_FIELDS.map((f) => f.key));
const ASSET_LABELS = new Map(ASSET_KNOWN_FIELDS.map((f) => [f.key, f.label]));
const hasOwn = (value, key) => Object.prototype.hasOwnProperty.call(value, key);

const trimmed = (value) => typeof value === "string" ? value.trim() : value;

// 백엔드의 model_fields_set + extra key merge 규칙과 같은 순수 함수.
// 매핑되지 않은 핵심 필드는 유지하고, 매핑된 빈칸 및 빈 extra 값만 삭제/초기화한다.
export function mergeAssetRecord(current, record) {
  const merged = current
    ? { ...current, extra: { ...(current.extra || {}) } }
    : {
        ip: String(record.ip || "").trim(), hostname: "", dept: "", owner: "",
        contact: "", asset_no: "", note: "", extra: {},
      };
  ASSET_KNOWN_FIELDS.forEach(({ key }) => {
    if (hasOwn(record, key)) merged[key] = trimmed(record[key]);
  });
  if (hasOwn(record, "extra")) {
    Object.entries(record.extra || {}).forEach(([rawKey, rawValue]) => {
      const key = String(rawKey).trim();
      if (!key) return;
      const value = trimmed(rawValue);
      if (value == null || value === "") delete merged.extra[key];
      else merged.extra[key] = value;
    });
  }
  return merged;
}

const displayValue = (value) => {
  if (value == null) return "";
  return typeof value === "object" ? JSON.stringify(value) : String(value);
};

const sameValue = (a, b) => JSON.stringify(a ?? "") === JSON.stringify(b ?? "");

// 중복 IP도 백엔드와 같은 순서로 접어 최종 업서트 결과 하나만 비교한다.
export function diffAssetRecords(records, assets) {
  const existing = new Map();
  (assets || []).forEach((asset) => {
    const ip = String(asset.ip || "");
    const previous = existing.get(ip);
    if (!previous || Number(asset.id || 0) >= Number(previous.id || 0)) existing.set(ip, asset);
  });

  const finalByIp = new Map();
  const order = [];
  const seen = new Set();
  (records || []).forEach((record) => {
    const ip = String(record.ip || "").trim();
    if (!ip) return;
    if (!seen.has(ip)) order.push(ip);
    seen.add(ip);
    const current = finalByIp.get(ip) || existing.get(ip) || null;
    finalByIp.set(ip, mergeAssetRecord(current, { ...record, ip }));
  });

  const result = { neu: [], changed: [], same: 0, missing: 0 };
  order.forEach((ip) => {
    const current = existing.get(ip);
    const final = finalByIp.get(ip);
    if (!current) {
      result.neu.push(final);
      return;
    }
    const changes = [];
    ASSET_KNOWN_FIELDS.forEach(({ key }) => {
      if (!sameValue(current[key], final[key])) {
        changes.push({ label: ASSET_LABELS.get(key), old: displayValue(current[key]), neu: displayValue(final[key]) });
      }
    });
    const extraKeys = new Set([...Object.keys(current.extra || {}), ...Object.keys(final.extra || {})]);
    extraKeys.forEach((key) => {
      const oldHas = hasOwn(current.extra || {}, key);
      const newHas = hasOwn(final.extra || {}, key);
      if (oldHas !== newHas || !sameValue(current.extra?.[key], final.extra?.[key])) {
        changes.push({ label: key, old: displayValue(current.extra?.[key]), neu: displayValue(final.extra?.[key]) });
      }
    });
    if (changes.length) result.changed.push({ ip, changes });
    else result.same += 1;
  });
  result.missing = (assets || []).filter((asset) => !seen.has(String(asset.ip || ""))).length;
  return result;
}

// 매핑 + (선택) 커스텀 컬럼 → 백엔드 Asset 임포트용 레코드 배열(ip 필수).
// mapping[field] = 컬럼번호 또는 {col,sep,part}. fields = 화면에 표시된 필드 정의([{key,label,custom}]).
// custom 필드는 extra[label] 로 저장. extraCols = 매핑과 별개로 통째 보존할 컬럼 index 배열(extra[header]).
export function buildAssetRecords(cols, mapping, extraCols = [], fields = ASSET_MAP_FIELDS) {
  const ipSpec = normalizeSpec(mapping.ip);
  if (!ipSpec || !cols[ipSpec.col]) return [];
  const n = cols[ipSpec.col].values.length;
  const out = [];
  for (let i = 0; i < n; i++) {
    const ip = resolveCell(cols, mapping.ip, i);
    if (!ip) continue;
    const rec = { ip, extra: {} };
    for (const fld of fields) {
      if (fld.key === "ip" || mapping[fld.key] == null) continue;
      const v = resolveCell(cols, mapping[fld.key], i);
      if (fld.custom) {
        rec.extra[fld.label] = v;                 // 매핑된 빈칸은 해당 extra 키 삭제
      } else if (KNOWN_KEYS.has(fld.key)) {
        rec[fld.key] = v;                         // 매핑된 빈칸은 해당 Asset 필드 초기화
      }
    }
    for (const idx of extraCols) {
      const col = cols[idx];
      if (!col) continue;
      const v = cleanVal(col.values[i]);
      rec.extra[col.header] = v;
    }
    out.push(rec);
  }
  return out;
}

// 가져오기 매핑 UI의 기본 표시 필드(IP 필수 + 자주 쓰는 선택 필드). 사용자가 행을 추가/제거한다.
export const ASSET_MAP_FIELDS = [
  { key: "ip", label: "IP 주소", req: true },
  { key: "asset_no", label: "자산번호", req: false },
  { key: "hostname", label: "호스트명", req: false },
  { key: "dept", label: "부서", req: false },
  { key: "owner", label: "담당자", req: false },
  { key: "contact", label: "연락처", req: false },
];

// 새 import 세션의 필드 목록 — 기본 정의를 깊은 복사(상태 변형 방지).
export const defaultMapFields = () => ASSET_MAP_FIELDS.map((f) => ({ ...f }));
